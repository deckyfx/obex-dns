import { Env, User, ExecutionContext } from '../types';
import { getOrCreateJwtSecret, readCsrfCookie } from './auth';
import { importJwtSecret, verifyJWT } from './jwt';
import { SessionModel } from '../models/session';
import { UserModel } from '../models/user';

/**
 * Applies standard security headers and Content-Security-Policy (CSP) with a nonce.
 */
export function applySecurityHeaders(response: Response, nonce: string): Response {
  const newHeaders = new Headers(response.headers);
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('X-Frame-Options', 'DENY');
  newHeaders.set('X-XSS-Protection', '1; mode=block');
  newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  if (!newHeaders.has('Content-Security-Policy')) {
    newHeaders.set(
      'Content-Security-Policy',
      `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://challenges.cloudflare.com https://static.cloudflareinsights.com; script-src-attr 'unsafe-inline'; frame-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://icons.duckduckgo.com; connect-src 'self' https://challenges.cloudflare.com https://cloudflare-dns.com https://1.1.1.1;`
    );
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

/**
 * Parses authorization header and verifies JWT to get the current authenticated user.
 */
interface CachedAuthUser {
  user: User;
  expiresAt: number;
}
const authUserMemoryCache = new Map<string, CachedAuthUser>();

export function invalidateAuthUserCache(sessionId: string): void {
  authUserMemoryCache.delete(sessionId);
}

/**
 * Minimum seconds between session last-active writes. This is a liveness
 * timestamp used for the idle-lock check, so second-level precision buys
 * nothing while costing a D1 write on every request.
 */
const SESSION_ACTIVITY_THROTTLE_SEC = 60;

/**
 * Activity this isolate has observed per session, as a unix timestamp.
 *
 * The idle-lock check reads session.last_active_at from D1. When the throttled
 * write below fails - the rows_written quota being the realistic cause - that
 * column stops advancing even while the user keeps clicking, and the check
 * would lock a session that is in continuous use.
 *
 * This records the activity the write was meant to persist, so the check can
 * take the later of the two. It is deliberately keyed by session: an earlier
 * attempt used a single isolate-wide "writes are failing" flag, which let one
 * user's transient failure suppress the idle lock for every other session in
 * the isolate - a security control failing open on unrelated evidence.
 *
 * Isolate-local and lossy by design. A session with no entry falls back to the
 * D1 value, so a genuinely idle session still locks.
 */
const observedActivity = new Map<string, number>();

/** Cap on {@link observedActivity} so a long-lived isolate cannot grow it without bound. */
const OBSERVED_ACTIVITY_MAX = 5000;

function recordObservedActivity(sessionId: string, atSeconds: number): void {
  if (observedActivity.size >= OBSERVED_ACTIVITY_MAX && !observedActivity.has(sessionId)) {
    // Map preserves insertion order, so the first key is the oldest entry.
    const oldest = observedActivity.keys().next();
    if (!oldest.done) observedActivity.delete(oldest.value);
  }
  observedActivity.set(sessionId, atSeconds);
}

export async function getCurrentUser(
  request: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<User | null> {
  const authHeader = request.headers.get("Authorization") || "";
  let accessToken = "";
  if (authHeader.startsWith("Bearer ")) {
    accessToken = authHeader.slice(7);
  }

  if (!accessToken) {
    return null;
  }

  try {
    const secret = await getOrCreateJwtSecret(env);
    const jwtKey = await importJwtSecret(secret);
    const payload = await verifyJWT<{ userId: string; role: string; sessionId: string; exp: number }>(
      accessToken,
      jwtKey
    );
    if (payload) {
      // Check 10-second micro-cache to collapse parallel dashboard requests into 1 D1 read
      const cached = authUserMemoryCache.get(payload.sessionId);
      if (cached && cached.expiresAt > Date.now()) {
        return cached.user;
      }

      // Validate session in database (enforce statefulness and idle timeout)
      const sessionModel = new SessionModel(env.DB);
      const session = await sessionModel.getSession(payload.sessionId);
      if (!session) {
        authUserMemoryCache.delete(payload.sessionId);
        return null;
      }

      const now = Math.floor(Date.now() / 1000);
      const lastActive = session.last_active_at || session.created_at;

      // Single Source of Truth inactivity check on server
      const userModel = new UserModel(env.DB, env);
      const dbUser = await userModel.getById(payload.userId);

      // Judge idleness on the later of D1's timestamp and the activity this
      // isolate has actually seen, so a failing last-active write cannot lock a
      // session that is in continuous use. Scoped to this session only.
      const effectiveLastActive = Math.max(
        lastActive,
        observedActivity.get(payload.sessionId) ?? 0
      );

      if (dbUser && dbUser.pin_hash && !session.is_paused) {
        const timeoutSeconds = (dbUser.session_lock_timeout || 15) * 60;
        if (now - effectiveLastActive > timeoutSeconds) {
          await sessionModel.pauseSession(session.id);
          session.is_paused = 1;
        }
      }

      if (session.is_paused) {
        const pausedUser: User = { id: payload.userId, username: dbUser?.username || "", role: payload.role as any, isPaused: true, sessionId: payload.sessionId };
        return pausedUser;
      }

      // Refresh the session's last-active timestamp, throttled.
      //
      // Deliberately NOT awaited inline. This write used to block the auth
      // path, which made it an availability risk: when D1 rejects the write -
      // the daily rows_written quota being the realistic cause - it throws,
      // the outer catch swallows it, getCurrentUser returns null and the user
      // is answered 401. A liveness timestamp must never fail a request.
      //
      // Handed to waitUntil where available so it still completes after the
      // response is sent, rather than being cancelled with the request.
      if (now - lastActive > SESSION_ACTIVITY_THROTTLE_SEC) {
        // Record it locally first: this is what keeps the idle check honest if
        // the write below never lands.
        recordObservedActivity(payload.sessionId, now);
        const write = sessionModel
          .updateLastActive(session.id, now)
          .catch((e) => console.error("[Auth] session last-active write failed:", e));
        if (ctx) {
          ctx.waitUntil(write);
        }
      }

      const validatedUser: User = { id: payload.userId, username: dbUser?.username || "", role: payload.role as any, sessionId: payload.sessionId };

      // Cache for 10 seconds (cap size at 100)
      if (authUserMemoryCache.size > 100) {
        const oldestKey = authUserMemoryCache.keys().next().value;
        if (oldestKey) authUserMemoryCache.delete(oldestKey);
      }
      authUserMemoryCache.set(payload.sessionId, {
        user: validatedUser,
        expiresAt: Date.now() + 10_000
      });

      return validatedUser;
    }
  } catch (e) {
    // Ignore verification errors and return null
  }
  return null;
}

/**
 * Validates CSRF double submit cookie against the request header.
 */
export function validateCsrf(request: Request): boolean {
  const cookieHeader = request.headers.get("Cookie") || "";
  const csrfCookie = readCsrfCookie(cookieHeader);
  const csrfHeader = request.headers.get("X-CSRF-Token");
  return !!csrfCookie && !!csrfHeader && csrfCookie === csrfHeader;
}
