export function base64urlEncode(buf: ArrayBuffer | Uint8Array | string): string {
  let stringToEncode = "";
  if (typeof buf === "string") {
    stringToEncode = buf;
  } else {
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) {
      stringToEncode += String.fromCharCode(bytes[i]);
    }
  }
  return btoa(stringToEncode)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Minimum accepted length for JWT_SECRET. At 32 characters a hex secret carries
 * 128 bits, and it rejects the 30-character placeholder used in the setup docs.
 */
export const MIN_JWT_SECRET_LENGTH = 32;

/**
 * Reports whether a JWT_SECRET is present and long enough to be usable.
 * Used by the router so a misconfigured secret surfaces as a configuration
 * error rather than a 500 from deep inside an auth handler.
 */
export function isValidJwtSecret(secret: string | undefined | null): boolean {
  return typeof secret === "string" && secret.trim().length >= MIN_JWT_SECRET_LENGTH;
}

/** Memoised signing key. The secret is constant per isolate. */
let cachedSecret: string | null = null;
let cachedKey: CryptoKey | null = null;

/**
 * Derives the HMAC signing key from JWT_SECRET.
 *
 * The secret is hashed with SHA-256 rather than parsed as hex. Parsing it with
 * `parseInt(pair, 16)` yields NaN for any non-hex pair, and NaN coerces to 0
 * inside a Uint8Array, so a passphrase silently produced a key with far less
 * entropy than the configured secret implied. Hashing accepts any secret format
 * at full strength and matches importKek() in utils/envelope.ts.
 *
 * @throws If the secret is missing or shorter than MIN_JWT_SECRET_LENGTH.
 */
export async function importJwtSecret(secret: string): Promise<CryptoKey> {
  const trimmed = (secret ?? "").trim();
  if (!isValidJwtSecret(trimmed)) {
    throw new Error(
      `JWT_SECRET must be at least ${MIN_JWT_SECRET_LENGTH} characters. ` +
      `Generate one with: openssl rand -hex 32`
    );
  }

  if (cachedKey !== null && cachedSecret === trimmed) {
    return cachedKey;
  }

  const material = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(trimmed)
  );
  const key = await crypto.subtle.importKey(
    "raw",
    material,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign", "verify"]
  );

  cachedSecret = trimmed;
  cachedKey = key;
  return key;
}

export async function signJWT(payload: any, key: CryptoKey): Promise<string> {
  const header = { alg: "HS512", typ: "JWT" };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    stringToUint8Array(dataToSign)
  );
  
  const encodedSignature = base64urlEncode(signatureBuffer);
  return `${dataToSign}.${encodedSignature}`;
}

export async function verifyJWT<T = any>(token: string, key: CryptoKey): Promise<T | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const dataToVerify = `${encodedHeader}.${encodedPayload}`;
  
  const signatureBytes = base64urlDecode(encodedSignature);
  
  const isValid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    stringToUint8Array(dataToVerify)
  );
  
  if (!isValid) return null;
  
  try {
    const payloadBytes = base64urlDecode(encodedPayload);
    const payloadStr = new TextDecoder().decode(payloadBytes);
    const payload = JSON.parse(payloadStr) as any;
    
    // Check expiry
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      return null;
    }
    
    return payload as T;
  } catch (e) {
    return null;
  }
}
