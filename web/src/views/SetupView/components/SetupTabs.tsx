import React from "react";
import { Tabs, Tab, H5, Button, Icon, Intent, Tag, Callout } from "@blueprintjs/core";
import { Globe, AppWindowMac, Monitor, Terminal, Smartphone, Router } from "lucide-react";
import { clsx } from "clsx";
import { useTranslation } from "react-i18next";
import type {  RegionConfigItem  } from "../../../config/regions";
import { generateMobileConfig, formatProfileLabel, extractDomain } from "../../../utils/mobileconfig";

export interface SetupTabsProps {
  isMobile: boolean;
  copyToClipboard: (text: string) => void;
  profileKey: string;
  profileName?: string;
  accessPointName?: string;
  allRegions: Record<string, RegionConfigItem>;
  selectedRegion: string;
  currentIps: { ip: string; area: string | null }[];
}

/** RouterOS commands that do not vary between deployments. */
const MIKROTIK_CERT_CMD = `/ip dns set servers=1.1.1.1 use-doh-server="" verify-doh-cert=no
/tool fetch url=https://curl.se/ca/cacert.pem
/certificate import file-name=cacert.pem passphrase=""
/certificate print`;

const MIKROTIK_REDIRECT_CMD = `/ip firewall nat add chain=dstnat protocol=udp dst-port=53 action=redirect to-ports=53 in-interface-list=LAN
/ip firewall nat add chain=dstnat protocol=tcp dst-port=53 action=redirect to-ports=53 in-interface-list=LAN`;

/** A copyable terminal block with a hover copy button. */
const CommandBlock: React.FC<{ text: string; copyToClipboard: (t: string) => void }> = ({
  text,
  copyToClipboard,
}) => (
  <div className="relative group">
    <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-gray-200 dark:border-gray-700 whitespace-pre">
      <code>{text}</code>
    </pre>
    <Button
      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity"
      icon="duplicate"
      minimal
      small
      onClick={() => copyToClipboard(text)}
    />
  </div>
);

export const SetupTabs: React.FC<SetupTabsProps> = ({
  isMobile,
  copyToClipboard,
  profileKey,
  profileName,
  accessPointName,
  allRegions,
  selectedRegion,
  currentIps,
}) => {
  const { t } = useTranslation();

  // MikroTik: the DoH endpoint is this origin plus the access key, and RouterOS
  // needs a static A record for the hostname or it cannot resolve the resolver.
  const dohHost = window.location.hostname;
  const dohUrl = `${window.location.origin}/${profileKey}`;
  const pinnedIp = currentIps.find((entry) => entry.ip && !entry.ip.includes(":"))?.ip ?? "";
  const mikrotikStaticCmd = `/ip dns static add name=${dohHost} address=${pinnedIp || "<edge-ip-from-above>"} type=A`;
  // servers="" matters: RouterOS keeps the plain-DNS list as a fallback, so
  // leaving 1.1.1.1 there would silently resolve every LAN query through an
  // unfiltered resolver whenever DoH is unavailable. The static A record added
  // in the previous step is what keeps the DoH hostname resolvable without it.
  const mikrotikDohCmd = `/ip dns set servers="" use-doh-server="${dohUrl}" verify-doh-cert=yes\n/ip dns cache flush`;

  return (
    <Tabs
      id="setup-tabs"
      renderActiveTabPanelOnly={true}
      vertical={!isMobile} // 移动端使用水平 Tab
      size="large"
      className={clsx(
        "bg-white dark:bg-gray-900 p-4 md:p-6 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm setup-tabs-container",
        isMobile && [
          "[&_.bp6-tab-list]:overflow-x-auto!",
          "[&_.bp6-tab-list]:flex-nowrap!",
          "[&_.bp6-tab-list]:pb-1",
          "[&_.bp6-tab-list]:scrollbar-none",
          "[&_.bp6-tab-list]:[-ms-overflow-style:none]",
          "[&_.bp6-tab-list::-webkit-scrollbar]:hidden",
          "[&_.bp6-tab]:shrink-0",
        ]
      )}
    >
      <Tab
        id="browsers"
        title={
          <span>
            <Globe size={16} className="inline mr-2" />
            {t("setup.browsers")}
          </span>
        }
        panel={
          <div className="space-y-4 md:ml-4 mt-4 md:mt-0">
            <H5 className="font-bold">{t("setup.browserTitle")}</H5>
            <p className="text-sm">{t("setup.browserSteps")}</p>
            <p className="text-[10px] opacity-50 cursor-pointer" onClick={() => copyToClipboard("chrome://settings/security")}>
              {t("setup.browserTips", "or copy this URL to the address bar: ") + "chrome://settings/security"}
            </p>
          </div>
        }
      />

      <Tab
        id="apple"
        title={
          <span>
            <AppWindowMac size={16} className="inline mr-2" />
            {t("setup.apple")}
          </span>
        }
        panel={
          <div className="space-y-4 md:ml-4 mt-4 md:mt-0">
            <H5 className="font-bold">{t("setup.appleTitle")}</H5>
            <p className="text-sm">{t("setup.appleDesc")}</p>
            <p className="text-[10px] opacity-50 text-center">{t("setup.appleWarning")}</p>
            <div className="p-6 bg-gray-50 dark:bg-gray-800 rounded-xl border border-dashed border-gray-300 dark:border-gray-700 flex flex-col items-center justify-center">
              <Icon icon="document" size={40} className="opacity-20 mb-4" />
              <Button
                intent={Intent.PRIMARY}
                text={t("setup.downloadConfig")}
                icon="download"
                onClick={() => {
                  const xml = generateMobileConfig({
                    profileKey,
                    profileName,
                    accessPointName,
                    origin: window.location.origin,
                  });
                  const blob = new Blob([xml], { type: "application/x-apple-aspen-config" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  const label = formatProfileLabel(profileName, accessPointName);
                  const domain = extractDomain(window.location.origin);
                  const fileTag = (label || domain)
                    .replace(/[^a-zA-Z0-9_\-\u4e00-\u9fa5]/g, "_")
                    .replace(/_+/g, "_")
                    .replace(/^_|_$/g, "");
                  a.download = `dns_worker-${fileTag}-${profileKey}.mobileconfig`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              />
            </div>
            <p className="text-[10px] opacity-50 mt-4! text-center">{t("setup.appleInstallHint")}</p>
          </div>
        }
      />
      <Tab
        id="windows"
        title={
          <span>
            <Monitor size={16} className="inline mr-2" />
            {t("setup.windows")}
          </span>
        }
        panel={
          <div className="space-y-4 md:ml-4 mt-4 md:mt-0">
            <H5 className="font-bold">
              {t("setup.windowsTitle", {
                region: allRegions[selectedRegion]?.label || t("setup.otherRegion"),
              })}
            </H5>
            <ol className="list-decimal list-inside space-y-4 text-sm leading-relaxed">
              <li>
                <a href="ms-settings:network-status">{t("setup.windowsStep0")}</a>
              </li>
              <li>{t("setup.windowsStep1")}</li>
              <li>
                {t("setup.windowsStep2")}
                <div className="mt-2 flex flex-wrap gap-2">
                  {currentIps.map((item) => (
                    <div key={item.ip} className="flex flex-col gap-1">
                      <Tag minimal interactive onClick={() => copyToClipboard(item.ip)} icon="duplicate" className="font-mono">
                        {item.ip}
                      </Tag>
                      {!isMobile && <span className="text-[9px] opacity-40 ml-1">{item.area}</span>}
                    </div>
                  ))}
                </div>
              </li>
              <li>{t("setup.windowsStep3")}</li>
              <li>{t("setup.windowsStep4")}</li>
            </ol>
          </div>
        }
      />

      <Tab
        id="linux"
        title={
          <span>
            <Terminal size={16} className="inline mr-2" />
            {t("setup.linux")}
          </span>
        }
        panel={
          <div className="space-y-4 md:ml-4 mt-4 md:mt-0">
            <H5 className="font-bold">{t("setup.linuxTitle")}</H5>
            <p className="text-sm">{t("setup.linuxDesc")}</p>

            <div className="mt-4">
              <p className="text-sm font-bold mb-2">{t("setup.linuxStep1")}</p>
              <div className="relative group">
                <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-gray-200 dark:border-gray-700">
                  <code>{`curl -sL "${window.location.origin}/setup.sh?key=${profileKey}&origin=${window.location.origin}" | sudo bash`}</code>
                </pre>
                <Button
                  className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity"
                  icon="duplicate"
                  minimal
                  small
                  onClick={() => {
                    copyToClipboard(`curl -sL "${window.location.origin}/setup.sh?key=${profileKey}&origin=${window.location.origin}" | sudo bash`);
                  }}
                />
              </div>
            </div>

            <div className="mt-4">
              <p className="text-sm font-bold">{t("setup.linuxStep2")}</p>
            </div>
          </div>
        }
      />

      <Tab
        id="android"
        title={
          <span>
            <Smartphone size={16} className="inline mr-2" />
            {t("setup.android")}
          </span>
        }
        panel={
          <div className="space-y-4 md:ml-4 mt-4 md:mt-0">
            <H5 className="font-bold">{t("setup.androidTitle")}</H5>
            <p className="text-sm">{t("setup.androidDesc")}</p>

            <div className="p-4 bg-gray-50 dark:bg-gray-800/60 rounded-xl border border-gray-200 dark:border-gray-700 space-y-2">
              <div className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                {t("setup.androidDotTitle", "私有 DNS (DoT - Serverfull 模式)")}
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {t("setup.androidDotDesc", "设置 > 网络和互联网 > 私有 DNS > 提供商主机名：")}
              </p>
              <div className="flex items-center gap-2">
                <Tag
                  minimal
                  interactive
                  onClick={() => copyToClipboard(`${profileKey}.${window.location.hostname}`)}
                  icon="duplicate"
                  className="font-mono text-sm py-1 px-3"
                  intent={Intent.PRIMARY}
                >
                  {`${profileKey}.${window.location.hostname}`}
                </Tag>
              </div>
            </div>

            <Callout intent={Intent.PRIMARY} icon="info-sign" className="text-xs">
              {t("setup.androidWarning")}
            </Callout>
          </div>
        }
      />

      <Tab
        id="mikrotik"
        title={
          <span>
            <Router size={16} className="inline mr-2" />
            {t("setup.mikrotik", "MikroTik")}
          </span>
        }
        panel={
          <div className="space-y-4 md:ml-4 mt-4 md:mt-0">
            <H5 className="font-bold">{t("setup.mikrotikTitle", "MikroTik RouterOS (network-wide)")}</H5>
            <p className="text-sm">
              {t("setup.mikrotikDesc", "Applies to every device on the LAN. Requires RouterOS 6.47 or later. Run these in a RouterOS terminal, in order.")}
            </p>

            <Callout intent={Intent.PRIMARY} icon="info-sign" className="text-xs">
              {t("setup.mikrotikOrderWarning", "Order matters: the router needs working DNS to download the CA bundle, so plain DNS is set first and DoH is switched on last.")}
            </Callout>

            <Callout intent={Intent.WARNING} icon="warning-sign" className="text-xs mt-2">
              {t("setup.mikrotikNoFallbackWarning", "The last step clears the plain DNS servers so queries cannot leak to an unfiltered resolver. That also leaves DoH as the only way the router can resolve anything: if its clock is wrong after a power loss, certificate validation fails and there is no plain resolver left to reach an NTP server. Keep console access, or re-add a server temporarily while recovering.")}
            </Callout>

            <div className="mt-4">
              <p className="text-sm font-bold mb-2">{t("setup.mikrotikStep1", "1. Trust public CAs (RouterOS ships with no CA store)")}</p>
              <CommandBlock text={MIKROTIK_CERT_CMD} copyToClipboard={copyToClipboard} />
              <p className="text-xs opacity-60 mt-1">
                {t("setup.mikrotikStep1Hint", "Without this, certificate verification fails and DoH silently stops resolving.")}
              </p>
            </div>

            <div className="mt-4">
              <p className="text-sm font-bold mb-2">{t("setup.mikrotikStep2", "2. Pin this server's address (avoids a chicken-and-egg lookup)")}</p>
              <CommandBlock text={mikrotikStaticCmd} copyToClipboard={copyToClipboard} />
              {!pinnedIp && (
                <p className="text-xs opacity-60 mt-1">
                  {t("setup.mikrotikStep2Hint", "Replace the address with one of the IPs shown in the region section above.")}
                </p>
              )}
            </div>

            <div className="mt-4">
              <p className="text-sm font-bold mb-2">{t("setup.mikrotikStep3", "3. Enable DNS-over-HTTPS")}</p>
              <CommandBlock text={mikrotikDohCmd} copyToClipboard={copyToClipboard} />
            </div>

            <div className="mt-4">
              <p className="text-sm font-bold mb-2">{t("setup.mikrotikStep4", "4. Force LAN clients through the router (optional)")}</p>
              <CommandBlock text={MIKROTIK_REDIRECT_CMD} copyToClipboard={copyToClipboard} />
              <p className="text-xs opacity-60 mt-1">
                {t("setup.mikrotikStep4Hint", "Stops devices with hardcoded resolvers from bypassing filtering.")}
              </p>
            </div>

            <Callout intent={Intent.WARNING} icon="warning-sign" className="text-xs">
              {t("setup.mikrotikAttributionWarning", "All LAN devices share this access point, so logs show the router rather than individual clients. Set up devices individually if you need per-device visibility.")}
            </Callout>
          </div>
        }
      />
    </Tabs>
  );
};
