/**
 * Opt-in Z.ai Start Plan auth using the current desktop OAuth session.
 *
 * The official accountProviderRequestAuthService supplies zcodeJwtToken as
 * requestAuth.apiKey for start-plan; oauthCredentialRepo binds that shared
 * token to oauth:active_provider. Read the same material without refreshing,
 * copying, or modifying the desktop login. Verification challenges remain the
 * provider's responsibility; this module does not generate captcha headers.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { ZCODE_CREDS_PATH, zcodePersonalProviderPath } from "../utils.js";
import { readCredentialStoreSync } from "./credential-store.js";

export const START_PLAN_PROVIDER_ID = "account:zai-start-plan";
const LEGACY_PROVIDER_ID = "builtin:zai-start-plan";

export function startPlanEnabled(): boolean {
  return process.env.ZCODE_ACP_START_PLAN === "1";
}

/** Never substitute a business OAuth token or an individual Coding Plan key. */
export function startPlanRequestAuthFor(providerId: string | undefined): { apiKey: string } | null {
  if (!startPlanEnabled()) return null;
  if (providerId !== START_PLAN_PROVIDER_ID && providerId !== LEGACY_PROVIDER_ID) return null;
  // Explicit local disablement wins over the opt-in and catalog fallback.
  try {
    const config = JSON.parse(readFileSync(ZCODE_CREDS_PATH, "utf8")) as {
      provider?: Record<string, { enabled?: boolean }>;
    };
    if (
      config.provider?.[LEGACY_PROVIDER_ID]?.enabled === false ||
      config.provider?.[START_PLAN_PROVIDER_ID]?.enabled === false
    )
      return null;
  } catch {
    // Legacy config is absent on fresh desktop-only installs.
  }
  try {
    const personal = JSON.parse(readFileSync(zcodePersonalProviderPath(), "utf8")) as {
      config?: {
        providerConfigRules?: {
          providerRules?: Array<{
            providerId?: string;
            enabled?: boolean;
            config?: { enabled?: boolean };
          }>;
        };
      };
    };
    if (
      personal.config?.providerConfigRules?.providerRules?.some(
        (rule) =>
          (rule.providerId === START_PLAN_PROVIDER_ID || rule.providerId === LEGACY_PROVIDER_ID) &&
          (rule.enabled === false || rule.config?.enabled === false),
      )
    )
      return null;
  } catch {
    // No personal override is the normal fresh-install case.
  }
  const store = readCredentialStoreSync();
  if (store["oauth:active_provider"] !== "zai" || !store["oauth:zai:access_token"]?.trim()) {
    return null;
  }
  const apiKey = store.zcodejwttoken?.trim();
  if (!apiKey) return null;
  // A token is not evidence that an explicitly unavailable plan became usable.
  try {
    const cache = JSON.parse(
      readFileSync(path.join(path.dirname(ZCODE_CREDS_PATH), "coding-plan-cache.json"), "utf8"),
    ) as { entryStatus?: { items?: Record<string, { status?: string }> } };
    const items = cache.entryStatus?.items;
    if (
      items?.[LEGACY_PROVIDER_ID]?.status === "unavailable" ||
      items?.[START_PLAN_PROVIDER_ID]?.status === "unavailable"
    ) {
      return null;
    }
  } catch {
    // Fresh desktop installs may have no cache. The server decides entitlement.
  }
  return { apiKey };
}
