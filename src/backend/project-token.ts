/**
 * Desktop OAuth Coding Plan authentication (ZCode 3.15+).
 *
 * The desktop stores a business JWT and a non-secret project/key locator, not
 * a long-lived API key. Reuse that locator to issue a short-lived project token
 * through the official endpoint. Nothing here writes credentials or creates
 * keys. Tokens live only in this process and the private runtime-headers reply.
 *
 * Contract: zai-org/ZCode packages/shared/src/project-access-token{,-client}.ts
 * and bootstrap/src/app/standalone-account-provider-runtime.ts.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { zcodeHomeDir } from "../utils.js";
import { readCredentialStoreSync } from "./credential-store.js";
import { discoverZcodeBin } from "./resolve.js";

const ORIGINS = { zai: "https://api.z.ai", bigmodel: "https://bigmodel.cn" } as const;
type Family = keyof typeof ORIGINS;
const TIMEOUT_MS = 15_000;
const REFRESH_LEAD_MS = 120_000;
const REFRESH_JITTER_MS = 60_000;
const RETRY_BACKOFF_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

export interface ProjectTokenRequestAuth {
  apiKey: string;
  apiKeyId: string;
  accountScope: string;
}

interface Context {
  providerId: string;
  family: Family;
  loginToken: string;
  accountScope: string;
  snapshot: string;
  organizationId: string;
  projectId: string;
  apiKeyId: string;
}

interface CachedToken {
  auth: ProjectTokenRequestAuth;
  fingerprint: string;
  expiresAt: number;
  refreshAt: number;
}

interface Entry {
  snapshot: string;
  value?: CachedToken;
  pending?: Promise<ProjectTokenRequestAuth>;
}

// Provider-scoped entries are replaced whenever login or locator state changes.
const entries = new Map<string, Entry>();

class ProjectTokenError extends Error {
  constructor(
    code: string,
    readonly transient = false,
  ) {
    super(code);
    this.name = "ProjectTokenError";
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function readJson(file: string): Record<string, unknown> | null {
  try {
    return record(JSON.parse(readFileSync(file, "utf8")));
  } catch {
    return null;
  }
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** A selected OAuth login must never fall back to an old, unrelated API key. */
export function hasProjectTokenOAuth(providerId: string): boolean {
  const family = (Object.keys(ORIGINS) as Family[]).find(
    (candidate) => providerId === `account:${candidate}-individual-coding-plan`,
  );
  if (!family) return false;
  const store = readCredentialStoreSync();
  return (
    store["oauth:active_provider"] === family && nonempty(store[`oauth:${family}:access_token`])
  );
}

function readContext(providerId: string): Context | null {
  const family = (Object.keys(ORIGINS) as Family[]).find(
    (candidate) => providerId === `account:${candidate}-individual-coding-plan`,
  );
  if (!family) return null;
  const store = readCredentialStoreSync();
  if (store["oauth:active_provider"] !== family) return null;
  const loginToken = store[`oauth:${family}:access_token`]?.trim().replace(/^Bearer\s+/i, "");
  if (!loginToken) return null;
  const settings = readJson(path.join(zcodeHomeDir(), "v2", "setting.json"));
  const selections = record(settings?.providerFamilyConnectionSelections);
  if (record(selections?.[family])?.kind !== "individual-coding-plan") return null;
  // A remembered UI selection must not override an explicit unavailable verdict.
  const verdict = readJson(path.join(zcodeHomeDir(), "v2", "coding-plan-cache.json"));
  const items = record(record(verdict?.entryStatus)?.items);
  if (record(items?.[`builtin:${family}-coding-plan`])?.status === "unavailable") return null;
  try {
    const profile = record(JSON.parse(store[`oauth:${family}:user_info`] ?? "null"));
    // Desktop Z.ai persists the backend profile; BigModel persists OAuthUserProfile.
    const accountId = family === "zai" ? profile?.user_id : profile?.id;
    if (!nonempty(accountId) || accountId === "unknown") return null;
    const locatorKey = `project-key-location:v1:${encodeURIComponent(
      JSON.stringify([ORIGINS[family], family, accountId, null, 1, "non-team"]),
    )}`;
    const location = record(JSON.parse(store[locatorKey] ?? "null"));
    if (
      !location ||
      !nonempty(location.organizationId) ||
      !nonempty(location.projectId) ||
      !nonempty(location.apiKeyId)
    ) {
      return null;
    }
    // Keep the official standalone accountScope digest exactly; the separate
    // snapshot also guards the desktop locator and data-root boundaries.
    const accountScope = digest(JSON.stringify([providerId, family, accountId, loginToken]));
    const snapshot = digest(
      JSON.stringify([
        zcodeHomeDir(),
        accountScope,
        locatorKey,
        location.organizationId,
        location.projectId,
        location.apiKeyId,
      ]),
    );
    return {
      providerId,
      family,
      loginToken,
      accountScope,
      snapshot,
      organizationId: location.organizationId,
      projectId: location.projectId,
      apiKeyId: location.apiKeyId,
    };
  } catch {
    return null;
  }
}

/** Discover only the current desktop individual account; never probe the network. */
export function discoverProjectTokenProviders(): string[] {
  return (Object.keys(ORIGINS) as Family[]).flatMap((family) => {
    const providerId = `account:${family}-individual-coding-plan`;
    const context = readContext(providerId);
    if (!context || entries.get(providerId)?.snapshot !== context.snapshot) {
      entries.delete(providerId);
    }
    return context ? [providerId] : [];
  });
}

function desktopVersion(): string {
  const entry = process.env.ZCODE_BIN ?? discoverZcodeBin();
  // This integration consumes a desktop login. A macOS app bundle publishes its
  // product version here; the bundled CLI's --version is a different version.
  const contents = entry?.match(/^(.*\.app[\\/]Contents)[\\/]Resources[\\/]/)?.[1];
  if (contents) {
    try {
      const plist = readFileSync(path.join(contents, "Info.plist"), "utf8");
      const version = plist.match(
        /<key>CFBundleShortVersionString<\/key>\s*<string>(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)<\/string>/,
      )?.[1];
      if (version) return version;
    } catch {
      // Do not substitute the bridge or CLI version when desktop metadata is absent.
    }
  }
  throw new ProjectTokenError("project_token_desktop_version_unavailable");
}

function assertCurrent(context: Context, entry: Entry): void {
  if (
    entries.get(context.providerId) !== entry ||
    readContext(context.providerId)?.snapshot !== context.snapshot
  ) {
    if (entries.get(context.providerId) === entry) entries.delete(context.providerId);
    throw new ProjectTokenError("project_token_scope_invalidated");
  }
}

async function issueToken(context: Context): Promise<unknown> {
  const url =
    `${ORIGINS[context.family]}/api/biz/v1/organization/` +
    `${encodeURIComponent(context.organizationId)}/projects/` +
    `${encodeURIComponent(context.projectId)}/api_keys/` +
    `${encodeURIComponent(context.apiKeyId)}/access_tokens`;
  const clientVersion = desktopVersion();
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new ProjectTokenError("project_token_timeout", true));
    }, TIMEOUT_MS);
    timer.unref?.();
  });
  try {
    return await Promise.race([
      (async () => {
        let response: Response;
        try {
          response = await fetch(url, {
            method: "POST",
            // Never forward the login JWT through a redirect. Manual handling
            // also distinguishes 3xx from fetch's TypeError network failures.
            redirect: "manual",
            signal: controller.signal,
            headers: {
              Authorization: `Bearer ${context.loginToken}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ clientType: "zcode", clientVersion }),
          });
        } catch (error) {
          // Fetch exposes network failures as TypeError. No raw message/cause,
          // which can include request URLs or credentials, leaves this boundary.
          throw new ProjectTokenError("project_token_request_failed", error instanceof TypeError);
        }
        if (!response.ok) {
          // Discard error/redirect streams without retaining their private body.
          void response.body?.cancel().catch(() => {});
          throw new ProjectTokenError(
            "project_token_request_failed",
            response.status === 429 || response.status >= 500,
          );
        }
        const reader = response.body?.getReader();
        if (!reader) throw new ProjectTokenError("project_token_invalid_response");
        try {
          const decoder = new TextDecoder();
          let text = "";
          let size = 0;
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > MAX_RESPONSE_BYTES) {
              void reader.cancel().catch(() => {});
              throw new ProjectTokenError("project_token_invalid_response");
            }
            text += decoder.decode(value, { stream: true });
          }
          return JSON.parse(text + decoder.decode());
        } catch {
          throw new ProjectTokenError("project_token_invalid_response");
        } finally {
          reader.releaseLock();
        }
      })(),
      timeout,
    ]);
  } finally {
    controller.abort();
    if (timer) clearTimeout(timer);
  }
}

function parseToken(raw: unknown, startedAt: number, context: Context): CachedToken {
  const envelope = record(raw);
  if (![0, 200, "0", "200"].includes(envelope?.code as string | number)) {
    throw new ProjectTokenError("project_token_invalid_response");
  }
  const data = record(envelope?.data);
  if (data?.enable === false) throw new ProjectTokenError("project_token_disabled");
  if (
    !data ||
    (data.enable !== undefined && data.enable !== true) ||
    !nonempty(data.accessToken) ||
    data.tokenType !== "Bearer" ||
    typeof data.expiresIn !== "number" ||
    !Number.isFinite(data.expiresIn) ||
    data.expiresIn <= 0 ||
    typeof data.expiresAt !== "number" ||
    !Number.isFinite(data.expiresAt) ||
    data.expiresAt <= 0
  ) {
    throw new ProjectTokenError("project_token_invalid_response");
  }
  const expiresAt = Math.min(data.expiresAt * 1000, startedAt + data.expiresIn * 1000);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    throw new ProjectTokenError("project_token_invalid_response");
  }
  const apiKey = data.accessToken.trim();
  return {
    auth: { apiKey, apiKeyId: context.apiKeyId, accountScope: context.accountScope },
    fingerprint: digest(apiKey),
    expiresAt,
    refreshAt: expiresAt - REFRESH_LEAD_MS - Math.random() * REFRESH_JITTER_MS,
  };
}

/** Return private request auth, or null when this is not a supported desktop login. */
export async function getProjectTokenRequestAuth(
  providerId: string,
  options: { expectedAccountScope?: string; rejectedProjectTokenFingerprint?: string } = {},
): Promise<ProjectTokenRequestAuth | null> {
  const { expectedAccountScope, rejectedProjectTokenFingerprint } = options;
  if (
    (expectedAccountScope !== undefined && !/^[0-9a-f]{64}$/.test(expectedAccountScope)) ||
    (rejectedProjectTokenFingerprint !== undefined &&
      (!/^[0-9a-f]{64}$/.test(rejectedProjectTokenFingerprint) ||
        expectedAccountScope === undefined))
  ) {
    throw new ProjectTokenError("project_token_scope_invalidated");
  }
  const context = readContext(providerId);
  if (!context) {
    entries.delete(providerId);
    if (expectedAccountScope !== undefined || rejectedProjectTokenFingerprint !== undefined) {
      throw new ProjectTokenError("project_token_scope_invalidated");
    }
    return null;
  }
  if (expectedAccountScope !== undefined && expectedAccountScope !== context.accountScope) {
    throw new ProjectTokenError("project_token_scope_invalidated");
  }
  let entry = entries.get(providerId);
  if (!entry || entry.snapshot !== context.snapshot) {
    entry = { snapshot: context.snapshot };
    entries.set(providerId, entry);
  }
  if (
    rejectedProjectTokenFingerprint !== undefined &&
    entry.value?.fingerprint === rejectedProjectTokenFingerprint
  ) {
    entry.value = undefined;
  }
  if (entry.pending) return entry.pending;
  if (entry.value && Date.now() < Math.min(entry.value.refreshAt, entry.value.expiresAt)) {
    return entry.value.auth;
  }
  const current = entry;
  const startedAt = Date.now();
  const pending = Promise.resolve()
    .then(async () => {
      assertCurrent(context, current);
      const raw = await issueToken(context);
      assertCurrent(context, current);
      current.value = parseToken(raw, startedAt, context);
      return current.value.auth;
    })
    .catch((error: unknown) => {
      assertCurrent(context, current);
      if (
        error instanceof ProjectTokenError &&
        error.transient &&
        current.value &&
        Date.now() < current.value.expiresAt
      ) {
        current.value.refreshAt = Math.min(Date.now() + RETRY_BACKOFF_MS, current.value.expiresAt);
        return current.value.auth;
      }
      entries.delete(providerId);
      throw error instanceof ProjectTokenError
        ? error
        : new ProjectTokenError("project_token_request_failed");
    })
    .finally(() => {
      if (current.pending === pending) current.pending = undefined;
    });
  current.pending = pending;
  return pending;
}
