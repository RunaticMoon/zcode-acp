/**
 * The desktop's Start Plan catalog is an account entitlement, not the static
 * provider rule's builtinModelIds. Mirror its billing/balance read and publish
 * one in-memory snapshot for both the ACP picker and account-registry push.
 * Source: zai-org/ZCode packages/services/src/model-provider/zaiStartPlanBilling.ts
 * and codingPlanProviderAvailability.ts. Never write or refresh desktop auth.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { appBundlePath, installedAppVersion } from "../settings/app-update.js";
import { warn, ZCODE_CREDS_PATH } from "../utils.js";
import { readCredentialStoreSync } from "./credential-store.js";
import { START_PLAN_PROVIDER_ID, startPlanRequestAuthFor } from "./start-plan.js";

const BALANCE_URL = "https://zcode.z.ai/api/v1/zcode-plan/billing/balance";
const TTL_MS = 60_000;
const FAILURE_TTL_MS = 30_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

export interface StartPlanCatalog {
  availability: "available" | "pending" | "unavailable" | "unknown";
  modelIds: string[];
}

type JsonRecord = Record<string, unknown>;
const record = (v: unknown): JsonRecord =>
  v !== null && typeof v === "object" && !Array.isArray(v) ? (v as JsonRecord) : {};
const records = (v: unknown): JsonRecord[] => (Array.isArray(v) ? v.map(record) : []);
const text = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
const seconds = (v: unknown): number | undefined => {
  if (v === null || v === undefined || v === "") return undefined;
  const n = typeof v === "number" || typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};

interface CachedCatalog {
  scope: string;
  expiresAt: number;
  catalog: StartPlanCatalog;
}
let cached: CachedCatalog | undefined;
let inflight: { scope: string; promise: Promise<void> } | undefined;

function authContext(): { scope: string; apiKey: string } | null {
  const auth = startPlanRequestAuthFor(START_PLAN_PROVIDER_ID);
  if (!auth) return null;
  const store = readCredentialStoreSync();
  // Bind to BOTH desktop tokens: even if a shared JWT lingers during an
  // account switch, the old account's resolved entitlement cannot survive it.
  if (store["oauth:active_provider"] !== "zai" || !store["oauth:zai:access_token"]?.trim())
    return null;
  if (store.zcodejwttoken?.trim() !== auth.apiKey) return null;
  const scope = createHash("sha256")
    .update(JSON.stringify([ZCODE_CREDS_PATH, auth.apiKey, store["oauth:zai:access_token"]]))
    .digest("hex");
  return { scope, apiKey: auth.apiKey };
}

/** Synchronous consumers see only fresh data for the CURRENT desktop login. */
export function startPlanCatalog(): StartPlanCatalog | null {
  const scope = authContext()?.scope;
  if (!scope || cached?.scope !== scope || cached.expiresAt <= Date.now()) return null;
  return { ...cached.catalog, modelIds: [...cached.catalog.modelIds] };
}

function normalizeBalance(
  raw: unknown,
  responseDate: string | null,
): { catalog: StartPlanCatalog; ttl: number } {
  const payload = record(raw);
  const data = record(payload.data);
  if (
    payload.success === false ||
    (payload.code !== undefined && payload.code !== 0 && payload.code !== 200) ||
    !Array.isArray(data.plans) ||
    !Array.isArray(data.balances)
  ) {
    throw new Error("Start Plan balance returned an invalid or unsuccessful response.");
  }
  const httpTime = Date.parse(responseDate ?? "") / 1000;
  const now = Number.isFinite(httpTime)
    ? httpTime
    : (seconds(data.server_time) ?? Date.now() / 1000);
  const plans = records(data.plans).map((plan): JsonRecord & { status: string } => {
    const end = seconds(plan.ends_at);
    return {
      ...plan,
      status:
        text(plan.status).toLowerCase() === "active" && end !== undefined && end > 0 && end <= now
          ? "expired"
          : text(plan.status).toLowerCase(),
    };
  });
  const active = plans.filter((plan) => {
    const id = text(plan.plan_id).toLowerCase();
    const name = text(plan.name).toLowerCase();
    const matches = (s: string) => s.includes("start-plan") || s.includes("start plan");
    return plan.status === "active" && ((!id && !name) || matches(id) || matches(name));
  });
  if (active.length === 0)
    return { catalog: { availability: "unavailable", modelIds: [] }, ttl: TTL_MS };

  const modelIds: string[] = [];
  const seen = new Set<string>();
  const bucketExpiries: number[] = [];
  for (const bucket of records(data.balances)) {
    const owners = plans.filter((plan) =>
      bucket.user_plan_id && plan.user_plan_id
        ? bucket.user_plan_id === plan.user_plan_id
        : bucket.plan_id === plan.plan_id,
    );
    // A known inactive/non-Start owner cannot grant this provider's models.
    // Unowned buckets retain the desktop's compatibility behavior.
    if (owners.length && !owners.some((plan) => active.includes(plan))) continue;
    const bucketExpiry = seconds(bucket.expires_at);
    if (bucketExpiry !== undefined && bucketExpiry > 0 && bucketExpiry <= now) continue;
    if (bucketExpiry !== undefined && bucketExpiry > now) bucketExpiries.push(bucketExpiry);
    const capabilities = Array.isArray(bucket.capabilities) ? bucket.capabilities : [];
    const models = capabilities
      .map((capability) => text(capability))
      .filter((capability) => /^model:/i.test(capability))
      .map((capability) => capability.slice(6).trim())
      .filter(Boolean);
    for (const model of models.length ? models : [text(bucket.show_name)]) {
      const key = model.toLowerCase();
      if (model && !seen.has(key)) {
        seen.add(key);
        modelIds.push(model);
      }
    }
  }
  const effective = active.flatMap((plan) => {
    const entitlements = records(plan.entitlements);
    return (entitlements.length ? entitlements.map((e) => e.effective_at) : [plan.starts_at]).map(
      seconds,
    );
  });
  const pending =
    modelIds.length === 0 &&
    effective.length > 0 &&
    effective.every((at) => at !== undefined && at > now);
  const nextExpiry = active
    .map((plan) => seconds(plan.ends_at))
    .filter((at): at is number => at !== undefined && at > now);
  return {
    catalog: { availability: pending ? "pending" : "available", modelIds },
    ttl: Math.min(
      TTL_MS,
      ...[...nextExpiry, ...bucketExpiries].map((at) => (at - now) * 1000),
      ...(pending ? effective.map((at) => (at! - now) * 1000) : []),
    ),
  };
}

/** No configurable credential destination and no redirects to another host. */
async function fetchCatalog(apiKey: string): Promise<{ catalog: StartPlanCatalog; ttl: number }> {
  let deviceMid = "";
  try {
    deviceMid = text(
      record(
        JSON.parse(
          readFileSync(path.join(path.dirname(ZCODE_CREDS_PATH), "telemetry-state.json"), "utf8"),
        ),
      ).deviceMid,
    );
  } catch {
    // The desktop owns this identity. Do not manufacture or persist a new one.
  }
  if (!deviceMid)
    throw new Error("Start Plan needs the desktop device identity. Open ZCode first.");
  const cli = process.env.ZCODE_BIN;
  const bundle = cli?.includes(".app/Contents/")
    ? cli.slice(0, cli.indexOf(".app/Contents/") + 4)
    : appBundlePath();
  const version = bundle ? await installedAppVersion(bundle) : null;
  if (!version) throw new Error("Cannot read the installed ZCode app version for Start Plan.");
  const url = new URL(BALANCE_URL);
  url.searchParams.set("app_version", version);
  const response = await fetch(url, {
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "X-Device-Mid": deviceMid,
      "X-ZCode-App-Version": version,
      "User-Agent": `ZCode/${version}`,
    },
  });
  if (!response.ok) {
    // Only report status, never a remote body or headers containing account data.
    const hint =
      response.status === 401 || response.status === 403
        ? "Check the current ZCode login."
        : response.status === 429
          ? "Rate limited; no automatic retry was made."
          : "Check ZCode desktop connectivity and account availability.";
    throw new Error(`Start Plan balance HTTP ${response.status}. ${hint}`);
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Start Plan balance returned an empty response.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("Start Plan balance response exceeded the size limit.");
    }
    chunks.push(value);
  }
  return normalizeBalance(
    JSON.parse(Buffer.concat(chunks).toString("utf8")),
    response.headers.get("date"),
  );
}

/** Await before building ACP options or pushing the account registry snapshot. */
export async function resolveStartPlanCatalog(): Promise<void> {
  const auth = authContext();
  if (!auth) {
    cached = undefined;
    return;
  }
  if (cached?.scope === auth.scope && cached.expiresAt > Date.now()) return;
  if (inflight?.scope === auth.scope) return inflight.promise;
  const promise = (async () => {
    let result: { catalog: StartPlanCatalog; ttl: number };
    try {
      result = await fetchCatalog(auth.apiKey);
    } catch (error) {
      // Unknown transport failures are not evidence of entitlement. Fail closed
      // for this bridge and throttle subsequent reads; no blind 429 retry loop.
      result = { catalog: { availability: "unknown", modelIds: [] }, ttl: FAILURE_TTL_MS };
      const message = error instanceof Error ? error.message : "Start Plan balance request failed.";
      // Fetch may include URLs in its own errors; only our fixed diagnostics are safe.
      warn(
        `start-plan: ${message.startsWith("Start Plan") || message.startsWith("Cannot read") ? message : "Balance lookup failed. Check ZCode desktop connectivity."}`,
      );
    }
    if (authContext()?.scope !== auth.scope) return;
    cached = { scope: auth.scope, expiresAt: Date.now() + result.ttl, catalog: result.catalog };
  })();
  inflight = { scope: auth.scope, promise };
  try {
    await promise;
  } finally {
    if (inflight?.promise === promise) inflight = undefined;
  }
}
