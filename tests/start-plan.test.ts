import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const paths = vi.hoisted(() => ({ root: "", table: "" }));
vi.mock("../src/utils.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/utils.js")>();
  return {
    ...actual,
    get ZCODE_CREDS_PATH() {
      return path.join(paths.root, "config.json");
    },
    zcodeCredentialsPath: () => path.join(paths.root, "credentials.json"),
    zcodePersonalProviderPath: () => path.join(paths.root, "provider_config.json"),
  };
});
vi.mock("../src/backend/resolve.js", () => ({
  builtinProviderEnv: () => ({ ZCODE_BUILTIN_PROVIDER_CONFIG_FILE: paths.table }),
  BUILTIN_PROVIDER_ENV: "ZCODE_BUILTIN_PROVIDER_CONFIG_FILE",
}));

import { resolveCredentialSecret } from "../src/backend/credential-store.js";
import { resolveStartPlanCatalog, startPlanCatalog } from "../src/backend/start-plan-catalog.js";
import { START_PLAN_PROVIDER_ID, startPlanRequestAuthFor } from "../src/backend/start-plan.js";
import {
  buildAccountProviderConfig,
  codingPlanRequestAuthFor,
  startPlanModels,
} from "../src/config/account-provider.js";
import { buildConfigOptions, loadAllModels } from "../src/config/options.js";
import type { ZcodeAcpServer } from "../src/server.js";

vi.mock("../src/settings/app-update.js", () => ({
  appBundlePath: () => "/Applications/ZCode.app",
  installedAppVersion: async () => "3.15.3",
}));

const LEGACY_ID = "builtin:zai-start-plan";
const LOGIN = {
  "oauth:active_provider": "zai",
  "oauth:zai:access_token": "business-token-not-for-model-requests",
  zcodejwttoken: "start-plan-token",
};

function writeStore(entries: Record<string, string>): void {
  const key = createHash("sha256").update(resolveCredentialSecret()).digest();
  const encrypted = Object.fromEntries(
    Object.entries(entries).map(([name, value]) => {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const bytes = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
      return [
        name,
        `enc:v1:${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${bytes.toString("base64url")}`,
      ];
    }),
  );
  writeFileSync(path.join(paths.root, "credentials.json"), JSON.stringify(encrypted));
}

function cache(items: Record<string, { status: string }>): void {
  writeFileSync(
    path.join(paths.root, "coding-plan-cache.json"),
    JSON.stringify({ entryStatus: { items } }),
  );
}

beforeEach(() => {
  paths.root = mkdtempSync(path.join(tmpdir(), "start-plan-"));
  paths.table = path.join(paths.root, "provider", "zcode-builtin.json");
  mkdirSync(path.dirname(paths.table));
  writeFileSync(
    paths.table,
    JSON.stringify({
      revision: 28,
      config: {
        providerConfigRules: {
          providerRules: [
            {
              providerId: START_PLAN_PROVIDER_ID,
              providerName: "Z.ai Start Plan",
              config: {
                access: { type: "zhipu-account", mode: "start-plan", accountType: "zai" },
                builtinModelIds: ["GLM-5.3-Flash"],
              },
            },
            {
              providerId: "account:zai-individual-coding-plan",
              config: {
                access: {
                  type: "zhipu-account",
                  mode: "individual-coding-plan",
                  accountType: "zai",
                },
                builtinModelIds: ["GLM-5.3"],
              },
            },
          ],
        },
      },
    }),
  );
  writeFileSync(
    path.join(paths.root, "telemetry-state.json"),
    JSON.stringify({ deviceMid: "existing-device" }),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => balanceResponse()),
  );
  vi.stubEnv("ZCODE_ACP_START_PLAN", "1");
  vi.stubEnv("ZCODE_PROVIDER", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function balanceResponse(data: Record<string, unknown> = {}, init?: ResponseInit): Response {
  return Response.json(
    {
      code: 0,
      data: {
        server_time: Date.now() / 1000,
        plans: [{ status: "active", plan_id: "zcode-v3-start-plan" }],
        balances: [{ capabilities: ["model:glm-5.3", "model:glm-5.3-flash"] }],
        ...data,
      },
    },
    init,
  );
}

describe("opt-in Z.ai Start Plan desktop auth", () => {
  it.each([undefined, "", "0", "true"])("stays off for flag %s", (flag) => {
    vi.stubEnv("ZCODE_ACP_START_PLAN", flag);
    writeStore(LOGIN);
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
    expect(startPlanModels()).toEqual([]);
    expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(
      false,
    );
  });

  it("serves only the ZCode token from the active Z.ai login", () => {
    writeStore(LOGIN);
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toEqual({ apiKey: "start-plan-token" });
    expect(startPlanRequestAuthFor(LEGACY_ID)).toEqual({ apiKey: "start-plan-token" });
    expect(codingPlanRequestAuthFor("account:zai-individual-coding-plan")).toBeNull();
  });

  it.each(["bigmodel", "", "unknown"])(
    "refuses a different or missing active family: %s",
    (family) => {
      writeStore({ ...LOGIN, "oauth:active_provider": family });
      expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
      expect(startPlanModels()).toEqual([]);
    },
  );

  it.each(["zcodejwttoken", "oauth:zai:access_token"])("requires %s", (missing) => {
    writeStore({ ...LOGIN, [missing]: "   " });
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
    expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(
      false,
    );
  });

  it.each([
    undefined,
    "account:bigmodel-start-plan",
    "account:zai-individual-coding-plan",
    "account:zai-team-coding-plan",
    "builtin:zai-coding-plan",
    "custom-provider",
  ])("never shares the token with %s", (providerId) => {
    writeStore(LOGIN);
    expect(startPlanRequestAuthFor(providerId)).toBeNull();
  });

  it.each([LEGACY_ID, START_PLAN_PROVIDER_ID])(
    "honors an explicit unavailable verdict for %s",
    (id) => {
      writeStore(LOGIN);
      cache({ [id]: { status: "unavailable" } });
      // Stale legacy config/selection must not resurrect this provider.
      writeFileSync(
        path.join(paths.root, "config.json"),
        JSON.stringify({
          provider: {
            [LEGACY_ID]: { enabled: true, options: { apiKey: "old" }, models: { "GLM-5.3": {} } },
          },
        }),
      );
      expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
      expect(startPlanModels()).toEqual([]);
      expect(loadAllModels()).toEqual([]);
      expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(
        false,
      );
    },
  );

  it("does not confuse a different plan's unavailable verdict with Start Plan", () => {
    writeStore(LOGIN);
    cache({ "builtin:zai-coding-plan": { status: "unavailable" } });
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toEqual({ apiKey: "start-plan-token" });
  });

  it.each([LEGACY_ID, START_PLAN_PROVIDER_ID])("honors a legacy provider disable for %s", (id) => {
    writeStore(LOGIN);
    writeFileSync(
      path.join(paths.root, "config.json"),
      JSON.stringify({ provider: { [id]: { enabled: false } } }),
    );
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
    expect(loadAllModels().some((m) => m.providerId === LEGACY_ID)).toBe(false);
    expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(
      false,
    );
  });

  it.each([
    { providerId: START_PLAN_PROVIDER_ID, enabled: false },
    { providerId: LEGACY_ID, enabled: false },
    { providerId: START_PLAN_PROVIDER_ID, config: { enabled: false } },
    { providerId: LEGACY_ID, config: { enabled: false } },
  ])("honors a personal provider disable: %j", (rule) => {
    writeStore(LOGIN);
    writeFileSync(
      path.join(paths.root, "provider_config.json"),
      JSON.stringify({ config: { providerConfigRules: { providerRules: [rule] } } }),
    );
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
    expect(loadAllModels().some((m) => m.providerId === LEGACY_ID)).toBe(false);
    expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(
      false,
    );
  });

  it("does not fall back to a business token or individual key when the ZCode token is absent", () => {
    writeStore({
      ...LOGIN,
      zcodejwttoken: "",
      "account-provider:coding-plan:account:zai-individual-coding-plan:account:108:api-key":
        "individual-key",
    });
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
  });

  it("does not reuse a cached token after logout", () => {
    writeStore(LOGIN);
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).not.toBeNull();
    writeStore({});
    expect(startPlanRequestAuthFor(START_PLAN_PROVIDER_ID)).toBeNull();
  });
});

describe("Start Plan registry and model discovery", () => {
  it("replaces static Start membership with remote GLM-5.3 without legacy config.json", async () => {
    writeStore(LOGIN);
    await resolveStartPlanCatalog();
    expect(loadAllModels()).toEqual([
      { providerId: LEGACY_ID, providerName: "Z.ai Start Plan", modelId: "GLM-5.3" },
      { providerId: LEGACY_ID, providerName: "Z.ai Start Plan", modelId: "GLM-5.3-Flash" },
    ]);
    const payload = buildAccountProviderConfig()!;
    expect(payload.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(true);
    expect(payload.providers["account:zai-individual-coding-plan"]!.access.entitled).toBe(false);
  });

  it("discovers Start Plan alongside custom providers without duplicate models", async () => {
    writeStore(LOGIN);
    await resolveStartPlanCatalog();
    writeFileSync(
      path.join(paths.root, "config.json"),
      JSON.stringify({
        provider: {
          [LEGACY_ID]: { enabled: true, options: { apiKey: "legacy" }, models: { "GLM-5.3": {} } },
          local: { options: { baseURL: "http://localhost:8000" }, models: { local: {} } },
        },
      }),
    );
    const models = loadAllModels();
    expect(models.filter((m) => m.providerId === LEGACY_ID)).toHaveLength(2);
    expect(models.some((m) => m.providerId === "local")).toBe(true);
  });

  it.each([LEGACY_ID, START_PLAN_PROVIDER_ID])(
    "accepts the matching provider pin %s",
    async (id) => {
      writeStore(LOGIN);
      await resolveStartPlanCatalog();
      vi.stubEnv("ZCODE_PROVIDER", id);
      expect(loadAllModels().map((m) => m.providerId)).toEqual([LEGACY_ID, LEGACY_ID]);
    },
  );

  it("does not advertise Start Plan when another provider is pinned", async () => {
    writeStore(LOGIN);
    await resolveStartPlanCatalog();
    vi.stubEnv("ZCODE_PROVIDER", "builtin:zai-coding-plan");
    expect(loadAllModels().some((m) => m.providerId === LEGACY_ID)).toBe(false);
  });
});

describe("dynamic Start Plan entitlement", () => {
  it("resolves before the pending ACP picker and uses the installed app identity", async () => {
    writeStore(LOGIN);
    vi.stubEnv("ZCODE_ENDPOINT_ORIGIN", "https://untrusted.invalid");
    const options = await buildConfigOptions({ backendKind: "zcode" } as ZcodeAcpServer, null);
    expect(options.find((o) => o.id === "model")).toMatchObject({
      options: expect.arrayContaining([{ value: `${LEGACY_ID}\\GLM-5.3`, name: "GLM-5.3" }]),
    });
    const [url, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(String(url)).toBe(
      "https://zcode.z.ai/api/v1/zcode-plan/billing/balance?app_version=3.15.3",
    );
    expect(init).toMatchObject({
      method: "GET",
      redirect: "error",
      headers: {
        Authorization: "Bearer start-plan-token",
        "X-Device-Mid": "existing-device",
        "X-ZCode-App-Version": "3.15.3",
      },
    });
    expect(init?.signal).toBeDefined();
    expect(
      buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.builtinModelIds,
    ).toEqual(["GLM-5.3", "GLM-5.3-Flash"]);
  });

  it("normalizes capability spelling, deduplicates, and uses show_name only as fallback", async () => {
    writeStore(LOGIN);
    vi.mocked(fetch).mockResolvedValue(
      balanceResponse({
        balances: [
          {
            capabilities: [" MODEL: glm-5.3 ", "model:GLM-5.3", "vision"],
            show_name: "wrong-model",
          },
          { capabilities: ["vision"], show_name: "GLM-5.3-Flash" },
          { capabilities: ["model:future-model"] },
        ],
      }),
    );
    await resolveStartPlanCatalog();
    expect(startPlanModels().map((m) => m.modelId)).toEqual([
      "GLM-5.3",
      "GLM-5.3-Flash",
      "future-model",
    ]);
  });

  it("an authoritative empty catalog does not restore legacy or bundled models", async () => {
    writeStore(LOGIN);
    writeFileSync(
      path.join(paths.root, "config.json"),
      JSON.stringify({
        provider: {
          [LEGACY_ID]: { enabled: true, options: { apiKey: "old" }, models: { "GLM-5.3": {} } },
        },
      }),
    );
    vi.stubEnv("ZCODE_PROVIDER", LEGACY_ID);
    vi.mocked(fetch).mockResolvedValue(balanceResponse({ balances: [] }));
    await resolveStartPlanCatalog();
    expect(startPlanCatalog()?.availability).toBe("available");
    expect(loadAllModels()).toEqual([]);
    expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]).toEqual({
      builtinModelIds: [],
      access: { type: "zhipu-account", entitled: true },
    });
    const options = await buildConfigOptions({ backendKind: "zcode" } as ZcodeAcpServer, null);
    expect(options.find((o) => o.id === "model")).toMatchObject({ options: [] });
  });

  it.each(["expired", "cancelled", "pending"])(
    "inactive %s plans have no executable models",
    async (status) => {
      writeStore(LOGIN);
      vi.mocked(fetch).mockResolvedValue(
        balanceResponse({ plans: [{ status, plan_id: "zcode-v3-start-plan" }] }),
      );
      await resolveStartPlanCatalog();
      expect(startPlanCatalog()?.availability).toBe("unavailable");
      expect(loadAllModels()).toEqual([]);
      expect(buildAccountProviderConfig()!.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(
        false,
      );
    },
  );

  it("future entitlements with no balances are pending", async () => {
    writeStore(LOGIN);
    vi.mocked(fetch).mockResolvedValue(
      balanceResponse({
        server_time: 100,
        plans: [{ status: "active", starts_at: 200 }],
        balances: [],
      }),
    );
    await resolveStartPlanCatalog();
    expect(startPlanCatalog()).toEqual({ availability: "pending", modelIds: [] });
    expect(buildAccountProviderConfig()!.states[START_PLAN_PROVIDER_ID]!.availability).toBe(
      "pending",
    );
  });

  it("uses HTTP time for expiry and distinguishes separate instances of the same plan", async () => {
    writeStore(LOGIN);
    vi.mocked(fetch).mockResolvedValue(
      balanceResponse(
        {
          server_time: 50,
          plans: [
            { status: "active", plan_id: "start-plan", user_plan_id: "old", ends_at: 99 },
            { status: "active", plan_id: "start-plan", user_plan_id: "current", ends_at: 999 },
            { status: "cancelled", plan_id: "start-plan", user_plan_id: "cancelled" },
            { status: "active", plan_id: "other-plan", user_plan_id: "other" },
          ],
          balances: [
            { user_plan_id: "old", plan_id: "start-plan", capabilities: ["model:expired"] },
            { user_plan_id: "current", plan_id: "start-plan", capabilities: ["model:glm-5.3"] },
            { user_plan_id: "cancelled", plan_id: "start-plan", capabilities: ["model:cancelled"] },
            { user_plan_id: "other", plan_id: "other-plan", capabilities: ["model:other"] },
            {
              user_plan_id: "current",
              plan_id: "start-plan",
              capabilities: ["model:old-bucket"],
              expires_at: 99,
            },
          ],
        },
        { headers: { date: new Date(100_000).toUTCString() } },
      ),
    );
    await resolveStartPlanCatalog();
    expect(startPlanModels().map((m) => m.modelId)).toEqual(["GLM-5.3"]);
  });

  it("does not fetch while off, disabled, or signed into another family", async () => {
    writeStore(LOGIN);
    vi.stubEnv("ZCODE_ACP_START_PLAN", "0");
    await resolveStartPlanCatalog();
    vi.stubEnv("ZCODE_ACP_START_PLAN", "1");
    writeStore({ ...LOGIN, "oauth:active_provider": "bigmodel" });
    await resolveStartPlanCatalog();
    writeStore(LOGIN);
    writeFileSync(
      path.join(paths.root, "config.json"),
      JSON.stringify({ provider: { [LEGACY_ID]: { enabled: false } } }),
    );
    await resolveStartPlanCatalog();
    expect(fetch).not.toHaveBeenCalled();
    expect(startPlanModels()).toEqual([]);
  });

  it("merges concurrent reads and refreshes after the short TTL", async () => {
    writeStore(LOGIN);
    const clock = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    await Promise.all([
      resolveStartPlanCatalog(),
      resolveStartPlanCatalog(),
      resolveStartPlanCatalog(),
    ]);
    await resolveStartPlanCatalog();
    expect(fetch).toHaveBeenCalledTimes(1);
    clock.mockReturnValue(1_061_000);
    vi.mocked(fetch).mockResolvedValue(balanceResponse({ plans: [], balances: [] }));
    await resolveStartPlanCatalog();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(startPlanModels()).toEqual([]);
  });

  it.each([400, 401, 403, 429, 500])(
    "fails closed and throttles HTTP %s without retrying",
    async (status) => {
      writeStore(LOGIN);
      vi.mocked(fetch).mockResolvedValue(new Response("private upstream diagnostic", { status }));
      await resolveStartPlanCatalog();
      await resolveStartPlanCatalog();
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(loadAllModels()).toEqual([]);
      expect(startPlanCatalog()?.availability).toBe("unknown");
    },
  );

  it.each([null, {}, { code: 3001 }, { code: 0, data: { plans: "bad", balances: [] } }])(
    "rejects malformed or unsuccessful envelopes: %j",
    async (body) => {
      writeStore(LOGIN);
      vi.mocked(fetch).mockResolvedValue(Response.json(body));
      await resolveStartPlanCatalog();
      expect(startPlanModels()).toEqual([]);
      expect(startPlanCatalog()?.availability).toBe("unknown");
    },
  );

  it("does not generate a missing desktop device identity or contact the server", async () => {
    writeStore(LOGIN);
    writeFileSync(path.join(paths.root, "telemetry-state.json"), "{}");
    await resolveStartPlanCatalog();
    expect(fetch).not.toHaveBeenCalled();
    expect(startPlanModels()).toEqual([]);
  });

  it("never reuses an old login's catalog after account switch or logout", async () => {
    writeStore(LOGIN);
    await resolveStartPlanCatalog();
    expect(startPlanModels()).toHaveLength(2);
    writeStore({ ...LOGIN, "oauth:zai:access_token": "next-account-business-token" });
    expect(startPlanModels()).toEqual([]);
    await resolveStartPlanCatalog();
    expect(fetch).toHaveBeenCalledTimes(2);
    writeStore({});
    expect(startPlanModels()).toEqual([]);
  });

  it("discards a response that belongs to an account changed while awaiting fetch", async () => {
    writeStore(LOGIN);
    let complete!: (response: Response) => void;
    vi.mocked(fetch).mockImplementation(
      () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
    );
    const request = resolveStartPlanCatalog();
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled());
    writeStore({ ...LOGIN, zcodejwttoken: "next-account-token" });
    complete(balanceResponse());
    await request;
    expect(startPlanCatalog()).toBeNull();
    expect(startPlanModels()).toEqual([]);
  });
});

describe("Start Plan catalog and backend stay aligned", () => {
  it("pushes changed membership before advertising it to an existing session without redundant pushes", async () => {
    writeStore(LOGIN);
    const clock = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    vi.mocked(fetch).mockResolvedValue(
      balanceResponse({ balances: [{ capabilities: ["model:glm-5.3-flash"] }] }),
    );
    const request = vi.fn(async (_id: number, method: string) => ({
      result:
        method === "session/read"
          ? {
              settings: {
                model: {
                  current: { providerId: START_PLAN_PROVIDER_ID, modelId: "GLM-5.3-Flash" },
                },
              },
            }
          : {},
    }));
    const backend = { request };
    const server = {
      backendKind: "zcode",
      ensureBackend: async () => backend,
      nextId: () => 1,
      sessionPlanActive: new Set(),
    } as unknown as ZcodeAcpServer;
    await buildConfigOptions(server, "existing");
    await buildConfigOptions(server, "existing");
    expect(
      request.mock.calls.filter((call) => call[1] === "provider/updateAccountConfig"),
    ).toHaveLength(1);
    clock.mockReturnValue(1_061_000);
    vi.mocked(fetch).mockResolvedValue(balanceResponse());
    const options = await buildConfigOptions(server, "existing");
    const pushes = request.mock.calls.filter((call) => call[1] === "provider/updateAccountConfig");
    expect(pushes).toHaveLength(2);
    expect((pushes[1] as unknown[])[2]).toMatchObject({
      providers: {
        [START_PLAN_PROVIDER_ID]: { builtinModelIds: ["GLM-5.3", "GLM-5.3-Flash"] },
      },
    });
    expect(options.find((o) => o.id === "model")).toMatchObject({
      options: expect.arrayContaining([{ value: `${LEGACY_ID}\\GLM-5.3`, name: "GLM-5.3" }]),
    });
    expect(request.mock.calls.at(-2)![1]).toBe("provider/updateAccountConfig");
    expect(request.mock.calls.at(-1)![1]).toBe("session/read");
  });

  it("does not cache a model past its bucket expiry", async () => {
    writeStore(LOGIN);
    const clock = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    vi.mocked(fetch).mockImplementation(async () =>
      balanceResponse({ balances: [{ capabilities: ["model:glm-5.3"], expires_at: 1001 }] }),
    );
    await resolveStartPlanCatalog();
    expect(startPlanModels()).toHaveLength(1);
    clock.mockReturnValue(1_001_001);
    expect(startPlanCatalog()).toBeNull();
    expect(startPlanModels()).toEqual([]);
    await resolveStartPlanCatalog();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("does not retain a pending verdict past its known activation time", async () => {
    writeStore(LOGIN);
    const clock = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    vi.mocked(fetch).mockResolvedValue(
      balanceResponse({ plans: [{ status: "active", starts_at: 1001 }], balances: [] }),
    );
    await resolveStartPlanCatalog();
    expect(startPlanCatalog()?.availability).toBe("pending");
    clock.mockReturnValue(1_001_001);
    vi.mocked(fetch).mockResolvedValue(balanceResponse());
    await resolveStartPlanCatalog();
    expect(startPlanCatalog()?.availability).toBe("available");
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

describe("Start Plan configured model", () => {
  it("advertises a granted model pin even when the server lists Flash first", async () => {
    writeStore(LOGIN);
    vi.stubEnv("ZCODE_PROVIDER", LEGACY_ID);
    vi.stubEnv("ZCODE_MODEL", "GLM-5.3");
    vi.mocked(fetch).mockResolvedValue(
      balanceResponse({ balances: [{ capabilities: ["model:glm-5.3-flash", "model:glm-5.3"] }] }),
    );
    const options = await buildConfigOptions({ backendKind: "zcode" } as ZcodeAcpServer, null);
    expect(options.find((o) => o.id === "model")?.currentValue).toBe(`${LEGACY_ID}\\GLM-5.3`);
  });

  it("does not invent an unavailable configured model", async () => {
    writeStore(LOGIN);
    vi.stubEnv("ZCODE_PROVIDER", LEGACY_ID);
    vi.stubEnv("ZCODE_MODEL", "unavailable-model");
    const options = await buildConfigOptions({ backendKind: "zcode" } as ZcodeAcpServer, null);
    expect(options.find((o) => o.id === "model")?.currentValue).toBe(`${LEGACY_ID}\\GLM-5.3`);
  });
});
