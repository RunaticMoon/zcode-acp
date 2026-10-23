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
import { START_PLAN_PROVIDER_ID, startPlanRequestAuthFor } from "../src/backend/start-plan.js";
import {
  buildAccountProviderConfig,
  codingPlanRequestAuthFor,
  startPlanModels,
} from "../src/config/account-provider.js";
import { loadAllModels } from "../src/config/options.js";

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
                builtinModelIds: ["GLM-5.3", "GLM-5.3-Flash"],
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
  vi.stubEnv("ZCODE_ACP_START_PLAN", "1");
  vi.stubEnv("ZCODE_PROVIDER", "");
});

afterEach(() => vi.unstubAllEnvs());

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
  it("advertises the bundled Start Plan catalog without legacy config.json", () => {
    writeStore(LOGIN);
    expect(loadAllModels()).toEqual([
      { providerId: LEGACY_ID, providerName: "Z.ai Start Plan", modelId: "GLM-5.3" },
      { providerId: LEGACY_ID, providerName: "Z.ai Start Plan", modelId: "GLM-5.3-Flash" },
    ]);
    const payload = buildAccountProviderConfig()!;
    expect(payload.providers[START_PLAN_PROVIDER_ID]!.access.entitled).toBe(true);
    expect(payload.providers["account:zai-individual-coding-plan"]!.access.entitled).toBe(false);
  });

  it("discovers Start Plan alongside custom providers without duplicate models", () => {
    writeStore(LOGIN);
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

  it.each([LEGACY_ID, START_PLAN_PROVIDER_ID])("accepts the matching provider pin %s", (id) => {
    writeStore(LOGIN);
    vi.stubEnv("ZCODE_PROVIDER", id);
    expect(loadAllModels().map((m) => m.providerId)).toEqual([LEGACY_ID, LEGACY_ID]);
  });

  it("does not advertise Start Plan when another provider is pinned", () => {
    writeStore(LOGIN);
    vi.stubEnv("ZCODE_PROVIDER", "builtin:zai-coding-plan");
    expect(loadAllModels().some((m) => m.providerId === LEGACY_ID)).toBe(false);
  });
});
