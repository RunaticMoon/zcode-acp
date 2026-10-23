import { afterEach, describe, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({ legacy: undefined as unknown }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    readFileSync: (file: string, ...args: unknown[]) => {
      if (file.endsWith("/v2/provider_config.json")) return "{}";
      if (file.endsWith("/v2/config.json")) {
        if (fixture.legacy === undefined) throw new Error("missing legacy config");
        return JSON.stringify(fixture.legacy);
      }
      return (actual.readFileSync as (...args: unknown[]) => unknown)(file, ...args);
    },
  };
});
vi.mock("../src/config/account-provider.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/config/account-provider.js")>()),
  projectTokenCodingPlanModels: () => [
    { providerId: "builtin:zai-coding-plan", providerName: "Z.ai", modelId: "GLM-5.3" },
    { providerId: "builtin:zai-coding-plan", providerName: "Z.ai", modelId: "GLM-5.3-Flash" },
  ],
}));

import { loadAllModels } from "../src/config/options.js";

afterEach(() => {
  fixture.legacy = undefined;
  vi.unstubAllEnvs();
});

describe("desktop OAuth model discovery", () => {
  it("advertises Z.ai models on a fresh desktop-only install", () => {
    vi.stubEnv("ZCODE_PROVIDER", "builtin:zai-coding-plan");
    expect(loadAllModels().map((m) => `${m.providerId}/${m.modelId}`)).toEqual([
      "builtin:zai-coding-plan/GLM-5.3",
      "builtin:zai-coding-plan/GLM-5.3-Flash",
    ]);
  });

  it("deduplicates a mixed legacy and OAuth model catalog", () => {
    fixture.legacy = {
      provider: {
        "builtin:zai-coding-plan": {
          enabled: true,
          options: { apiKey: "fixture-key" },
          models: { "GLM-5.3": {} },
        },
      },
    };
    expect(loadAllModels().map((m) => m.modelId)).toEqual(["GLM-5.3", "GLM-5.3-Flash"]);
  });

  it("honors an explicitly pinned different provider", () => {
    fixture.legacy = {
      provider: { custom: { enabled: true, options: { apiKey: "fixture" }, models: { test: {} } } },
    };
    vi.stubEnv("ZCODE_PROVIDER", "custom");
    expect(loadAllModels().map((m) => m.providerId)).toEqual(["custom"]);
  });
});
