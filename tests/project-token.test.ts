import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  store: {} as Record<string, string>,
  files: new Map<string, string>(),
}));

vi.mock("node:fs", () => ({
  readFileSync: vi.fn((file: string) => {
    const value = fixture.files.get(String(file));
    if (value === undefined) throw new Error("fixture file missing");
    return value;
  }),
}));
vi.mock("../src/backend/credential-store.js", () => ({
  readCredentialStoreSync: () => fixture.store,
}));
vi.mock("../src/utils.js", () => ({ zcodeHomeDir: () => "/fake/.zcode" }));
vi.mock("../src/backend/resolve.js", () => ({ discoverZcodeBin: () => null }));

const PROVIDER = "account:zai-individual-coding-plan";
const SETTINGS = "/fake/.zcode/v2/setting.json";
const PLIST = "/Applications/Fixture.app/Contents/Info.plist";
const NOW = 1_800_000_000_000;
let now: number;
let fetchMock: ReturnType<typeof vi.fn>;

function locatorKey(
  family = "zai",
  accountId = "fixture-account",
  origin = family === "zai" ? "https://api.z.ai" : "https://bigmodel.cn",
  selection: unknown = "non-team",
): string {
  return `project-key-location:v1:${encodeURIComponent(
    JSON.stringify([origin, family, accountId, null, 1, selection]),
  )}`;
}

function setLogin(family: "zai" | "bigmodel" = "zai", accountId = "fixture-account"): void {
  fixture.store = {
    "oauth:active_provider": family,
    [`oauth:${family}:access_token`]: "fixture-business-jwt",
    [`oauth:${family}:user_info`]: JSON.stringify(
      family === "zai" ? { user_id: accountId } : { id: accountId },
    ),
    [locatorKey(family, accountId)]: JSON.stringify({
      organizationId: "fixture-org",
      projectId: "fixture-project",
      apiKeyId: "fixture-key-id",
    }),
  };
  fixture.files.set(
    SETTINGS,
    JSON.stringify({
      providerFamilyConnectionSelections: { [family]: { kind: "individual-coding-plan" } },
    }),
  );
}

function responseBody(token = "fixture-pat", overrides: Record<string, unknown> = {}) {
  return {
    code: 200,
    data: {
      accessToken: token,
      tokenType: "Bearer",
      expiresIn: 3600,
      expiresAt: (now + 3_600_000) / 1000,
      ...overrides,
    },
  };
}

function reply(token = "fixture-pat", overrides: Record<string, unknown> = {}): Response {
  return new Response(JSON.stringify(responseBody(token, overrides)), {
    headers: { "Content-Type": "application/json" },
  });
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

beforeEach(() => {
  vi.resetModules();
  now = NOW;
  vi.spyOn(Date, "now").mockImplementation(() => now);
  vi.spyOn(Math, "random").mockReturnValue(0);
  fixture.files.clear();
  fixture.files.set(
    PLIST,
    "<plist><key>CFBundleShortVersionString</key><string>3.15.3</string></plist>",
  );
  setLogin();
  vi.stubEnv("ZCODE_BIN", "/Applications/Fixture.app/Contents/Resources/glm/zcode.cjs");
  fetchMock = vi.fn(async () => reply());
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("desktop OAuth project token discovery", () => {
  it("discovers the signed-in individual account without networking", async () => {
    const { discoverProjectTokenProviders } = await import("../src/backend/project-token.js");
    expect(discoverProjectTokenProviders()).toEqual([PROVIDER]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps the OAuth route selected even when its locator is missing", async () => {
    delete fixture.store[locatorKey()];
    const { discoverProjectTokenProviders, hasProjectTokenOAuth } =
      await import("../src/backend/project-token.js");
    expect(hasProjectTokenOAuth(PROVIDER)).toBe(true);
    expect(discoverProjectTokenProviders()).toEqual([]);
    expect(hasProjectTokenOAuth("account:bigmodel-individual-coding-plan")).toBe(false);
    expect(hasProjectTokenOAuth("account:zai-start-plan")).toBe(false);
  });

  it("uses the BigModel profile id and fixed business origin", async () => {
    setLogin("bigmodel");
    const { discoverProjectTokenProviders, getProjectTokenRequestAuth } =
      await import("../src/backend/project-token.js");
    const provider = "account:bigmodel-individual-coding-plan";
    expect(discoverProjectTokenProviders()).toEqual([provider]);
    await getProjectTokenRequestAuth(provider);
    expect(fetchMock.mock.calls[0][0]).toMatch(/^https:\/\/bigmodel\.cn\/api\/biz\//);
  });

  it.each(["missing login", "different active family", "missing identity", "unknown identity"])(
    "does not infer authorization from a locator alone: %s",
    async (caseName) => {
      if (caseName === "missing login") delete fixture.store["oauth:zai:access_token"];
      if (caseName === "different active family")
        fixture.store["oauth:active_provider"] = "bigmodel";
      if (caseName === "missing identity") delete fixture.store["oauth:zai:user_info"];
      if (caseName === "unknown identity") {
        fixture.store["oauth:zai:user_info"] = JSON.stringify({ user_id: "unknown" });
      }
      const { discoverProjectTokenProviders } = await import("../src/backend/project-token.js");
      expect(discoverProjectTokenProviders()).toEqual([]);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each(["start-plan", "team-coding-plan"])("does not promote %s", async (kind) => {
    fixture.files.set(
      SETTINGS,
      JSON.stringify({ providerFamilyConnectionSelections: { zai: { kind } } }),
    );
    const { discoverProjectTokenProviders } = await import("../src/backend/project-token.js");
    expect(discoverProjectTokenProviders()).toEqual([]);
  });

  it("honors an explicit unavailable verdict over a remembered selection", async () => {
    fixture.files.set(
      "/fake/.zcode/v2/coding-plan-cache.json",
      JSON.stringify({
        entryStatus: { items: { "builtin:zai-coding-plan": { status: "unavailable" } } },
      }),
    );
    const { discoverProjectTokenProviders } = await import("../src/backend/project-token.js");
    expect(discoverProjectTokenProviders()).toEqual([]);
  });

  it("ignores an unavailable verdict for an unrelated provider family", async () => {
    fixture.files.set(
      "/fake/.zcode/v2/coding-plan-cache.json",
      JSON.stringify({
        entryStatus: { items: { "builtin:bigmodel-coding-plan": { status: "unavailable" } } },
      }),
    );
    const { discoverProjectTokenProviders } = await import("../src/backend/project-token.js");
    expect(discoverProjectTokenProviders()).toEqual([PROVIDER]);
  });

  it.each(["https://attacker.invalid", "http://api.z.ai", "https://api.z.ai.attacker.invalid"])(
    "never accepts a locator for another origin: %s",
    async (origin) => {
      fixture.store[locatorKey("zai", "fixture-account", origin)] = fixture.store[locatorKey()];
      delete fixture.store[locatorKey()];
      const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
      expect(await getProjectTokenRequestAuth(PROVIDER)).toBeNull();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("does not reuse another account or standalone project's locator", async () => {
    fixture.store[locatorKey("zai", "other-account")] = fixture.store[locatorKey()];
    fixture.store[locatorKey("zai", "fixture-account", "https://api.z.ai", "default")] =
      fixture.store[locatorKey()];
    delete fixture.store[locatorKey()];
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    expect(await getProjectTokenRequestAuth(PROVIDER)).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("project token issuance", () => {
  it("uses the desktop business JWT directly, encoded path IDs and actual product version", async () => {
    fixture.store[locatorKey()] = JSON.stringify({
      organizationId: "org/segment",
      projectId: "project?part",
      apiKeyId: "key#part",
    });
    const before = JSON.stringify(fixture.store);
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const auth = await getProjectTokenRequestAuth(PROVIDER);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(
      "https://api.z.ai/api/biz/v1/organization/org%2Fsegment/projects/project%3Fpart/api_keys/key%23part/access_tokens",
    );
    expect(init).toMatchObject({
      method: "POST",
      redirect: "manual",
      headers: { Authorization: "Bearer fixture-business-jwt", "Content-Type": "application/json" },
    });
    expect(JSON.parse(init.body)).toEqual({ clientType: "zcode", clientVersion: "3.15.3" });
    expect(auth).toEqual({
      apiKey: "fixture-pat",
      apiKeyId: "key#part",
      accountScope: hash(
        JSON.stringify([PROVIDER, "zai", "fixture-account", "fixture-business-jwt"]),
      ),
    });
    expect(JSON.stringify(fixture.store)).toBe(before);
  });

  it("never guesses a product version or contacts the endpoint without bundle metadata", async () => {
    fixture.files.delete(PLIST);
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_desktop_version_unavailable",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([0, 200, "0", "200"])("accepts only supported success envelopes (%s)", async (code) => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ ...responseBody(), code })));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    expect((await getProjectTokenRequestAuth(PROVIDER))?.apiKey).toBe("fixture-pat");
  });

  it.each([
    { enable: false },
    { enable: "true" },
    { accessToken: "" },
    { tokenType: "bearer" },
    { expiresIn: 0 },
    { expiresIn: "3600" },
    { expiresAt: NOW / 1000 - 1 },
  ])("rejects disabled or malformed token material: %j", async (overrides) => {
    fetchMock.mockResolvedValue(reply("fixture-pat", overrides));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      overrides.enable === false ? "project_token_disabled" : "project_token_invalid_response",
    );
  });

  it.each([302, 401, 403, 404, 429, 500])("sanitizes HTTP %s failures", async (status) => {
    fetchMock.mockResolvedValue(new Response("fixture-secret-do-not-print", { status }));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      /^project_token_request_failed$/,
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("sanitizes network failures without retaining causes", async () => {
    fetchMock.mockRejectedValue(new TypeError("fixture-secret-do-not-print"));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const error = await getProjectTokenRequestAuth(PROVIDER).catch((failure) => failure);
    expect(error.message).toBe("project_token_request_failed");
    expect(error.cause).toBeUndefined();
  });

  it("cancels an error response stream without reading its contents", async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream({ cancel });
    fetchMock.mockResolvedValue(new Response(stream, { status: 403 }));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_request_failed",
    );
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
  });

  it("rejects oversized response bodies", async () => {
    fetchMock.mockResolvedValue(new Response("x".repeat(65_537)));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_invalid_response",
    );
  });

  it("bounds a stalled request and aborts its network operation", async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(() => new Promise(() => {}));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const pending = getProjectTokenRequestAuth(PROVIDER);
    const assertion = expect(pending).rejects.toThrow("project_token_timeout");
    await vi.advanceTimersByTimeAsync(15_000);
    await assertion;
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
  });
});

describe("project token lifetime and account isolation", () => {
  it("coalesces concurrent requests and reuses an unexpired cached token", async () => {
    const issued = deferred<Response>();
    fetchMock.mockReturnValue(issued.promise);
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const first = getProjectTokenRequestAuth(PROVIDER);
    const second = getProjectTokenRequestAuth(PROVIDER);
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    issued.resolve(reply());
    expect(await first).toEqual(await second);
    await getProjectTokenRequestAuth(PROVIDER);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refreshes before the earlier expiresIn deadline, measured from request start", async () => {
    fetchMock.mockImplementation(async () => {
      const response = reply(`fixture-pat-${fetchMock.mock.calls.length}`, { expiresIn: 600 });
      now += 30_000;
      return response;
    });
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await getProjectTokenRequestAuth(PROVIDER);
    now = NOW + 479_999;
    await getProjectTokenRequestAuth(PROVIDER);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    now = NOW + 480_000;
    expect((await getProjectTokenRequestAuth(PROVIDER))?.apiKey).toBe("fixture-pat-2");
  });

  it("applies refresh jitter", async () => {
    vi.mocked(Math.random).mockReturnValue(1);
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await getProjectTokenRequestAuth(PROVIDER);
    now += 3_420_000;
    await getProjectTokenRequestAuth(PROVIDER);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("shares temporary refresh failure fallback without extending the original TTL", async () => {
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const initial = await getProjectTokenRequestAuth(PROVIDER);
    fetchMock.mockResolvedValue(new Response("busy", { status: 503 }));
    now = NOW + 3_480_000;
    expect(await getProjectTokenRequestAuth(PROVIDER)).toEqual(initial);
    now += 4_999;
    await getProjectTokenRequestAuth(PROVIDER);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    now += 1;
    await getProjectTokenRequestAuth(PROVIDER);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    now = NOW + 3_600_000;
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_request_failed",
    );
  });

  it("never falls back on an authentication rejection or malformed response", async () => {
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await getProjectTokenRequestAuth(PROVIDER);
    now += 3_480_000;
    fetchMock.mockResolvedValue(new Response("unauthorized", { status: 401 }));
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_request_failed",
    );
    fetchMock.mockResolvedValue(new Response("not JSON"));
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_invalid_response",
    );
  });

  it("never follows a redirect or treats it as a transient refresh failure", async () => {
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await getProjectTokenRequestAuth(PROVIDER);
    now += 3_480_000;
    fetchMock.mockResolvedValue(
      new Response(null, { status: 302, headers: { Location: "https://attacker.invalid" } }),
    );
    await expect(getProjectTokenRequestAuth(PROVIDER)).rejects.toThrow(
      "project_token_request_failed",
    );
    expect(fetchMock.mock.calls[1][1].redirect).toBe("manual");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects mismatched or missing account scope before any network request", async () => {
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    await expect(
      getProjectTokenRequestAuth(PROVIDER, { expectedAccountScope: "wrong" }),
    ).rejects.toThrow("project_token_scope_invalidated");
    await expect(
      getProjectTokenRequestAuth(PROVIDER, {
        rejectedProjectTokenFingerprint: hash("fixture-pat"),
      }),
    ).rejects.toThrow("project_token_scope_invalidated");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["", " ", "not-a-fingerprint"])(
    "rejects a supplied malformed scope or fingerprint (%j)",
    async (value) => {
      const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
      await expect(
        getProjectTokenRequestAuth(PROVIDER, { expectedAccountScope: value }),
      ).rejects.toThrow("project_token_scope_invalidated");
      await expect(
        getProjectTokenRequestAuth(PROVIDER, {
          expectedAccountScope: hash(
            JSON.stringify([PROVIDER, "zai", "fixture-account", "fixture-business-jwt"]),
          ),
          rejectedProjectTokenFingerprint: value,
        }),
      ).rejects.toThrow("project_token_scope_invalidated");
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("refreshes a rejected token but ignores a late rejection of an older token", async () => {
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const first = (await getProjectTokenRequestAuth(PROVIDER))!;
    fetchMock.mockResolvedValue(reply("fixture-pat-new"));
    const options = {
      expectedAccountScope: first.accountScope,
      rejectedProjectTokenFingerprint: hash(first.apiKey),
    };
    const next = await getProjectTokenRequestAuth(PROVIDER, options);
    expect(next?.apiKey).toBe("fixture-pat-new");
    expect(await getProjectTokenRequestAuth(PROVIDER, options)).toEqual(next);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("never reuses a rejected token when its replacement fails", async () => {
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const first = (await getProjectTokenRequestAuth(PROVIDER))!;
    fetchMock.mockRejectedValue(new TypeError("network failure"));
    await expect(
      getProjectTokenRequestAuth(PROVIDER, {
        expectedAccountScope: first.accountScope,
        rejectedProjectTokenFingerprint: hash(first.apiKey),
      }),
    ).rejects.toThrow("project_token_request_failed");
  });

  it.each(["logout", "account change", "locator change", "selection change"])(
    "discards a late issued token after %s",
    async (change) => {
      const issued = deferred<Response>();
      fetchMock.mockReturnValue(issued.promise);
      const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
      const pending = getProjectTokenRequestAuth(PROVIDER);
      await Promise.resolve();
      if (change === "logout") delete fixture.store["oauth:zai:access_token"];
      if (change === "account change") setLogin("zai", "second-account");
      if (change === "locator change") {
        fixture.store[locatorKey()] = JSON.stringify({
          organizationId: "other-org",
          projectId: "other-project",
          apiKeyId: "other-key",
        });
      }
      if (change === "selection change") fixture.files.set(SETTINGS, "{}");
      issued.resolve(reply());
      await expect(pending).rejects.toThrow("project_token_scope_invalidated");
    },
  );

  it("a late old-account failure cannot evict a newer account's cached token", async () => {
    const oldResponse = deferred<Response>();
    fetchMock.mockReturnValueOnce(oldResponse.promise).mockResolvedValue(reply("new-account-pat"));
    const { getProjectTokenRequestAuth } = await import("../src/backend/project-token.js");
    const old = getProjectTokenRequestAuth(PROVIDER);
    await Promise.resolve();
    setLogin("zai", "second-account");
    const current = await getProjectTokenRequestAuth(PROVIDER);
    oldResponse.resolve(new Response("denied", { status: 401 }));
    await expect(old).rejects.toThrow("project_token_scope_invalidated");
    expect(await getProjectTokenRequestAuth(PROVIDER)).toEqual(current);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
