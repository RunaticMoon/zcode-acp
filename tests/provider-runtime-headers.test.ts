/**
 * Provider runtime headers (Start Plan captcha session) — issue #123.
 *
 * Start Plan providers (zcode-plan endpoints) ask their host via
 * `interaction/requestProviderRuntimeHeaders` to solve an Aliyun captcha and
 * inject X-Aliyun-Captcha-Verify-* headers; only the desktop renderer can.
 * The bridge must answer `headersApplied:false` with a clear reason so the
 * backend fails with its -32031 error — NOT fall through to the generic
 * unsupported-request error, which made the backend fall back to client
 * signing with the provider's OAuth JWT and die with the misleading
 * "must contain one separator" invalid-config error.
 */

import type * as acp from "@agentclientprotocol/sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ServerRequest, ZcodeBackend } from "../src/backend/client.js";
import type { PendingTurn, ZcodeAcpServer } from "../src/server.js";

vi.mock("../src/handlers/io.js", () => ({
  sendSessionUpdate: vi.fn().mockResolvedValue(undefined),
}));

// Coding-plan request auth resolves against the user's real HOME files
// (config.json + the builtin table); the hermetic tests mock both lookups.
vi.mock("../src/config/account-provider.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/config/account-provider.js")>();
  return {
    ...actual,
    codingPlanRequestAuthFor: vi.fn((providerId: string | undefined): { apiKey: string } | null =>
      providerId === "account:bigmodel-individual-coding-plan" ? { apiKey: "test-key" } : null,
    ),
  };
});

vi.mock("../src/backend/start-plan.js", () => ({
  START_PLAN_PROVIDER_ID: "account:zai-start-plan",
  startPlanEnabled: vi.fn(() => false),
  startPlanRequestAuthFor: vi.fn(() => null),
}));

import { startPlanEnabled, startPlanRequestAuthFor } from "../src/backend/start-plan.js";

import {
  answerProviderRuntimeHeaders,
  handleServerRequests,
} from "../src/handlers/server-requests.js";

beforeEach(() => {
  vi.mocked(startPlanEnabled).mockReset().mockReturnValue(false);
  vi.mocked(startPlanRequestAuthFor).mockReset().mockReturnValue(null);
});

function makeServer(): ZcodeAcpServer {
  return {
    nextId: () => 1,
    resolveSid: () => undefined,
  } as unknown as ZcodeAcpServer;
}

function makeBackend(queue: ServerRequest[]) {
  return {
    pollServerRequests: () => queue.splice(0, queue.length),
    requeueServerRequests: (reqs: ServerRequest[]) => queue.unshift(...reqs),
    sendReply: vi.fn(),
    sendError: vi.fn(),
  } as unknown as ZcodeBackend;
}

function runtimeHeadersRequest(zcodeId: number): ServerRequest {
  return {
    id: zcodeId,
    method: "interaction/requestProviderRuntimeHeaders",
    params: {
      requestId: "zs1:provider-runtime-headers:1725597000000",
      sessionId: "zs1",
      turnId: "t1",
      providerId: "builtin:bigmodel-start-plan",
      reason: "model-request",
    },
  };
}

describe("interaction/requestProviderRuntimeHeaders", () => {
  it("declines with headersApplied:false and a clear reason, without touching the editor", async () => {
    const server = makeServer();
    const backend = makeBackend([runtimeHeadersRequest(301)]);
    const cx = { request: vi.fn() } as unknown as acp.AgentContext;

    const handled = await handleServerRequests(server, backend, cx, "s1");
    expect(handled).toBe(true);
    expect(backend.sendReply).toHaveBeenCalledTimes(1);
    const [id, result] = vi.mocked(backend.sendReply).mock.calls[0]!;
    expect(id).toBe(301);
    expect(result).toMatchObject({ headersApplied: false });
    expect((result as { errorMessage?: string }).errorMessage).toContain("Start Plan");
    // No ACP request forwarded, no unsupported-request protocol error.
    expect(cx.request).not.toHaveBeenCalled();
    expect(backend.sendError).not.toHaveBeenCalled();
  });

  it("keeps the headersApplied result shape when the turn is cancelled", async () => {
    const server = makeServer();
    const backend = makeBackend([runtimeHeadersRequest(302)]);
    const cx = { request: vi.fn() } as unknown as acp.AgentContext;
    const turn = { cancelled: true, zcodeSid: "zs1" } as unknown as PendingTurn;

    const handled = await handleServerRequests(server, backend, cx, "s1", turn);
    expect(handled).toBe(true);
    expect(backend.sendReply).toHaveBeenCalledWith(302, {
      headersApplied: false,
      errorMessage: "turn cancelled",
    });
  });

  it("serves the coding-plan API key for an individual-plan account provider", async () => {
    const server = makeServer();
    const backend = makeBackend([
      {
        id: 303,
        method: "interaction/requestProviderRuntimeHeaders",
        params: {
          requestId: "zs1:provider-runtime-headers:2",
          sessionId: "zs1",
          providerId: "account:bigmodel-individual-coding-plan",
          modelSelection: {
            providerId: "account:bigmodel-individual-coding-plan",
            modelId: "GLM-5.3",
          },
          reason: "model-request",
        },
      },
    ]);
    const cx = { request: vi.fn() } as unknown as acp.AgentContext;

    const handled = await handleServerRequests(server, backend, cx, "s1");
    expect(handled).toBe(true);
    expect(backend.sendReply).toHaveBeenCalledWith(303, {
      headersApplied: true,
      requestAuth: { apiKey: "test-key" },
    });
    expect(cx.request).not.toHaveBeenCalled();
  });
});

describe("answerProviderRuntimeHeaders (arrival-time responder)", () => {
  it("reports missing or disabled opt-in desktop auth without claiming a captcha failure", () => {
    vi.mocked(startPlanEnabled).mockReturnValue(true);
    const backend = makeBackend([]);
    answerProviderRuntimeHeaders(backend, 91, "interaction/requestProviderRuntimeHeaders", {
      providerId: "account:zai-start-plan",
    });
    const [, result] = vi.mocked(backend.sendReply).mock.calls[0]!;
    expect(result).toMatchObject({
      headersApplied: false,
      errorMessage: expect.stringContaining("desktop credentials"),
    });
    expect(JSON.stringify(result)).not.toContain("captcha");
  });
  it("answers an opted-in Start Plan request with its dedicated token", () => {
    vi.mocked(startPlanRequestAuthFor).mockReturnValue({ apiKey: "start-token" });
    const backend = makeBackend([]);
    expect(
      answerProviderRuntimeHeaders(backend, 90, "interaction/requestProviderRuntimeHeaders", {
        providerId: "builtin:zai-start-plan",
        modelSelection: { providerId: "account:zai-start-plan", modelId: "GLM-5.3" },
      }),
    ).toBe(true);
    expect(startPlanRequestAuthFor).toHaveBeenCalledWith("account:zai-start-plan");
    expect(backend.sendReply).toHaveBeenCalledWith(90, {
      headersApplied: true,
      requestAuth: { apiKey: "start-token" },
    });
  });
  // The backend asks for runtime headers before EVERY model request on a
  // zhipu-account provider; outside a turn loop (compact's internal turn,
  // session/goal set) the queued request went unanswered and the generation
  // died at the backend's 180s cap ("Captcha verification request timed
  // out" — auto-compact silently failed that way). The responder answers at
  // frame ARRIVAL; these tests pin its contract with the client hook.
  it("returns false for non-headers methods — the caller keeps its own handling", () => {
    const backend = makeBackend([]);
    expect(answerProviderRuntimeHeaders(backend, 1, "interaction/requestPermission", {})).toBe(
      false,
    );
    expect(backend.sendReply).not.toHaveBeenCalled();
  });

  it("answers the coding-plan key inline with the same result shape as the queue path", () => {
    const backend = makeBackend([]);
    expect(
      answerProviderRuntimeHeaders(backend, 88, "interaction/requestProviderRuntimeHeaders", {
        providerId: "account:bigmodel-individual-coding-plan",
      }),
    ).toBe(true);
    expect(backend.sendReply).toHaveBeenCalledWith(88, {
      headersApplied: true,
      requestAuth: { apiKey: "test-key" },
    });
  });

  it("declines a keyless provider inline instead of leaving the ask to time out", () => {
    const backend = makeBackend([]);
    expect(
      answerProviderRuntimeHeaders(backend, "zid-1", "interaction/requestProviderRuntimeHeaders", {
        providerId: "builtin:bigmodel-start-plan",
      }),
    ).toBe(true);
    const [id, result] = vi.mocked(backend.sendReply).mock.calls[0]!;
    expect(id).toBe("zid-1");
    expect((result as { headersApplied?: boolean }).headersApplied).toBe(false);
  });
});
