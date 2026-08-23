// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("Veyra desktop control plane", () => {
  beforeEach(() => {
    localStorage.clear();
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: false }),
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows an explicit local connection state without fake transaction data", async () => {
    render(<App />);
    expect(
      await screen.findByRole("heading", { name: "Connect to Veyra" }),
    ).toBeTruthy();
    expect(screen.getByLabelText("Local bearer token")).toBeTruthy();
  });

  it("loads the empty control plane through the authenticated real API shape", async () => {
    localStorage.setItem("veyra.apiUrl", "http://127.0.0.1:7843/v1/");
    localStorage.setItem("veyra.token", "test-local-token");
    const fetch = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input, init) => {
        const path = new URL(
          input instanceof Request ? input.url : input.toString(),
        ).pathname;
        const authorization = new Headers(init?.headers).get("authorization");
        expect(authorization).toBe("Bearer test-local-token");
        if (path.endsWith("/health")) {
          return Response.json({
            status: "ok",
            api_version: "v1",
            protocol_version: "veyra.protocol/v1",
          });
        }
        if (path.endsWith("/transactions") || path.endsWith("/audit/events")) {
          return Response.json([]);
        }
        if (path.endsWith("/audit/verify")) {
          return Response.json({
            valid: true,
            events_checked: 0,
            first_invalid_sequence: null,
            message: "journal is empty and valid",
          });
        }
        return Response.json(
          { error: { code: "not_found", message: "not found" } },
          { status: 404 },
        );
      });

    render(<App />);

    expect(
      await screen.findByText("Make the next side effect inspectable."),
    ).toBeTruthy();
    expect(await screen.findByText("0 events verified")).toBeTruthy();
    expect(fetch).toHaveBeenCalled();
  });
});
