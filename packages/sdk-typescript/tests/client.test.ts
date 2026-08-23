import { describe, expect, it, vi } from "vitest";

import { VeyraApiError, VeyraClient } from "../src/index.js";

describe("VeyraClient", () => {
  it("binds auth to a loopback v1 request and encodes IDs", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ id: "tx" }));
    const client = new VeyraClient({
      baseUrl: "http://127.0.0.1:7843/v1",
      token: "local-secret-token",
      fetch,
    });

    await client.getTransaction("id/with/slashes");

    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url.toString()).toBe(
      "http://127.0.0.1:7843/v1/transactions/id%2Fwith%2Fslashes",
    );
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer local-secret-token",
    );
  });

  it("returns safe typed API errors without retaining the raw response", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json(
        {
          error: {
            code: "insufficient_authority",
            message: "capability missing",
          },
        },
        { status: 403 },
      ),
    );
    const client = new VeyraClient({
      baseUrl: "http://localhost:7843/v1/",
      token: "token",
      fetch,
    });

    const error = await client
      .runTransaction("tx")
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(VeyraApiError);
    expect(error).toMatchObject({
      status: 403,
      code: "insufficient_authority",
    });
    expect(String(error)).not.toContain("token");
  });

  it("rejects non-loopback authority endpoints", () => {
    expect(
      () =>
        new VeyraClient({ baseUrl: "https://example.com/v1/", token: "token" }),
    ).toThrow(/loopback/);
  });

  it("sends an empty demo body without introducing unknown fields", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({}));
    const client = new VeyraClient({
      baseUrl: "http://[::1]:7843/v1/",
      token: "token",
      fetch,
    });

    await client.seedDemo();

    const [, init] = fetch.mock.calls[0]!;
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe("{}");
  });
});
