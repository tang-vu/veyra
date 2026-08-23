import { describe, expect, it, vi } from "vitest";

import { VeyraApiError, VeyraClient } from "../src/index.js";

const TOKEN = `vyr_${"a".repeat(64)}`;

describe("VeyraClient", () => {
  it("binds auth to a loopback v1 request and encodes IDs", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ id: "tx" }));
    const client = new VeyraClient({
      baseUrl: "http://127.0.0.1:7843/v1",
      token: TOKEN,
      fetch,
    });

    await client.getTransaction("id/with/slashes");

    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url.toString()).toBe(
      "http://127.0.0.1:7843/v1/transactions/id%2Fwith%2Fslashes",
    );
    expect(new Headers(init?.headers).get("authorization")).toBe(
      `Bearer ${TOKEN}`,
    );
    expect(init?.redirect).toBe("error");
    expect(init?.credentials).toBe("omit");
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
      token: TOKEN,
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
        new VeyraClient({ baseUrl: "https://example.com/v1/", token: TOKEN }),
    ).toThrow(/loopback/);
    expect(
      () =>
        new VeyraClient({
          baseUrl: "http://operator:secret@127.0.0.1:7843/v1/",
          token: TOKEN,
        }),
    ).toThrow(/without credentials/);
  });

  it("bounds response bodies before JSON decoding", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ value: "too large" }));
    const client = new VeyraClient({
      baseUrl: "http://127.0.0.1:7843/v1/",
      token: TOKEN,
      fetch,
      maximumResponseBytes: 4,
    });

    await expect(client.health()).rejects.toThrow(/response exceeds/);
  });

  it("sends an empty demo body without introducing unknown fields", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({}));
    const client = new VeyraClient({
      baseUrl: "http://[::1]:7843/v1/",
      token: TOKEN,
      fetch,
    });

    await client.seedDemo();

    const [, init] = fetch.mock.calls[0]!;
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe("{}");
  });

  it("rejects malformed administrative bearer material", () => {
    expect(
      () =>
        new VeyraClient({
          baseUrl: "http://127.0.0.1:7843/v1/",
          token: "short",
        }),
    ).toThrow(/malformed/);
  });
});
