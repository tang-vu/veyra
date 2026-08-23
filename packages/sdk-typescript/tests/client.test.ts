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
            message: `capability missing ${TOKEN}\n\u001b[31m`,
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
    if (!(error instanceof VeyraApiError))
      throw new Error("expected API error");
    expect(error).toMatchObject({
      status: 403,
      code: "insufficient_authority",
    });
    expect(error.message).toContain("[REDACTED]");
    expect(error.message).not.toContain(TOKEN);
    expect(error.message).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/u);
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

  it("encodes opaque keyset pagination without exposing authority in the URL", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(async () =>
        Response.json({ items: [], next_cursor: null }),
      );
    const client = new VeyraClient({
      baseUrl: "http://127.0.0.1:7843/v1/",
      token: TOKEN,
      fetch,
    });

    await client.listTransactionPage({ limit: 25, cursor: "opaque+/=" });
    await client.auditEventPage({
      limit: 50,
      cursor: "42",
      transactionId: "transaction/id",
    });
    await client.recoveryActionPage({ limit: 10, cursor: "recovery-cursor" });

    expect(fetch.mock.calls[0]![0].toString()).toBe(
      "http://127.0.0.1:7843/v1/transactions/page?limit=25&cursor=opaque%2B%2F%3D",
    );
    expect(fetch.mock.calls[1]![0].toString()).toBe(
      "http://127.0.0.1:7843/v1/audit/events/page?limit=50&cursor=42&transaction_id=transaction%2Fid",
    );
    expect(fetch.mock.calls[2]![0].toString()).toBe(
      "http://127.0.0.1:7843/v1/recovery/page?limit=10&cursor=recovery-cursor",
    );
    expect(fetch.mock.calls[0]![0].toString()).not.toContain(TOKEN);
  });

  it("rejects unsafe pagination values before making a request", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const client = new VeyraClient({
      baseUrl: "http://127.0.0.1:7843/v1/",
      token: TOKEN,
      fetch,
    });

    expect(() => client.listTransactionPage({ limit: 0 })).toThrow(
      "positive integer",
    );
    expect(() => client.auditEventPage({ cursor: "bad\ncursor" })).toThrow(
      "cursor is malformed",
    );
    expect(fetch).not.toHaveBeenCalled();
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
