import type {
  ApprovalOutcome,
  AuditEvent,
  AuditVerification,
  Capability,
  DemoSeed,
  Intent,
  Plan,
  PreviewOutcome,
  Principal,
  RecoveryRecord,
  RollbackOutcome,
  RunOutcome,
  Submission,
  Transaction,
  TransactionBundle,
} from "./types.js";

export interface VeyraClientOptions {
  baseUrl: string;
  token: string;
  fetch?: typeof globalThis.fetch;
  /** Per-request deadline. Defaults to 60 seconds. */
  timeoutMs?: number;
  /** Maximum decoded response body. Defaults to 64 MiB. */
  maximumResponseBytes?: number;
}

interface ApiErrorEnvelope {
  error?: { code?: string; message?: string };
}

const MAXIMUM_REQUEST_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAXIMUM_RESPONSE_BYTES = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

/** Safe error returned by the versioned local API. Response bodies are not retained. */
export class VeyraApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "VeyraApiError";
    this.status = status;
    this.code = code;
  }
}

/** Thin typed client. All authority remains in the local Rust kernel. */
export class VeyraClient {
  readonly #baseUrl: URL;
  readonly #token: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #timeoutMs: number;
  readonly #maximumResponseBytes: number;

  constructor(options: VeyraClientOptions) {
    const baseUrl = new URL(options.baseUrl);
    if (!baseUrl.pathname.endsWith("/")) baseUrl.pathname += "/";
    if (
      baseUrl.protocol !== "http:" ||
      !isLoopback(baseUrl.hostname) ||
      baseUrl.username !== "" ||
      baseUrl.password !== "" ||
      baseUrl.search !== "" ||
      baseUrl.hash !== ""
    ) {
      throw new TypeError(
        "Veyra API URL must use HTTP on an explicit loopback host without credentials, query, or fragment",
      );
    }
    if (
      options.token.length < 64 ||
      options.token.length > 4096 ||
      !/^[A-Za-z0-9_]+$/u.test(options.token)
    )
      throw new TypeError("Veyra API token is malformed");
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maximumResponseBytes =
      options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
    if (
      !isPositiveInteger(timeoutMs) ||
      !isPositiveInteger(maximumResponseBytes)
    )
      throw new TypeError("Veyra client limits must be positive integers");
    this.#baseUrl = baseUrl;
    this.#token = options.token;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = timeoutMs;
    this.#maximumResponseBytes = maximumResponseBytes;
  }

  health(): Promise<{
    status: string;
    api_version: string;
    protocol_version: string;
  }> {
    return this.#request("health");
  }

  registerPrincipal(principal: Principal): Promise<Principal> {
    return this.#request("principals", { method: "POST", body: principal });
  }

  submitIntent(intent: Intent): Promise<Submission> {
    return this.#request("intents", { method: "POST", body: intent });
  }

  getIntent(id: string): Promise<Intent> {
    return this.#request(`intents/${encodeURIComponent(id)}`);
  }

  getPlan(id: string): Promise<Plan> {
    return this.#request(`plans/${encodeURIComponent(id)}`);
  }

  listTransactions(): Promise<Transaction[]> {
    return this.#request("transactions");
  }

  getTransaction(id: string): Promise<Transaction> {
    return this.#request(`transactions/${encodeURIComponent(id)}`);
  }

  getTransactionBundle(id: string): Promise<TransactionBundle> {
    return this.#request(`transactions/${encodeURIComponent(id)}/bundle`);
  }

  previewTransaction(id: string): Promise<PreviewOutcome> {
    return this.#request(`transactions/${encodeURIComponent(id)}/preview`, {
      method: "POST",
    });
  }

  runTransaction(id: string): Promise<RunOutcome> {
    return this.#request(`transactions/${encodeURIComponent(id)}/run`, {
      method: "POST",
    });
  }

  rollbackTransaction(id: string): Promise<RollbackOutcome> {
    return this.#request(`transactions/${encodeURIComponent(id)}/rollback`, {
      method: "POST",
    });
  }

  grantApproval(
    requestId: string,
    approverId: string,
  ): Promise<ApprovalOutcome> {
    return this.#request(`approvals/${encodeURIComponent(requestId)}/grant`, {
      method: "POST",
      body: { approver_id: approverId },
    });
  }

  issueCapability(
    issuerId: string,
    capability: Capability,
  ): Promise<Capability> {
    return this.#request("capabilities", {
      method: "POST",
      body: { issuer_id: issuerId, capability },
    });
  }

  revokeCapability(id: string, revokerId: string): Promise<void> {
    return this.#request(`capabilities/${encodeURIComponent(id)}/revoke`, {
      method: "POST",
      body: { revoker_id: revokerId },
    });
  }

  auditEvents(transactionId?: string): Promise<AuditEvent[]> {
    return this.#request(withTransactionQuery("audit/events", transactionId));
  }

  auditExport(
    transactionId?: string,
  ): Promise<{ transaction_id: string | null; text: string }> {
    return this.#request(withTransactionQuery("audit/export", transactionId));
  }

  verifyAudit(): Promise<AuditVerification> {
    return this.#request("audit/verify");
  }

  recoveryActions(): Promise<RecoveryRecord[]> {
    return this.#request("recovery");
  }

  seedDemo(content?: string): Promise<DemoSeed> {
    return this.#request("demo/seed", {
      method: "POST",
      body: content === undefined ? {} : { content },
    });
  }

  async #request<T>(
    path: string,
    options: { method?: "GET" | "POST"; body?: unknown } = {},
  ): Promise<T> {
    const headers = new Headers({ Authorization: `Bearer ${this.#token}` });
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
      if (new TextEncoder().encode(body).byteLength > MAXIMUM_REQUEST_BYTES)
        throw new RangeError(
          `Veyra API request exceeds the ${MAXIMUM_REQUEST_BYTES}-byte limit`,
        );
    }
    const controller = new AbortController();
    const deadline = globalThis.setTimeout(
      () => controller.abort(new Error("Veyra API request timed out")),
      this.#timeoutMs,
    );
    try {
      const response = await this.#fetch(new URL(path, this.#baseUrl), {
        method: options.method ?? "GET",
        headers,
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
        ...(body === undefined ? {} : { body }),
      });
      if (response.status === 204) return undefined as T;
      const text = await readBoundedBody(response, this.#maximumResponseBytes);
      let value: unknown;
      try {
        value = JSON.parse(text) as unknown;
      } catch {
        if (response.ok) throw new TypeError("Veyra API returned invalid JSON");
        value = undefined;
      }
      if (!response.ok) {
        const envelope = isObject(value) ? (value as ApiErrorEnvelope) : {};
        const rawCode = envelope.error?.code;
        const code =
          rawCode !== undefined && /^[a-z0-9_]{1,64}$/u.test(rawCode)
            ? rawCode
            : "api_error";
        const message = (envelope.error?.message ?? "Veyra API request failed")
          .split(this.#token)
          .join("[REDACTED]")
          .slice(0, 1024);
        throw new VeyraApiError(response.status, code, message);
      }
      return value as T;
    } finally {
      globalThis.clearTimeout(deadline);
    }
  }
}

async function readBoundedBody(
  response: Response,
  limit: number,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/u.test(declared) && Number(declared) > limit)
    throw new RangeError(`Veyra API response exceeds the ${limit}-byte limit`);
  if (response.body === null) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      length += item.value.byteLength;
      if (!Number.isSafeInteger(length) || length > limit) {
        await reader.cancel();
        throw new RangeError(
          `Veyra API response exceeds the ${limit}-byte limit`,
        );
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(body);
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]"
  );
}

function isPositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function withTransactionQuery(path: string, transactionId?: string): string {
  return transactionId === undefined
    ? path
    : `${path}?transaction_id=${encodeURIComponent(transactionId)}`;
}
