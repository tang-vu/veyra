import type {
  ApprovalOutcome,
  ApiPage,
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

export interface PageOptions {
  /** Requested page size; the server applies an endpoint-specific hard maximum. */
  limit?: number;
  /** Opaque cursor returned by the previous page. */
  cursor?: string;
}

export interface AuditPageOptions extends PageOptions {
  transactionId?: string;
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

  listTransactionPage(
    options: PageOptions = {},
  ): Promise<ApiPage<Transaction>> {
    return this.#request(pagePath("transactions/page", options));
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

  auditEventPage(options: AuditPageOptions = {}): Promise<ApiPage<AuditEvent>> {
    return this.#request(auditPagePath("audit/events/page", options));
  }

  auditExport(
    transactionId?: string,
    options: PageOptions = {},
  ): Promise<{
    transaction_id: string | null;
    text: string;
    next_cursor: string | null;
  }> {
    const auditOptions: AuditPageOptions =
      transactionId === undefined ? options : { ...options, transactionId };
    return this.#request(auditPagePath("audit/export", auditOptions));
  }

  verifyAudit(): Promise<AuditVerification> {
    return this.#request("audit/verify");
  }

  recoveryActions(): Promise<RecoveryRecord[]> {
    return this.#request("recovery");
  }

  recoveryActionPage(
    options: PageOptions = {},
  ): Promise<ApiPage<RecoveryRecord>> {
    return this.#request(pagePath("recovery/page", options));
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
        const message = safeErrorMessage(
          envelope.error?.message ?? "Veyra API request failed",
          this.#token,
        );
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

function safeErrorMessage(message: string, token: string): string {
  return Array.from(message.split(token).join("[REDACTED]"))
    .slice(0, 1024)
    .join("")
    .replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ");
}

function withTransactionQuery(path: string, transactionId?: string): string {
  return transactionId === undefined
    ? path
    : `${path}?transaction_id=${encodeURIComponent(transactionId)}`;
}

function pagePath(path: string, options: PageOptions): string {
  const query = new URLSearchParams();
  if (options.limit !== undefined) {
    if (!isPositiveInteger(options.limit))
      throw new TypeError("Veyra page limit must be a positive integer");
    query.set("limit", String(options.limit));
  }
  if (options.cursor !== undefined) {
    if (
      options.cursor.length === 0 ||
      options.cursor.length > 4096 ||
      /[\u0000-\u001f\u007f]/u.test(options.cursor)
    )
      throw new TypeError("Veyra page cursor is malformed");
    query.set("cursor", options.cursor);
  }
  const suffix = query.toString();
  return suffix === "" ? path : `${path}?${suffix}`;
}

function auditPagePath(path: string, options: AuditPageOptions): string {
  const paged = pagePath(path, options);
  if (options.transactionId === undefined) return paged;
  const separator = paged.includes("?") ? "&" : "?";
  return `${paged}${separator}transaction_id=${encodeURIComponent(options.transactionId)}`;
}
