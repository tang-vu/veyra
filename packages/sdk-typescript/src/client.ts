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
}

interface ApiErrorEnvelope {
  error?: { code?: string; message?: string };
}

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

  constructor(options: VeyraClientOptions) {
    const baseUrl = new URL(options.baseUrl);
    if (!baseUrl.pathname.endsWith("/")) baseUrl.pathname += "/";
    if (baseUrl.protocol !== "http:" || !isLoopback(baseUrl.hostname)) {
      throw new TypeError(
        "Veyra API URL must use HTTP on an explicit loopback host",
      );
    }
    if (options.token.length < 1)
      throw new TypeError("Veyra API token is required");
    this.#baseUrl = baseUrl;
    this.#token = options.token;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
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
    }
    const response = await this.#fetch(new URL(path, this.#baseUrl), {
      method: options.method ?? "GET",
      headers,
      ...(body === undefined ? {} : { body }),
    });
    if (response.status === 204) return undefined as T;
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const envelope = isObject(value) ? (value as ApiErrorEnvelope) : {};
      throw new VeyraApiError(
        response.status,
        envelope.error?.code ?? "api_error",
        envelope.error?.message ?? "Veyra API request failed",
      );
    }
    return value as T;
  }
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]"
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function withTransactionQuery(path: string, transactionId?: string): string {
  return transactionId === undefined
    ? path
    : `${path}?transaction_id=${encodeURIComponent(transactionId)}`;
}
