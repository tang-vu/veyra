import { useCallback, useEffect, useState } from "react";
import type {
  AuditEvent,
  AuditVerification,
  Effect,
  EffectPreview,
  ResourceScope,
  Transaction,
  TransactionBundle,
  TransactionState,
  VeyraClient,
} from "@veyra/sdk";

import {
  type ConnectionInfo,
  createClient,
  discoverConnection,
  saveBrowserConnection,
} from "./connection";

type View = "transactions" | "audit";
type Theme = "light" | "dark";

export function App() {
  const [client, setClient] = useState<VeyraClient | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void discoverConnection()
      .then(async (connection) => {
        if (connection === null) return;
        const candidate = createClient(connection);
        await candidate.health();
        if (active) setClient(candidate);
      })
      .catch((error: unknown) => {
        if (active) setBootError(messageOf(error));
      });
    return () => {
      active = false;
    };
  }, []);

  if (client === null) {
    return (
      <ConnectionScreen
        initialError={bootError}
        onConnect={async (connection) => {
          const candidate = createClient(connection);
          await candidate.health();
          saveBrowserConnection(connection);
          setClient(candidate);
          setBootError(null);
        }}
      />
    );
  }
  return <ControlPlane client={client} />;
}

function ControlPlane({ client }: { client: VeyraClient }) {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [bundle, setBundle] = useState<TransactionBundle | null>(null);
  const [view, setView] = useState<View>("transactions");
  const [query, setQuery] = useState("");
  const [intentContent, setIntentContent] = useState("Hello from Veyra.\n");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [audit, setAudit] = useState<AuditVerification | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(() => preferredTheme());
  const [approvers, setApprovers] = useState<Record<string, string>>(() =>
    storedApprovers(),
  );

  const refreshTransactions = useCallback(async () => {
    const latest = await client.listTransactions();
    setTransactions(latest);
    setSelectedId((current) => current ?? latest[0]?.id ?? null);
  }, [client]);

  const loadBundle = useCallback(
    async (id: string) => {
      const next = await client.getTransactionBundle(id);
      setBundle(next);
    },
    [client],
  );

  const refreshAudit = useCallback(async () => {
    const [nextEvents, verification] = await Promise.all([
      client.auditEvents(),
      client.verifyAudit(),
    ]);
    setEvents(nextEvents);
    setAudit(verification);
  }, [client]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("veyra.theme", theme);
  }, [theme]);

  useEffect(() => {
    void refreshTransactions().catch((caught: unknown) =>
      setError(messageOf(caught)),
    );
    void refreshAudit().catch((caught: unknown) => setError(messageOf(caught)));
  }, [refreshAudit, refreshTransactions]);

  useEffect(() => {
    if (selectedId === null) {
      setBundle(null);
      return;
    }
    setBundle(null);
    void loadBundle(selectedId).catch((caught: unknown) =>
      setError(messageOf(caught)),
    );
  }, [loadBundle, selectedId]);

  const perform = useCallback(
    async (label: string, operation: () => Promise<unknown>, id?: string) => {
      setBusy(label);
      setError(null);
      try {
        await operation();
        await refreshTransactions();
        await refreshAudit();
        const target = id ?? selectedId;
        if (target !== null) await loadBundle(target);
      } catch (caught: unknown) {
        setError(messageOf(caught));
      } finally {
        setBusy(null);
      }
    },
    [loadBundle, refreshAudit, refreshTransactions, selectedId],
  );

  const seedIntent = async () => {
    setBusy("Creating intent");
    setError(null);
    try {
      const seed = await client.seedDemo(intentContent);
      const id = seed.submission.transaction.id;
      const nextApprovers = { ...approvers, [id]: seed.human.id };
      setApprovers(nextApprovers);
      localStorage.setItem(
        "veyra.demoApprovers",
        JSON.stringify(nextApprovers),
      );
      setSelectedId(id);
      setView("transactions");
      await refreshTransactions();
      await loadBundle(id);
      await refreshAudit();
    } catch (caught: unknown) {
      setError(messageOf(caught));
    } finally {
      setBusy(null);
    }
  };

  const filteredTransactions = transactions.filter((transaction) => {
    const needle = query.toLowerCase();
    return (
      transaction.id.toLowerCase().includes(needle) ||
      transaction.state.includes(needle)
    );
  });
  const filteredEvents = events.filter((event) => {
    const needle = query.toLowerCase();
    return (
      event.event_type.toLowerCase().includes(needle) ||
      event.transaction_id?.toLowerCase().includes(needle) === true ||
      event.causal_parent?.toLowerCase().includes(needle) === true
    );
  });

  return (
    <div className="app-shell">
      <Header
        audit={audit}
        theme={theme}
        onTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
      />
      <div className="workspace-shell">
        <aside className="sidebar" aria-label="Veyra navigation">
          <nav className="view-switcher" aria-label="Primary views">
            <button
              className={view === "transactions" ? "active" : ""}
              onClick={() => setView("transactions")}
            >
              Transactions <span>{transactions.length}</span>
            </button>
            <button
              className={view === "audit" ? "active" : ""}
              onClick={() => setView("audit")}
            >
              Audit <span>{events.length}</span>
            </button>
          </nav>

          <label className="search-field">
            <span className="sr-only">Search {view}</span>
            <SearchIcon />
            <input
              type="search"
              placeholder={
                view === "audit" ? "Search causal history" : "Find transaction"
              }
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>

          {view === "transactions" && (
            <div className="transaction-list" aria-label="Current transactions">
              {filteredTransactions.length === 0 ? (
                <EmptyCompact message="No matching transactions" />
              ) : (
                filteredTransactions.map((transaction) => (
                  <button
                    key={transaction.id}
                    className={`transaction-row ${selectedId === transaction.id ? "selected" : ""}`}
                    onClick={() => setSelectedId(transaction.id)}
                  >
                    <span className="transaction-row-top">
                      <StateDot state={transaction.state} />
                      <strong>{shortId(transaction.id)}</strong>
                      <time>{relativeTime(transaction.updated_at)}</time>
                    </span>
                    <span className="transaction-row-bottom">
                      {readableState(transaction.state)} ·{" "}
                      {transaction.effect_ids.length} effect
                      {transaction.effect_ids.length === 1 ? "" : "s"}
                    </span>
                  </button>
                ))
              )}
            </div>
          )}

          {view === "audit" && (
            <div
              className="audit-mini-list"
              aria-label="Audit event search results"
            >
              {filteredEvents
                .slice()
                .reverse()
                .map((event) => (
                  <button
                    key={event.id}
                    onClick={() => {
                      if (event.transaction_id !== null) {
                        setSelectedId(event.transaction_id);
                        setView("transactions");
                      }
                    }}
                  >
                    <span>{event.event_type.replaceAll(".", " / ")}</span>
                    <small>#{event.sequence.toString().padStart(4, "0")}</small>
                  </button>
                ))}
            </div>
          )}

          <IntentComposer
            content={intentContent}
            disabled={busy !== null}
            onChange={setIntentContent}
            onSubmit={() => void seedIntent()}
          />
        </aside>

        <main className="content" aria-live="polite">
          {error !== null && (
            <div className="error-banner" role="alert">
              <strong>Action stopped safely</strong>
              <span>{error}</span>
              <button aria-label="Dismiss error" onClick={() => setError(null)}>
                ×
              </button>
            </div>
          )}
          {busy !== null && <LoadingBar label={busy} />}
          {view === "audit" ? (
            <AuditView events={filteredEvents} verification={audit} />
          ) : selectedId === null ? (
            <EmptyState onCreate={() => void seedIntent()} />
          ) : bundle === null ? (
            <InspectorSkeleton />
          ) : (
            <TransactionInspector
              bundle={bundle}
              busy={busy !== null}
              approverId={approvers[bundle.transaction.id]}
              onPreview={() =>
                void perform(
                  "Running preflight",
                  () => client.previewTransaction(bundle.transaction.id),
                  bundle.transaction.id,
                )
              }
              onApprove={(requestId) => {
                const approverId = approvers[bundle.transaction.id];
                if (approverId === undefined) {
                  setError(
                    "This demo approver is unavailable in this browser profile.",
                  );
                  return;
                }
                void perform(
                  "Binding approval",
                  () => client.grantApproval(requestId, approverId),
                  bundle.transaction.id,
                );
              }}
              onRun={() =>
                void perform(
                  "Executing effects",
                  () => client.runTransaction(bundle.transaction.id),
                  bundle.transaction.id,
                )
              }
              onRollback={() =>
                void perform(
                  "Restoring prior state",
                  () => client.rollbackTransaction(bundle.transaction.id),
                  bundle.transaction.id,
                )
              }
            />
          )}
        </main>
      </div>
    </div>
  );
}

function Header({
  audit,
  theme,
  onTheme,
}: {
  audit: AuditVerification | null;
  theme: Theme;
  onTheme: () => void;
}) {
  return (
    <header className="topbar">
      <div className="identity">
        <span className="mark" aria-hidden="true">
          V
        </span>
        <div>
          <strong>Veyra</strong>
          <span>Execution control plane</span>
        </div>
      </div>
      <div className="topbar-actions">
        <span
          className={`integrity ${audit?.valid === true ? "valid" : "pending"}`}
        >
          <span aria-hidden="true">{audit?.valid === true ? "✓" : "·"}</span>
          {audit?.valid === true
            ? `${audit.events_checked} events verified`
            : "Checking journal"}
        </span>
        <button
          className="icon-button"
          onClick={onTheme}
          aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </button>
      </div>
    </header>
  );
}

function IntentComposer({
  content,
  disabled,
  onChange,
  onSubmit,
}: {
  content: string;
  disabled: boolean;
  onChange: (value: string) => void;
  onSubmit: () => void;
}) {
  return (
    <section className="intent-composer" aria-labelledby="new-intent-heading">
      <div className="section-label">
        <span id="new-intent-heading">New intent</span>
        <small>Fixture planner</small>
      </div>
      <textarea
        aria-label="Public content for a reversible workspace note"
        value={content}
        maxLength={4096}
        onChange={(event) => onChange(event.target.value)}
      />
      <div className="composer-meta">
        <span>demo/ · create</span>
        <span>{content.length}/4096</span>
      </div>
      <button
        className="primary-button full"
        disabled={disabled || content.length === 0}
        onClick={onSubmit}
      >
        <PlusIcon /> Create transaction
      </button>
    </section>
  );
}

function TransactionInspector({
  bundle,
  busy,
  approverId,
  onPreview,
  onApprove,
  onRun,
  onRollback,
}: {
  bundle: TransactionBundle;
  busy: boolean;
  approverId: string | undefined;
  onPreview: () => void;
  onApprove: (requestId: string) => void;
  onRun: () => void;
  onRollback: () => void;
}) {
  const transaction = bundle.transaction;
  const pendingApproval = bundle.approval_requests.find(
    (request) =>
      !bundle.approval_grants.some((grant) => grant.request_id === request.id),
  );
  return (
    <div className="inspector">
      <section className="inspector-heading">
        <div>
          <p className="eyebrow">Transaction / {shortId(transaction.id)}</p>
          <h1>{bundle.intent.summary}</h1>
          <div className="heading-meta">
            <StateBadge state={transaction.state} />
            <span>revision {transaction.revision}</span>
            <span>{bundle.plan.planner}</span>
          </div>
        </div>
        <TransactionActions
          state={transaction.state}
          busy={busy}
          canApprove={pendingApproval !== undefined && approverId !== undefined}
          onPreview={onPreview}
          onApprove={() =>
            pendingApproval !== undefined && onApprove(pendingApproval.id)
          }
          onRun={onRun}
          onRollback={onRollback}
        />
      </section>

      {transaction.state === "manual_recovery" && (
        <section className="recovery-banner" role="alert">
          <strong>Manual recovery required</strong>
          <p>
            {transaction.manual_recovery_reason ??
              "Execution evidence is ambiguous. Do not retry blindly."}
          </p>
        </section>
      )}

      <section className="summary-strip" aria-label="Transaction summary">
        <SummaryDatum
          label="Effects"
          value={String(transaction.effect_ids.length)}
        />
        <SummaryDatum label="Receipts" value={String(bundle.receipts.length)} />
        <SummaryDatum
          label="Verified"
          value={`${bundle.verifications.filter((item) => item.passed).length}/${bundle.plan.steps.flatMap((step) => step.effects).length}`}
        />
        <SummaryDatum label="Recovery" value={recoveryLabel(bundle)} />
      </section>

      {pendingApproval !== undefined && (
        <ApprovalPanel
          request={pendingApproval}
          canApprove={approverId !== undefined}
          busy={busy}
          onApprove={() => onApprove(pendingApproval.id)}
        />
      )}

      <div className="inspector-grid">
        <section className="panel effects-panel">
          <PanelHeading
            eyebrow="Plan"
            title="Proposed effects"
            meta={`${bundle.plan.steps.length} step`}
          />
          {bundle.plan.steps.map((step, index) => (
            <div className="step" key={step.id}>
              <div className="step-index">
                {String(index + 1).padStart(2, "0")}
              </div>
              <div className="step-body">
                <h3>{step.summary}</h3>
                {step.effects.map((effect) => (
                  <EffectCard key={effect.id} effect={effect} />
                ))}
              </div>
            </div>
          ))}
        </section>

        <section className="panel timeline-panel">
          <PanelHeading
            eyebrow="Causality"
            title="Execution timeline"
            meta={`${bundle.events.length} events`}
          />
          <Timeline events={bundle.events} />
        </section>
      </div>

      {(bundle.receipts.length > 0 || bundle.verifications.length > 0) && (
        <section className="panel evidence-panel">
          <PanelHeading
            eyebrow="Evidence"
            title="Receipts & verification"
            meta="Kernel authenticated"
          />
          <div className="evidence-grid">
            {bundle.receipts.map((receipt) => (
              <article className="evidence-card" key={receipt.id}>
                <div className="evidence-title">
                  <span className="evidence-icon">R</span>
                  <div>
                    <strong>{receipt.outcome}</strong>
                    <span>{shortId(receipt.id)}</span>
                  </div>
                </div>
                <dl>
                  <div>
                    <dt>Effect</dt>
                    <dd>{shortId(receipt.effect_id)}</dd>
                  </div>
                  <div>
                    <dt>Result</dt>
                    <dd title={receipt.result_digest}>
                      {shortDigest(receipt.result_digest)}
                    </dd>
                  </div>
                  <div>
                    <dt>Signer</dt>
                    <dd>{receipt.signer_key_id.split(":").at(-1)}</dd>
                  </div>
                </dl>
              </article>
            ))}
            {bundle.verifications.map((verification) => (
              <article
                className={`evidence-card ${verification.passed ? "passed" : "failed"}`}
                key={verification.id}
              >
                <div className="evidence-title">
                  <span className="evidence-icon">
                    {verification.passed ? "✓" : "!"}
                  </span>
                  <div>
                    <strong>
                      {verification.passed
                        ? "Postconditions satisfied"
                        : "Verification failed"}
                    </strong>
                    <span>{verification.checks.length} checks</span>
                  </div>
                </div>
                <ul className="check-list">
                  {verification.checks.map((check, index) => (
                    <li key={`${verification.id}-${index}`}>
                      <span>{check.passed ? "✓" : "×"}</span>
                      {check.message}
                    </li>
                  ))}
                </ul>
              </article>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function TransactionActions({
  state,
  busy,
  canApprove,
  onPreview,
  onApprove,
  onRun,
  onRollback,
}: {
  state: TransactionState;
  busy: boolean;
  canApprove: boolean;
  onPreview: () => void;
  onApprove: () => void;
  onRun: () => void;
  onRollback: () => void;
}) {
  if (state === "planned")
    return (
      <button className="primary-button" disabled={busy} onClick={onPreview}>
        Review effects <ArrowIcon />
      </button>
    );
  if (state === "awaiting_approval")
    return (
      <button
        className="primary-button"
        disabled={busy || !canApprove}
        onClick={onApprove}
      >
        Approve exact effect <CheckIcon />
      </button>
    );
  if (state === "approved")
    return (
      <button className="primary-button" disabled={busy} onClick={onRun}>
        Execute transaction <ArrowIcon />
      </button>
    );
  if (state === "committed")
    return (
      <button
        className="secondary-button danger"
        disabled={busy}
        onClick={onRollback}
      >
        Roll back <UndoIcon />
      </button>
    );
  return <span className="terminal-label">No forward action available</span>;
}

function ApprovalPanel({
  request,
  canApprove,
  busy,
  onApprove,
}: {
  request: TransactionBundle["approval_requests"][number];
  canApprove: boolean;
  busy: boolean;
  onApprove: () => void;
}) {
  return (
    <section
      className={`approval-panel risk-${request.risk}`}
      aria-labelledby="approval-heading"
    >
      <div className="approval-copy">
        <p className="eyebrow">Permission required · {request.risk} risk</p>
        <h2 id="approval-heading">Authorize this exact effect</h2>
        <p>
          Approval binds the complete preflighted effect to digest{" "}
          <code>{shortDigest(request.effect_digest)}</code> and expires{" "}
          {relativeTime(request.expires_at)}.
        </p>
      </div>
      <div className="approval-scope">
        <span>Exact resource scope</span>
        <strong>{formatResource(request.resource)}</strong>
      </div>
      <button
        className="primary-button"
        disabled={busy || !canApprove}
        onClick={onApprove}
      >
        <CheckIcon /> {canApprove ? "Grant approval" : "Approver unavailable"}
      </button>
    </section>
  );
}

function EffectCard({ effect }: { effect: Effect }) {
  return (
    <article className="effect-card">
      <div className="effect-head">
        <div>
          <span className="adapter-tag">{effect.adapter}</span>
          <strong>{effect.operation}</strong>
        </div>
        <div className="risk-group">
          <span className={`risk-badge risk-${effect.risk}`}>
            {effect.risk}
          </span>
          <span className="reversibility">{effect.reversibility}</span>
        </div>
      </div>
      <dl className="effect-spec">
        <div>
          <dt>Resource</dt>
          <dd>{formatResource(effect.resource)}</dd>
        </div>
        <div>
          <dt>Principal</dt>
          <dd>{shortId(effect.principal_id)}</dd>
        </div>
        <div>
          <dt>Timeout</dt>
          <dd>{effect.timeout_ms.toLocaleString()} ms</dd>
        </div>
        <div>
          <dt>Idempotency</dt>
          <dd title={effect.idempotency_key}>
            {truncateMiddle(effect.idempotency_key, 25)}
          </dd>
        </div>
      </dl>
      <PreviewBlock preview={effect.preview} />
      <details className="conditions">
        <summary>
          {effect.expected_postconditions.length} declared postconditions
        </summary>
        <pre>{JSON.stringify(effect.expected_postconditions, null, 2)}</pre>
      </details>
    </article>
  );
}

function PreviewBlock({ preview }: { preview: EffectPreview }) {
  if (preview.kind === "pending") {
    return (
      <div className="preview-pending">Adapter preview has not run yet.</div>
    );
  }
  if (preview.kind === "filesystem") {
    return (
      <div className="diff-block">
        <div className="diff-header">
          <span>{preview.path}</span>
          <small>{preview.operation}</small>
        </div>
        <pre>
          {preview.unified_diff ?? `${preview.operation} ${preview.path}`}
        </pre>
      </div>
    );
  }
  return (
    <pre className="structured-preview">{JSON.stringify(preview, null, 2)}</pre>
  );
}

function Timeline({ events }: { events: AuditEvent[] }) {
  if (events.length === 0)
    return <EmptyCompact message="No journal events yet" />;
  return (
    <ol className="timeline">
      {events
        .slice()
        .reverse()
        .map((event) => (
          <li key={event.id}>
            <span className="timeline-node" aria-hidden="true" />
            <div>
              <strong>{event.event_type.replaceAll(".", " / ")}</strong>
              <p>
                <time>
                  {new Date(event.recorded_at).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </time>
                {event.causal_parent !== null && (
                  <span>caused by {shortId(event.causal_parent)}</span>
                )}
              </p>
            </div>
            <code>#{event.sequence.toString().padStart(4, "0")}</code>
          </li>
        ))}
    </ol>
  );
}

function AuditView({
  events,
  verification,
}: {
  events: AuditEvent[];
  verification: AuditVerification | null;
}) {
  return (
    <div className="inspector audit-view">
      <section className="inspector-heading">
        <div>
          <p className="eyebrow">Append-only local evidence</p>
          <h1>Audit history</h1>
          <div className="heading-meta">
            <span>{events.length} visible events</span>
            <span>SHA-256 linked</span>
            <span>Not a blockchain</span>
          </div>
        </div>
        <StateBadge
          state={verification?.valid === true ? "committed" : "manual_recovery"}
          label={
            verification?.valid === true
              ? "Chain verified"
              : "Verification pending"
          }
        />
      </section>
      <section className="panel audit-table-panel">
        <PanelHeading
          eyebrow="Journal"
          title="Causal event stream"
          meta={verification?.message ?? "Checking integrity"}
        />
        {events.length === 0 ? (
          <EmptyCompact message="No events match this search" />
        ) : (
          <div
            className="audit-table"
            role="table"
            aria-label="Audit journal events"
          >
            <div className="audit-row audit-header" role="row">
              <span>Sequence</span>
              <span>Event</span>
              <span>Transaction</span>
              <span>Hash</span>
              <span>Time</span>
            </div>
            {events
              .slice()
              .reverse()
              .map((event) => (
                <div className="audit-row" role="row" key={event.id}>
                  <code>#{event.sequence.toString().padStart(6, "0")}</code>
                  <strong>{event.event_type}</strong>
                  <span>
                    {event.transaction_id === null
                      ? "global"
                      : shortId(event.transaction_id)}
                  </span>
                  <code title={event.hash}>{shortDigest(event.hash)}</code>
                  <time>{new Date(event.recorded_at).toLocaleString()}</time>
                </div>
              ))}
          </div>
        )}
      </section>
    </div>
  );
}

function ConnectionScreen({
  initialError,
  onConnect,
}: {
  initialError: string | null;
  onConnect: (connection: ConnectionInfo) => Promise<void>;
}) {
  const [apiUrl, setApiUrl] = useState("http://127.0.0.1:7843/v1/");
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(initialError);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setError(initialError);
  }, [initialError]);

  return (
    <main className="connection-screen">
      <section className="connection-card">
        <span className="mark large" aria-hidden="true">
          V
        </span>
        <p className="eyebrow">Local execution boundary</p>
        <h1>Connect to Veyra</h1>
        <p>
          The desktop build connects automatically. Browser development requires
          the local loopback URL and token.
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            setLoading(true);
            setError(null);
            void onConnect({ apiUrl, token })
              .catch((caught: unknown) => setError(messageOf(caught)))
              .finally(() => setLoading(false));
          }}
        >
          <label>
            API URL
            <input
              value={apiUrl}
              onChange={(event) => setApiUrl(event.target.value)}
            />
          </label>
          <label>
            Administrative bearer token
            <input
              type="password"
              autoComplete="off"
              value={token}
              onChange={(event) => setToken(event.target.value)}
            />
          </label>
          {error !== null && (
            <div className="inline-error" role="alert">
              {error}
            </div>
          )}
          <button
            className="primary-button full"
            disabled={loading || token.length === 0}
          >
            {loading ? "Connecting…" : "Connect locally"}
          </button>
        </form>
        <small>
          This root credential is saved in this local browser profile and sent
          only to the explicit loopback endpoint. Never give it to a model.
        </small>
      </section>
    </main>
  );
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <section className="empty-state">
      <span className="empty-symbol" aria-hidden="true">
        ↺
      </span>
      <p className="eyebrow">No transaction selected</p>
      <h1>Make the next side effect inspectable.</h1>
      <p>
        Create a deterministic workspace intent, then review its exact scope
        before anything executes.
      </p>
      <button className="primary-button" onClick={onCreate}>
        <PlusIcon /> Create demo transaction
      </button>
    </section>
  );
}

function InspectorSkeleton() {
  return (
    <div className="skeleton" aria-label="Loading transaction">
      <div />
      <div />
      <div />
      <div />
    </div>
  );
}

function LoadingBar({ label }: { label: string }) {
  return (
    <div className="loading-bar" role="status">
      <span />
      {label}…
    </div>
  );
}

function EmptyCompact({ message }: { message: string }) {
  return <div className="empty-compact">{message}</div>;
}

function PanelHeading({
  eyebrow,
  title,
  meta,
}: {
  eyebrow: string;
  title: string;
  meta: string;
}) {
  return (
    <header className="panel-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h2>{title}</h2>
      </div>
      <span>{meta}</span>
    </header>
  );
}

function SummaryDatum({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StateBadge({
  state,
  label,
}: {
  state: TransactionState;
  label?: string;
}) {
  return (
    <span className={`state-badge state-${state}`}>
      <StateDot state={state} />
      {label ?? readableState(state)}
    </span>
  );
}

function StateDot({ state }: { state: TransactionState }) {
  return <span className={`state-dot state-${state}`} aria-hidden="true" />;
}

function recoveryLabel(bundle: TransactionBundle): string {
  if (bundle.compensations.length === 0) return "Available";
  const restored = bundle.compensations.filter((item) => item.restored).length;
  return `${restored}/${bundle.compensations.length} restored`;
}

function readableState(state: TransactionState): string {
  return state
    .replaceAll("_", " ")
    .replace(/^./, (value) => value.toUpperCase());
}

function formatResource(resource: ResourceScope): string {
  switch (resource.kind) {
    case "filesystem":
      return `${resource.workspace}:/${resource.path}`;
    case "filesystem_set":
      return `${resource.workspace}:/${resource.paths.join(" ↔ ")}`;
    case "http":
      return `${resource.scheme}://${resource.domain}${resource.port === null ? "" : `:${resource.port}`}${resource.path_prefix}`;
    case "process":
      return `${resource.executable} @ ${resource.workdir}`;
    case "generic":
      return `${resource.namespace}:${resource.resource}`;
  }
}

function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function shortDigest(value: string): string {
  return truncateMiddle(value, 20);
}

function truncateMiddle(value: string, size: number): string {
  if (value.length <= size) return value;
  const side = Math.floor((size - 1) / 2);
  return `${value.slice(0, side)}…${value.slice(-side)}`;
}

function relativeTime(value: string): string {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  return formatter.format(Math.round(minutes / 60), "hour");
}

function preferredTheme(): Theme {
  const saved = localStorage.getItem("veyra.theme");
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

function storedApprovers(): Record<string, string> {
  try {
    const value: unknown = JSON.parse(
      localStorage.getItem("veyra.demoApprovers") ?? "{}",
    );
    return value !== null && typeof value === "object"
      ? (value as Record<string, string>)
      : {};
  } catch {
    return {};
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "An unknown local error occurred";
}

function SearchIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <circle cx="8.5" cy="8.5" r="5.5" />
      <path d="m13 13 4 4" />
    </svg>
  );
}
function PlusIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M10 4v12M4 10h12" />
    </svg>
  );
}
function ArrowIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="m7 4 6 6-6 6" />
    </svg>
  );
}
function CheckIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="m4 10 4 4 8-9" />
    </svg>
  );
}
function UndoIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M7 5 3 9l4 4M4 9h7a5 5 0 0 1 5 5" />
    </svg>
  );
}
function SunIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <circle cx="10" cy="10" r="3" />
      <path d="M10 1v2M10 17v2M1 10h2M17 10h2M3.6 3.6 5 5M15 15l1.4 1.4M16.4 3.6 15 5M5 15l-1.4 1.4" />
    </svg>
  );
}
function MoonIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M16 13.5A7 7 0 0 1 6.5 4 7 7 0 1 0 16 13.5Z" />
    </svg>
  );
}
