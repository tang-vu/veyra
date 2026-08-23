//! Authenticated versioned loopback API.

use std::{collections::BTreeMap, fmt::Write as _, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use veyra_core::{
    ApprovalOutcome, Kernel, KernelError, PreviewOutcome, RollbackOutcome, RunOutcome, Submission,
};
use veyra_journal::{JournalError, JournalPage, RecoveryRecord};
use veyra_protocol::{
    ApprovalGrant, ApprovalRequest, AuditEvent, AuditVerification, Capability, CapabilityId,
    Compensation, Execution, Intent, IntentId, PROTOCOL_VERSION, Plan, PlanId, PolicyDecision,
    Principal, PrincipalId, PrincipalKind, Receipt, ResourceScope, Transaction, TransactionId,
    Verification,
};

/// Shared API state. The bearer token is deliberately omitted from `Debug` and responses.
#[derive(Clone)]
pub struct ApiState {
    kernel: Kernel,
    token: Arc<str>,
    workspace_name: Arc<str>,
}

impl ApiState {
    /// Bind a prepared kernel to one bearer token and demo workspace name.
    pub fn new(kernel: Kernel, token: Arc<str>, workspace_name: impl Into<Arc<str>>) -> Self {
        Self {
            kernel,
            token,
            workspace_name: workspace_name.into(),
        }
    }

    /// Access the trusted kernel for embedded integrations and tests.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }
}

/// Construct the complete `/v1` API with bounded bodies, exact CORS origins, and bearer auth.
pub fn router(state: ApiState) -> Router {
    let origins = [
        HeaderValue::from_static("tauri://localhost"),
        HeaderValue::from_static("http://tauri.localhost"),
        HeaderValue::from_static("http://localhost:1420"),
        HeaderValue::from_static("http://127.0.0.1:1420"),
    ];
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/principals", post(register_principal))
        .route("/v1/intents", post(submit_intent))
        .route("/v1/intents/{id}", get(get_intent))
        .route("/v1/plans/{id}", get(get_plan))
        .route("/v1/transactions", get(list_transactions))
        .route("/v1/transactions/page", get(list_transaction_page))
        .route("/v1/transactions/{id}", get(get_transaction))
        .route("/v1/transactions/{id}/bundle", get(get_transaction_bundle))
        .route("/v1/transactions/{id}/preview", post(preview_transaction))
        .route("/v1/transactions/{id}/run", post(run_transaction))
        .route("/v1/transactions/{id}/rollback", post(rollback_transaction))
        .route("/v1/approvals/{id}/grant", post(grant_approval))
        .route("/v1/capabilities", post(issue_capability))
        .route("/v1/capabilities/{id}/revoke", post(revoke_capability))
        .route("/v1/audit/events", get(audit_events))
        .route("/v1/audit/events/page", get(audit_event_page))
        .route("/v1/audit/export", get(audit_export))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/v1/recovery", get(recovery_actions))
        .route("/v1/recovery/page", get(recovery_action_page))
        .route("/v1/demo/seed", post(seed_demo))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(no_store_response))
        .with_state(state)
}

async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn authenticate(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    let valid: bool = provided.as_bytes().ct_eq(state.token.as_bytes()).into();
    if !valid {
        return Err(ApiError::unauthorized());
    }
    Ok(next.run(request).await)
}

async fn health() -> Json<Value> {
    Json(json!({"status":"ok", "api_version":"v1", "protocol_version":PROTOCOL_VERSION}))
}

async fn register_principal(
    State(state): State<ApiState>,
    Json(principal): Json<Principal>,
) -> Result<(StatusCode, Json<Principal>), ApiError> {
    state.kernel.register_principal(&principal)?;
    Ok((StatusCode::CREATED, Json(principal)))
}

async fn submit_intent(
    State(state): State<ApiState>,
    Json(intent): Json<Intent>,
) -> Result<(StatusCode, Json<Submission>), ApiError> {
    let submission = state.kernel.submit_intent(intent).await?;
    Ok((StatusCode::CREATED, Json(submission)))
}

async fn get_intent(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Intent>, ApiError> {
    let id: IntentId = parse_id(&id, "intent")?;
    Ok(Json(
        state
            .kernel
            .journal()
            .get_object("intent", &id.to_string())?,
    ))
}

async fn get_plan(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Plan>, ApiError> {
    let id: PlanId = parse_id(&id, "plan")?;
    Ok(Json(load_plan(&state.kernel, id)?))
}

async fn list_transactions(
    State(state): State<ApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Vec<Transaction>>, ApiError> {
    let limit = page_limit(query.limit, 100, 500)?;
    Ok(Json(
        state
            .kernel
            .journal()
            .transaction_page(limit, query.cursor.as_deref())?
            .items,
    ))
}

/// A bounded page with an opaque keyset cursor.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiPage<T> {
    /// Values in stable endpoint order.
    pub items: Vec<T>,
    /// Opaque cursor for the next page, absent at the end.
    pub next_cursor: Option<String>,
}

impl<T> From<JournalPage<T>> for ApiPage<T> {
    fn from(page: JournalPage<T>) -> Self {
        Self {
            items: page.items,
            next_cursor: page.next_cursor,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn list_transaction_page(
    State(state): State<ApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApiPage<Transaction>>, ApiError> {
    let limit = page_limit(query.limit, 100, 500)?;
    Ok(Json(
        state
            .kernel
            .journal()
            .transaction_page(limit, query.cursor.as_deref())?
            .into(),
    ))
}

async fn get_transaction(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Transaction>, ApiError> {
    Ok(Json(
        state
            .kernel
            .journal()
            .transaction(parse_id(&id, "transaction")?)?,
    ))
}

async fn preview_transaction(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<PreviewOutcome>, ApiError> {
    Ok(Json(
        state
            .kernel
            .preview_transaction(parse_id(&id, "transaction")?)
            .await?,
    ))
}

async fn run_transaction(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<RunOutcome>, ApiError> {
    Ok(Json(
        state
            .kernel
            .run_transaction(parse_id(&id, "transaction")?)
            .await?,
    ))
}

async fn rollback_transaction(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<RollbackOutcome>, ApiError> {
    Ok(Json(
        state
            .kernel
            .rollback_transaction(parse_id(&id, "transaction")?)
            .await?,
    ))
}

/// Body for a human approval grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantApprovalRequest {
    /// Registered human approving the exact content-addressed challenge.
    pub approver_id: PrincipalId,
}

async fn grant_approval(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<GrantApprovalRequest>,
) -> Result<Json<ApprovalOutcome>, ApiError> {
    Ok(Json(
        state
            .kernel
            .grant_approval(parse_id(&id, "approval request")?, body.approver_id)
            .await?,
    ))
}

/// Body for issuing a scoped capability through a human authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCapabilityRequest {
    /// Registered human issuing the grant.
    pub issuer_id: PrincipalId,
    /// Exact scoped grant.
    pub capability: Capability,
}

async fn issue_capability(
    State(state): State<ApiState>,
    Json(body): Json<IssueCapabilityRequest>,
) -> Result<(StatusCode, Json<Capability>), ApiError> {
    state
        .kernel
        .issue_capability(body.issuer_id, &body.capability)?;
    Ok((StatusCode::CREATED, Json(body.capability)))
}

/// Body for revoking a capability through a human authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCapabilityRequest {
    /// Registered human revoking the grant.
    pub revoker_id: PrincipalId,
}

async fn revoke_capability(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<RevokeCapabilityRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .kernel
        .revoke_capability(body.revoker_id, parse_id(&id, "capability")?)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AuditQuery {
    transaction_id: Option<TransactionId>,
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn audit_events(
    State(state): State<ApiState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    let limit = page_limit(query.limit, 200, 1_000)?;
    Ok(Json(
        state
            .kernel
            .journal()
            .recent_audit_event_page(query.transaction_id, limit, query.cursor.as_deref())?
            .items,
    ))
}

async fn audit_event_page(
    State(state): State<ApiState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ApiPage<AuditEvent>>, ApiError> {
    let limit = page_limit(query.limit, 200, 1_000)?;
    Ok(Json(
        state
            .kernel
            .journal()
            .recent_audit_event_page(query.transaction_id, limit, query.cursor.as_deref())?
            .into(),
    ))
}

/// Human-readable audit export response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditTextExport {
    /// Optional transaction filter.
    pub transaction_id: Option<TransactionId>,
    /// Redacted, line-oriented timeline.
    pub text: String,
    /// Opaque cursor for the next bounded export page.
    pub next_cursor: Option<String>,
}

async fn audit_export(
    State(state): State<ApiState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditTextExport>, ApiError> {
    let limit = page_limit(query.limit, 1_000, 5_000)?;
    let page = state.kernel.journal().audit_event_page(
        query.transaction_id,
        limit,
        query.cursor.as_deref(),
    )?;
    Ok(Json(AuditTextExport {
        transaction_id: query.transaction_id,
        text: render_audit_text(&page.items),
        next_cursor: page.next_cursor,
    }))
}

async fn audit_verify(State(state): State<ApiState>) -> Result<Json<AuditVerification>, ApiError> {
    Ok(Json(state.kernel.journal().verify_chain()?))
}

async fn recovery_actions(
    State(state): State<ApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Vec<RecoveryRecord>>, ApiError> {
    let limit = page_limit(query.limit, 200, 500)?;
    Ok(Json(
        state
            .kernel
            .journal()
            .recovery_action_page(limit, query.cursor.as_deref())?
            .items,
    ))
}

async fn recovery_action_page(
    State(state): State<ApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApiPage<RecoveryRecord>>, ApiError> {
    let limit = page_limit(query.limit, 200, 500)?;
    Ok(Json(
        state
            .kernel
            .journal()
            .recovery_action_page(limit, query.cursor.as_deref())?
            .into(),
    ))
}

/// Optional labels for a real deterministic demo transaction.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DemoSeedRequest {
    /// Public file contents. This endpoint does not accept secrets.
    pub content: Option<String>,
}

/// Identities, grant, and planned transaction created by demo seeding.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DemoSeed {
    /// Human operator who can issue and approve.
    pub human: Principal,
    /// Agent principal that proposed the intent.
    pub agent: Principal,
    /// One-use, transaction-bound filesystem capability.
    pub capability: Capability,
    /// Real kernel submission.
    pub submission: Submission,
}

async fn seed_demo(
    State(state): State<ApiState>,
    Json(request): Json<DemoSeedRequest>,
) -> Result<(StatusCode, Json<DemoSeed>), ApiError> {
    let human = Principal {
        id: PrincipalId::new(),
        display_name: "Demo operator".into(),
        kind: PrincipalKind::Human,
    };
    let agent = Principal {
        id: PrincipalId::new(),
        display_name: "Deterministic fixture agent".into(),
        kind: PrincipalKind::Agent,
    };
    state.kernel.register_principal(&human)?;
    state.kernel.register_principal(&agent)?;
    let intent_id = IntentId::new();
    let relative_path = format!("demo/hello-{}.txt", &intent_id.to_string()[..8]);
    let content = request
        .content
        .unwrap_or_else(|| "Hello from Veyra.\n".into());
    let intent = demo_intent(
        &state.workspace_name,
        intent_id,
        agent.id,
        &relative_path,
        &content,
    );
    let submission = state.kernel.submit_intent(intent).await?;
    let capability = demo_capability(&state.workspace_name, &submission, &relative_path);
    state.kernel.issue_capability(human.id, &capability)?;
    Ok((
        StatusCode::CREATED,
        Json(DemoSeed {
            human,
            agent,
            capability,
            submission,
        }),
    ))
}

fn demo_intent(
    workspace: &str,
    id: IntentId,
    principal_id: PrincipalId,
    path: &str,
    content: &str,
) -> Intent {
    Intent {
        schema_version: PROTOCOL_VERSION.into(),
        id,
        principal_id,
        summary: "Create a deterministic, reversible workspace greeting".into(),
        requested_resources: vec![ResourceScope::Filesystem {
            workspace: workspace.into(),
            path: "demo".into(),
        }],
        context: BTreeMap::from([
            ("workspace".into(), json!(workspace)),
            ("operation".into(), json!("create")),
            ("path".into(), json!(path)),
            ("content".into(), json!(content)),
        ]),
        created_at: Utc::now(),
    }
}

fn demo_capability(workspace: &str, submission: &Submission, path: &str) -> Capability {
    let now = Utc::now();
    Capability {
        id: CapabilityId::new(),
        principal_id: submission.intent.principal_id,
        intent_id: Some(submission.intent.id),
        transaction_id: Some(submission.transaction.id),
        adapter: "filesystem".into(),
        operations: vec!["create".into()],
        resources: vec![ResourceScope::Filesystem {
            workspace: workspace.into(),
            path: path.into(),
        }],
        constraints: BTreeMap::from([
            ("max_timeout_ms".into(), "5000".into()),
            ("max_risk".into(), "medium".into()),
        ]),
        not_before: now - Duration::seconds(1),
        expires_at: now + Duration::minutes(10),
        nonce: format!("demo-capability-{}", CapabilityId::new()),
        max_uses: 1,
        issued_at: now,
    }
}

/// Aggregate needed by the desktop transaction inspector in one consistent read.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionBundle {
    /// Latest transaction snapshot.
    pub transaction: Transaction,
    /// Source intent.
    pub intent: Intent,
    /// Proposed or preflighted plan.
    pub plan: Plan,
    /// Policy decisions for effects in this plan.
    pub policy_decisions: Vec<PolicyDecision>,
    /// Approval challenges for this transaction.
    pub approval_requests: Vec<ApprovalRequest>,
    /// Approval grants for this transaction.
    pub approval_grants: Vec<ApprovalGrant>,
    /// Adapter execution attempts.
    pub executions: Vec<Execution>,
    /// Authenticated receipts.
    pub receipts: Vec<Receipt>,
    /// Postcondition evidence.
    pub verifications: Vec<Verification>,
    /// Recovery attempts.
    pub compensations: Vec<Compensation>,
    /// Causal, redacted audit timeline.
    pub events: Vec<AuditEvent>,
}

async fn get_transaction_bundle(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<TransactionBundle>, ApiError> {
    let transaction_id = parse_id(&id, "transaction")?;
    let journal = state.kernel.journal();
    let bundle = journal.read_snapshot(|snapshot| {
        let transaction = snapshot.transaction(transaction_id)?;
        let intent = snapshot.get_object("intent", &transaction.intent_id.to_string())?;
        let plan = match snapshot.get_object("preflighted_plan", &transaction.plan_id.to_string()) {
            Ok(plan) => plan,
            Err(JournalError::NotFound { .. }) => {
                snapshot.get_object("proposed_plan", &transaction.plan_id.to_string())?
            }
            Err(error) => return Err(error),
        };
        let policy_decisions =
            snapshot.objects_for_effects("policy_decision", &transaction.effect_ids)?;
        Ok(TransactionBundle {
            transaction,
            intent,
            plan,
            policy_decisions,
            approval_requests: snapshot
                .objects_for_transaction("approval_request", transaction_id)?,
            approval_grants: snapshot.objects_for_transaction("approval_grant", transaction_id)?,
            executions: snapshot.objects_for_transaction("execution", transaction_id)?,
            receipts: snapshot.objects_for_transaction("receipt", transaction_id)?,
            verifications: snapshot.objects_for_transaction("verification", transaction_id)?,
            compensations: snapshot.objects_for_transaction("compensation", transaction_id)?,
            events: snapshot.export_events(Some(transaction_id))?,
        })
    })?;
    Ok(Json(bundle))
}

fn load_plan(kernel: &Kernel, id: PlanId) -> Result<Plan, JournalError> {
    match kernel
        .journal()
        .get_object("preflighted_plan", &id.to_string())
    {
        Ok(plan) => Ok(plan),
        Err(JournalError::NotFound { .. }) => kernel
            .journal()
            .get_object("proposed_plan", &id.to_string()),
        Err(error) => Err(error),
    }
}

fn page_limit(requested: Option<usize>, default: usize, maximum: usize) -> Result<usize, ApiError> {
    let limit = requested.unwrap_or(default);
    if limit == 0 || limit > maximum {
        return Err(ApiError::bad_request(
            "invalid_pagination",
            format!("page limit must be within 1..={maximum}"),
        ));
    }
    Ok(limit)
}

fn render_audit_text(events: &[AuditEvent]) -> String {
    let mut output = String::new();
    for event in events {
        let _ = writeln!(
            output,
            "{:06} {} {} tx={} hash={}",
            event.sequence,
            event.recorded_at.to_rfc3339(),
            event.event_type,
            event
                .transaction_id
                .map_or_else(|| "-".into(), |id| id.to_string()),
            event.hash.get(..12).unwrap_or(&event.hash),
        );
    }
    output
}

fn parse_id<T>(value: &str, kind: &'static str) -> Result<T, ApiError>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid_id", format!("invalid {kind} ID")))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(code: &'static str, message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "authentication_required",
            message: "a valid local bearer token is required".into(),
        }
    }
}

impl From<JournalError> for ApiError {
    fn from(error: JournalError) -> Self {
        let status = if matches!(error, JournalError::InvalidCursor(_)) {
            StatusCode::BAD_REQUEST
        } else if matches!(error, JournalError::NotFound { .. }) {
            StatusCode::NOT_FOUND
        } else if matches!(
            error,
            JournalError::ObjectConflict { .. }
                | JournalError::RevisionConflict { .. }
                | JournalError::CapabilityUnavailable(_)
                | JournalError::ApprovalReplay
        ) {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Self {
            status,
            code: if matches!(error, JournalError::InvalidCursor(_)) {
                "invalid_pagination"
            } else {
                "journal_error"
            },
            message: error.to_string(),
        }
    }
}

impl From<KernelError> for ApiError {
    fn from(error: KernelError) -> Self {
        let (status, code) = match &error {
            KernelError::InvalidInput(_) | KernelError::InvalidPlan(_) => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            KernelError::Authority(_) | KernelError::ApprovalMissing(_) => {
                (StatusCode::FORBIDDEN, "insufficient_authority")
            }
            KernelError::Journal(JournalError::NotFound { .. }) => {
                (StatusCode::NOT_FOUND, "not_found")
            }
            KernelError::InvalidState { .. }
            | KernelError::AlreadyApproved(_)
            | KernelError::ManualRecoveryRequired(_) => {
                (StatusCode::CONFLICT, "transaction_conflict")
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "kernel_error"),
        };
        Self {
            status,
            code,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let body = Json(json!({
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }));
        let mut response = (status, body).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"veyra\""),
            );
        }
        response
    }
}
