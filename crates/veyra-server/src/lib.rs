//! Embeddable, authenticated, loopback-only Veyra API server.

mod api;
mod config;

use std::{future::Future, net::SocketAddr};

use thiserror::Error;
use tokio::net::TcpListener;

pub use api::{
    ApiPage, ApiState, AuditTextExport, DemoSeed, DemoSeedRequest, GrantApprovalRequest,
    IssueCapabilityRequest, RevokeCapabilityRequest, TransactionBundle, router,
};
pub use config::{
    PlannerRuntimeConfig, PreparedInstance, RuntimeConfig, ServerConfigError, prepare_instance,
};

/// Serve the authenticated API, rejecting non-loopback listener addresses.
///
/// # Errors
///
/// Returns [`ServeError`] if the listener is not loopback-bound or the HTTP server fails.
pub async fn serve(listener: TcpListener, state: ApiState) -> Result<(), ServeError> {
    serve_with_shutdown(listener, state, std::future::pending::<()>()).await
}

/// Serve until the supplied shutdown future completes.
///
/// # Errors
///
/// Returns [`ServeError`] if the listener is not loopback-bound or the HTTP server fails.
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    state: ApiState,
    shutdown: F,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let address = listener.local_addr().map_err(ServeError::Io)?;
    if !address.ip().is_loopback() {
        return Err(ServeError::NonLoopback(address));
    }
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(ServeError::Io)
}

/// Loopback server startup or transport failure.
#[derive(Debug, Error)]
pub enum ServeError {
    /// Network listener is not confined to the local host.
    #[error("refusing to expose local authority on non-loopback address {0}")]
    NonLoopback(SocketAddr),
    /// Listener or HTTP serving failed.
    #[error("local API I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn authenticated_api_runs_the_real_reversible_demo() {
        let temporary = TempDir::new().unwrap();
        let config = RuntimeConfig::new(
            temporary.path().join("data"),
            temporary.path().join("workspace"),
        );
        let instance = prepare_instance(&config).unwrap();
        let state = ApiState::new(
            instance.kernel,
            Arc::clone(&instance.token),
            config.workspace_name,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, state));
        let client = reqwest::Client::new();
        let root = format!("http://{address}/v1");

        let unauthorized = client.get(format!("{root}/health")).send().await.unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"veyra\"")
        );
        assert_eq!(
            unauthorized
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );

        let seed: DemoSeed = client
            .post(format!("{root}/demo/seed"))
            .bearer_auth(&*instance.token)
            .json(&DemoSeedRequest::default())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let transaction_id = seed.submission.transaction.id;
        let preview: veyra_core::PreviewOutcome = client
            .post(format!("{root}/transactions/{transaction_id}/preview"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(preview.approval_requests.len(), 1);
        let request_id = preview.approval_requests[0].id;
        client
            .post(format!("{root}/approvals/{request_id}/grant"))
            .bearer_auth(&*instance.token)
            .json(&GrantApprovalRequest {
                approver_id: seed.human.id,
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let run: veyra_core::RunOutcome = client
            .post(format!("{root}/transactions/{transaction_id}/run"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(run.committed);
        let bundle: TransactionBundle = client
            .get(format!("{root}/transactions/{transaction_id}/bundle"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(bundle.receipts.len(), 1);
        client
            .post(format!("{root}/transactions/{transaction_id}/rollback"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let verification: veyra_protocol::AuditVerification = client
            .get(format!("{root}/audit/verify"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(verification.valid);
        let transactions: ApiPage<veyra_protocol::Transaction> = client
            .get(format!("{root}/transactions/page?limit=1"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(transactions.items.len(), 1);
        let events: ApiPage<veyra_protocol::AuditEvent> = client
            .get(format!("{root}/audit/events/page?limit=2"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(events.items.len(), 2);
        assert!(events.items[0].sequence > events.items[1].sequence);
        assert!(events.next_cursor.is_some());
        let recovery: ApiPage<veyra_journal::RecoveryRecord> = client
            .get(format!("{root}/recovery/page?limit=2"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(recovery.items.is_empty());
        let invalid_page = client
            .get(format!("{root}/audit/events/page?limit=2&cursor=invalid"))
            .bearer_auth(&*instance.token)
            .send()
            .await
            .unwrap();
        assert_eq!(invalid_page.status(), StatusCode::BAD_REQUEST);
        server.abort();
    }
}
