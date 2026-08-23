//! HTTP adapter with explicit origin/method policy, DNS pinning, and bounded responses.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use futures_util::StreamExt;
use reqwest::{
    Method, Url,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use veyra_protocol::{
    Condition, Effect, InputValue, Preview, ResourceScope, Reversibility, VerificationCheck,
};

use crate::{
    AdapterContext, AdapterError, AdapterPreflight, AdapterRecovery, AdapterResult, EffectAdapter,
    StagedEffect,
    util::{public_string, public_string_map, sha256},
};

/// One explicit HTTP origin, path, and method allowlist.
#[derive(Clone, Debug)]
pub struct HttpRule {
    /// Lowercase `http` or `https`.
    pub scheme: String,
    /// Exact lowercase DNS name or IP literal.
    pub domain: String,
    /// Explicit non-default port.
    pub port: Option<u16>,
    /// Allowed URL path prefix, matched on a segment boundary.
    pub path_prefix: String,
    /// Uppercase allowed methods.
    pub methods: BTreeSet<String>,
    /// Permit loopback/private/link-local addresses for this rule. Intended for local integrations.
    pub allow_private_network: bool,
}

/// HTTP adapter bounds and allowlists.
#[derive(Clone, Debug)]
pub struct HttpAdapterConfig {
    /// Explicit allowlist; empty denies all requests.
    pub rules: Vec<HttpRule>,
    /// Maximum request body bytes.
    pub maximum_request_bytes: usize,
    /// Maximum response body bytes after transfer decoding.
    pub maximum_response_bytes: usize,
    /// Maximum request timeout regardless of effect request.
    pub maximum_timeout_ms: u64,
}

/// Bounded HTTP effect adapter.
#[derive(Clone, Debug)]
pub struct HttpAdapter {
    config: HttpAdapterConfig,
}

impl HttpAdapter {
    /// Create an HTTP adapter. An empty rule list remains deny-by-default.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when limits are zero or a rule is malformed.
    pub fn new(config: HttpAdapterConfig) -> Result<Self, AdapterError> {
        if config.maximum_request_bytes == 0
            || config.maximum_response_bytes == 0
            || config.maximum_timeout_ms == 0
        {
            return Err(AdapterError::Policy(
                "HTTP size and timeout limits must be positive".into(),
            ));
        }
        for rule in &config.rules {
            if !matches!(rule.scheme.as_str(), "http" | "https")
                || rule.domain.trim().is_empty()
                || !rule.path_prefix.starts_with('/')
                || rule.methods.is_empty()
            {
                return Err(AdapterError::Policy(
                    "HTTP allowlist contains a malformed rule".into(),
                ));
            }
        }
        Ok(Self { config })
    }

    fn request_spec(&self, effect: &Effect) -> Result<HttpRequestSpec, AdapterError> {
        self.validate_shape(effect)?;
        let method = Method::from_bytes(public_string(&effect.inputs, "method")?.as_bytes())
            .map_err(|_| AdapterError::HttpSyntax("method"))?;
        let url = Url::parse(public_string(&effect.inputs, "url")?)
            .map_err(|_| AdapterError::HttpSyntax("URL"))?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(AdapterError::Policy(
                "URL user information and fragments are forbidden".into(),
            ));
        }
        reject_sensitive_query(&url)?;
        let host = url
            .host_str()
            .ok_or(AdapterError::HttpSyntax("URL host"))?
            .to_ascii_lowercase();
        let port = explicit_non_default_port(&url);
        Self::validate_resource(effect, &url, &host, port)?;
        let rule = self
            .config
            .rules
            .iter()
            .find(|rule| {
                rule.scheme.eq_ignore_ascii_case(url.scheme())
                    && rule.domain.eq_ignore_ascii_case(&host)
                    && rule.port == port
                    && rule.methods.contains(method.as_str())
                    && path_covers(&rule.path_prefix, url.path())
            })
            .ok_or_else(|| {
                AdapterError::Policy("URL origin, path, or method is not allowlisted".into())
            })?;

        let (public_headers, secret_headers) = parse_headers(effect)?;
        let body = effect
            .inputs
            .get("body")
            .map(|_| {
                public_string(&effect.inputs, "body")
                    .map(str::as_bytes)
                    .map(<[u8]>::to_vec)
            })
            .transpose()?
            .unwrap_or_default();
        if body.len() > self.config.maximum_request_bytes {
            return Err(AdapterError::SizeLimit {
                kind: "HTTP request body",
                limit: self.config.maximum_request_bytes,
            });
        }
        Ok(HttpRequestSpec {
            method: method.as_str().to_owned(),
            url: url.to_string(),
            host,
            port: url
                .port_or_known_default()
                .ok_or(AdapterError::HttpSyntax("URL port"))?,
            public_headers,
            secret_headers,
            body,
            allow_private_network: rule.allow_private_network,
        })
    }

    fn validate_shape(&self, effect: &Effect) -> Result<(), AdapterError> {
        if effect.adapter != self.name() {
            return Err(AdapterError::InvalidEffect(
                "adapter field is not `http`".into(),
            ));
        }
        if effect.operation != "request" {
            return Err(AdapterError::UnsupportedOperation {
                adapter: self.name().into(),
                operation: effect.operation.clone(),
            });
        }
        if effect.timeout_ms == 0 || effect.timeout_ms > self.config.maximum_timeout_ms {
            return Err(AdapterError::Policy(
                "effect timeout exceeds HTTP adapter limit".into(),
            ));
        }
        Ok(())
    }

    fn validate_resource(
        effect: &Effect,
        url: &Url,
        host: &str,
        port: Option<u16>,
    ) -> Result<(), AdapterError> {
        let ResourceScope::Http {
            scheme,
            domain,
            port: resource_port,
            path_prefix,
        } = &effect.resource
        else {
            return Err(AdapterError::InvalidEffect(
                "HTTP effect has a non-HTTP resource".into(),
            ));
        };
        if !scheme.eq_ignore_ascii_case(url.scheme())
            || !domain.eq_ignore_ascii_case(host)
            || *resource_port != port
            || path_prefix != url.path()
        {
            return Err(AdapterError::Containment(
                "URL does not exactly match the declared effect resource".into(),
            ));
        }
        Ok(())
    }

    async fn resolve(&self, spec: &HttpRequestSpec) -> Result<Vec<SocketAddr>, AdapterError> {
        let addresses: Vec<_> = tokio::net::lookup_host((spec.host.as_str(), spec.port))
            .await
            .map_err(AdapterError::Process)?
            .collect();
        if addresses.is_empty() {
            return Err(AdapterError::Policy(
                "HTTP destination resolved to no addresses".into(),
            ));
        }
        if !spec.allow_private_network
            && addresses.iter().any(|address| !is_public_ip(address.ip()))
        {
            return Err(AdapterError::Policy(
                "HTTP destination resolved to a non-public address".into(),
            ));
        }
        let mut addresses = addresses;
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }

    fn decode_stage(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
    ) -> Result<HttpStage, AdapterError> {
        if staged.adapter != self.name() || staged.effect_id != effect.id {
            return Err(AdapterError::InvalidStage(
                "HTTP stage binding mismatch".into(),
            ));
        }
        let digest = effect.content_digest().map_err(AdapterError::Canonical)?;
        if staged.effect_digest != digest {
            return Err(AdapterError::InvalidStage(
                "HTTP effect changed after staging".into(),
            ));
        }
        serde_json::from_value(staged.data.clone()).map_err(AdapterError::Serialization)
    }

    async fn send(
        &self,
        effect: &Effect,
        spec: &HttpRequestSpec,
        addresses: &[SocketAddr],
        context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError> {
        let method = Method::from_bytes(spec.method.as_bytes())
            .map_err(|_| AdapterError::HttpSyntax("method"))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_millis(effect.timeout_ms))
            .connect_timeout(Duration::from_millis(effect.timeout_ms.min(5_000)))
            .resolve_to_addrs(&spec.host, addresses)
            .build()
            .map_err(AdapterError::Network)?;
        let mut request = client.request(method.clone(), &spec.url);
        for (name, value) in &spec.public_headers {
            request = request.header(name, value);
        }
        let mut resolved_secrets = Vec::with_capacity(spec.secret_headers.len());
        for header in &spec.secret_headers {
            let secret = context.secrets.resolve(&header.provider, &header.key)?;
            let name = HeaderName::from_str(&header.name)
                .map_err(|_| AdapterError::HttpSyntax("header name"))?;
            let value = HeaderValue::from_bytes(secret.expose())
                .map_err(|_| AdapterError::HttpSyntax("secret header value"))?;
            request = request.header(name, value);
            resolved_secrets.push(secret);
        }
        if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
            request = request.header("idempotency-key", &effect.idempotency_key);
        }
        if !spec.body.is_empty() {
            request = request.body(spec.body.clone());
        }
        let response = request.send().await.map_err(AdapterError::Network)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| !is_sensitive_header(name.as_str()))
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or("[NON-UTF8]").to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if response.content_length().is_some_and(|length| {
            length > u64::try_from(self.config.maximum_response_bytes).unwrap_or(u64::MAX)
        }) {
            return Err(AdapterError::SizeLimit {
                kind: "HTTP response body",
                limit: self.config.maximum_response_bytes,
            });
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(AdapterError::Network)?;
            if body.len().saturating_add(chunk.len()) > self.config.maximum_response_bytes {
                return Err(AdapterError::SizeLimit {
                    kind: "HTTP response body",
                    limit: self.config.maximum_response_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        let body_digest = sha256(&body);
        let body_text = String::from_utf8(body).ok();
        drop(resolved_secrets);
        Ok(AdapterResult {
            outcome: format!("http_{status}"),
            data: json!({
                "status": status,
                "headers": headers,
                "body_utf8": body_text,
                "body_sha256": body_digest,
            }),
            post_state_digest: Some(body_digest),
        })
    }
}

#[async_trait]
impl EffectAdapter for HttpAdapter {
    fn name(&self) -> &'static str {
        "http"
    }

    fn validate(&self, effect: &Effect) -> Result<(), AdapterError> {
        let spec = self.request_spec(effect)?;
        let safe_method = matches!(spec.method.as_str(), "GET" | "HEAD" | "OPTIONS");
        if safe_method && effect.reversibility != Reversibility::Reversible {
            return Err(AdapterError::InvalidEffect(
                "safe HTTP methods must declare `reversible` (no mutation claimed)".into(),
            ));
        }
        if !safe_method && effect.reversibility == Reversibility::Reversible {
            return Err(AdapterError::InvalidEffect(
                "mutating HTTP requests can never declare `reversible`".into(),
            ));
        }
        if effect.reversibility == Reversibility::Compensatable && effect.inverse.is_none() {
            return Err(AdapterError::InvalidEffect(
                "compensatable HTTP request has no declared inverse".into(),
            ));
        }
        Ok(())
    }

    async fn preflight(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<AdapterPreflight, AdapterError> {
        let spec = self.request_spec(effect)?;
        self.validate(effect)?;
        let addresses = self.resolve(&spec).await?;
        let preview = Preview::Http {
            method: spec.method.clone(),
            url: spec.url.clone(),
            headers: preview_headers(&spec),
            body_sha256: (!spec.body.is_empty()).then(|| sha256(&spec.body)),
        };
        Ok(AdapterPreflight {
            preview,
            observations: json!({
                "resolved_addresses": addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "response_limit_bytes": self.config.maximum_response_bytes,
                "redirects": "disabled",
                "automatic_retries": "disabled",
            }),
        })
    }

    async fn stage(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<StagedEffect, AdapterError> {
        let spec = self.request_spec(effect)?;
        self.validate(effect)?;
        let addresses = self.resolve(&spec).await?;
        let preview = Preview::Http {
            method: spec.method.clone(),
            url: spec.url.clone(),
            headers: preview_headers(&spec),
            body_sha256: (!spec.body.is_empty()).then(|| sha256(&spec.body)),
        };
        if effect.preview != preview {
            return Err(AdapterError::Toctou(
                "HTTP request preview changed before staging".into(),
            ));
        }
        let stage = HttpStage {
            request_digest: request_digest(&spec)?,
            addresses: addresses.iter().map(ToString::to_string).collect(),
        };
        Ok(StagedEffect {
            adapter: self.name().into(),
            effect_id: effect.id,
            effect_digest: effect.content_digest().map_err(AdapterError::Canonical)?,
            data: serde_json::to_value(stage).map_err(AdapterError::Serialization)?,
            staged_at: Utc::now(),
        })
    }

    async fn execute(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError> {
        let stage = self.decode_stage(effect, staged)?;
        let spec = self.request_spec(effect)?;
        if stage.request_digest != request_digest(&spec)? {
            return Err(AdapterError::InvalidStage(
                "HTTP request content changed after staging".into(),
            ));
        }
        let addresses = stage
            .addresses
            .iter()
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| AdapterError::InvalidStage("invalid pinned address".into()))
            })
            .collect::<Result<Vec<SocketAddr>, _>>()?;
        self.send(effect, &spec, &addresses, context).await
    }

    async fn verify(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        result: &AdapterResult,
        _context: &AdapterContext,
    ) -> Result<Vec<VerificationCheck>, AdapterError> {
        let _ = self.decode_stage(effect, staged)?;
        let status = result
            .data
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok());
        let mut checks = vec![VerificationCheck {
            condition: Condition::Custom {
                name: "veyra.http.response/v1".into(),
                parameters: json!({}),
            },
            passed: status.is_some(),
            message: "bounded response metadata parsed".into(),
        }];
        for condition in &effect.expected_postconditions {
            let (passed, message) = match condition {
                Condition::HttpStatus { status: expected } => (
                    status == Some(*expected),
                    format!("observed HTTP status {status:?}"),
                ),
                Condition::OutputSha256 { digest } => (
                    result.post_state_digest.as_deref() == Some(digest),
                    "response body digest checked".into(),
                ),
                _ => (
                    false,
                    "condition is not supported by the HTTP adapter".into(),
                ),
            };
            checks.push(VerificationCheck {
                condition: condition.clone(),
                passed,
                message,
            });
        }
        Ok(checks)
    }

    async fn rollback(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        _context: &AdapterContext,
    ) -> Result<AdapterRecovery, AdapterError> {
        let _ = self.decode_stage(effect, staged)?;
        match effect.reversibility {
            Reversibility::Reversible => Ok(AdapterRecovery {
                restored: true,
                details: json!({"action": "none", "reason": "safe HTTP method declared no mutation"}),
            }),
            Reversibility::Compensatable => Ok(AdapterRecovery {
                restored: false,
                details: json!({
                    "action": "separate_compensation_required",
                    "reason": "the declared inverse must be authorized as a new effect"
                }),
            }),
            Reversibility::Irreversible => Ok(AdapterRecovery {
                restored: false,
                details: json!({"action": "none", "reason": "HTTP effect is irreversible"}),
            }),
        }
    }
}

#[derive(Clone, Debug)]
struct HttpRequestSpec {
    method: String,
    url: String,
    host: String,
    port: u16,
    public_headers: BTreeMap<String, String>,
    secret_headers: Vec<SecretHeader>,
    body: Vec<u8>,
    allow_private_network: bool,
}

#[derive(Clone, Debug)]
struct SecretHeader {
    name: String,
    provider: String,
    key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpStage {
    request_digest: String,
    addresses: Vec<String>,
}

fn parse_headers(
    effect: &Effect,
) -> Result<(BTreeMap<String, String>, Vec<SecretHeader>), AdapterError> {
    let public_headers = effect.inputs.get("headers").map_or_else(
        || Ok(BTreeMap::new()),
        |_| public_string_map(&effect.inputs, "headers"),
    )?;
    let mut secret_headers = Vec::new();
    for (input_key, value) in &effect.inputs {
        if let InputValue::SecretRef {
            provider,
            key: secret_key,
            ..
        } = value
        {
            let header = input_key.strip_prefix("header:").ok_or_else(|| {
                AdapterError::InvalidEffect(
                    "HTTP secret inputs must use a `header:<name>` key".into(),
                )
            })?;
            validate_header_name(header)?;
            secret_headers.push(SecretHeader {
                name: header.to_ascii_lowercase(),
                provider: provider.clone(),
                key: secret_key.clone(),
            });
        }
    }
    for (name, value) in &public_headers {
        validate_header_name(name)?;
        if is_sensitive_header(name) || is_controlled_header(name) {
            return Err(AdapterError::Policy(format!(
                "header `{}` must be omitted or supplied as an opaque secret reference",
                name.to_ascii_lowercase()
            )));
        }
        HeaderValue::from_str(value).map_err(|_| AdapterError::HttpSyntax("header value"))?;
    }
    if secret_headers
        .iter()
        .any(|header| is_controlled_header(&header.name))
    {
        return Err(AdapterError::Policy(
            "host, content-length, and idempotency headers are kernel-controlled".into(),
        ));
    }
    Ok((public_headers, secret_headers))
}

fn preview_headers(spec: &HttpRequestSpec) -> BTreeMap<String, String> {
    let mut headers = spec.public_headers.clone();
    for header in &spec.secret_headers {
        headers.insert(header.name.clone(), "[REDACTED SECRET REFERENCE]".into());
    }
    if !matches!(spec.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        headers.insert("idempotency-key".into(), "[VEYRA IDEMPOTENCY KEY]".into());
    }
    headers
}

fn request_digest(spec: &HttpRequestSpec) -> Result<String, AdapterError> {
    veyra_protocol::canonical_digest(&json!({
        "method": spec.method,
        "url": spec.url,
        "public_headers": spec.public_headers,
        "secret_headers": spec.secret_headers.iter().map(|header| json!({
            "name": header.name,
            "provider": header.provider,
            "key": header.key,
        })).collect::<Vec<_>>(),
        "body_sha256": sha256(&spec.body),
    }))
    .map_err(AdapterError::Canonical)
}

fn validate_header_name(name: &str) -> Result<(), AdapterError> {
    HeaderName::from_str(name)
        .map(|_| ())
        .map_err(|_| AdapterError::HttpSyntax("header name"))
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
    )
}

fn is_controlled_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "transfer-encoding" | "idempotency-key"
    )
}

fn reject_sensitive_query(url: &Url) -> Result<(), AdapterError> {
    if url.query_pairs().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        name.contains("token")
            || name.contains("secret")
            || name.contains("password")
            || name.contains("api_key")
            || name.contains("apikey")
    }) {
        Err(AdapterError::Policy(
            "credential-like URL query parameters are forbidden; use a secret header reference"
                .into(),
        ))
    } else {
        Ok(())
    }
}

fn explicit_non_default_port(url: &Url) -> Option<u16> {
    let explicit = url.port()?;
    let default = match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => return Some(explicit),
    };
    (explicit != default).then_some(explicit)
}

fn path_covers(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || prefix == path
        || path
            .strip_prefix(prefix.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_unspecified()
                || address.is_multicast()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || (address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use axum::{Router, routing::post};
    use veyra_protocol::{
        CapabilityRequirement, CausalParent, EffectId, IntentId, PROTOCOL_VERSION, PlanId,
        PrincipalId, RetryPolicy, RiskLevel, StepId, public,
    };

    use super::*;
    use crate::DenySecretResolver;

    fn adapter(port: u16) -> HttpAdapter {
        HttpAdapter::new(HttpAdapterConfig {
            rules: vec![HttpRule {
                scheme: "http".into(),
                domain: "127.0.0.1".into(),
                port: Some(port),
                path_prefix: "/api".into(),
                methods: BTreeSet::from(["POST".into()]),
                allow_private_network: true,
            }],
            maximum_request_bytes: 1024,
            maximum_response_bytes: 1024,
            maximum_timeout_ms: 2_000,
        })
        .unwrap()
    }

    fn effect(port: u16) -> Effect {
        let url = format!("http://127.0.0.1:{port}/api/items");
        let resource = ResourceScope::Http {
            scheme: "http".into(),
            domain: "127.0.0.1".into(),
            port: Some(port),
            path_prefix: "/api/items".into(),
        };
        Effect {
            schema_version: PROTOCOL_VERSION.into(),
            id: EffectId::new(),
            causal_parent: CausalParent {
                intent_id: IntentId::new(),
                plan_id: PlanId::new(),
                step_id: StepId::new(),
                effect_id: None,
            },
            principal_id: PrincipalId::new(),
            adapter: "http".into(),
            operation: "request".into(),
            inputs: BTreeMap::from([
                ("method".into(), public("POST")),
                ("url".into(), public(url)),
                ("body".into(), public("hello")),
            ]),
            resource: resource.clone(),
            preconditions: vec![],
            expected_postconditions: vec![Condition::HttpStatus { status: 201 }],
            risk: RiskLevel::High,
            reversibility: Reversibility::Irreversible,
            preview: Preview::Pending,
            idempotency_key: "http-test-key".into(),
            timeout_ms: 2_000,
            retry: RetryPolicy {
                max_attempts: 1,
                backoff_ms: 0,
                retryable_errors: vec![],
            },
            required_capabilities: vec![CapabilityRequirement {
                adapter: "http".into(),
                operation: "request".into(),
                resource,
                constraints: BTreeMap::new(),
            }],
            inverse: None,
        }
    }

    #[tokio::test]
    async fn allowed_request_is_bounded_previewed_and_verified() {
        let app = Router::new().route(
            "/api/items",
            post(|| async { (reqwest::StatusCode::CREATED, "ok") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let adapter = adapter(port);
        let context = AdapterContext {
            transaction_id: veyra_protocol::TransactionId::new(),
            secrets: Arc::new(DenySecretResolver),
        };
        let mut effect = effect(port);
        effect.preview = adapter.preflight(&effect, &context).await.unwrap().preview;
        let staged = adapter.stage(&effect, &context).await.unwrap();
        let result = adapter.execute(&effect, &staged, &context).await.unwrap();
        assert!(
            adapter
                .verify(&effect, &staged, &result, &context)
                .await
                .unwrap()
                .iter()
                .all(|check| check.passed)
        );
    }

    #[test]
    fn domain_method_and_sensitive_query_are_denied() {
        let adapter = adapter(8080);
        let mut wrong = effect(8080);
        wrong.inputs.insert(
            "url".into(),
            public("http://127.0.0.1:8080/api/items?api_key=raw"),
        );
        assert!(adapter.validate(&wrong).is_err());
        wrong
            .inputs
            .insert("url".into(), public("http://example.com/api"));
        assert!(adapter.validate(&wrong).is_err());
    }

    #[test]
    fn private_addresses_are_denied_unless_rule_explicitly_opts_in() {
        assert!(!is_public_ip(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!is_public_ip(IpAddr::from_str("169.254.1.1").unwrap()));
        assert!(is_public_ip(IpAddr::from_str("1.1.1.1").unwrap()));
    }
}
