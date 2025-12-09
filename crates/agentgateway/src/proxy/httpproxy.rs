use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use ::http::uri::PathAndQuery;
use ::http::{HeaderMap, header};
use anyhow::anyhow;
use futures_util::FutureExt;
use headers::HeaderMapExt;
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use rand::Rng;
use rand::seq::IndexedRandom;
use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use cbc::Decryptor;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, info, trace, warn};
use types::agent::*;
use types::discovery::*;
use once_cell::sync::Lazy;

use crate::client::Transport;
use crate::http::backendtls::BackendTLS;
use crate::http::ext_proc::ExtProcRequest;
use crate::http::filters::AutoHostname;
use crate::http::transformation_cel::Transformation;
use crate::http::{
	Authority, HeaderName, HeaderValue, PolicyResponse, Request, Response, Scheme, StatusCode, Uri,
	auth, filters, get_host, merge_in_headers, retry,
};
use crate::llm::{LLMRequest, RequestResult, RouteType};
use crate::proxy::{ProxyError, ProxyResponse, ProxyResponseReason, resolve_simple_backend};
use crate::store::{
	BackendPolicies, FrontendPolices, GatewayPolicies, LLMRequestPolicies, LLMResponsePolicies,
	RoutePath,
};
use crate::telemetry::log;
use crate::telemetry::log::{AsyncLog, DropOnLog, LogBody, RequestLog};
use crate::telemetry::metrics::{Metrics, SelectorBodyParseLabels, SelectorEvalLabels};
use crate::telemetry::trc::TraceParent;
use crate::transport::stream::{Extension, TCPConnectionInfo, TLSConnectionInfo};
use crate::types::{backend, frontend};
use crate::{ProxyInputs, store, *};

/// Cached parsed request body for selector evaluation
#[derive(Debug, Clone)]
struct ParsedRequestBody {
	json: serde_json::Value,
}

const MAX_BODY_SIZE_FOR_SELECTORS: usize = 1024 * 1024; // 1MB
const BODY_PARSE_TIMEOUT_MS: u64 = 50;
/// Header to prevent fallback loops (Phase 4.2)
const FALLBACK_HOP_HEADER: &str = "x-ag-fallback-hop";

/// Forward a request to a fallback gateway when no local backend is available (Phase 4.2)
///
/// This function:
/// 1. Clones the request (method, path, headers, body)
/// 2. Adds the hop header to prevent loops
/// 3. Forwards to the fallback gateway URL
/// 4. Returns the response from the fallback gateway
async fn forward_to_fallback_gateway(
	req: Request,
	fallback: &crate::FallbackGateway,
	log: &mut crate::telemetry::log::RequestLog,
	metrics: &Arc<Metrics>,
) -> Result<Response, crate::proxy::ProxyError> {
	use http_body_util::BodyExt;
	use crate::telemetry::metrics::FallbackLabels;

	let fallback_url = &fallback.url;
	let timeout = fallback.timeout;

	// Extract request parts
	let (parts, body) = req.into_parts();
	let method = parts.method;
	let uri = parts.uri;
	let headers = parts.headers;

	// Build the full URL for fallback: fallback_url + request path
	let path_and_query = uri.path_and_query()
		.map(|pq| pq.as_str())
		.unwrap_or("/");
	let full_url = format!("{}{}", fallback_url.trim_end_matches('/'), path_and_query);

	info!(
		fallback_url = %fallback_url,
		path = %path_and_query,
		"Forwarding request to fallback gateway (no local backend available)"
	);

	// Log fallback in request log
	log.fallback_gateway = Some(fallback_url.clone());

	// Collect body bytes
	let body_bytes = match body.collect().await {
		Ok(collected) => collected.to_bytes(),
		Err(e) => {
			warn!(error = ?e, "Failed to collect body for fallback forwarding");
			return Err(crate::proxy::ProxyError::Internal(format!(
				"Failed to collect body for fallback: {}",
				e
			)));
		}
	};

	// Build reqwest client with timeout
	let client = reqwest::Client::builder()
		.timeout(timeout)
		.build()
		.map_err(|e| crate::proxy::ProxyError::Internal(format!(
			"Failed to create fallback HTTP client: {}",
			e
		)))?;

	// Build the forwarded request
	let mut req_builder = client.request(
		reqwest::Method::from_bytes(method.as_str().as_bytes())
			.unwrap_or(reqwest::Method::POST),
		&full_url,
	);

	// Copy headers, adding the hop header
	for (name, value) in headers.iter() {
		// Skip hop-by-hop headers and host (will be set by reqwest)
		if name == "host" || name == "connection" || name == "transfer-encoding" {
			continue;
		}
		if let Ok(value_str) = value.to_str() {
			req_builder = req_builder.header(name.as_str(), value_str);
		}
	}

	// Add hop header to prevent loops
	req_builder = req_builder.header(FALLBACK_HOP_HEADER, "1");

	// Set body
	req_builder = req_builder.body(body_bytes.to_vec());

	// Execute request
	let response = match req_builder.send().await {
		Ok(resp) => resp,
		Err(e) => {
			warn!(error = ?e, fallback_url = %fallback_url, "Fallback gateway request failed");
			let status = if e.is_timeout() { "timeout" } else { "error" };
			metrics.gateway_fallback
				.get_or_create(&FallbackLabels {
					target_gateway: fallback_url.clone().into(),
					status: status.to_string().into(),
				})
				.inc();
			if e.is_timeout() {
				return Err(crate::proxy::ProxyError::GatewayTimeout);
			}
			return Err(crate::proxy::ProxyError::BadGateway(format!(
				"Fallback gateway error: {}",
				e
			)));
		}
	};

	// Convert reqwest response to our Response type
	let status = response.status();
	let resp_headers = response.headers().clone();

	info!(
		fallback_url = %fallback_url,
		status = %status,
		"Received response from fallback gateway"
	);

	let resp_body = match response.bytes().await {
		Ok(bytes) => bytes,
		Err(e) => {
			warn!(error = ?e, "Failed to read fallback response body");
			return Err(crate::proxy::ProxyError::BadGateway(format!(
				"Failed to read fallback response: {}",
				e
			)));
		}
	};

	// Build our response
	let mut builder = ::http::Response::builder()
		.status(::http::StatusCode::from_u16(status.as_u16()).unwrap_or(::http::StatusCode::BAD_GATEWAY));

	for (name, value) in resp_headers.iter() {
		// Skip hop-by-hop headers
		if name == "connection" || name == "transfer-encoding" {
			continue;
		}
		builder = builder.header(name.as_str(), value.as_bytes());
	}

	let response = builder
		.body(crate::http::Body::from(resp_body.to_vec()))
		.map_err(|e| crate::proxy::ProxyError::Internal(format!(
			"Failed to build fallback response: {}",
			e
		)))?;

	// Record success metric
	metrics.gateway_fallback
		.get_or_create(&FallbackLabels {
			target_gateway: fallback_url.clone().into(),
			status: "success".to_string().into(),
		})
		.inc();

	Ok(response)
}

/// Selectors are always enabled in InferRouter fork.
/// This is a core feature required for correct model routing (Phase 3-5).
/// Legacy AG_ENABLE_SELECTORS env var is no longer used.
const SELECTORS_ENABLED: bool = true;

fn select_backend(
	route: &Route,
	req: &Request,
	metrics: &Arc<Metrics>,
) -> Option<RouteBackendReference> {
	// Phase 5 Fix: SELECTOR-FIRST, then BYOK filtering
	//
	// Order of operations:
	// 1. Apply selector filter (model matching) - get model-matched backends
	// 2. Within matched backends, apply BYOK/project filtering
	// 3. Return result or None (503) - NO fallback to all backends

	// Step 1: Apply selector filter to get model-matched backends
	let selector_matched = apply_selector_filter(route, req, metrics);

	// Log selector-matched backend names for debugging
	let matched_names: Vec<_> = selector_matched.iter()
		.map(|b| b.backend.name().to_string())
		.collect();
	debug!(
		total_backends = route.backends.len(),
		selector_matched = selector_matched.len(),
		matched_backends = ?matched_names,
		"Backend selection: selector filter applied"
	);

	// If no backends match selector, return None (will result in 503)
	if selector_matched.is_empty() {
		debug!("No backends matched selector - returning None (503)");
		metrics
			.selector_eval
			.get_or_create(&SelectorEvalLabels {
				route: route.route_name.clone().into(),
				outcome: "no_match".to_string().into(),
			})
			.inc();
		return None;
	}

	metrics
		.selector_eval
		.get_or_create(&SelectorEvalLabels {
			route: route.route_name.clone().into(),
			outcome: "match".to_string().into(),
		})
		.inc();

	// Step 2: Apply BYOK filtering within selector-matched backends
	let project_claim = req
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("project_id"))
		.and_then(|v| v.as_str());

	if let Some(project_id) = project_claim {
		debug!(
			project_id,
			selector_matched = selector_matched.len(),
			"BYOK routing: checking selector-matched backends for project_id"
		);

		// Find BYOK backends with matching project_id within selector-matched
		let byok_matches: Vec<_> = selector_matched
			.iter()
			.filter(|b| {
				let meta = &b.metadata;
				let provider = meta
					.get("provider")
					.and_then(|v| v.as_str())
					.unwrap_or_default();
				if !provider.ends_with("_byok") {
					return false;
				}
				let pid = meta
					.get("project_id")
					.and_then(|v| v.as_str())
					.unwrap_or_default();
				pid == project_id
			})
			.collect();

		if !byok_matches.is_empty() {
			debug!(
				project_id,
				byok_matches = byok_matches.len(),
				"BYOK routing: found matching BYOK backends for project"
			);
			return byok_matches
				.choose_weighted(&mut rand::rng(), |b| b.weight)
				.ok()
				.map(|b| (**b).clone());
		}

		// No BYOK match - use mesh backends (non-BYOK) from selector-matched
		let mesh_backends: Vec<_> = selector_matched
			.iter()
			.filter(|b| {
				let provider = b.metadata
					.get("provider")
					.and_then(|v| v.as_str())
					.unwrap_or_default();
				!provider.ends_with("_byok")
			})
			.collect();

		if !mesh_backends.is_empty() {
			let selected = mesh_backends
				.choose_weighted(&mut rand::rng(), |b| b.weight)
				.ok()
				.map(|b| (**b).clone());
			if let Some(ref backend) = selected {
				debug!(
					project_id,
					mesh_backends = mesh_backends.len(),
					backend_name = ?backend.backend.name(),
					backend_model = ?backend.metadata.get("model"),
					"BYOK routing: no BYOK match, selected mesh backend"
				);
			}
			return selected;
		}

		// All selector-matched backends are BYOK but none match project_id
		debug!(
			project_id,
			"BYOK routing: no BYOK or mesh backends available - returning None (503)"
		);
		return None;
	}

	// No project_id claim - filter out BYOK backends, use mesh only
	debug!("BYOK routing: no project_id claim, filtering to mesh-only backends");

	let mesh_backends: Vec<_> = selector_matched
		.iter()
		.filter(|b| {
			let provider = b.metadata
				.get("provider")
				.and_then(|v| v.as_str())
				.unwrap_or_default();
			!provider.ends_with("_byok")
		})
		.collect();

	if !mesh_backends.is_empty() {
		debug!(mesh_backends = mesh_backends.len(), "Using mesh backends (no project_id)");
		return mesh_backends
			.choose_weighted(&mut rand::rng(), |b| b.weight)
			.ok()
			.map(|b| (**b).clone());
	}

	// All backends are BYOK but no project_id - cannot route
	debug!("No mesh backends available and no project_id - returning None (503)");
	None
}

/// Apply selector filter to get model-matched backends
fn apply_selector_filter<'a>(
	route: &'a Route,
	req: &Request,
	_metrics: &Arc<Metrics>,
) -> Vec<&'a RouteBackendReference> {
	if !SELECTORS_ENABLED {
		// Selectors disabled - return all backends
		return route.backends.iter().collect();
	}

	// Check if route has selector expressions
	let selectors: Vec<&Strng> = route
		.matches
		.iter()
		.filter_map(|m| m.selector.as_ref())
		.collect();

	if selectors.is_empty() {
		// No selectors - return all backends
		return route.backends.iter().collect();
	}

	// Get cached parsed body (if available)
	let parsed_body = req.extensions().get::<ParsedRequestBody>();

	// Filter backends based on selector evaluation
	route
		.backends
		.iter()
		.filter(|backend| {
			selectors.iter().all(|selector_expr| {
				if !selector_is_valid(selector_expr) {
					trace!("Invalid selector expression, skipping filter: {}", selector_expr);
					return true;
				}
				evaluate_selector(selector_expr, parsed_body, backend)
			})
		})
		.collect()
}

/// Evaluate a selector expression against request body and backend metadata
fn evaluate_selector(
	selector_expr: &Strng,
	parsed_body: Option<&ParsedRequestBody>,
	backend: &RouteBackendReference,
) -> bool {
	let expr = selector_expr.as_str();

	// Parse expression: "request.body.max_tokens <= backend.metadata.max_tokens"
	if let Some((left_expr, op, right_expr)) = parse_comparison_expr(expr) {
		let left_value = evaluate_expr(&left_expr, parsed_body, backend);
		let right_value = evaluate_expr(&right_expr, parsed_body, backend);

	match (left_value, right_value) {
		(Some(ExprValue::Number(l)), Some(ExprValue::Number(r))) => match op {
			"<=" => l <= r,
			">=" => l >= r,
			"<" => l < r,
			">" => l > r,
			"==" => (l - r).abs() < f64::EPSILON,
			_ => true,
		},
		(Some(ExprValue::String(l)), Some(ExprValue::String(r))) => {
			if op == "==" {
				l == r
			} else {
				true
			}
		},
		_ => true, // Can't evaluate, don't filter out this backend
		}
	} else {
		true // Can't parse selector, don't filter
	}
}

#[derive(Debug, Clone)]
enum ExprValue {
	Number(f64),
	String(String),
}

	fn parse_comparison_expr(expr: &str) -> Option<(String, &'static str, String)> {
		for op in &["<=", ">=", "==", "<", ">"] {
			if let Some(pos) = expr.find(op) {
				let left = expr[..pos].trim().to_string();
				let right = expr[pos + op.len()..].trim().to_string();
				return Some((left, *op, right));
			}
		}
		None
	}

	fn evaluate_expr(
		expr: &str,
		parsed_body: Option<&ParsedRequestBody>,
		backend: &RouteBackendReference,
	) -> Option<ExprValue> {
		if expr.starts_with("request.body.") {
		let field = expr.strip_prefix("request.body.")?;
		let json = &parsed_body?.json;
		if let Some(value) = json.get(field) {
			if let Some(num) = value.as_i64() {
				return Some(ExprValue::Number(num as f64));
			} else if let Some(num) = value.as_f64() {
				return Some(ExprValue::Number(num));
			} else if let Some(s) = value.as_str() {
				return Some(ExprValue::String(s.to_string()));
			}
		}
	} else if expr.starts_with("backend.metadata.") {
		let field = expr.strip_prefix("backend.metadata.")?;
		if let Some(value) = backend.metadata.get(field) {
			if let Some(num) = value.as_i64() {
				return Some(ExprValue::Number(num as f64));
			} else if let Some(num) = value.as_f64() {
				return Some(ExprValue::Number(num));
			} else if let Some(s) = value.as_str() {
				return Some(ExprValue::String(s.to_string()));
			}
		}
		}
		None
	}

fn selector_is_valid(expr: &str) -> bool {
	if let Some((left, _, right)) = parse_comparison_expr(expr) {
		left.starts_with("request.body.") && right.starts_with("backend.metadata.")
	} else {
		false
	}
}

/// Parse request body and cache it in request extensions if route has selectors
async fn maybe_parse_body_for_selectors(
	route: &Route,
	req: &mut Request,
	metrics: &Arc<Metrics>,
) -> Result<(), ProxyError> {
	if !SELECTORS_ENABLED {
		return Ok(());
	}
	// Check if any route match has a selector
	let has_selector = route.matches.iter().any(|m| m.selector.is_some());
	if !has_selector {
		return Ok(()); // Fast path: no selectors, skip parsing
	}

	// Check if already parsed
	if req.extensions().get::<ParsedRequestBody>().is_some() {
		metrics
			.selector_body_parse
			.get_or_create(&SelectorBodyParseLabels {
				route: route.route_name.clone().into(),
				status: "cached".to_string().into(),
			})
			.inc();
		return Ok(());
	}

	use http_body_util::BodyExt;

	// Extract body while preserving all request metadata (headers, URI, etc.)
	let (mut parts, body) = std::mem::take(req).into_parts();

	// Collect body with timeout
	let timeout_duration = std::time::Duration::from_millis(BODY_PARSE_TIMEOUT_MS);
	let collect_future = body.collect();

	let body_bytes = match tokio::time::timeout(timeout_duration, collect_future).await {
		Ok(Ok(collected)) => {
			let bytes = collected.to_bytes();
			// Check size AFTER collecting to fail fast on large bodies
			if bytes.len() > MAX_BODY_SIZE_FOR_SELECTORS {
				trace!(
					"Body too large for selector parsing: {} bytes (max: {})",
					bytes.len(),
					MAX_BODY_SIZE_FOR_SELECTORS
				);
				// Reconstruct and return
				*req = Request::from_parts(parts, crate::http::Body::from(bytes));
				metrics
					.selector_body_parse
					.get_or_create(&SelectorBodyParseLabels {
						route: route.route_name.clone().into(),
						status: "too_large".to_string().into(),
					})
					.inc();
				return Ok(());
			}
			bytes
		},
		Ok(Err(e)) => {
			trace!("Failed to collect body for selector: {:?}", e);
			// Can't reconstruct - body is consumed. Create empty body.
			*req = Request::from_parts(parts, crate::http::Body::default());
			metrics
				.selector_body_parse
				.get_or_create(&SelectorBodyParseLabels {
					route: route.route_name.clone().into(),
					status: "error".to_string().into(),
				})
				.inc();
			return Ok(());
		},
		Err(_timeout) => {
			trace!("Timeout collecting body for selectors ({:?})", timeout_duration);
			// Can't reconstruct - body is consumed. Create empty body.
			*req = Request::from_parts(parts, crate::http::Body::default());
			metrics
				.selector_body_parse
				.get_or_create(&SelectorBodyParseLabels {
					route: route.route_name.clone().into(),
					status: "timeout".to_string().into(),
				})
				.inc();
			return Ok(());
		}
	};

	// Try to parse as JSON and cache in extensions
	if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
		let parsed = ParsedRequestBody {
			json,
		};
		parts.extensions.insert(parsed);
		trace!("Parsed request body for selector evaluation");
		metrics
			.selector_body_parse
			.get_or_create(&SelectorBodyParseLabels {
				route: route.route_name.clone().into(),
				status: "success".to_string().into(),
			})
			.inc();
	} else {
		trace!("Body is not valid JSON, skipping selector evaluation");
		metrics
			.selector_body_parse
			.get_or_create(&SelectorBodyParseLabels {
				route: route.route_name.clone().into(),
				status: "non_json".to_string().into(),
			})
			.inc();
	}

	// Reconstruct request with buffered body (preserves all metadata)
	*req = Request::from_parts(parts, crate::http::Body::from(body_bytes));

	Ok(())
}

fn apply_logging_policy_to_log(log: &mut RequestLog, lp: &frontend::LoggingPolicy) {
	// Merge filter/fields into config for this request
	if lp.filter.is_some() {
		log.cel.filter = lp.filter.clone();
	}
	if lp.add.is_empty() && lp.remove.is_empty() {
		return;
	}
	if !lp.add.is_empty() {
		log.cel.fields.add = lp.add.clone();
	}
	if !lp.remove.is_empty() {
		log.cel.fields.remove = lp.remove.clone();
	}
}

fn build_ctx<'a>(
	exec: &'a once_cell::sync::OnceCell<cel::Executor<'static>>,
	log: &RequestLog,
) -> Result<&'a cel::Executor<'static>, ProxyError> {
	let res = exec.get_or_try_init(|| {
		log
			.cel
			.ctx_borrow()
			.build()
			.map_err(|_| ProxyError::ProcessingString("failed to build cel context".to_string()))
	})?;
	Ok(res)
}

async fn apply_request_policies(
	policies: &store::RoutePolicies,
	client: PolicyClient,
	log: &mut RequestLog,
	req: &mut Request,
	response_policies: &mut ResponsePolicies,
) -> Result<(), ProxyResponse> {
	if let Some(j) = &policies.jwt {
		j.apply(log, req)
			.await
			.map_err(|e| ProxyResponse::from(ProxyError::JwtAuthenticationFailure(e)))?;
	}
	if let Some(b) = &policies.basic_auth {
		b.apply(log, req).await?;
	}
	if let Some(b) = &policies.api_key {
		b.apply(log, req).await?;
	}

	let exec = once_cell::sync::OnceCell::new();

	if let Some(x) = &policies.ext_authz {
		x.check(build_ctx(&exec, log)?, client.clone(), req).await?
	} else {
		http::PolicyResponse::default()
	}
	.apply(response_policies.headers())?;
	// Extract dynamic metadata for CEL context
	log.cel.ctx().with_extauthz(req);

	if let Some(j) = &policies.authorization {
		j.apply(build_ctx(&exec, log)?)
			.map_err(|_| ProxyResponse::from(ProxyError::AuthorizationFailed))?;
	}

	for lrl in &policies.local_rate_limit {
		lrl.check_request()?;
	}

	if let Some(rrl) = &policies.remote_rate_limit {
		rrl.check(client, req, build_ctx(&exec, log)?).await?
	} else {
		http::PolicyResponse::default()
	}
	.apply(response_policies.headers())?;

	if let Some(x) = response_policies.ext_proc.as_mut() {
		x.mutate_request(req).await?
	} else {
		http::PolicyResponse::default()
	}
	.apply(response_policies.headers())?;

	if let Some(j) = &policies.transformation {
		j.apply_request(req, build_ctx(&exec, log)?);
	}

	if let Some(csrf) = &policies.csrf {
		csrf
			.apply(req)
			.map_err(|_| ProxyError::CsrfValidationFailed)?
			.apply(response_policies.headers())?;
	}
	if let Some(rhm) = &policies.request_header_modifier {
		rhm.apply(req.headers_mut()).map_err(ProxyError::from)?;
	}

	// Enable Auto Hostname rewrite by default. This may be disabled by a URL Rewrite, or explicitly
	// setting hostname_rewrite = None
	if policies
		.hostname_rewrite
		.unwrap_or(HostRedirectOverride::Auto)
		== HostRedirectOverride::Auto
	{
		req.extensions_mut().insert(AutoHostname());
	}
	if let Some(r) = &policies.url_rewrite {
		r.apply(req).map_err(ProxyError::from)?;
	}
	if let Some(c) = &policies.cors {
		c.apply(req)
			.map_err(ProxyError::from)?
			.apply(response_policies.headers())?;
	}
	if let Some(rr) = &policies.request_redirect {
		rr.apply(req)
			.map_err(ProxyError::from)?
			.apply(response_policies.headers())?;
	}
	if let Some(dr) = &policies.direct_response {
		PolicyResponse::default()
			.with_response(dr.apply().map_err(ProxyError::from)?)
			.apply(response_policies.headers())?;
	}

	// Mirror, timeout, and retry are handled separately.

	Ok(())
}

async fn apply_backend_policies(
	backend_info: auth::BackendInfo,
	backend_call: &BackendCall,
	req: &mut Request,
	log: &mut Option<&mut RequestLog>,
	response_policies: &mut ResponsePolicies,
) -> Result<(), ProxyResponse> {
	let BackendPolicies {
		backend_tls: _,
		backend_auth,
		a2a,
		http,
		// Doesn't currently have any options to set, todo
		tcp: _,
		// Applied elsewhere
		llm_provider: _,
		// Applied elsewhere
		llm: _,
		// Applied elsewhere
		inference_routing: _,
		request_header_modifier,
		response_header_modifier,
		request_redirect,
		// Applied elsewhere
		request_mirror: _,
	} = &backend_call.backend_policies;
	response_policies.backend_response_header = response_header_modifier.clone();

	let dh = backend::HTTP::default();
	http
		.as_ref()
		.unwrap_or(&dh)
		.apply(req, backend_call.http_version_override);

	if let Some(auth) = backend_auth {
		auth::apply_backend_auth(&backend_info, auth, req).await?;
	}
	if let Some(rhm) = request_header_modifier {
		rhm.apply(req.headers_mut()).map_err(ProxyError::from)?;
	}
	if let Some(rr) = request_redirect {
		rr.apply(req)
			.map_err(ProxyError::from)?
			.apply(response_policies.headers())?;
	}

	if let Some(a2a) = a2a {
		let a2a_type = a2a::apply_to_request(a2a, req).await;
		if let a2a::RequestType::Call(method) = a2a_type {
			log.add(|l| {
				l.a2a_method = Some(method);
			});
		}
		if matches!(
			a2a_type,
			a2a::RequestType::Call(_) | a2a::RequestType::AgentCard(_)
		) {
			log.add(|l| {
				l.backend_protocol = Some(cel::BackendProtocol::a2a);
			});
		}
		response_policies.a2a_type = a2a_type;
	}

	Ok(())
}

async fn apply_gateway_policies(
	policies: &GatewayPolicies,
	client: PolicyClient,
	log: &mut RequestLog,
	req: &mut Request,
	ext_proc: Option<&mut ExtProcRequest>,
	response_headers: &mut HeaderMap,
) -> Result<(), ProxyResponse> {
	if let Some(j) = &policies.jwt {
		j.apply(log, req)
			.await
			.map_err(|e| ProxyResponse::from(ProxyError::JwtAuthenticationFailure(e)))?;
	}
	if let Some(b) = &policies.basic_auth {
		b.apply(log, req).await?;
	}
	if let Some(b) = &policies.api_key {
		b.apply(log, req).await?;
	}

	let exec = once_cell::sync::OnceCell::new();
	if let Some(x) = &policies.ext_authz {
		x.check(build_ctx(&exec, log)?, client.clone(), req).await?
	} else {
		http::PolicyResponse::default()
	}
	.apply(response_headers)?;
	// Extract dynamic metadata for CEL context
	log.cel.ctx().with_extauthz(req);

	if let Some(x) = ext_proc {
		x.mutate_request(req).await?
	} else {
		http::PolicyResponse::default()
	}
	.apply(response_headers)?;

	if let Some(j) = &policies.transformation {
		j.apply_request(req, build_ctx(&exec, log)?);
	}

	Ok(())
}

async fn apply_llm_request_policies(
	policies: &store::LLMRequestPolicies,
	client: PolicyClient,
	log: &mut Option<&mut RequestLog>,
	req: &mut Request,
	llm_req: &LLMRequest,
	response_headers: &mut HeaderMap,
) -> Result<store::LLMResponsePolicies, ProxyResponse> {
	for lrl in &policies.local_rate_limit {
		lrl.check_llm_request(llm_req)?;
	}
	let (rl_resp, response) = if let Some(rrl) = &policies.remote_rate_limit
		&& let Some(log) = log
	{
		let exec = log
			.cel
			.ctx()
			.build()
			.map_err(|_| ProxyError::ProcessingString("failed to build cel context".to_string()))?;
		// For the LLM request side, request either the count of the input tokens (if tokenization was done)
		// or 0.
		// Either way, we will 'true up' on the response side.
		rrl
			.check_llm(client, req, &exec, llm_req.input_tokens.unwrap_or_default())
			.await?
	} else {
		(http::PolicyResponse::default(), None)
	};
	rl_resp.apply(response_headers)?;
	Ok(store::LLMResponsePolicies {
		local_rate_limit: policies.local_rate_limit.clone(),
		remote_rate_limit: response,
		prompt_guard: policies
			.llm
			.as_deref()
			.and_then(|llm| llm.prompt_guard.as_ref())
			.map(|g| g.response.clone())
			.unwrap_or_default(),
	})
}

#[derive(Clone)]
pub struct HTTPProxy {
	pub(super) bind_name: BindName,
	pub(super) inputs: Arc<ProxyInputs>,
	pub(super) selected_listener: Option<Arc<Listener>>,
	pub(super) target_address: SocketAddr,
}

impl HTTPProxy {
	pub async fn proxy(
		&self,
		connection: Arc<Extension>,
		policies: &FrontendPolices,
		mut req: ::http::Request<Incoming>,
	) -> Response {
		let start = Instant::now();
		let start_time = agent_core::telemetry::render_current_time();

		// Copy connection level attributes into request level attributes
		connection.copy::<TCPConnectionInfo>(req.extensions_mut());
		connection.copy::<TLSConnectionInfo>(req.extensions_mut());

		let tcp = connection
			.get::<TCPConnectionInfo>()
			.expect("tcp connection must be set");
		let mut log = RequestLog::new(
			log::CelLogging::new(
				self.inputs.cfg.logging.clone(),
				self.inputs.cfg.tracing.clone(),
			),
			self.inputs.metrics.clone(),
			start,
			start_time,
			tcp.clone(),
		);
		policies.register_cel_expressions(log.cel.ctx());
		if let Some(lp) = &policies.access_log {
			apply_logging_policy_to_log(&mut log, lp);
		}
		let mut log: DropOnLog = log.into();

		// Setup ResponsePolicies outside of proxy_internal, so we have can unconditionally run them even on errors
		// or direct responses
		let mut response_policies = ResponsePolicies::default();
		let ret = self
			.proxy_internal(
				connection,
				req,
				log.as_mut().unwrap(),
				&mut response_policies,
			)
			.await;

		log.with(|l| {
			l.error = ret.as_ref().err().and_then(|e| {
				if let ProxyResponse::Error(e) = e {
					Some(e.to_string())
				} else {
					None
				}
			})
		});
		let reason = match &ret {
			Ok(_) => ProxyResponseReason::Upstream,
			Err(e) => e.as_reason(),
		};
		let mut resp = ret.unwrap_or_else(|err| match err {
			ProxyResponse::Error(e) => e.into_response(),
			ProxyResponse::DirectResponse(dr) => *dr,
		});

		if let Some(l) = log.as_mut() {
			let needs_body = l.cel.ctx().with_response(&resp);
			if needs_body && let Ok(body) = crate::http::inspect_response_body(&mut resp).await {
				l.cel.ctx().with_response_body(body);
			}
		}

		let resp = match response_policies
			.apply(
				&mut resp,
				log.as_mut().unwrap(),
				reason == ProxyResponseReason::Upstream,
			)
			.await
		{
			Ok(_) => resp,
			Err(e) => match e {
				ProxyResponse::Error(e) => e.into_response(),
				ProxyResponse::DirectResponse(dr) => *dr,
			},
		};

		// Pass the log into the body so it finishes once the stream is entirely complete.
		// We will also record trailer info there.
		log.with(|l| {
			l.status = Some(resp.status());
			l.reason = Some(reason);
			l.retry_after = http::outlierdetection::retry_after(resp.status(), resp.headers());
		});

		resp.map(move |b| http::Body::new(LogBody::new(b, log)))
	}
	async fn proxy_internal(
		&self,
		connection: Arc<Extension>,
		req: ::http::Request<Incoming>,
		log: &mut RequestLog,
		response_policies: &mut ResponsePolicies,
	) -> Result<Response, ProxyResponse> {
		log.tls_info = connection.get::<TLSConnectionInfo>().cloned();
		log.backend_protocol = Some(cel::BackendProtocol::http);
		let selected_listener = self.selected_listener.clone();
		let inputs = self.inputs.clone();
		let bind_name = self.bind_name.clone();
		debug!(bind=%bind_name, "route for bind");
		let Some(listeners) = ({
			let state = inputs.stores.read_binds();
			state.listeners(bind_name.clone())
		}) else {
			return Err(ProxyError::BindNotFound.into());
		};

		let mut req = req.map(http::Body::new);

		sensitive_headers(&mut req);
		normalize_uri(&connection, &mut req).map_err(ProxyError::Processing)?;
		let mut req_upgrade = hop_by_hop_headers(&mut req);

		let host = http::get_host(&req)?.to_string();
		log.host = Some(host.clone());
		log.method = Some(req.method().clone());
		log.path = Some(
			req
				.uri()
				.path_and_query()
				.map(|pq| pq.to_string())
				.unwrap_or_else(|| req.uri().path().to_string()),
		);
		log.version = Some(req.version());

		// Record request now. We may do it later as well, after we have more expressions registered.
		Self::apply_request_to_cel(log, &mut req).await;

		let trace_parent = trc::TraceParent::from_request(&req);
		let trace_sampled = log.trace_sampled(trace_parent.as_ref());
		if trace_sampled {
			log.tracer = self.inputs.tracer.clone();
			let ns = match trace_parent {
				Some(tp) => {
					// Build a new span off the existing trace
					let ns = tp.new_span();
					log.incoming_span = Some(tp);
					ns
				},
				None => {
					// Build an entirely new trace
					let mut ns = TraceParent::new();
					ns.flags = 1;
					ns
				},
			};
			ns.insert_header(&mut req);
			req.extensions_mut().insert(ns.clone());
			log.outgoing_span = Some(ns);
		}

		if let Some(tracer) = &log.tracer {
			log.cel.register(&tracer.fields);
		}

		let selected_listener = selected_listener
			.or_else(|| listeners.best_match(&host))
			.ok_or(ProxyError::ListenerNotFound)?;
		log.bind_name = Some(bind_name.clone());
		log.gateway_name = Some(selected_listener.gateway_name.clone());
		log.listener_name = Some(selected_listener.name.clone());

		debug!(bind=%bind_name, listener=%selected_listener.key, "selected listener");
		let mut gateway_policies = inputs.stores.read_binds().gateway_policies(
			selected_listener.key.clone(),
			selected_listener.gateway_name.clone(),
		);
		gateway_policies.register_cel_expressions(log.cel.ctx());
		// This is unfortunate but we record the request twice possibly; we want to record it as early as possible
		// (for logging, etc) and also after we register the expressions since new fields may be available.
		Self::apply_request_to_cel(log, &mut req).await;

		let mut response_headers = HeaderMap::new();
		let mut maybe_gateway_ext_proc = gateway_policies
			.ext_proc
			.take()
			.map(|c| c.build(self.policy_client()));
		apply_gateway_policies(
			&gateway_policies,
			self.policy_client(),
			log,
			&mut req,
			maybe_gateway_ext_proc.as_mut(),
			&mut response_headers,
		)
		.await?;

		let (selected_route, path_match) = http::route::select_best_route(
			inputs.stores.clone(),
			inputs.cfg.network.clone(),
			inputs.cfg.self_addr.clone(),
			self.target_address,
			selected_listener.clone(),
			&req,
		)
		.ok_or(ProxyError::RouteNotFound)?;
		log.route_rule_name = selected_route.rule_name.clone();
		log.route_name = Some(selected_route.route_name.clone());
		// Record the matched path for tracing/logging span names
		log.path_match = Some(match &path_match {
			PathMatch::Exact(p) => p.clone(),
			PathMatch::PathPrefix(p) => {
				if p == "/" {
					strng::literal!("/*")
				} else {
					strng::format!("{}/*", p)
				}
			},
			PathMatch::Regex(r, _) => r.as_str().into(),
		});
		req.extensions_mut().insert(path_match);

		debug!(bind=%bind_name, listener=%selected_listener.key, route=%selected_route.key, "selected route");

		let route_path = RoutePath {
			route_rule: selected_route.rule_name.clone(),
			route: selected_route.route_name.clone(),
			listener: selected_listener.key.clone(),
			gateway: selected_listener.gateway_name.clone(),
		};

		let mut route_policies = inputs
			.stores
			.read_binds()
			.route_policies(route_path.clone(), &selected_route.inline_policies);
		// Register all expressions
		route_policies.register_cel_expressions(log.cel.ctx());
		// This is unfortunate but we record the request twice possibly; we want to record it as early as possible
		// (for logging, etc) and also after we register the expressions since new fields may be available.
		Self::apply_request_to_cel(log, &mut req).await;

		let maybe_ext_proc = route_policies
			.ext_proc
			.take()
			.map(|c| c.build(self.policy_client()));
		response_policies.route_response_header = route_policies.response_header_modifier.clone();
		// backend_response_header is set much later
		response_policies.timeout = route_policies.timeout.clone();
		response_policies.transformation = route_policies.transformation.clone();
		response_policies.gateway_transformation = gateway_policies.transformation.clone();
		response_policies.ext_proc = maybe_ext_proc;
		response_policies.gateway_ext_proc = maybe_gateway_ext_proc;

		apply_request_policies(
			&route_policies,
			self.policy_client(),
			log,
			&mut req,
			response_policies,
		)
		.await?;

		// Phase 6B: In-process AuthZ check
		#[cfg(feature = "inproc")]
		{
			use crate::inproc::{AuthzMode, extract_api_key, is_jwt_validated};
			use crate::http::jwt::Claims;
			if self.inputs.cfg.authz.mode == AuthzMode::Inproc {
				// JWT passthrough: check if JWT policy already validated the request
				// The JWT policy runs before this check, validates JWT, removes Authorization header,
				// and inserts Claims into request extensions. If claims exist, JWT auth succeeded.
				// NOTE: We check extensions, NOT the Authorization header (which is removed by JWT policy).
				let jwt_validated = is_jwt_validated::<Claims>(req.extensions());
				debug!(jwt_validated, "inproc authz: checking auth method");

				if jwt_validated {
					debug!("inproc authz: JWT already validated, passthrough");
				} else if let Some(api_key) = extract_api_key(req.headers(), &self.inputs.cfg.authz.header) {
					let decision = self
						.inputs
						.inproc_runtime
						.authz
						.check_authz(&api_key, &self.inputs.cfg.authz)
						.await;

					match decision {
						authz_core::AuthzDecision::Allow { .. } => {
							debug!(api_key_len = api_key.len(), "inproc authz: allowed");
						}
						authz_core::AuthzDecision::Deny { status, reason, .. } => {
							debug!(api_key_len = api_key.len(), status, %reason, "inproc authz: denied");
							// Internal errors come as Deny with status 500
							if status == 500 && self.inputs.cfg.authz.fail_open {
								warn!(%reason, "inproc authz: internal error (fail-open)");
							} else {
								return Err(ProxyError::AuthzDenied { status, reason }.into());
							}
						}
					}
				} else if !self.inputs.cfg.authz.fail_open {
					// No API key, no JWT, and fail-closed mode
					return Err(ProxyError::AuthzDenied {
						status: 401,
						reason: "missing API key".to_string(),
					}
					.into());
				}
			}
		}

		// Phase 6B: In-process RateLimit check
		#[cfg(feature = "inproc")]
		{
			use crate::inproc::RateLimitMode;
			if self.inputs.cfg.rate_limit.mode == RateLimitMode::Inproc {
				// Build descriptors from request context
				// For now, use a simple model-based descriptor if available
				let mut descriptors = std::collections::HashMap::new();

				// Extract model from request body if JSON (optional)
				// Note: Body parsing happens later, so we use path-based heuristics for now
				if let Some(path) = req.uri().path().strip_prefix("/v1/") {
					descriptors.insert("endpoint".to_string(), path.to_string());
				}

				// Use default domain "inferrouter-llm" for LLM requests
				let domain = "inferrouter-llm";
				let decision = self
					.inputs
					.inproc_runtime
					.ratelimit
					.check_ratelimit(domain, &descriptors);

				match decision {
					ratelimit_core::RateLimitDecision::Allow { current, limit, remaining } => {
						debug!(current, limit, remaining, "inproc ratelimit: allowed");
					}
					ratelimit_core::RateLimitDecision::LimitExceeded { retry_after, limit } => {
						let reset_seconds = retry_after.as_secs();
						debug!(limit, reset_seconds, "inproc ratelimit: denied");
						return Err(ProxyError::RateLimitExceeded {
							limit: limit as u64,
							remaining: 0,
							reset_seconds,
						}
						.into());
					}
				}
			}
		}

		// Parse body if route has selectors (for context-window routing)
		maybe_parse_body_for_selectors(selected_route.as_ref(), &mut req, &self.inputs.metrics)
			.await?;

		// Phase 4.2: Backend selection with fallback support
		let maybe_backend = select_backend(selected_route.as_ref(), &req, &self.inputs.metrics);

		let selected_backend_ref = match maybe_backend {
			Some(backend) => backend,
			None => {
				// No local backend available - check for fallback gateway
				if let Some(fallback) = &self.inputs.cfg.fallback_gateway {
					// Check hop header to prevent loops (single-hop fallback only)
					if req.headers().contains_key(FALLBACK_HOP_HEADER) {
						warn!(
							"Fallback refused: {} header present (request already forwarded once)",
							FALLBACK_HOP_HEADER
						);
						return Err(ProxyError::NoValidBackends.into());
					}

					// Forward to fallback gateway and return its response directly
					info!(
						fallback_url = %fallback.url,
						"No local backend available, forwarding to fallback gateway"
					);
					let response = forward_to_fallback_gateway(req, fallback, log, &self.inputs.metrics).await?;
					return Ok(response);
				}

				// No fallback configured - return error
				return Err(ProxyError::NoValidBackends.into());
			}
		};

		// Phase 4.2: Also handle NoHealthyEndpoints with fallback
		let selected_backend = match resolve_backend(selected_backend_ref.clone(), self.inputs.as_ref()) {
			Ok(backend) => backend,
			Err(ProxyError::NoHealthyEndpoints) => {
				// All backends are unhealthy - try fallback if configured
				if let Some(fallback) = &self.inputs.cfg.fallback_gateway {
					if req.headers().contains_key(FALLBACK_HOP_HEADER) {
						warn!(
							"Fallback refused on NoHealthyEndpoints: {} header present",
							FALLBACK_HOP_HEADER
						);
						return Err(ProxyError::NoHealthyEndpoints.into());
					}

					info!(
						fallback_url = %fallback.url,
						"No healthy backends, forwarding to fallback gateway"
					);
					let response = forward_to_fallback_gateway(req, fallback, log, &self.inputs.metrics).await?;
					return Ok(response);
				}
				return Err(ProxyError::NoHealthyEndpoints.into());
			}
			Err(e) => return Err(e.into()),
		};

		// Token limits enforcement (prepaid caps, BYOK limits, credit balance)
		// Uses cached limits from backend /internal/limits/snapshot
		let provider = selected_backend_ref
			.metadata
			.get("provider")
			.and_then(|v| v.as_str());

		if provider.map(|p| p.ends_with("_byok")).unwrap_or(false) {
			// Record BYOK provider for usage tracking
			log.byok_provider = provider.map(|p| p.to_string());
		}

		// Extract account_id from JWT claims for BYOR and limits enforcement
		if let Some(claims) = req.extensions().get::<crate::http::jwt::Claims>() {
			if let Some(account_id) = crate::limits::extract_account_id_from_claims(&claims.inner) {
				// BYOR check: verify account owns this gateway (if BYOR mode enabled)
				if let Err(byor_err) = crate::limits::check_byor_access(
					&account_id,
					self.inputs.limits_cache.config(),
				) {
					if let crate::limits::LimitError::ByorAccessDenied { .. } = byor_err {
						debug!(
							account_id,
							"BYOR access denied – rejecting with 403"
						);
						return Err(
							ProxyError::ByorForbidden {
								account_id: account_id.clone(),
							}
							.into(),
						);
					}
				}

				// Determine model type from provider
				let model_type = crate::limits::ModelType::from_provider(provider);

				// Check limits via cache
				if let Err(limit_err) = crate::limits::check_account_limits(
					&account_id,
					model_type,
					&self.inputs.limits_cache,
				) {
					match limit_err {
						crate::limits::LimitError::PrepaidCapExceeded {
							reason,
							daily_used,
							daily_limit,
							..
						} => {
							debug!(
								account_id,
								reason,
								daily_used,
								daily_limit,
								"Prepaid cap exceeded – rejecting with 429"
							);
							return Err(
								ProxyError::RateLimitExceeded {
									limit: daily_limit as u64,
									remaining: 0,
									reset_seconds: 0, // TODO: calculate from reset_at
								}
								.into(),
							);
						}
						crate::limits::LimitError::ByokLimitExceeded {
							byok_used,
							byok_limit,
							..
						} => {
							debug!(
								account_id,
								byok_used,
								byok_limit,
								"BYOK limit exceeded – rejecting with 429"
							);
							return Err(
								ProxyError::RateLimitExceeded {
									limit: byok_limit as u64,
									remaining: 0,
									reset_seconds: 0,
								}
								.into(),
							);
						}
						crate::limits::LimitError::InsufficientCredits { balance } => {
							debug!(
								account_id,
								balance,
								"Insufficient credits – rejecting with 402"
							);
							return Err(
								ProxyError::PaymentRequired {
									balance,
								}
								.into(),
							);
						}
						crate::limits::LimitError::ByorAccessDenied { .. } => {
							// Already handled above, but match must be exhaustive
							unreachable!("BYOR error should be caught above");
						}
					}
				}
			} else {
				debug!("No account_id in JWT claims; skipping limits enforcement");
			}
		}

		let backend_policies = get_backend_policies(
			self.inputs.as_ref(),
			&selected_backend.backend,
			&selected_backend.inline_policies,
			Some(route_path.clone()),
		);
		log.backend_info = Some(selected_backend.backend.backend.backend_info());
		if let Some(bp) = selected_backend.backend.backend.backend_protocol() {
			log.backend_protocol = Some(bp)
		}

		let (head, body) = req.into_parts();
		for mirror in route_policies
			.request_mirror
			.iter()
			.chain(backend_policies.request_mirror.iter())
		{
			if !rand::rng().random_bool(mirror.percentage) {
				trace!(
					"skipping mirror, percentage {} not triggered",
					mirror.percentage
				);
				continue;
			}
			// TODO: mirror the body. For now, we just ignore the body
			let req = Request::from_parts(head.clone(), http::Body::empty());
			let inputs = inputs.clone();
			let policy_client = self.policy_client();
			let mirror = mirror.clone();
			tokio::task::spawn(async move {
				if let Err(e) = send_mirror(inputs, policy_client, mirror, req).await {
					warn!("error sending mirror request: {}", e);
				}
			});
		}

		const MAX_BUFFERED_BYTES: usize = 64 * 1024;
		let retries = route_policies.retry.clone();
		let late_route_policies: Arc<LLMRequestPolicies> = Arc::new(route_policies.into());
		// attempts is the total number of attempts, not the retries
		let attempts = retries.as_ref().map(|r| r.attempts.get() + 1).unwrap_or(1);
		let body = if attempts > 1 {
			// If we are going to attempt a retry we will need to track the incoming bytes for replay
			let body = http::retry::ReplayBody::try_new(body, MAX_BUFFERED_BYTES);
			if body.is_err() {
				debug!("initial body is too large to retry, disabling retries")
			}
			body
		} else {
			Err(body)
		};
		let mut next = match body {
			Ok(retry) => Some(retry),
			Err(body) => {
				trace!("no retries");
				// no retries at all, just send the request as normal
				let req = Request::from_parts(head, http::Body::new(body));
				return self
					.attempt_upstream(
						log,
						&mut req_upgrade,
						late_route_policies,
						&selected_backend,
						backend_policies,
						response_policies,
						req,
					)
					.await;
			},
		};
		let mut last_res: Option<Result<Response, ProxyResponse>> = None;
		for n in 0..attempts {
			let last = n == attempts - 1;
			let this = next.take().expect("next should be set");
			debug!("attempt {n}/{}", attempts - 1);
			if matches!(this.is_capped(), None | Some(true)) {
				// This could be either too much buffered, or it could mean we got a response before we read the request body.
				debug!("buffered too much to attempt a retry");
				return last_res.expect("should only be capped if we had a previous attempt");
			}
			if !last {
				// Stop cloning on our last
				next = Some(this.clone());
			}
			let mut head = head.clone();
			if n > 0 {
				log.retry_attempt = Some(n);
				head.headers.insert(
					HeaderName::from_static("x-retry-attempt"),
					HeaderValue::try_from(format!("{n}"))
						.map_err(|e| ProxyError::ProcessingString(e.to_string()))?,
				);
			}
			let req = Request::from_parts(head, http::Body::new(this));
			let res = self
				.attempt_upstream(
					log,
					&mut req_upgrade,
					late_route_policies.clone(),
					&selected_backend,
					backend_policies.clone(),
					response_policies,
					req,
				)
				.await;
			if last || !should_retry(&res, retries.as_ref().unwrap()) {
				if !last {
					debug!("response not retry-able");
				}
				return res;
			}
			debug!(
				"attempting another retry, last result was {} {:?}",
				res.is_err(),
				res.as_ref().map(|r| r.status())
			);
			last_res = Some(res);
		}
		unreachable!()
	}

	async fn apply_request_to_cel(log: &mut RequestLog, req: &mut Request) {
		log
			.cel
			.ctx()
			.with_source(&log.tcp_info, log.tls_info.as_ref());
		let needs_body = log.cel.ctx().with_request(req, log.start_time.clone());
		if needs_body && let Ok(body) = crate::http::inspect_body(req).await {
			log.cel.ctx().with_request_body(body);
		}
		if let Some(claims) = req.extensions().get::<crate::http::jwt::Claims>() {
			log.cel.ctx().with_jwt(claims);
		}
	}

	#[allow(clippy::too_many_arguments)]
	async fn attempt_upstream(
		&self,
		log: &mut RequestLog,
		req_upgrade: &mut Option<RequestUpgrade>,
		route_policies: Arc<store::LLMRequestPolicies>,
		selected_backend: &RouteBackend,
		backend_policies: BackendPolicies,
		response_policies: &mut ResponsePolicies,
		req: Request,
	) -> Result<Response, ProxyResponse> {
		let call = make_backend_call(
			self.inputs.clone(),
			route_policies.clone(),
			&selected_backend.backend.backend,
			Some(&selected_backend.metadata),
			backend_policies,
			req,
			Some(log),
			response_policies,
		)
		.await?;

		let timeout = response_policies
			.timeout
			.as_ref()
			.and_then(|t| t.effective_timeout());

		// Setup timeout
		let call_result = if let Some(timeout) = timeout {
			let deadline = tokio::time::Instant::from_std(log.start + timeout);
			let fut = tokio::time::timeout_at(deadline, call);
			fut.await
		} else {
			Ok(call.await)
		};

		// Run the actual call
		let resp = match call_result {
			Ok(Ok(resp)) => resp,
			Ok(Err(e)) => {
				return Err(e.into());
			},
			Err(_) => {
				return Err(ProxyError::RequestTimeout.into());
			},
		};
		if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
			return handle_upgrade(req_upgrade, resp).await.map_err(Into::into);
		}

		// gRPC status can be in the initial headers or a trailer, add if they are here
		maybe_set_grpc_status(&log.grpc_status, resp.headers());

		Ok(resp)
	}

	fn policy_client(&self) -> PolicyClient {
		PolicyClient {
			inputs: self.inputs.clone(),
		}
	}
}

fn resolve_backend(b: RouteBackendReference, pi: &ProxyInputs) -> Result<RouteBackend, ProxyError> {
	let backend = super::resolve_backend(&b.backend, pi)?;
	Ok(RouteBackend {
		weight: b.weight,
		backend,
		inline_policies: b.inline_policies,
		metadata: b.metadata,
	})
}

async fn handle_upgrade(
	req_upgrade_type: &mut Option<RequestUpgrade>,
	mut resp: Response,
) -> Result<Response, ProxyError> {
	let Some(RequestUpgrade {
		upgade_type,
		upgrade,
	}) = std::mem::take(req_upgrade_type)
	else {
		return Err(ProxyError::UpgradeFailed(None, None));
	};
	let resp_upgrade_type = upgrade_type(resp.headers());
	if Some(&upgade_type) != resp_upgrade_type.as_ref() {
		return Err(ProxyError::UpgradeFailed(
			Some(upgade_type),
			resp_upgrade_type,
		));
	}
	let response_upgraded = resp
		.extensions_mut()
		.remove::<OnUpgrade>()
		.ok_or_else(|| ProxyError::ProcessingString("no upgrade".to_string()))?
		.await
		.map_err(|e| ProxyError::ProcessingString(format!("upgrade failed: {e:?}")))?;
	tokio::task::spawn(async move {
		let req = match upgrade.await {
			Ok(u) => u,
			Err(e) => {
				error!("upgrade error: {e}");
				return;
			},
		};
		let _ = agent_core::copy::copy_bidirectional(
			&mut TokioIo::new(req),
			&mut TokioIo::new(response_upgraded),
			&agent_core::copy::ConnectionResult {},
		)
		.await;
	});
	Ok(resp)
}

pub async fn build_transport(
	inputs: &ProxyInputs,
	backend_call: &BackendCall,
	backend_tls: Option<BackendTLS>,
	backend_http_version_override: Option<::http::Version>,
) -> Result<Transport, ProxyError> {
	let backend_tls = backend_tls.map(|btls| btls.config_for(backend_http_version_override));
	// Check if we need double hbone
	if let (
		Some((gw_addr, gw_identity)),
		Some((InboundProtocol::HBONE, waypoint_identity)),
		Some(ca),
	) = (
		&backend_call.network_gateway,
		&backend_call.transport_override,
		&inputs.ca,
	) {
		if ca.get_identity().await.is_ok() {
			// Extract gateway IP from the gateway address
			let gateway_ip = match &gw_addr.destination {
				types::discovery::gatewayaddress::Destination::Address(net_addr) => net_addr.address,
				types::discovery::gatewayaddress::Destination::Hostname(_) => {
					warn!("hostname-based gateway addresses not yet supported");
					return Ok(Transport::Plaintext);
				},
			};

			let gateway_socket_addr = SocketAddr::new(gateway_ip, gw_addr.hbone_mtls_port);

			tracing::debug!(
				"using double hbone through gateway {:?} at {}",
				gw_addr,
				gateway_socket_addr
			);
			return Ok(Transport::DoubleHbone {
				gateway_address: gateway_socket_addr,
				gateway_identity: gw_identity.clone(),
				waypoint_identity: waypoint_identity.clone(),
				inner_tls: backend_tls,
			});
		} else {
			warn!("wanted double hbone but CA is not available");
			return Ok(Transport::Plaintext);
		}
	}

	Ok(
		match (&backend_call.transport_override, backend_tls, &inputs.ca) {
			// Use legacy mTLS if they did not define a TLS policy. We could do double TLS but Istio doesn't,
			// so maintain bug-for-bug parity
			(Some((InboundProtocol::LegacyIstioMtls, ident)), None, Some(ca)) => {
				if let Ok(id) = ca.get_identity().await {
					Some(
						id.legacy_mtls(vec![ident.clone()])
							.map_err(|e| ProxyError::Processing(anyhow!("{e}")))?,
					)
					.into()
				} else {
					warn!("wanted TLS but CA is not available");
					Transport::Plaintext
				}
			},
			(Some((InboundProtocol::HBONE, ident)), btls, Some(ca)) => {
				if ca.get_identity().await.is_ok() {
					Transport::Hbone(btls, ident.clone())
				} else {
					warn!("wanted TLS but CA is not available");
					Transport::Plaintext
				}
			},
			(_, pol, _) => pol.into(),
		},
	)
}

fn get_backend_policies(
	inputs: &ProxyInputs,
	backend: &BackendWithPolicies,
	inline_policies: &[BackendPolicy],
	path: Option<RoutePath>,
) -> BackendPolicies {
	let service = match &backend.backend {
		Backend::Service(svc, _) => Some(strng::format!("{}/{}", svc.namespace, svc.hostname)),
		_ => None,
	};

	inputs.stores.read_binds().backend_policies(
		backend.backend.name(),
		service,
		// Precedence: Selector < Backend inline < backendRef inline
		// Note this differs from the logical chain of objects (Route -> backendRef -> backend),
		// because a backendRef is actually more specific: its one *specific usage* of the backend.
		// For example, we may say to use TLS for a Backend, but in a specific TLSRoute backendRef we disable
		// as it is already TLS.
		&[&backend.inline_policies, inline_policies],
		path,
	)
}

async fn make_backend_call(
	inputs: Arc<ProxyInputs>,
	route_policies: Arc<store::LLMRequestPolicies>,
	backend: &Backend,
	backend_metadata: Option<&HashMap<Strng, serde_json::Value>>,
	base_policies: BackendPolicies,
	mut req: Request,
	mut log: Option<&mut RequestLog>,
	response_policies: &mut ResponsePolicies,
) -> Result<Pin<Box<dyn Future<Output = Result<Response, ProxyError>> + Send>>, ProxyResponse> {
	let policy_client = PolicyClient {
		inputs: inputs.clone(),
	};

	// The MCP backend aggregates multiple backends into a single backend.
	// In some cases, we want to treat this as a normal backend, so we swap it out.
	let (backend, policies) = match backend {
		Backend::MCP(name, mcp_backend) => {
			if let Some(be) = inputs
				.clone()
				.mcp_state
				.should_passthrough(name.clone(), mcp_backend, &req)
			{
				let (target, inline_policies) =
					super::resolve_simple_backend_with_policies(&be, inputs.as_ref())?;
				// The typical MCP flow will apply the top level Backend policies as default_policies
				// When we passthrough, we should preserve this behavior.
				let target_name = target.name();
				let policies = inputs
					.stores
					.read_binds()
					.sub_backend_policies(target_name, Some(&inline_policies));

				(&Backend::from(target), base_policies.merge(policies))
			} else {
				(backend, base_policies)
			}
		},
		_ => (backend, base_policies),
	};

	log.add(|l| {
		l.backend_info = Some(backend.backend_info());
		if let Some(bp) = backend.backend_protocol() {
			l.backend_protocol = Some(bp)
		}
	});

	// BYOK injection: replace Authorization header with provider key when hitting BYOK backends.
	if let Err(e) = inject_byok_if_needed(
		&inputs,
		backend_metadata,
		&mut req,
		log.as_deref_mut(),
	) {
		return Err(ProxyResponse::from(e));
	}

	let mut maybe_inference = policies.build_inference(policy_client.clone());
	let (override_dest, ext_proc_resp) = maybe_inference.mutate_request(&mut req).await?;
	ext_proc_resp.apply(response_policies.headers())?;
	log.add(|l| l.inference_pool = override_dest);

	let backend_call = match backend {
		Backend::AI(n, ai) => {
			let (provider, handle) = ai.select_provider().ok_or(ProxyError::NoHealthyEndpoints)?;
			log.add(move |l| l.request_handle = Some(handle));
			let k = strng::format!("{}/{}", n, provider.name);
			let sub_backend_policies = inputs
				.stores
				.read_binds()
				.sub_backend_policies(k, Some(&provider.inline_policies));

			let (target, provider_defaults) = match &provider.host_override {
				Some(target) => (
					target.clone(),
					BackendPolicies {
						// Attach LLM provider, but don't use default setup
						llm_provider: Some(provider.clone()),
						..Default::default()
					},
				),
				None => {
					let (tgt, mut pol) = provider.provider.default_connector();
					pol.llm_provider = Some(provider.clone());
					(tgt, pol)
				},
			};
			// Defaults for the provider < Backend level policies < Sub Backend
			let effective_policies = provider_defaults
				.merge(policies)
				.merge(sub_backend_policies);
			if let Some(po) = &provider.path_override {
				http::modify_req_uri(&mut req, |p| {
					p.path_and_query = Some(PathAndQuery::from_str(po)?);
					Ok(())
				})
				.map_err(ProxyError::Processing)?;
			}
			BackendCall {
				target,
				backend_policies: effective_policies,
				http_version_override: None,
				transport_override: None,
				network_gateway: None,
			}
		},
		Backend::Service(svc, port) => {
			build_service_call(&inputs, policies, &mut log, override_dest, svc, port)?
		},
		Backend::Opaque(_, target) => BackendCall {
			target: target.clone(),
			http_version_override: None,
			transport_override: None,
			network_gateway: None,
			backend_policies: policies,
		},
		Backend::Dynamic {} => {
			let port = req
				.extensions()
				.get::<TCPConnectionInfo>()
				.unwrap()
				.local_addr
				.port();
			let target = Target::try_from((get_host(&req)?, port)).map_err(ProxyError::Processing)?;
			BackendCall {
				target: target.clone(),
				http_version_override: None,
				transport_override: None,
				network_gateway: None,
				backend_policies: policies,
			}
		},
		Backend::MCP(name, backend) => {
			let inputs = inputs.clone();
			let backend = backend.clone();
			let name = name.clone();
			let time = log.as_ref().unwrap().start_time.clone();
			set_backend_cel_context(&mut log);
			let mcp_response_log = log.map(|l| l.mcp_status.clone()).expect("must be set");
			return Ok(Box::pin(async move {
				inputs
					.clone()
					.mcp_state
					.serve(inputs, name, backend, req, mcp_response_log, time)
					.map(Ok)
					.await
			}));
		},
		Backend::Invalid => return Err(ProxyResponse::from(ProxyError::BackendDoesNotExist)),
	};

	// Apply auth before LLM request setup, so the providers can assume auth is in standardized header
	// Apply auth as early as possible so any ext_proc or transformations won't be repeated on retries in case it fails.
	let backend_name = backend.name();
	let backend_info = auth::BackendInfo {
		name: backend_name.clone(),
		inputs: inputs.clone(),
	};
	apply_backend_policies(
		backend_info.clone(),
		&backend_call,
		&mut req,
		&mut log,
		response_policies,
	)
	.await?;

	log.add(|l| {
		l.endpoint = Some(backend_call.target.clone());
	});

	let llm_request_policies =
		route_policies.merge_backend_policies(backend_call.backend_policies.llm.clone());

	set_backend_cel_context(&mut log);

	let (mut req, llm_response_policies, llm_request) =
		if let Some(llm) = &backend_call.backend_policies.llm_provider {
			let route_type = llm.resolve_route(req.uri().path());
			trace!("llm: route {} to {route_type:?}", req.uri().path());
			// First, we process the incoming request. This entails translating to the relevant provider,
			// and parsing the request to build the LLMRequest for logging/etc, and applying LLM policies like
			// prompt enrichment, prompt guard, etc.
			match route_type {
				RouteType::Completions | RouteType::Messages | RouteType::Responses => {
					let r = match route_type {
						RouteType::Completions => llm
							.provider
							.process_completions_request(
								&backend_info,
								llm_request_policies.llm.as_deref(),
								req,
								llm.tokenize,
								&mut log,
							)
							.await
							.map_err(|e| ProxyError::Processing(e.into()))?,
						RouteType::Messages => llm
							.provider
							.process_messages_request(
								&backend_info,
								llm_request_policies.llm.as_deref(),
								req,
								llm.tokenize,
								&mut log,
							)
							.await
							.map_err(|e| ProxyError::Processing(e.into()))?,
						RouteType::Responses => llm
							.provider
							.process_responses_request(
								&backend_info,
								llm_request_policies.llm.as_deref(),
								req,
								llm.tokenize,
								&mut log,
							)
							.await
							.map_err(|e| ProxyError::Processing(e.into()))?,
						_ => unreachable!(),
					};
					let (mut req, llm_request) = match r {
						RequestResult::Success(r, lr) => (r, lr),
						RequestResult::Rejected(dr) => return Ok(Box::pin(async move { Ok(dr) })),
					};
					// If a user doesn't configure explicit overrides for connecting to a provider, setup default
					// paths, TLS, etc.
					llm
						.provider
						.setup_request(
							&mut req,
							route_type,
							Some(&llm_request),
							llm.use_default_policies(),
						)
						.map_err(ProxyError::Processing)?;

					// Apply all policies (rate limits)
					let response_policies = apply_llm_request_policies(
						&llm_request_policies,
						policy_client.clone(),
						&mut log,
						&mut req,
						&llm_request,
						&mut response_policies.response_headers,
					)
					.await?;
					log.add(|l| l.llm_request = Some(llm_request.clone()));
					(req, response_policies, Some(llm_request))
				},
				RouteType::Models => {
					return Ok(Box::pin(async move {
						Ok(
							::http::Response::builder()
								.status(::http::StatusCode::NOT_IMPLEMENTED)
								.header(::http::header::CONTENT_TYPE, "application/json")
								.body(http::Body::from(format!(
									"{{\"error\":\"Route '{route_type:?}' not implemented\"}}"
								)))
								.expect("Failed to build response"),
						)
					}));
				},
				RouteType::Passthrough => {
					// For passthrough, we only need to setup the response so we get default TLS, hostname, etc set.
					// We do not need LLM policies nor token-based rate limits, etc.
					llm
						.provider
						.setup_request(&mut req, route_type, None, true)
						.map_err(ProxyError::Processing)?;
					(req, LLMResponsePolicies::default(), None)
				},
				RouteType::AnthropicTokenCount => {
					let (mut req, llm_request) = llm
						.provider
						.process_count_tokens_request(req, llm_request_policies.llm.as_deref())
						.await
						.map_err(|e| ProxyError::Processing(e.into()))?;

					llm
						.provider
						.setup_request(
							&mut req,
							route_type,
							Some(&llm_request),
							llm.use_default_policies(),
						)
						.map_err(ProxyError::Processing)?;

					(req, LLMResponsePolicies::default(), Some(llm_request))
				},
			}
		} else {
			(req, LLMResponsePolicies::default(), None)
		};
	// Some auth types (AWS) need to be applied after all request processing
	auth::apply_late_backend_auth(
		backend_call.backend_policies.backend_auth.as_ref(),
		&mut req,
	)
	.await?;
	let transport = build_transport(
		&inputs,
		&backend_call,
		backend_call.backend_policies.backend_tls.clone(),
		backend_call
			.backend_policies
			.http
			.as_ref()
			.and_then(|h| h.version)
			.or(backend_call.http_version_override),
	)
	.await?;
	let call = client::Call {
		req,
		target: backend_call.target,
		transport,
	};
	let upstream = inputs.upstream.clone();
	let llm_response_log = log.as_ref().map(|l| l.llm_response.clone());
	let include_completion_in_log = log
		.as_ref()
		.map(|l| l.cel.cel_context.needs_llm_completion())
		.unwrap_or_default();
	let a2a_type = response_policies.a2a_type.clone();
	// Capture route type before moving call
	let route_type = backend_call
		.backend_policies
		.llm_provider
		.as_ref()
		.map(|llm| llm.resolve_route(call.req.uri().path()));
	Ok(Box::pin(async move {
		let mut resp = upstream.call(call).await?;
		a2a::apply_to_response(
			backend_call.backend_policies.a2a.as_ref(),
			a2a_type,
			&mut resp,
		)
		.await
		.map_err(ProxyError::Processing)?;
		let mut resp = if let Some(rt) = route_type
			&& rt == RouteType::AnthropicTokenCount
		{
			// count_tokens has simpler response handling (no streaming, no logging)
			crate::llm::bedrock::process_count_tokens_response(resp)
				.await
				.map_err(ProxyError::Processing)?
		} else if let (Some(llm), Some(llm_request)) =
			(backend_call.backend_policies.llm_provider, llm_request)
		{
			llm
				.provider
				.process_response(
					policy_client.clone(),
					llm_request,
					llm_response_policies,
					llm_response_log.expect("must be set"),
					include_completion_in_log,
					resp,
				)
				.await
				.map_err(|e| ProxyError::Processing(e.into()))?
		} else {
			resp
		};
		// TODO: we currently do not support ImmediateResponse from inference router
		let _ = maybe_inference.mutate_response(&mut resp).await?;
		Ok(resp)
	}))
}

fn set_backend_cel_context(log: &mut Option<&mut RequestLog>) {
	log.add(|l| {
		if let Some(bp) = l.backend_protocol
			&& let Some(bi) = &l.backend_info
		{
			l.cel.ctx().with_backend(bi, bp)
		}
	});
}

pub fn build_service_call(
	inputs: &ProxyInputs,
	backend_policies: BackendPolicies,
	log: &mut Option<&mut RequestLog>,
	override_dest: Option<SocketAddr>,
	svc: &Arc<Service>,
	port: &u16,
) -> Result<BackendCall, ProxyError> {
	let port = *port;
	let workloads = &inputs.stores.read_discovery().workloads;
	let (ep, handle, wl) = svc
		.endpoints
		.select_endpoint(workloads, svc.as_ref(), port, override_dest)
		.ok_or(ProxyError::NoHealthyEndpoints)?;

	let svc_target_port = svc.ports.get(&port).copied().unwrap_or_default();
	let target_port = if let Some(&ep_target_port) = ep.port.get(&port) {
		// prefer endpoint port mapping
		ep_target_port
	} else if svc_target_port > 0 {
		// otherwise, see if the service has this port
		svc_target_port
	} else {
		return Err(ProxyError::NoHealthyEndpoints);
	};
	let http_version_override = if svc.port_is_http2(port) {
		Some(::http::Version::HTTP_2)
	} else if svc.port_is_http1(port) {
		Some(::http::Version::HTTP_11)
	} else {
		None
	};

	log.add(move |l| l.request_handle = Some(handle));

	// Check if we need double hbone (workload on remote network with gateway)
	let network_gateway = if wl.network != inputs.cfg.network {
		if let Some(gw_addr) = &wl.network_gateway {
			// Look up the gateway workload to get its identity
			let gateway_workload = match &gw_addr.destination {
				types::discovery::gatewayaddress::Destination::Address(net_addr) => {
					workloads.find_address(net_addr)
				},
				types::discovery::gatewayaddress::Destination::Hostname(_hostname) => {
					// TODO: Implement hostname resolution for gateway
					// For now, we don't support hostname-based gateways
					tracing::warn!("hostname-based network gateways not yet supported");
					None
				},
			};

			if let Some(gw_wl) = gateway_workload {
				tracing::debug!(
					source_network=%inputs.cfg.network,
					dest_network=%wl.network,
					gateway=?gw_addr,
					"picked workload on remote network, using double hbone"
				);
				Some((gw_addr.clone(), gw_wl.identity()))
			} else {
				tracing::warn!(
					"network gateway {:?} not found for remote workload",
					gw_addr
				);
				None
			}
		} else {
			tracing::warn!(
				source_network=%inputs.cfg.network,
				dest_network=%wl.network,
				"workload on remote network but no gateway configured"
			);
			None
		}
	} else {
		None
	};

	// For double HBONE, use hostname-based target so the gateway can resolve it
	let target = if network_gateway.is_some() {
		tracing::debug!(
			hostname=%svc.hostname,
			port=%port,
			"using hostname-based target for double hbone"
		);
		Target::Hostname(svc.hostname.clone(), port)
	} else {
		// For direct connections, we need the workload IP
		let Some(ip) = wl.workload_ips.first() else {
			return Err(ProxyError::NoHealthyEndpoints);
		};
		let dest = SocketAddr::from((*ip, target_port));
		Target::Address(dest)
	};

	Ok(BackendCall {
		target,
		http_version_override,
		transport_override: Some((wl.protocol, wl.identity())),
		network_gateway,
		backend_policies,
	})
}

fn should_retry(res: &Result<Response, ProxyResponse>, pol: &retry::Policy) -> bool {
	match res {
		Ok(resp) => pol.codes.contains(&resp.status()),
		Err(ProxyResponse::Error(e)) => e.is_retryable(),
		Err(ProxyResponse::DirectResponse(_)) => false,
	}
}

pub fn maybe_set_grpc_status(status: &AsyncLog<u8>, headers: &HeaderMap) {
	if let Some(s) = headers.get("grpc-status") {
		let parsed = std::str::from_utf8(s.as_bytes())
			.ok()
			.and_then(|s| s.parse::<u8>().ok());
		status.store(parsed);
	}
}

async fn send_mirror(
	inputs: Arc<ProxyInputs>,
	upstream: PolicyClient,
	mirror: filters::RequestMirror,
	mut req: Request,
) -> Result<(), ProxyError> {
	req.headers_mut().remove(http::header::CONTENT_LENGTH);
	let backend = super::resolve_simple_backend(&mirror.backend, inputs.as_ref())?;
	let _ = upstream.call(req, backend).await?;
	Ok(())
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
static HOP_HEADERS: [HeaderName; 9] = [
	header::CONNECTION,
	// non-standard but still sent by libcurl and rejected by e.g. google
	HeaderName::from_static("proxy-connection"),
	HeaderName::from_static("keep-alive"),
	header::PROXY_AUTHENTICATE,
	header::PROXY_AUTHORIZATION,
	header::TE,
	header::TRAILER,
	header::TRANSFER_ENCODING,
	header::UPGRADE,
];

struct RequestUpgrade {
	upgade_type: HeaderValue,
	upgrade: OnUpgrade,
}

fn hop_by_hop_headers(req: &mut Request) -> Option<RequestUpgrade> {
	let trailers = req
		.headers()
		.get(header::TE)
		.and_then(|h| h.to_str().ok())
		.map(|s| s.contains("trailers"))
		.unwrap_or(false);
	let upgrade_type = upgrade_type(req.headers());
	for h in HOP_HEADERS.iter() {
		req.headers_mut().remove(h);
	}
	// If the incoming request supports trailers, the downstream one will as well
	if trailers {
		req.headers_mut().typed_insert(headers::Te::trailers());
	}
	// After stripping all the hop-by-hop connection headers above, add back any
	// necessary for protocol upgrades, such as for websockets.
	if let Some(upgrade_type) = upgrade_type.clone() {
		req
			.headers_mut()
			.typed_insert(headers::Connection::upgrade());
		req.headers_mut().insert(header::UPGRADE, upgrade_type);
	}
	let on_upgrade = req.extensions_mut().remove::<OnUpgrade>();
	if let Some(t) = upgrade_type
		&& let Some(u) = on_upgrade
	{
		Some(RequestUpgrade {
			upgade_type: t,
			upgrade: u,
		})
	} else {
		None
	}
}

fn upgrade_type(headers: &HeaderMap) -> Option<HeaderValue> {
	if let Some(con) = headers.typed_get::<headers::Connection>() {
		if con.contains(http::header::UPGRADE) {
			headers.get(http::header::UPGRADE).cloned()
		} else {
			None
		}
	} else {
		None
	}
}

fn sensitive_headers(req: &mut Request) {
	for (name, value) in req.headers_mut() {
		if name == http::header::AUTHORIZATION {
			value.set_sensitive(true)
		}
	}
}

// The http library will not put the authority into req.uri().authority for HTTP/1. Normalize so
// the rest of the code doesn't need to worry about it
fn normalize_uri(connection: &Extension, req: &mut Request) -> anyhow::Result<()> {
	debug!("request before normalization: {req:?}");
	if let ::http::Version::HTTP_10 | ::http::Version::HTTP_11 = req.version()
		&& req.uri().authority().is_none()
	{
		let mut parts = std::mem::take(req.uri_mut()).into_parts();
		// TODO: handle absolute HTTP/1.1 form
		let host = req
			.headers()
			.get(http::header::HOST)
			.and_then(|h| h.to_str().ok())
			.and_then(|h| h.parse::<Authority>().ok())
			.ok_or_else(|| anyhow::anyhow!("no authority or host"))?;
		req.headers_mut().remove(http::header::HOST);

		parts.authority = Some(host);
		if parts.path_and_query.is_some() {
			// TODO: or always do this?
			if connection.get::<TLSConnectionInfo>().is_some() {
				parts.scheme = Some(Scheme::HTTPS);
			} else {
				parts.scheme = Some(Scheme::HTTP);
			}
		}
		*req.uri_mut() = Uri::from_parts(parts)?
	}
	debug!("request after normalization: {req:?}");
	Ok(())
}

pub struct BackendCall {
	pub target: Target,
	pub http_version_override: Option<::http::Version>,
	pub transport_override: Option<(InboundProtocol, Identity)>,
	pub network_gateway: Option<(GatewayAddress, Identity)>, // For double hbone: (gateway_address, gateway_identity)
	pub backend_policies: BackendPolicies,
}

#[derive(Debug, Default)]
struct ResponsePolicies {
	timeout: Option<http::timeout::Policy>,
	route_response_header: Option<filters::HeaderModifier>,
	backend_response_header: Option<filters::HeaderModifier>,
	transformation: Option<Transformation>,
	gateway_transformation: Option<Transformation>,
	response_headers: HeaderMap,
	ext_proc: Option<ExtProcRequest>,
	gateway_ext_proc: Option<ExtProcRequest>,
	a2a_type: a2a::RequestType,
}

impl ResponsePolicies {
	pub fn headers(&mut self) -> &mut HeaderMap {
		&mut self.response_headers
	}

	pub async fn apply(
		&mut self,
		resp: &mut Response,
		log: &mut RequestLog,
		is_upstream_response: bool,
	) -> Result<(), ProxyResponse> {
		let exec = std::cell::LazyCell::new(|| log.cel.ctx().build());
		let cel_err = |_| ProxyError::ProcessingString("failed to build cel context".to_string());

		if let Some(rhm) = &self.route_response_header {
			rhm.apply(resp.headers_mut()).map_err(ProxyError::from)?;
		}
		if let Some(rhm) = &self.backend_response_header {
			rhm.apply(resp.headers_mut()).map_err(ProxyError::from)?;
		}
		if let Some(j) = &self.transformation {
			j.apply_response(resp, exec.deref().as_ref().map_err(cel_err)?);
		}
		if let Some(j) = &self.gateway_transformation {
			j.apply_response(resp, exec.deref().as_ref().map_err(cel_err)?);
		}

		// ext_proc is only intended to run on responses from upstream
		if is_upstream_response {
			if let Some(x) = self.ext_proc.as_mut() {
				x.mutate_response(resp).await?
			} else {
				PolicyResponse::default()
			}
			.apply(&mut self.response_headers)?;
			if let Some(x) = self.gateway_ext_proc.as_mut() {
				x.mutate_response(resp).await?
			} else {
				PolicyResponse::default()
			}
			.apply(&mut self.response_headers)?;
		}

		merge_in_headers(Some(self.response_headers.clone()), resp.headers_mut());
		Ok(())
	}
}

#[derive(Debug, Clone)]
pub struct PolicyClient {
	pub inputs: Arc<ProxyInputs>,
}

impl PolicyClient {
	pub async fn call_reference(
		&self,
		mut req: Request,
		backend_ref: &SimpleBackendReference,
	) -> Result<Response, ProxyError> {
		let backend = resolve_simple_backend(backend_ref, self.inputs.as_ref())?;
		trace!("resolved {:?} to {:?}", backend_ref, &backend);

		http::modify_req_uri(&mut req, |uri| {
			if uri.authority.is_none() {
				// If host is not set, set it to the backend
				uri.authority = Some(Authority::try_from(backend.hostport())?);
			}
			if uri.scheme.is_none() {
				// Default to HTTP, if the policy is TLS it will get set correctly later
				uri.scheme = Some(Scheme::HTTP);
			}
			Ok(())
		})
		.map_err(ProxyError::Processing)?;

		let backend = Backend::from(backend).into();
		let pols = get_backend_policies(&self.inputs, &backend, &[], None);
		self
			.internal_call_with_policies(req, backend.backend, pols)
			.await
	}

	pub async fn call(&self, req: Request, backend: SimpleBackend) -> Result<Response, ProxyError> {
		let backend = Backend::from(backend).into();
		let pols = get_backend_policies(&self.inputs, &backend, &[], None);
		self
			.internal_call_with_policies(req, backend.backend, pols)
			.await
	}

	pub async fn call_with_default_policies(
		&self,
		req: Request,
		backend: &SimpleBackend,
		defaults: BackendPolicies,
	) -> Result<Response, ProxyError> {
		let backend = Backend::from(backend.clone()).into();
		let pols = defaults.merge(get_backend_policies(&self.inputs, &backend, &[], None));
		self
			.internal_call_with_policies(req, backend.backend, pols)
			.await
	}

	pub async fn call_with_explicit_policies(
		&self,
		req: Request,
		backend: SimpleBackend,
		policies: Vec<BackendPolicy>,
	) -> Result<Response, ProxyError> {
		let backend = Backend::from(backend);
		let pols = self
			.inputs
			.stores
			.read_binds()
			.inline_backend_policies(&policies);
		self.internal_call_with_policies(req, backend, pols).await
	}

	pub fn internal_call_with_policies<'a>(
		&'a self,
		req: Request,
		backend: Backend,
		pols: BackendPolicies,
	) -> Pin<Box<dyn Future<Output = Result<Response, ProxyError>> + Send + '_>> {
		Box::pin(async move {
			make_backend_call(
				self.inputs.clone(),
				Arc::new(LLMRequestPolicies::default()),
				&backend,
				None,
				pols,
				req,
				None,
				&mut Default::default(),
			)
			.await
			.map_err(ProxyResponse::downcast)?
			.await
		})
	}

	pub async fn simple_call(&self, req: Request) -> Result<Response, ProxyError> {
		self.inputs.upstream.simple_call(req).await
	}
}
trait OptLogger {
	fn add<F>(&mut self, f: F)
	where
		F: FnOnce(&mut RequestLog);
}

impl OptLogger for Option<&mut RequestLog> {
	fn add<F>(&mut self, f: F)
	where
		F: FnOnce(&mut RequestLog),
	{
		if let Some(log) = self.as_mut() {
			f(log)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// BYOK helpers (pure Rust Fernet)
// -------------------------------------------------------------------------------------------------
#[derive(Clone, Debug)]
struct FernetKeys {
	signing: [u8; 16],
	encryption: [u8; 16],
}

static BYOK_KEYS: Lazy<Option<FernetKeys>> = Lazy::new(|| {
	std::env::var("FERNET_KEY").ok().and_then(|k| decode_fernet_key(&k).ok())
});

fn decode_fernet_key(key_b64: &str) -> Result<FernetKeys, ProxyError> {
	let decoded = URL_SAFE
		.decode(key_b64)
		.map_err(|e| ProxyError::ProcessingString(format!("FERNET_KEY base64 decode failed: {e}")))?;
	if decoded.len() != 32 {
		return Err(ProxyError::ProcessingString(format!(
			"FERNET_KEY must decode to 32 bytes, got {}",
			decoded.len()
		)));
	}
	let mut signing = [0u8; 16];
	let mut encryption = [0u8; 16];
	signing.copy_from_slice(&decoded[0..16]);
	encryption.copy_from_slice(&decoded[16..32]);
	Ok(FernetKeys {
		signing,
		encryption,
	})
}

fn decrypt_fernet(keys: &FernetKeys, token: &str) -> Result<String, ProxyError> {
	let decoded = URL_SAFE
		.decode(token)
		.map_err(|e| ProxyError::ProcessingString(format!("BYOK token base64 decode failed: {e}")))?;
	if decoded.len() < 1 + 8 + 16 + 32 {
		return Err(ProxyError::ProcessingString("BYOK token too short".to_string()));
	}
	// Fernet format: version (1) | timestamp (8) | IV (16) | ciphertext (N) | HMAC (32)
	// split_at(len-32) gives: msg = everything except last 32 bytes, sig = last 32 bytes (HMAC)
	let (msg, sig) = decoded.split_at(decoded.len() - 32);
	if msg[0] != 0x80 {
		return Err(ProxyError::ProcessingString("BYOK token version invalid".to_string()));
	}

	// HMAC verification
	type HmacSha256 = Hmac<Sha256>;
	let mut mac = HmacSha256::new_from_slice(&keys.signing)
		.map_err(|e| ProxyError::ProcessingString(format!("HMAC init failed: {e}")))?;
	mac.update(msg);
	let computed = mac.finalize().into_bytes();
	if computed.ct_eq(sig).unwrap_u8() != 1 {
		return Err(ProxyError::ProcessingString("BYOK token signature invalid".to_string()));
	}

	// Decrypt AES-128-CBC with PKCS7
	let iv = &msg[1 + 8..1 + 8 + 16];
	let ciphertext = &msg[1 + 8 + 16..];
	let mut buf = ciphertext.to_vec();
	let decrypted = Decryptor::<Aes128>::new_from_slices(&keys.encryption, iv)
		.map_err(|e| ProxyError::ProcessingString(format!("BYOK decrypt init failed: {e}")))?
		.decrypt_padded_mut::<Pkcs7>(&mut buf)
		.map_err(|e| ProxyError::ProcessingString(format!("BYOK decrypt failed: {e}")))?;

	String::from_utf8(decrypted.to_vec())
		.map_err(|e| ProxyError::ProcessingString(format!("BYOK key not valid UTF-8: {e}")))
}

fn inject_byok_if_needed(
	inputs: &ProxyInputs,
	backend_metadata: Option<&HashMap<Strng, serde_json::Value>>,
	req: &mut Request,
	_log: Option<&mut RequestLog>,
) -> Result<(), ProxyError> {
	let Some(metadata) = backend_metadata else {
		return Ok(());
	};
	let provider = match metadata.get("provider").and_then(|v| v.as_str()) {
		Some(p) if p.ends_with("_byok") => p,
		_ => return Ok(()),
	};

	let project_id = req
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("project_id"))
		.and_then(|v| v.as_str())
		.ok_or_else(|| ProxyError::ProcessingString("BYOK requires project_id claim".to_string()))?;

	let provider_id = metadata
		.get("external_provider_id")
		.and_then(|v| v.as_str())
		.ok_or_else(|| ProxyError::ProcessingString("BYOK backend missing external_provider_id".to_string()))?;

	let key_id = format!("{project_id}:{provider_id}");
	let creds_guard = inputs.read_byok_credentials();
	let encrypted = creds_guard
		.get(&key_id)
		.cloned()
		.ok_or_else(|| ProxyError::ProcessingString(format!("BYOK credential not found for {key_id}")))?;
	drop(creds_guard);

	let keys = BYOK_KEYS
		.as_ref()
		.ok_or_else(|| ProxyError::ProcessingString("FERNET_KEY not configured".to_string()))?;

	let api_key = decrypt_fernet(keys, &encrypted)?;

	req.headers_mut().insert(
		header::AUTHORIZATION,
		HeaderValue::try_from(format!("Bearer {api_key}"))
			.map_err(|e| ProxyError::ProcessingString(format!("invalid Authorization header: {e}")))?,
	);

	trace!(
		provider = provider,
		key_id = key_id,
		"Injected BYOK authorization header"
	);

	Ok(())
}

#[cfg(test)]
mod selector_tests {
	use super::*;

	#[test]
	fn validates_selector() {
		assert!(selector_is_valid(
			"request.body.max_tokens <= backend.metadata.max_tokens"
		));
		assert!(!selector_is_valid("request.body.max_tokens"));
	}

	#[test]
	fn parses_comparison_ops() {
		let parsed = parse_comparison_expr("request.body.a >= backend.metadata.b").unwrap();
		assert_eq!(parsed.1, ">=");
		assert_eq!(parsed.0, "request.body.a");
		assert_eq!(parsed.2, "backend.metadata.b");
	}

	#[test]
	fn evaluates_max_tokens_selector() {
		// Simulate a request body with max_tokens
		let body = ParsedRequestBody {
			json: serde_json::json!({"max_tokens": 20000}),
		};

		// Low-VRAM backend (8K max_tokens)
		let mut low_vram = RouteBackendReference {
			weight: 1,
			backend: BackendReference::Invalid,
			inline_policies: vec![],
			metadata: std::collections::HashMap::new(),
		};
		low_vram.metadata.insert("max_tokens".into(), serde_json::json!(8192));

		// High-VRAM backend (32K max_tokens)
		let mut high_vram = RouteBackendReference {
			weight: 1,
			backend: BackendReference::Invalid,
			inline_policies: vec![],
			metadata: std::collections::HashMap::new(),
		};
		high_vram.metadata.insert("max_tokens".into(), serde_json::json!(32768));

		let selector = "request.body.max_tokens <= backend.metadata.max_tokens";

		// Request with 20K tokens should NOT match 8K backend
		assert!(!evaluate_selector(&selector.into(), Some(&body), &low_vram));

		// Request with 20K tokens SHOULD match 32K backend
		assert!(evaluate_selector(&selector.into(), Some(&body), &high_vram));
	}

	#[test]
	fn context_window_routing_integration() {
		use std::collections::HashMap;

		// Create backends with different max_tokens capabilities
		let mut backends = vec![];

		// Low-VRAM backend (4K max)
		let mut backend_4k = RouteBackendReference {
			weight: 100,
			backend: BackendReference::Invalid,
			inline_policies: vec![],
			metadata: HashMap::new(),
		};
		backend_4k.metadata.insert("max_tokens".into(), serde_json::json!(4096));
		backends.push(backend_4k);

		// Mid-VRAM backend (32K max)
		let mut backend_32k = RouteBackendReference {
			weight: 100,
			backend: BackendReference::Invalid,
			inline_policies: vec![],
			metadata: HashMap::new(),
		};
		backend_32k.metadata.insert("max_tokens".into(), serde_json::json!(32768));
		backends.push(backend_32k);

		let selector = "request.body.max_tokens <= backend.metadata.max_tokens";

		// Test 1: Request with 20K tokens
		let body_20k = ParsedRequestBody {
			json: serde_json::json!({"max_tokens": 20000}),
		};

		let filtered_20k: Vec<_> = backends
			.iter()
			.filter(|b| evaluate_selector(&selector.into(), Some(&body_20k), b))
			.collect();

		// Should only match 32K backend (4K backend can't handle 20K)
		assert_eq!(filtered_20k.len(), 1);
		assert_eq!(
			filtered_20k[0].metadata.get("max_tokens"),
			Some(&serde_json::json!(32768))
		);

		// Test 2: Request with 2K tokens
		let body_2k = ParsedRequestBody {
			json: serde_json::json!({"max_tokens": 2000}),
		};

		let filtered_2k: Vec<_> = backends
			.iter()
			.filter(|b| evaluate_selector(&selector.into(), Some(&body_2k), b))
			.collect();

		// Should match BOTH backends (both can handle 2K)
		assert_eq!(filtered_2k.len(), 2);
	}
}

/// Phase 5 Regression Tests: Selector-first BYOK routing
///
/// These tests verify that:
/// 1. Model selector is applied BEFORE BYOK/project filtering
/// 2. A request for model X NEVER routes to model Y
/// 3. BYOK routing operates only on selector-matched backends
/// 4. Mesh fallback respects model selector
///
/// Run with:
/// ```
/// cargo test --lib proxy::httpproxy::selector_byok_tests
/// ```
#[cfg(test)]
mod selector_byok_tests {
	use super::*;
	use crate::http::jwt::Claims;
	use crate::types::agent::{PathMatch, RouteMatch};
	use prometheus_client::registry::Registry;
	use secrecy::SecretString;
	use serde_json::{Map, json};
	use std::collections::HashMap;

	/// Helper to create a backend with model/provider/project metadata
	fn make_backend(
		name: &str,
		model: &str,
		provider: &str,
		project_id: Option<&str>,
	) -> RouteBackendReference {
		let mut metadata = HashMap::new();
		metadata.insert("model".into(), json!(model));
		metadata.insert("provider".into(), json!(provider));
		if let Some(pid) = project_id {
			metadata.insert("project_id".into(), json!(pid));
		}
		RouteBackendReference {
			weight: 1,
			backend: BackendReference::Backend(name.into()),
			inline_policies: vec![],
			metadata,
		}
	}

	/// Helper to create a route with model-matching selector
	fn make_route_with_model_selector(backends: Vec<RouteBackendReference>) -> Route {
		Route {
			key: "test-model-pin".into(),
			route_name: "00-llm-chat-completions-model-pin".into(),
			hostnames: Default::default(),
			rule_name: None,
			matches: vec![RouteMatch {
				headers: vec![],
				path: PathMatch::PathPrefix("/v1/chat/completions".into()),
				method: None,
				query: vec![],
				selector: Some("request.body.model == backend.metadata.model".into()),
			}],
			inline_policies: vec![],
			backends,
		}
	}

	/// Helper to create a request with model in body and optional JWT project_id
	fn make_request_with_model_and_project(
		model: &str,
		project_id: Option<&str>,
	) -> Request {
		let mut req = ::http::Request::builder()
			.uri("/v1/chat/completions")
			.method("POST")
			.body(http::Body::empty())
			.unwrap();

		// Add parsed body with model
		let parsed = ParsedRequestBody {
			json: json!({"model": model, "messages": []}),
		};
		req.extensions_mut().insert(parsed);

		// Add JWT claims if project_id provided
		if let Some(pid) = project_id {
			let mut inner = Map::new();
			inner.insert("project_id".to_string(), json!(pid));
			req.extensions_mut().insert(Claims {
				inner,
				jwt: SecretString::new("test.jwt.token".into()),
			});
		}

		req
	}

	/// Helper to create test metrics
	fn test_metrics() -> Arc<Metrics> {
		Arc::new(Metrics::new(
			&mut Registry::default(),
			Default::default(),
		))
	}

	/// Test: Model selector filters backends BEFORE BYOK routing is considered
	///
	/// Scenario: Request for qwen3-32b with project_a that has BYOK for gpt-4o
	/// Expected: Route to local qwen3-32b, NOT gpt-4o BYOK
	#[test]
	fn test_select_backend_prefers_model_matched_local_over_byok() {
		let backends = vec![
			make_backend("qwen3-32b_local", "qwen3-32b", "local_mesh", None),
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("qwen3-32b", Some("project_a"));
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		assert!(result.is_some(), "Should select a backend");
		let backend = result.unwrap();
		// Must be qwen3-32b, NOT gpt-4o despite project_a having BYOK
		assert_eq!(
			backend.metadata.get("model"),
			Some(&json!("qwen3-32b")),
			"Must route to model-matched backend, not BYOK for different model"
		);
		assert_eq!(
			backend.metadata.get("provider"),
			Some(&json!("local_mesh")),
			"Must be local mesh backend"
		);
	}

	/// Test: Request for model X with only model Y available returns None (503)
	///
	/// Scenario: Request for qwen3-32b, only gpt-4o BYOK available
	/// Expected: None (503 error), NOT route to gpt-4o
	#[test]
	fn test_select_backend_does_not_route_to_different_model() {
		let backends = vec![
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("qwen3-32b", Some("project_a"));
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		// Must be None (503), NOT gpt-4o
		assert!(
			result.is_none(),
			"Must return None when no backend matches requested model"
		);
	}

	/// Test: When same model has both local and BYOK, BYOK is preferred for matching project
	///
	/// Scenario: Request for gpt-4o with project_a that has BYOK for gpt-4o
	/// Expected: Route to BYOK gpt-4o (project match)
	#[test]
	fn test_select_backend_prefers_byok_when_same_model_and_project() {
		let backends = vec![
			make_backend("gpt-4o_local", "gpt-4o", "local_mesh", None),
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("gpt-4o", Some("project_a"));
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		assert!(result.is_some(), "Should select a backend");
		let backend = result.unwrap();
		// Should use BYOK since project matches and same model
		assert_eq!(
			backend.metadata.get("model"),
			Some(&json!("gpt-4o")),
			"Must be gpt-4o model"
		);
		assert_eq!(
			backend.metadata.get("provider"),
			Some(&json!("openai_byok")),
			"Should prefer BYOK backend when project matches"
		);
	}

	/// Test: When BYOK exists but project doesn't match, fall back to mesh
	///
	/// Scenario: Request for gpt-4o with project_b, BYOK exists for project_a only
	/// Expected: Route to local mesh gpt-4o
	#[test]
	fn test_select_backend_falls_back_to_mesh_when_byok_project_mismatch() {
		let backends = vec![
			make_backend("gpt-4o_local", "gpt-4o", "local_mesh", None),
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("gpt-4o", Some("project_b")); // wrong project
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		assert!(result.is_some(), "Should fall back to mesh backend");
		let backend = result.unwrap();
		// Should fallback to local mesh, NOT BYOK with wrong project
		assert_eq!(
			backend.metadata.get("model"),
			Some(&json!("gpt-4o")),
			"Must be gpt-4o model"
		);
		assert_eq!(
			backend.metadata.get("provider"),
			Some(&json!("local_mesh")),
			"Should fall back to mesh when BYOK project doesn't match"
		);
	}

	/// Test: When only BYOK exists for a model and project doesn't match, return None
	///
	/// Scenario: Request for gpt-4o with project_b, only BYOK for project_a
	/// Expected: None (503 error) - no mesh fallback available
	#[test]
	fn test_select_backend_returns_none_when_only_byok_wrong_project() {
		let backends = vec![
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("gpt-4o", Some("project_b")); // wrong project
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		// No mesh fallback, wrong project for BYOK
		assert!(
			result.is_none(),
			"Must return None when only BYOK exists and project doesn't match"
		);
	}

	/// Test: Request without project_id only uses mesh backends
	///
	/// Scenario: Request for gpt-4o with no JWT/project_id
	/// Expected: Route to mesh backend only, ignore BYOK
	#[test]
	fn test_select_backend_uses_mesh_only_when_no_project() {
		let backends = vec![
			make_backend("gpt-4o_local", "gpt-4o", "local_mesh", None),
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("gpt-4o", None); // no project
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		assert!(result.is_some(), "Should select mesh backend");
		let backend = result.unwrap();
		assert_eq!(
			backend.metadata.get("provider"),
			Some(&json!("local_mesh")),
			"Must use mesh backend when no project_id"
		);
	}

	/// Test: Mixed scenario - multiple models, multiple providers
	///
	/// Scenario: 3 backends (qwen local, gpt-4o local, gpt-4o BYOK), request qwen
	/// Expected: Route to qwen local only
	#[test]
	fn test_select_backend_complex_mixed_scenario() {
		let backends = vec![
			make_backend("qwen3-32b_local", "qwen3-32b", "local_mesh", None),
			make_backend("gpt-4o_local", "gpt-4o", "local_mesh", None),
			make_backend("gpt-4o_byok", "gpt-4o", "openai_byok", Some("project_a")),
		];
		let route = make_route_with_model_selector(backends);
		let req = make_request_with_model_and_project("qwen3-32b", Some("project_a"));
		let metrics = test_metrics();

		let result = select_backend(&route, &req, &metrics);

		assert!(result.is_some(), "Should select qwen backend");
		let backend = result.unwrap();
		// Must be qwen, not gpt-4o (even though project_a has BYOK for gpt-4o)
		assert_eq!(
			backend.metadata.get("model"),
			Some(&json!("qwen3-32b")),
			"Must route to requested model only"
		);
	}
}
