use std::str::FromStr;

use ::http::{HeaderValue, Method, StatusCode, header};
use serde::de::Error;

use crate::http::{PolicyResponse, Request, filters};
use crate::*;

#[derive(Default, Debug, Clone)]
enum WildcardOrList<T> {
	#[default]
	None,
	Wildcard,
	List(Vec<T>),
}

impl<T> WildcardOrList<T> {
	fn is_none(&self) -> bool {
		matches!(self, WildcardOrList::None)
	}
}

impl<T: FromStr> TryFrom<Vec<String>> for WildcardOrList<T> {
	type Error = T::Err;

	fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
		if value.contains(&"*".to_string()) {
			Ok(WildcardOrList::Wildcard)
		} else if value.is_empty() {
			Ok(WildcardOrList::None)
		} else {
			let vec: Vec<T> = value
				.into_iter()
				.map(|v| T::from_str(&v))
				.collect::<Result<_, _>>()?;
			Ok(WildcardOrList::List(vec))
		}
	}
}

impl<T: Display> Serialize for WildcardOrList<T> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		match self {
			WildcardOrList::None => Vec::<String>::new().serialize(serializer),
			WildcardOrList::Wildcard => vec!["*"].serialize(serializer),
			WildcardOrList::List(list) => list
				.iter()
				.map(ToString::to_string)
				.collect::<Vec<_>>()
				.serialize(serializer),
		}
	}
}

impl<T> WildcardOrList<T>
where
	T: ToString,
{
	fn to_header_value(&self) -> Option<::http::HeaderValue> {
		match self {
			WildcardOrList::None => None,
			WildcardOrList::Wildcard => Some(::http::HeaderValue::from_static("*")),
			WildcardOrList::List(list) => {
				let value = list
					.iter()
					.map(|item| item.to_string())
					.collect::<Vec<_>>()
					.join(",");

				::http::HeaderValue::from_str(&value).ok()
			},
		}
	}
}

#[apply(schema_ser!)]
#[cfg_attr(feature = "schema", schemars(with = "CorsSerde"))]
pub struct Cors {
	allow_credentials: bool,
	#[serde(skip_serializing_if = "WildcardOrList::is_none")]
	allow_headers: WildcardOrList<http::HeaderName>,
	#[serde(skip_serializing_if = "WildcardOrList::is_none")]
	allow_methods: WildcardOrList<::http::Method>,
	#[serde(skip_serializing_if = "WildcardOrList::is_none")]
	allow_origins: WildcardOrList<Strng>,
	#[serde(skip_serializing_if = "WildcardOrList::is_none")]
	expose_headers: WildcardOrList<http::HeaderName>,
	#[serde(serialize_with = "ser_string_or_bytes_option")]
	max_age: Option<::http::HeaderValue>,
}

impl<'de> serde::Deserialize<'de> for Cors {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Cors::try_from(CorsSerde::deserialize(deserializer)?).map_err(D::Error::custom)
	}
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct CorsSerde {
	#[serde(default)]
	pub allow_credentials: bool,
	#[serde(default)]
	pub allow_headers: Vec<String>,
	#[serde(default)]
	pub allow_methods: Vec<String>,
	#[serde(default)]
	pub allow_origins: Vec<String>,
	#[serde(default)]
	pub expose_headers: Vec<String>,
	#[serde(default, with = "serde_dur_option")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub max_age: Option<Duration>,
}

impl TryFrom<CorsSerde> for Cors {
	type Error = anyhow::Error;
	fn try_from(value: CorsSerde) -> Result<Self, Self::Error> {
		Ok(Cors {
			allow_credentials: value.allow_credentials,
			allow_headers: WildcardOrList::try_from(value.allow_headers)?,
			allow_methods: WildcardOrList::try_from(value.allow_methods)?,
			allow_origins: WildcardOrList::try_from(value.allow_origins)?,
			expose_headers: WildcardOrList::try_from(value.expose_headers)?,
			max_age: value
				.max_age
				.map(|v| http::HeaderValue::from_str(&v.as_secs().to_string()))
				.transpose()?,
		})
	}
}

impl Cors {
	/// Apply applies the CORS header. It seems a lot of implementations handle this differently wrt when
	/// to add or not add headers, and when to forward the request.
	/// We follow Envoy semantics here (with forwardNotMatchingPreflights=true)
	pub fn apply(&self, req: &mut Request) -> Result<PolicyResponse, filters::Error> {
		// If no origin, return immediately
		let Some(origin) = req.headers().get(header::ORIGIN) else {
			return Ok(Default::default());
		};

		let allowed = match &self.allow_origins {
			WildcardOrList::None => false,
			WildcardOrList::Wildcard => true,
			WildcardOrList::List(origins) => {
				// Convert origin header to string for matching
				let origin_str = match std::str::from_utf8(origin.as_bytes()) {
					Ok(s) => s,
					Err(_) => return Ok(Default::default()), // Invalid UTF-8, reject
				};

				origins.iter().any(|want| {
					let want_str = want.as_str();

					// Exact match
					if want_str == origin_str {
						return true;
					}

					// Wildcard match: https://*.example.com matches https://dev.example.com
					if want_str.contains('*') {
						// Convert wildcard pattern to regex
						// Example: https://*.example.com → ^https://.*\.example\.com$
						let pattern = format!(
							"^{}$",
							want_str
								.replace('.', r"\.")
								.replace('*', ".*")
						);

						if let Ok(re) = regex::Regex::new(&pattern) {
							return re.is_match(origin_str);
						}
					}

					false
				})
			},
		};
		if !allowed {
			// None matching origin, return
			return Ok(Default::default());
		}

		if req.method() == Method::OPTIONS {
			// Handle preflight request
			let mut rb = ::http::Response::builder()
				.status(StatusCode::OK)
				.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
			if let Some(h) = self.allow_methods.to_header_value() {
				rb = rb.header(header::ACCESS_CONTROL_ALLOW_METHODS, h);
			}
			if let Some(h) = self.allow_headers.to_header_value() {
				rb = rb.header(header::ACCESS_CONTROL_ALLOW_HEADERS, h);
			}
			if let Some(h) = &self.max_age {
				rb = rb.header(header::ACCESS_CONTROL_MAX_AGE, h);
			}
			let response = rb.body(crate::http::Body::empty())?;
			return Ok(PolicyResponse {
				direct_response: Some(response),
				response_headers: None,
			});
		}

		let mut response_headers = http::HeaderMap::with_capacity(3);
		response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
		if self.allow_credentials {
			response_headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HEADER_VALUE_TRUE);
		}
		if let Some(h) = self.expose_headers.to_header_value() {
			response_headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, h);
		}
		// For actual requests, we would need to add CORS headers to the response
		// but since we only have access to the request here, we return None
		Ok(PolicyResponse {
			direct_response: None,
			response_headers: Some(response_headers),
		})
	}
}

const HEADER_VALUE_TRUE: http::HeaderValue = HeaderValue::from_static("true");

#[cfg(test)]
mod tests {
	use super::*;
	use ::http::header;

	/// Helper to create a CORS policy with given allow_origins
	fn create_cors_policy(origins: Vec<&str>) -> Cors {
		CorsSerde {
			allow_credentials: true,
			allow_headers: vec!["Authorization".to_string(), "Content-Type".to_string()],
			allow_methods: vec!["GET".to_string(), "POST".to_string()],
			allow_origins: origins.into_iter().map(|s| s.to_string()).collect(),
			expose_headers: vec![],
			max_age: Some(Duration::from_secs(3600)),
		}
		.try_into()
		.expect("Failed to create CORS policy")
	}

	/// Helper to create a request with Origin header
	fn create_request_with_origin(origin: &str, method: Method) -> Request {
		let mut req = ::http::Request::builder()
			.method(method)
			.uri("/test")
			.body(crate::http::Body::empty())
			.expect("Failed to build request");

		req.headers_mut()
			.insert(header::ORIGIN, origin.parse().expect("Invalid origin header"));

		req.into()
	}

	#[test]
	fn test_exact_origin_match() {
		let cors = create_cors_policy(vec!["https://lexhub.eu"]);
		let mut req = create_request_with_origin("https://lexhub.eu", Method::POST);

		let result = cors.apply(&mut req).expect("CORS apply failed");

		// Should have response headers (not blocking)
		assert!(result.response_headers.is_some());
		assert!(result.direct_response.is_none());

		let headers = result.response_headers.unwrap();
		assert_eq!(
			headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
			"https://lexhub.eu"
		);
	}

	#[test]
	fn test_exact_origin_no_match() {
		let cors = create_cors_policy(vec!["https://lexhub.eu"]);
		let mut req = create_request_with_origin("https://example.com", Method::POST);

		let result = cors.apply(&mut req).expect("CORS apply failed");

		// Should NOT have CORS headers (blocked)
		assert!(result.response_headers.is_none());
		assert!(result.direct_response.is_none());
	}

	#[test]
	fn test_wildcard_subdomain_match() {
		let cors = create_cors_policy(vec!["https://*.lexhub.eu"]);

		// Test various subdomains
		let test_cases = vec![
			"https://dev.lexhub.eu",
			"https://staging.lexhub.eu",
			"https://test.lexhub.eu",
			"https://api.v2.lexhub.eu", // Nested subdomain
		];

		for origin in test_cases {
			let mut req = create_request_with_origin(origin, Method::POST);
			let result = cors.apply(&mut req).expect("CORS apply failed");

			assert!(
				result.response_headers.is_some(),
				"Origin {} should match https://*.lexhub.eu",
				origin
			);

			let headers = result.response_headers.unwrap();
			assert_eq!(
				headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
				origin
			);
		}
	}

	#[test]
	fn test_wildcard_no_apex_match() {
		let cors = create_cors_policy(vec!["https://*.lexhub.eu"]);

		// Wildcard should NOT match apex domain
		let mut req = create_request_with_origin("https://lexhub.eu", Method::POST);
		let result = cors.apply(&mut req).expect("CORS apply failed");

		// Should NOT have CORS headers
		assert!(result.response_headers.is_none());
	}

	#[test]
	fn test_multiple_origins_exact_and_wildcard() {
		let cors = create_cors_policy(vec![
			"https://lexhub.eu",        // Exact apex
			"https://*.lexhub.eu",      // Wildcard subdomains
			"https://example.com",      // Another exact
		]);

		// Test apex match
		let mut req1 = create_request_with_origin("https://lexhub.eu", Method::POST);
		let result1 = cors.apply(&mut req1).expect("CORS apply failed");
		assert!(result1.response_headers.is_some());

		// Test subdomain match
		let mut req2 = create_request_with_origin("https://dev.lexhub.eu", Method::POST);
		let result2 = cors.apply(&mut req2).expect("CORS apply failed");
		assert!(result2.response_headers.is_some());

		// Test other exact match
		let mut req3 = create_request_with_origin("https://example.com", Method::POST);
		let result3 = cors.apply(&mut req3).expect("CORS apply failed");
		assert!(result3.response_headers.is_some());

		// Test non-matching origin
		let mut req4 = create_request_with_origin("https://attacker.com", Method::POST);
		let result4 = cors.apply(&mut req4).expect("CORS apply failed");
		assert!(result4.response_headers.is_none());
	}

	#[test]
	fn test_options_preflight_with_wildcard() {
		let cors = create_cors_policy(vec!["https://*.lexhub.eu"]);
		let mut req = create_request_with_origin("https://dev.lexhub.eu", Method::OPTIONS);

		let result = cors.apply(&mut req).expect("CORS apply failed");

		// Preflight should have direct_response (200 OK)
		assert!(result.direct_response.is_some());
		assert!(result.response_headers.is_none());

		let response = result.direct_response.unwrap();
		assert_eq!(response.status(), StatusCode::OK);

		// Check headers
		assert_eq!(
			response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
			"https://dev.lexhub.eu"
		);
		assert!(response.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS).is_some());
	}

	#[test]
	fn test_invalid_wildcard_pattern() {
		// Test that invalid regex patterns don't crash
		let cors = create_cors_policy(vec!["https://*[invalid.eu"]);

		let mut req = create_request_with_origin("https://dev.invalid.eu", Method::POST);
		let result = cors.apply(&mut req).expect("CORS apply failed");

		// Should not match (invalid regex)
		assert!(result.response_headers.is_none());
	}

	#[test]
	fn test_case_sensitive_origin_matching() {
		let cors = create_cors_policy(vec!["https://lexhub.eu"]);

		// Different case should NOT match (origins are case-sensitive per spec)
		let mut req = create_request_with_origin("https://LexHub.eu", Method::POST);
		let result = cors.apply(&mut req).expect("CORS apply failed");

		// Should NOT match (case mismatch)
		assert!(result.response_headers.is_none());
	}

	#[test]
	fn test_wildcard_only_in_subdomain() {
		let cors = create_cors_policy(vec!["https://*.lexhub.eu"]);

		// Test that wildcard doesn't match different domain
		let test_cases = vec![
			"https://lexhub.com",       // Different TLD
			"https://lexhub.eu.com",    // Extra TLD
			"https://evil-lexhub.eu",   // Different domain
		];

		for origin in test_cases {
			let mut req = create_request_with_origin(origin, Method::POST);
			let result = cors.apply(&mut req).expect("CORS apply failed");

			assert!(
				result.response_headers.is_none(),
				"Origin {} should NOT match https://*.lexhub.eu",
				origin
			);
		}
	}
}
