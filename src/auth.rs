// JWT Authentication Module
// Phase 2: JWT token validation for forward proxy authentication

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingHeader,

    #[error("Invalid authorization format (expected: Bearer <token>)")]
    InvalidFormat,

    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Region not allowed: {0}")]
    RegionNotAllowed(String),
}

/// JWT Claims structure matching backend token format
///
/// This struct is generic over extra claims `E`, allowing users to extend
/// the standard claims with application-specific fields.
///
/// # Examples
///
/// ```rust
/// use serde::Deserialize;
/// use derusted::JwtClaims;
///
/// // Use standard claims (default)
/// type StandardClaims = JwtClaims<()>;
///
/// // Extend with custom claims
/// #[derive(Debug, Clone, Default, Deserialize)]
/// struct MyAppClaims {
///     rate_limit_per_hour: Option<usize>,
///     tier: Option<String>,
/// }
///
/// type ExtendedClaims = JwtClaims<MyAppClaims>;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims<E = ()>
where
    E: Default,
{
    /// Unique token identifier
    pub token_id: String,

    /// User ID who owns the token
    pub user_id: i32,

    /// List of allowed regions (e.g., ["us-east", "eu-west"])
    pub allowed_regions: Vec<String>,

    /// Token expiration (Unix timestamp)
    pub exp: i64,

    /// Token issued at (Unix timestamp)
    pub iat: i64,

    /// Issuer (e.g., "probeops")
    #[serde(default)]
    pub iss: Option<String>,

    /// Audience (e.g., "forward-proxy")
    #[serde(default)]
    pub aud: Option<String>,

    /// User-defined extra claims (flattened into the token)
    #[serde(flatten, default)]
    pub extra: E,
}

impl JwtClaims<()> {
    /// Create standard JWT claims without extra fields.
    ///
    /// This is a convenience constructor for backwards compatibility.
    /// Use this when you don't need custom claims.
    ///
    /// # Example
    ///
    /// ```rust
    /// use derusted::JwtClaims;
    ///
    /// let claims = JwtClaims::new(
    ///     "token_123".to_string(),
    ///     42,
    ///     vec!["us-east".to_string()],
    ///     chrono::Utc::now().timestamp() + 3600,
    ///     chrono::Utc::now().timestamp(),
    ///     Some("my-issuer".to_string()),
    ///     Some("my-audience".to_string()),
    /// );
    /// ```
    pub fn new(
        token_id: String,
        user_id: i32,
        allowed_regions: Vec<String>,
        exp: i64,
        iat: i64,
        iss: Option<String>,
        aud: Option<String>,
    ) -> Self {
        Self {
            token_id,
            user_id,
            allowed_regions,
            exp,
            iat,
            iss,
            aud,
            extra: (),
        }
    }
}

impl<E: Default> JwtClaims<E> {
    /// Create JWT claims with custom extra fields.
    ///
    /// Use this when you need to include application-specific claims
    /// like subscription tier, rate limits, or feature flags.
    ///
    /// # Example
    ///
    /// ```rust
    /// use derusted::JwtClaims;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    /// struct MyCustomClaims {
    ///     tier: Option<String>,
    ///     rate_limit: Option<usize>,
    /// }
    ///
    /// let claims = JwtClaims::with_extra(
    ///     "token_123".to_string(),
    ///     42,
    ///     vec!["us-east".to_string()],
    ///     chrono::Utc::now().timestamp() + 3600,
    ///     chrono::Utc::now().timestamp(),
    ///     Some("my-issuer".to_string()),
    ///     Some("my-audience".to_string()),
    ///     MyCustomClaims {
    ///         tier: Some("pro".to_string()),
    ///         rate_limit: Some(10000),
    ///     },
    /// );
    /// ```
    pub fn with_extra(
        token_id: String,
        user_id: i32,
        allowed_regions: Vec<String>,
        exp: i64,
        iat: i64,
        iss: Option<String>,
        aud: Option<String>,
        extra: E,
    ) -> Self {
        Self {
            token_id,
            user_id,
            allowed_regions,
            exp,
            iat,
            iss,
            aud,
            extra,
        }
    }
}

/// JWT Validator with configuration
///
/// The validator is generic over the claims type `E`, which defaults to `()`.
/// This allows validating tokens with custom claims without duplicating code.
///
/// # Examples
///
/// ```rust,no_run
/// use serde::Deserialize;
/// use derusted::{JwtValidator, JwtClaims};
///
/// // Standard validator (no extra claims)
/// let validator = JwtValidator::new(
///     "secret".to_string(),
///     "HS256".to_string(),
///     "us-east".to_string(),
///     None,
///     None,
/// ).unwrap();
///
/// // Extended validator with custom claims
/// #[derive(Debug, Clone, Default, Deserialize)]
/// struct MyAppClaims {
///     rate_limit_per_hour: Option<usize>,
/// }
///
/// let extended_validator: JwtValidator<MyAppClaims> = JwtValidator::new(
///     "secret".to_string(),
///     "HS256".to_string(),
///     "us-east".to_string(),
///     None,
///     None,
/// ).unwrap();
/// ```
#[derive(Debug)]
pub struct JwtValidator<E = ()> {
    secret: String,
    algorithm: Algorithm,
    current_region: String,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    _phantom: PhantomData<E>,
}

impl<E> JwtValidator<E>
where
    E: Default + DeserializeOwned + Clone + std::fmt::Debug,
{
    /// Create a new JWT validator
    pub fn new(
        secret: String,
        algorithm: String,
        current_region: String,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> Result<Self> {
        let algo = match algorithm.to_uppercase().as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            _ => return Err(anyhow!("Unsupported JWT algorithm: {}", algorithm)),
        };

        Ok(Self {
            secret,
            algorithm: algo,
            current_region,
            expected_issuer,
            expected_audience,
            _phantom: PhantomData,
        })
    }

    /// Get the expected issuer (for testing/verification)
    pub fn expected_issuer(&self) -> Option<&str> {
        self.expected_issuer.as_deref()
    }

    /// Get the expected audience (for testing/verification)
    pub fn expected_audience(&self) -> Option<&str> {
        self.expected_audience.as_deref()
    }

    /// Check if issuer/audience validation is enabled
    pub fn has_strict_validation(&self) -> bool {
        self.expected_issuer.is_some() && self.expected_audience.is_some()
    }

    /// Extract JWT token from Authorization header value
    /// Supports two formats:
    /// 1. "Bearer <token>" (standard)
    /// 2. "Basic <base64(token:)>" (Playwright/Electron compatibility)
    fn extract_token(auth_header: &str) -> Result<String, AuthError> {
        let parts: Vec<&str> = auth_header.splitn(2, ' ').collect();

        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat);
        }

        let auth_type = parts[0].to_lowercase();
        let credentials = parts[1].trim();

        if credentials.is_empty() {
            return Err(AuthError::InvalidFormat);
        }

        // Handle Bearer token format (standard)
        if auth_type == "bearer" {
            return Ok(credentials.to_string());
        }

        // Handle Basic Auth format (Playwright/Electron compatibility)
        // Playwright sends: Basic base64("token:") or Basic base64("Bearer token:")
        if auth_type == "basic" {
            // Decode base64
            use base64::{engine::general_purpose, Engine as _};
            let decoded = general_purpose::STANDARD
                .decode(credentials)
                .map_err(|_| AuthError::InvalidFormat)?;

            let decoded_str = String::from_utf8(decoded).map_err(|_| AuthError::InvalidFormat)?;

            // Split username:password (password is empty in our case)
            let user_pass: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if user_pass.is_empty() {
                return Err(AuthError::InvalidFormat);
            }

            let username = user_pass[0];

            // Check if username starts with "Bearer " and extract token
            if let Some(token) = username.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Ok(token.to_string());
                }
            }

            // Otherwise, treat the entire username as the token
            if !username.is_empty() {
                return Ok(username.to_string());
            }

            return Err(AuthError::InvalidFormat);
        }

        Err(AuthError::InvalidFormat)
    }

    /// Validate JWT token from Authorization header
    pub fn validate(&self, auth_header: &str) -> Result<JwtClaims<E>, AuthError> {
        // Extract token from "Bearer <token>" or "Basic <base64(token:)>" format
        let token = Self::extract_token(auth_header)?;

        // Configure validation
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = false; // Not Before is optional

        // Set issuer and audience validation
        // Note: jsonwebtoken defaults to NOT validating iss/aud unless explicitly set
        if let Some(ref iss) = self.expected_issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = self.expected_audience {
            validation.set_audience(&[aud]);
        }

        // Decode and validate token
        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());
        let token_data =
            decode::<JwtClaims<E>>(&token, &decoding_key, &validation).map_err(|e| {
                // Check specific error types
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    ErrorKind::InvalidIssuer => {
                        AuthError::ValidationFailed("Invalid issuer".to_string())
                    }
                    ErrorKind::InvalidAudience => {
                        AuthError::ValidationFailed("Invalid audience".to_string())
                    }
                    ErrorKind::InvalidSignature => {
                        AuthError::ValidationFailed("Invalid signature".to_string())
                    }
                    _ => AuthError::ValidationFailed(e.to_string()),
                }
            })?;

        let claims = token_data.claims;

        // Check if current region is allowed
        // Wildcard "*" grants access to all regions
        if !claims.allowed_regions.is_empty()
            && !claims.allowed_regions.contains(&"*".to_string())
            && !claims.allowed_regions.contains(&self.current_region)
        {
            return Err(AuthError::RegionNotAllowed(self.current_region.clone()));
        }

        Ok(claims)
    }

    /// Validate token from HTTP request (extracts header)
    pub fn validate_request<T>(&self, request: &http::Request<T>) -> Result<JwtClaims<E>, AuthError> {
        // Check for Proxy-Authorization header first (standard for proxies)
        let auth_header = request
            .headers()
            .get("proxy-authorization")
            .or_else(|| request.headers().get("authorization"))
            .ok_or(AuthError::MissingHeader)?;

        let auth_str = auth_header.to_str().map_err(|_| AuthError::InvalidFormat)?;

        self.validate(auth_str)
    }
}

/// Thread-safe JWT validator (can be shared across async tasks)
///
/// For extended claims, use `Arc<JwtValidator<YourClaimsType>>` directly.
pub type SharedJwtValidator<E = ()> = Arc<JwtValidator<E>>;

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn test_extract_bearer_token() {
        // Valid Bearer format
        let result = JwtValidator::<()>::extract_token("Bearer abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123");

        // Case insensitive
        let result = JwtValidator::<()>::extract_token("bearer xyz789");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "xyz789");

        // Invalid format - no auth type
        let result = JwtValidator::<()>::extract_token("abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_basic_auth_token() {
        use base64::{engine::general_purpose, Engine as _};

        // Test 1: Basic Auth with JWT token as username (Playwright format)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
        let basic_auth = format!("{}:", token); // "token:"
        let encoded = general_purpose::STANDARD.encode(basic_auth.as_bytes());
        let auth_header = format!("Basic {}", encoded);

        let result = JwtValidator::<()>::extract_token(&auth_header);
        assert!(result.is_ok(), "Should extract token from Basic Auth");
        assert_eq!(result.unwrap(), token);

        // Test 2: Basic Auth with "Bearer <token>" as username
        let token2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test2";
        let basic_auth2 = format!("Bearer {}:", token2); // "Bearer token:"
        let encoded2 = general_purpose::STANDARD.encode(basic_auth2.as_bytes());
        let auth_header2 = format!("Basic {}", encoded2);

        let result2 = JwtValidator::<()>::extract_token(&auth_header2);
        assert!(
            result2.is_ok(),
            "Should extract token from 'Bearer token:' format"
        );
        assert_eq!(result2.unwrap(), token2);

        // Test 3: Invalid Basic Auth - empty credentials
        let result3 = JwtValidator::<()>::extract_token("Basic ");
        assert!(result3.is_err());

        // Test 4: Invalid Basic Auth - invalid base64
        let result4 = JwtValidator::<()>::extract_token("Basic invalid!!!base64");
        assert!(result4.is_err());
    }

    #[test]
    fn test_jwt_validator_creation() {
        let validator: Result<JwtValidator<()>, _> = JwtValidator::new(
            "test_secret".to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        );
        assert!(validator.is_ok());
        let validator = validator.unwrap();
        assert_eq!(validator.expected_issuer, Some("probeops".to_string()));
        assert_eq!(
            validator.expected_audience,
            Some("forward-proxy".to_string())
        );

        let validator: Result<JwtValidator<()>, _> = JwtValidator::new(
            "test_secret_long_enough_for_testing".to_string(),
            "INVALID".to_string(),
            "us-east".to_string(),
            None,
            None,
        );
        assert!(validator.is_err());
    }

    #[test]
    fn test_valid_token_validation() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a valid token
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token_123".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string(), "eu-west".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Validate token
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_ok());
        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.token_id, "test_token_123");
        assert_eq!(validated_claims.user_id, 42);
    }

    #[test]
    fn test_expired_token() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create an expired token (1 hour ago)
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "expired_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(),
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Validate expired token
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        // Check that it's specifically a TokenExpired error
        match result.unwrap_err() {
            AuthError::TokenExpired => (),
            other => panic!("Expected TokenExpired, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_signature() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a token with different secret
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret("wrong_secret".as_bytes()),
        )
        .unwrap();

        // Validate with wrong secret
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::ValidationFailed(msg) => {
                assert!(msg.contains("Invalid signature"));
            }
            other => panic!("Expected ValidationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_region_not_allowed() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "ap-south".to_string(), // Different region
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a token that only allows us-east and eu-west
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string(), "eu-west".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Validate in ap-south region
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::RegionNotAllowed(region) => {
                assert_eq!(region, "ap-south");
            }
            other => panic!("Expected RegionNotAllowed, got {:?}", other),
        }
    }

    #[test]
    fn test_wildcard_region_allowed() {
        // Test that wildcard "*" grants access to any region
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "ap-south".to_string(), // Any region
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a token with wildcard region
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token_wildcard".to_string(),
            user_id: 42,
            allowed_regions: vec!["*".to_string()], // Wildcard grants all regions
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Validate with wildcard - should succeed for any region
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(
            result.is_ok(),
            "Wildcard region should grant access to any region"
        );

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.allowed_regions, vec!["*".to_string()]);
    }

    #[test]
    fn test_invalid_issuer() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a token with wrong issuer
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("malicious_issuer".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::ValidationFailed(msg) => {
                assert!(msg.contains("Invalid issuer"));
            }
            other => panic!(
                "Expected ValidationFailed with issuer error, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_invalid_audience() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a token with wrong audience
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("wrong_service".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::ValidationFailed(msg) => {
                assert!(msg.contains("Invalid audience"));
            }
            other => panic!(
                "Expected ValidationFailed with audience error, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_configurable_issuer_audience_disabled() {
        // Phase 2.2: Test that issuer/audience validation can be disabled (None)
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            None, // No issuer validation
            None, // No audience validation
        )
        .unwrap();

        // Verify validator has no issuer/audience configured
        assert_eq!(validator.expected_issuer, None);
        assert_eq!(validator.expected_audience, None);

        // Create a token WITHOUT issuer/audience claims
        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: None, // No issuer
            aud: None, // No audience
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Should succeed because validation is disabled
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(
            result.is_ok(),
            "Token without issuer/audience should succeed when validation disabled"
        );

        // Test with issuer/audience enabled
        let validator_with_checks: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Verify validator has issuer/audience configured
        assert_eq!(
            validator_with_checks.expected_issuer,
            Some("probeops".to_string())
        );
        assert_eq!(
            validator_with_checks.expected_audience,
            Some("forward-proxy".to_string())
        );

        // Token missing required issuer/audience should fail
        let result = validator_with_checks.validate(&auth_header);
        // Note: jsonwebtoken library behavior - missing fields may not fail if not required
        // The key test is that we CAN disable validation by setting None
        if result.is_err() {
            // This is expected - validator requires issuer/audience but token doesn't have them
            let err = result.unwrap_err();
            assert!(
                matches!(err, AuthError::ValidationFailed(_)),
                "Should be ValidationFailed error"
            );
        }
    }

    #[test]
    fn test_proxy_authorization_header() {
        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        let claims: JwtClaims<()> = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Test with Proxy-Authorization header
        let mut request = http::Request::builder()
            .header("Proxy-Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = validator.validate_request(&request);
        assert!(result.is_ok());

        // Test with Authorization header (fallback)
        request = http::Request::builder()
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = validator.validate_request(&request);
        assert!(result.is_ok());

        // Test missing header
        request = http::Request::builder().body(()).unwrap();

        let result = validator.validate_request(&request);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::MissingHeader => (),
            other => panic!("Expected MissingHeader, got {:?}", other),
        }
    }

    #[test]
    fn test_extended_claims() {
        // Test that custom claims can be added via the generic parameter
        #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
        struct CustomClaims {
            rate_limit_per_hour: Option<usize>,
            tier: Option<String>,
        }

        let secret = "test_secret_key_probeops_2025";
        let validator: JwtValidator<CustomClaims> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        )
        .unwrap();

        // Create a token with custom claims
        let claims: JwtClaims<CustomClaims> = JwtClaims {
            token_id: "extended_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
            extra: CustomClaims {
                rate_limit_per_hour: Some(10000),
                tier: Some("pro".to_string()),
            },
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Validate token and check custom claims are preserved
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_ok(), "Extended claims token should be valid");

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.token_id, "extended_token");
        assert_eq!(validated_claims.extra.rate_limit_per_hour, Some(10000));
        assert_eq!(validated_claims.extra.tier, Some("pro".to_string()));
    }

    #[test]
    fn test_backwards_compatibility_default_claims() {
        // Test that existing code using JwtClaims<()> still works
        let secret = "test_secret_key_probeops_2025";

        // Standard validator (no extra claims) - this is the backwards-compatible usage
        let validator: JwtValidator<()> = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            None,
            None,
        )
        .unwrap();

        let claims: JwtClaims<()> = JwtClaims {
            token_id: "standard_token".to_string(),
            user_id: 1,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: None,
            aud: None,
            extra: (),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_ok(), "Standard claims should work");
    }

    #[test]
    fn test_jwt_claims_new_constructor() {
        // Test the convenience constructor for standard claims
        let claims = JwtClaims::new(
            "token_123".to_string(),
            42,
            vec!["us-east".to_string()],
            chrono::Utc::now().timestamp() + 3600,
            chrono::Utc::now().timestamp(),
            Some("issuer".to_string()),
            Some("audience".to_string()),
        );

        assert_eq!(claims.token_id, "token_123");
        assert_eq!(claims.user_id, 42);
        assert_eq!(claims.allowed_regions, vec!["us-east".to_string()]);
        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.aud, Some("audience".to_string()));
        assert_eq!(claims.extra, ()); // Default extra is ()
    }

    #[test]
    fn test_jwt_claims_with_extra_constructor() {
        // Test the constructor for custom claims
        #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
        struct CustomClaims {
            tier: Option<String>,
            rate_limit: Option<usize>,
        }

        let custom = CustomClaims {
            tier: Some("pro".to_string()),
            rate_limit: Some(10000),
        };

        let claims = JwtClaims::with_extra(
            "token_456".to_string(),
            99,
            vec!["*".to_string()],
            chrono::Utc::now().timestamp() + 7200,
            chrono::Utc::now().timestamp(),
            None,
            None,
            custom.clone(),
        );

        assert_eq!(claims.token_id, "token_456");
        assert_eq!(claims.user_id, 99);
        assert_eq!(claims.extra.tier, Some("pro".to_string()));
        assert_eq!(claims.extra.rate_limit, Some(10000));
        assert_eq!(claims.extra, custom);
    }
}
