//! Custom JWT Claims Example
//!
//! This example demonstrates how to extend derusted's JWT claims with
//! application-specific fields for tiered authentication and authorization.
//!
//! # Use Case
//!
//! SaaS applications often need to encode additional information in JWT tokens:
//! - User subscription tier (free, pro, enterprise)
//! - Custom rate limits per user
//! - Feature flags or permissions
//! - Organization/tenant information
//!
//! # Running this example
//!
//! ```bash
//! cargo run --example custom_auth
//! ```

use derusted::{JwtClaims, JwtValidator};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

/// Custom claims for a SaaS application with tiered pricing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SaasCustomClaims {
    /// Subscription tier: "free", "pro", "enterprise"
    #[serde(default)]
    tier: Option<String>,

    /// Custom rate limit override (requests per hour)
    #[serde(default)]
    rate_limit_per_hour: Option<usize>,

    /// Maximum concurrent connections allowed
    #[serde(default)]
    max_concurrent: Option<usize>,

    /// Organization ID for multi-tenant applications
    #[serde(default)]
    org_id: Option<String>,

    /// Feature flags enabled for this user
    #[serde(default)]
    features: Vec<String>,
}

/// Type alias for our extended claims
type ExtendedClaims = JwtClaims<SaasCustomClaims>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Secret key (in production, load from environment)
    let secret = "your-256-bit-secret-key-here-min-32-chars";

    // Create a validator for extended claims
    let validator: JwtValidator<SaasCustomClaims> = JwtValidator::new(
        secret.to_string(),
        "HS256".to_string(),
        "us-east".to_string(),
        Some("my-saas-app".to_string()),
        Some("proxy-service".to_string()),
    )?;

    // === Example 1: Free tier user ===
    let free_user_claims: ExtendedClaims = JwtClaims {
        token_id: "free_user_token_123".to_string(),
        user_id: 1001,
        allowed_regions: vec!["us-east".to_string()],
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        iss: Some("my-saas-app".to_string()),
        aud: Some("proxy-service".to_string()),
        extra: SaasCustomClaims {
            tier: Some("free".to_string()),
            rate_limit_per_hour: Some(100), // Free tier: 100 requests/hour
            max_concurrent: Some(1),
            org_id: None,
            features: vec![],
        },
    };

    let free_token = encode(
        &Header::default(),
        &free_user_claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    println!("=== Free Tier User ===");
    println!("Token: {}...", &free_token[..50]);

    // Validate and extract claims
    let validated = validator.validate(&format!("Bearer {}", free_token))?;
    println!("User ID: {}", validated.user_id);
    println!("Tier: {:?}", validated.extra.tier);
    println!("Rate Limit: {:?} req/hour", validated.extra.rate_limit_per_hour);
    println!("Max Concurrent: {:?}", validated.extra.max_concurrent);
    println!();

    // === Example 2: Pro tier user ===
    let pro_user_claims: ExtendedClaims = JwtClaims {
        token_id: "pro_user_token_456".to_string(),
        user_id: 2001,
        allowed_regions: vec!["*".to_string()], // Pro users get all regions
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        iss: Some("my-saas-app".to_string()),
        aud: Some("proxy-service".to_string()),
        extra: SaasCustomClaims {
            tier: Some("pro".to_string()),
            rate_limit_per_hour: Some(10000), // Pro tier: 10,000 requests/hour
            max_concurrent: Some(10),
            org_id: None,
            features: vec!["advanced_routing".to_string(), "custom_headers".to_string()],
        },
    };

    let pro_token = encode(
        &Header::default(),
        &pro_user_claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    println!("=== Pro Tier User ===");
    println!("Token: {}...", &pro_token[..50]);

    let validated = validator.validate(&format!("Bearer {}", pro_token))?;
    println!("User ID: {}", validated.user_id);
    println!("Tier: {:?}", validated.extra.tier);
    println!("Rate Limit: {:?} req/hour", validated.extra.rate_limit_per_hour);
    println!("Features: {:?}", validated.extra.features);
    println!();

    // === Example 3: Enterprise user with org ===
    let enterprise_claims: ExtendedClaims = JwtClaims {
        token_id: "enterprise_token_789".to_string(),
        user_id: 3001,
        allowed_regions: vec!["*".to_string()],
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        iss: Some("my-saas-app".to_string()),
        aud: Some("proxy-service".to_string()),
        extra: SaasCustomClaims {
            tier: Some("enterprise".to_string()),
            rate_limit_per_hour: Some(100000), // Enterprise: 100,000 requests/hour
            max_concurrent: Some(100),
            org_id: Some("acme-corp".to_string()),
            features: vec![
                "advanced_routing".to_string(),
                "custom_headers".to_string(),
                "dedicated_ips".to_string(),
                "sla_guarantee".to_string(),
            ],
        },
    };

    let enterprise_token = encode(
        &Header::default(),
        &enterprise_claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    println!("=== Enterprise User ===");
    println!("Token: {}...", &enterprise_token[..50]);

    let validated = validator.validate(&format!("Bearer {}", enterprise_token))?;
    println!("User ID: {}", validated.user_id);
    println!("Tier: {:?}", validated.extra.tier);
    println!("Organization: {:?}", validated.extra.org_id);
    println!("Rate Limit: {:?} req/hour", validated.extra.rate_limit_per_hour);
    println!("Max Concurrent: {:?}", validated.extra.max_concurrent);
    println!("Features: {:?}", validated.extra.features);

    // === Demonstrate using claims for authorization ===
    println!("\n=== Authorization Example ===");

    fn check_feature_access(claims: &ExtendedClaims, feature: &str) -> bool {
        claims.extra.features.contains(&feature.to_string())
    }

    fn get_effective_rate_limit(claims: &ExtendedClaims, default: usize) -> usize {
        claims.extra.rate_limit_per_hour.unwrap_or(default)
    }

    let claims = validator.validate(&format!("Bearer {}", enterprise_token))?;

    if check_feature_access(&claims, "dedicated_ips") {
        println!("User has access to dedicated IPs feature");
    }

    let rate_limit = get_effective_rate_limit(&claims, 100);
    println!("Effective rate limit: {} req/hour", rate_limit);

    Ok(())
}
