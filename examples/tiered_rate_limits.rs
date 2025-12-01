//! Tiered Rate Limiting Example
//!
//! This example demonstrates how to use derusted's dynamic rate limit override
//! feature to implement tiered rate limiting based on user subscription level.
//!
//! # Use Case
//!
//! SaaS applications often have tiered pricing with different rate limits:
//! - Free tier: 100 requests/minute
//! - Pro tier: 10,000 requests/minute
//! - Enterprise tier: 100,000 requests/minute
//!
//! Instead of running separate rate limiter instances, you can use a single
//! `RateLimiter` with dynamic overrides based on JWT claims.
//!
//! # Running this example
//!
//! ```bash
//! cargo run --example tiered_rate_limits
//! ```

use derusted::{JwtClaims, JwtValidator, RateLimiter, RateLimiterConfig};
use std::sync::Arc;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

/// Custom claims with rate limit information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TieredClaims {
    /// User's subscription tier
    #[serde(default)]
    tier: Option<String>,

    /// Custom rate limit (requests per minute) - if set, overrides tier default
    #[serde(default)]
    rate_limit_per_minute: Option<usize>,
}

/// Get rate limit based on tier
fn get_tier_rate_limit(tier: Option<&str>) -> usize {
    match tier {
        Some("enterprise") => 100_000,
        Some("pro") => 10_000,
        Some("free") | None => 100,
        Some(other) => {
            eprintln!("Unknown tier '{}', using free tier limit", other);
            100
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize rate limiter with conservative defaults (free tier)
    let config = RateLimiterConfig {
        requests_per_minute: 100,    // Default for free tier
        burst_size: 20,              // Allow small bursts
        bucket_ttl_seconds: 3600,    // 1 hour TTL
        max_buckets: 100_000,        // Support many concurrent users
    };

    let rate_limiter = Arc::new(RateLimiter::new(config));

    // JWT setup
    let secret = "your-256-bit-secret-key-here-min-32-chars";
    let validator: JwtValidator<TieredClaims> = JwtValidator::new(
        secret.to_string(),
        "HS256".to_string(),
        "us-east".to_string(),
        None,
        None,
    )?;

    // === Simulate different user tiers ===

    // Free tier user
    let free_user = create_token(secret, "free_user_1", "free", None)?;

    // Pro tier user
    let pro_user = create_token(secret, "pro_user_1", "pro", None)?;

    // Enterprise tier user
    let enterprise_user = create_token(secret, "enterprise_user_1", "enterprise", None)?;

    // Custom limit user (VIP with negotiated rate)
    let vip_user = create_token(secret, "vip_user_1", "enterprise", Some(500_000))?;

    println!("=== Tiered Rate Limiting Demo ===\n");

    // Process requests for each user type
    for (name, token, expected_limit) in [
        ("Free User", &free_user, 100),
        ("Pro User", &pro_user, 10_000),
        ("Enterprise User", &enterprise_user, 100_000),
        ("VIP User (custom)", &vip_user, 500_000),
    ] {
        println!("--- {} ---", name);

        // Validate token and extract claims
        let claims = validator.validate(&format!("Bearer {}", token))?;

        // Determine effective rate limit
        let effective_limit = claims
            .extra
            .rate_limit_per_minute
            .unwrap_or_else(|| get_tier_rate_limit(claims.extra.tier.as_deref()));

        println!("Token ID: {}", claims.token_id);
        println!("Tier: {:?}", claims.extra.tier);
        println!("Custom limit: {:?}", claims.extra.rate_limit_per_minute);
        println!("Effective limit: {} req/min", effective_limit);
        assert_eq!(effective_limit, expected_limit);

        // Make requests using dynamic rate limit
        let mut success_count = 0;
        let mut fail_count = 0;

        // Try to make burst_size + 1 requests (should hit limit on last one)
        for i in 0..21 {
            let result = rate_limiter
                .check_limit_with_override(&claims.token_id, Some(effective_limit))
                .await;

            match result {
                Ok(()) => success_count += 1,
                Err(_) => {
                    fail_count += 1;
                    if i == 20 {
                        println!("Request {} rate limited (expected after burst)", i + 1);
                    }
                }
            }
        }

        println!("Successful requests: {}", success_count);
        println!("Rate limited: {}", fail_count);
        println!();
    }

    // === Demonstrate concurrent users ===
    println!("=== Concurrent Users Demo ===\n");

    // Create multiple users of each tier
    let users: Vec<(&str, String)> = vec![
        ("free_a", create_token(secret, "free_a", "free", None)?),
        ("free_b", create_token(secret, "free_b", "free", None)?),
        ("pro_a", create_token(secret, "pro_a", "pro", None)?),
        ("enterprise_a", create_token(secret, "enterprise_a", "enterprise", None)?),
    ];

    // Process requests concurrently
    let mut handles = vec![];

    for (name, token) in users {
        let rate_limiter = Arc::clone(&rate_limiter);
        let validator_secret = secret.to_string();
        let name = name.to_string();
        let token = token.clone();

        let handle = tokio::spawn(async move {
            // Create a new validator in the async block (validators are cheap to create)
            let validator: JwtValidator<TieredClaims> = JwtValidator::new(
                validator_secret,
                "HS256".to_string(),
                "us-east".to_string(),
                None,
                None,
            )
            .unwrap();

            let claims = validator.validate(&format!("Bearer {}", token)).unwrap();
            let limit = get_tier_rate_limit(claims.extra.tier.as_deref());

            let mut success = 0;
            for _ in 0..10 {
                if rate_limiter
                    .check_limit_with_override(&claims.token_id, Some(limit))
                    .await
                    .is_ok()
                {
                    success += 1;
                }
            }
            (name, success)
        });

        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        let (name, success) = handle.await?;
        println!("{}: {} successful requests", name, success);
    }

    // === Show rate limiter stats ===
    println!("\n=== Rate Limiter Stats ===");
    let stats = rate_limiter.get_stats().await;
    println!("Active token buckets: {}", stats.active_tokens);
    println!("Max buckets: {}", stats.max_tokens);
    println!("Default requests/min: {}", stats.requests_per_minute);
    println!("Burst size: {}", stats.burst_size);

    Ok(())
}

/// Helper to create JWT tokens for testing
fn create_token(
    secret: &str,
    token_id: &str,
    tier: &str,
    custom_limit: Option<usize>,
) -> Result<String, Box<dyn std::error::Error>> {
    let claims: JwtClaims<TieredClaims> = JwtClaims {
        token_id: token_id.to_string(),
        user_id: 1,
        allowed_regions: vec!["us-east".to_string()],
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        iss: None,
        aud: None,
        extra: TieredClaims {
            tier: Some(tier.to_string()),
            rate_limit_per_minute: custom_limit,
        },
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok(token)
}
