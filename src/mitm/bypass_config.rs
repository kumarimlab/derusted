//! Bypass Configuration - File-based and environment-based configuration
//!
//! This module provides flexible configuration for the bypass system:
//! - YAML configuration files
//! - Environment variable overrides
//! - Programmatic API for library users
//! - Feature flags for enable/disable

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

use super::BypassReason;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileReadError(String),

    #[error("Failed to parse config: {0}")]
    ParseError(String),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

/// Bypass system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassConfig {
    /// Enable bypass system entirely
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Allow dynamic bypass on certificate pinning detection
    #[serde(default = "default_allow_dynamic")]
    pub allow_dynamic: bool,

    /// Static bypass rules (user-provided)
    #[serde(default)]
    pub static_rules: Vec<StaticBypassRule>,

    /// Dynamic bypass settings
    #[serde(default)]
    pub dynamic: DynamicBypassConfig,

    /// Alert settings
    #[serde(default)]
    pub alerts: AlertConfig,

    /// Load example rules (opt-in)
    #[serde(default = "default_false")]
    pub include_example_rules: bool,
}

impl Default for BypassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_dynamic: false, // Conservative default
            static_rules: Vec::new(),
            dynamic: DynamicBypassConfig::default(),
            alerts: AlertConfig::default(),
            include_example_rules: false,
        }
    }
}

impl BypassConfig {
    /// Load configuration from YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::FileReadError(e.to_string()))?;

        let config: Self =
            serde_yaml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // DERUSTED_BYPASS_ENABLED
        if let Ok(val) = std::env::var("DERUSTED_BYPASS_ENABLED") {
            config.enabled = val.parse().unwrap_or(true);
        }

        // DERUSTED_BYPASS_ALLOW_DYNAMIC
        if let Ok(val) = std::env::var("DERUSTED_BYPASS_ALLOW_DYNAMIC") {
            config.allow_dynamic = val.parse().unwrap_or(false);
        }

        // DERUSTED_BYPASS_CONFIG - path to config file
        if let Ok(path) = std::env::var("DERUSTED_BYPASS_CONFIG") {
            if let Ok(file_config) = Self::from_file(&path) {
                // File config takes precedence, but env vars override
                let enabled = config.enabled;
                let allow_dynamic = config.allow_dynamic;

                config = file_config;

                // Apply env var overrides
                if std::env::var("DERUSTED_BYPASS_ENABLED").is_ok() {
                    config.enabled = enabled;
                }
                if std::env::var("DERUSTED_BYPASS_ALLOW_DYNAMIC").is_ok() {
                    config.allow_dynamic = allow_dynamic;
                }
            }
        }

        // DERUSTED_BYPASS_INCLUDE_EXAMPLES
        if let Ok(val) = std::env::var("DERUSTED_BYPASS_INCLUDE_EXAMPLES") {
            config.include_example_rules = val.parse().unwrap_or(false);
        }

        // DERUSTED_BYPASS_ALERT_ENABLED
        if let Ok(val) = std::env::var("DERUSTED_BYPASS_ALERT_ENABLED") {
            config.alerts.enabled = val.parse().unwrap_or(true);
        }

        config
    }

    /// Merge with another config (other takes precedence)
    pub fn merge(&mut self, other: BypassConfig) {
        self.enabled = other.enabled;
        self.allow_dynamic = other.allow_dynamic;
        self.static_rules.extend(other.static_rules);
        self.dynamic = other.dynamic;
        self.alerts = other.alerts;
    }

    /// Validate configuration
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate static rules
        for rule in &self.static_rules {
            if rule.pattern.is_empty() {
                return Err(ConfigError::ValidationError(
                    "Empty bypass pattern not allowed".to_string(),
                ));
            }
        }

        // Validate TTL
        if self.dynamic.default_ttl == 0 {
            return Err(ConfigError::ValidationError(
                "Dynamic TTL must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

/// Static bypass rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticBypassRule {
    /// Domain pattern (exact or wildcard with *)
    pub pattern: String,

    /// Reason for bypass
    #[serde(default = "default_reason")]
    pub reason: String,

    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
}

impl StaticBypassRule {
    pub fn reason_enum(&self) -> BypassReason {
        match self.reason.to_lowercase().as_str() {
            "certificatepinning" => BypassReason::CertificatePinning,
            "localhost" => BypassReason::Localhost,
            "hstspolicy" => BypassReason::HstsPolicy,
            "emergency" => BypassReason::Emergency,
            _ => BypassReason::UserConfigured,
        }
    }
}

/// Dynamic bypass configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicBypassConfig {
    /// Default TTL for dynamic rules (seconds)
    #[serde(default = "default_ttl")]
    pub default_ttl: u64,

    /// Maximum number of dynamic rules
    #[serde(default = "default_max_dynamic_rules")]
    pub max_rules: usize,

    /// Cleanup interval (seconds)
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval: u64,
}

impl Default for DynamicBypassConfig {
    fn default() -> Self {
        Self {
            default_ttl: 3600, // 1 hour
            max_rules: 1000,
            cleanup_interval: 300, // 5 minutes
        }
    }
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerts on bypass events
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Alert on static rule matches
    #[serde(default = "default_true")]
    pub alert_on_static: bool,

    /// Alert on dynamic rule additions
    #[serde(default = "default_true")]
    pub alert_on_dynamic: bool,

    /// Alert on certificate pinning detection
    #[serde(default = "default_true")]
    pub alert_on_pinning: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            alert_on_static: true,
            alert_on_dynamic: true,
            alert_on_pinning: true,
        }
    }
}

/// Example bypass rules (opt-in)
pub struct ExampleBypassRules;

impl ExampleBypassRules {
    /// Get example rules for common scenarios
    pub fn all() -> Vec<StaticBypassRule> {
        let mut rules = Vec::new();
        rules.extend(Self::microsoft_office365());
        rules.extend(Self::banking_finance());
        rules.extend(Self::cloud_providers());
        rules.extend(Self::auth_services());
        rules.extend(Self::apple_google());
        rules.extend(Self::government());
        rules
    }

    /// Microsoft Office 365 services
    pub fn microsoft_office365() -> Vec<StaticBypassRule> {
        vec![
            StaticBypassRule {
                pattern: "*.office.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Microsoft Office Online".to_string()),
            },
            StaticBypassRule {
                pattern: "*.office365.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Office 365 services".to_string()),
            },
            StaticBypassRule {
                pattern: "*.microsoftonline.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Microsoft Online services".to_string()),
            },
            StaticBypassRule {
                pattern: "*.sharepoint.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("SharePoint Online".to_string()),
            },
        ]
    }

    /// Banking and financial services
    pub fn banking_finance() -> Vec<StaticBypassRule> {
        vec![
            StaticBypassRule {
                pattern: "*.chase.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Chase Bank".to_string()),
            },
            StaticBypassRule {
                pattern: "*.bankofamerica.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Bank of America".to_string()),
            },
            StaticBypassRule {
                pattern: "*.wellsfargo.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Wells Fargo".to_string()),
            },
            StaticBypassRule {
                pattern: "*.citibank.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Citibank".to_string()),
            },
        ]
    }

    /// Cloud provider admin consoles
    pub fn cloud_providers() -> Vec<StaticBypassRule> {
        vec![
            StaticBypassRule {
                pattern: "console.aws.amazon.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("AWS Console".to_string()),
            },
            StaticBypassRule {
                pattern: "console.cloud.google.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Google Cloud Console".to_string()),
            },
            StaticBypassRule {
                pattern: "portal.azure.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Azure Portal".to_string()),
            },
        ]
    }

    /// Authentication services
    pub fn auth_services() -> Vec<StaticBypassRule> {
        vec![
            StaticBypassRule {
                pattern: "*.okta.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Okta SSO".to_string()),
            },
            StaticBypassRule {
                pattern: "*.auth0.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Auth0".to_string()),
            },
            StaticBypassRule {
                pattern: "*.duo.com".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("Duo Security".to_string()),
            },
        ]
    }

    /// Apple and Google services (certificate pinning)
    pub fn apple_google() -> Vec<StaticBypassRule> {
        vec![
            StaticBypassRule {
                pattern: "*.apple.com".to_string(),
                reason: "CertificatePinning".to_string(),
                description: Some("Apple services (pinned)".to_string()),
            },
            StaticBypassRule {
                pattern: "*.icloud.com".to_string(),
                reason: "CertificatePinning".to_string(),
                description: Some("iCloud (pinned)".to_string()),
            },
            StaticBypassRule {
                pattern: "accounts.google.com".to_string(),
                reason: "CertificatePinning".to_string(),
                description: Some("Google Accounts (pinned)".to_string()),
            },
        ]
    }

    /// Government sites
    pub fn government() -> Vec<StaticBypassRule> {
        vec![
            StaticBypassRule {
                pattern: "*.gov".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("US Government sites".to_string()),
            },
            StaticBypassRule {
                pattern: "*.mil".to_string(),
                reason: "UserConfigured".to_string(),
                description: Some("US Military sites".to_string()),
            },
        ]
    }
}

// Default value functions for serde
fn default_enabled() -> bool {
    true
}
fn default_allow_dynamic() -> bool {
    false
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_reason() -> String {
    "UserConfigured".to_string()
}
fn default_ttl() -> u64 {
    3600
}
fn default_max_dynamic_rules() -> usize {
    1000
}
fn default_cleanup_interval() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BypassConfig::default();
        assert!(config.enabled);
        assert!(!config.allow_dynamic); // Conservative default
        assert_eq!(config.static_rules.len(), 0);
    }

    #[test]
    fn test_example_rules_count() {
        let all_rules = ExampleBypassRules::all();
        assert!(
            all_rules.len() >= 19,
            "Should have at least 19 example rules"
        );
        assert_eq!(
            all_rules.len(),
            19,
            "Expected exactly 19 example rules (4+4+3+3+3+2)"
        );
    }

    #[test]
    fn test_config_validation() {
        let mut config = BypassConfig::default();
        config.static_rules.push(StaticBypassRule {
            pattern: "".to_string(),
            reason: "UserConfigured".to_string(),
            description: None,
        });

        assert!(
            config.validate().is_err(),
            "Empty pattern should fail validation"
        );
    }

    #[test]
    fn test_reason_enum_conversion() {
        let rule = StaticBypassRule {
            pattern: "test.com".to_string(),
            reason: "CertificatePinning".to_string(),
            description: None,
        };

        assert_eq!(rule.reason_enum(), BypassReason::CertificatePinning);
    }
}
