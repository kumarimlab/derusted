# Bypass System Documentation

## Overview

The bypass system allows you to exclude specific domains from MITM interception. This is a **framework**, not a policy - you decide what to bypass based on your needs.

## Configuration Files

See `config/` directory for examples:
- `bypass.example.yaml` - Comprehensive example with comments
- `bypass.minimal.yaml` - Minimal conservative configuration
- `bypass.corporate.yaml` - Corporate environment example

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DERUSTED_BYPASS_ENABLED` | bool | `true` | Enable/disable bypass system |
| `DERUSTED_BYPASS_ALLOW_DYNAMIC` | bool | `false` | Allow automatic bypass on pinning |
| `DERUSTED_BYPASS_CONFIG` | path | - | Path to config file |
| `DERUSTED_BYPASS_INCLUDE_EXAMPLES` | bool | `false` | Load 60+ example rules |
| `DERUSTED_BYPASS_ALERT_ENABLED` | bool | `true` | Enable alerts on bypass |

## Quick Start

```rust
use derusted::BypassManager;

// From file
let manager = BypassManager::from_file("config/bypass.yaml")?;

// From environment variables
let manager = BypassManager::from_env();

// Check if should bypass
if let Some(reason) = manager.should_bypass("example.com").await {
    // Tunnel without inspection
} else {
    // Perform MITM
}
```

For full documentation, see examples in `config/` directory.
