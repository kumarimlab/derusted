# Contributing to Derusted

Thank you for your interest in contributing to Derusted! We welcome contributions from the community.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
- [Development Guidelines](#development-guidelines)
  - [Code Style](#code-style)
  - [Testing Requirements](#testing-requirements)
  - [Security Guidelines](#security-guidelines)
- [Project Structure](#project-structure)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. All contributors are expected to:

- Be respectful and considerate
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Respect differing viewpoints and experiences
- Accept responsibility for mistakes and learn from them

---

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub with:

1. **Clear title** - Describe the issue concisely
2. **Steps to reproduce** - Detailed steps to trigger the bug
3. **Expected behavior** - What you expected to happen
4. **Actual behavior** - What actually happened
5. **Environment** - OS, Rust version, Derusted version
6. **Logs/Screenshots** - Any relevant error messages or logs

**Security vulnerabilities**: Please report security issues privately to kumar.imlab@outlook.com instead of opening a public issue.

### Suggesting Features

Feature requests are welcome! Please open an issue with:

1. **Use case** - Explain the problem you're trying to solve
2. **Proposed solution** - Describe your suggested feature
3. **Alternatives** - Any alternative solutions you've considered
4. **Additional context** - Examples, mockups, or related issues

### Submitting Pull Requests

1. **Fork the repository** and create a branch from `main`
2. **Make your changes** following our development guidelines
3. **Add tests** for new functionality
4. **Ensure all tests pass** (`cargo test --all`)
5. **Run linters** (`cargo clippy --all-targets -- -D warnings`)
6. **Format code** (`cargo fmt --all`)
7. **Write a clear commit message** explaining your changes
8. **Open a pull request** with a detailed description

---

## Development Setup

### Prerequisites

- **Rust 1.70+** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - For version control
- **cargo-audit** (optional) - For security scanning: `cargo install cargo-audit`

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/your-org/derusted.git
cd derusted

# Build the project
cargo build

# Run tests
cargo test --all

# Run all quality checks
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit  # if cargo-audit is installed
```

### Environment Setup (Optional)

For testing CA key management features:

```bash
# Generate test CA certificate
openssl genrsa -out test-ca-key.pem 4096
openssl req -new -x509 -days 365 \
  -key test-ca-key.pem \
  -out test-ca-cert.pem \
  -subj "/C=US/ST=CA/L=SF/O=Test/OU=IT/CN=Test CA"

# Set environment variables
export CA_CERT=$(cat test-ca-cert.pem)
export CA_KEY=$(cat test-ca-key.pem)
```

---

## Development Guidelines

### Code Style

Derusted follows standard Rust formatting and conventions:

- **Use `cargo fmt`** - All code must be formatted with rustfmt
- **Follow Rust naming conventions**:
  - `snake_case` for functions, variables, modules
  - `CamelCase` for types, traits, structs
  - `SCREAMING_SNAKE_CASE` for constants
- **Write clear comments** - Explain "why", not "what"
- **Document public APIs** - All public items must have doc comments

### Testing Requirements

All code contributions must include appropriate tests:

#### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_name() {
        // Arrange
        let input = "test data";

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected_output);
    }
}
```

#### Integration Tests

Place integration tests in `tests/` directory:

```rust
// tests/integration_test.rs
use derusted::mitm::CertificateAuthority;

#[tokio::test]
async fn test_certificate_generation() {
    // Test realistic usage scenarios
}
```

#### Test Coverage Goals

- **New features**: Must have >80% test coverage
- **Bug fixes**: Must include a regression test
- **Refactoring**: Existing tests must continue to pass

### Security Guidelines

Derusted is security-focused software. When contributing:

#### DO:
- ✅ Use memory-safe Rust patterns (avoid `unsafe` unless absolutely necessary)
- ✅ Validate all external inputs (hostnames, headers, bodies)
- ✅ Follow the principle of least privilege
- ✅ Redact sensitive data in logs (use existing `logging.rs` patterns)
- ✅ Handle errors gracefully without exposing sensitive information
- ✅ Test for edge cases and error conditions

#### DON'T:
- ❌ Log CA private keys or other secrets
- ❌ Trust user input without validation
- ❌ Use deprecated or insecure cryptographic primitives
- ❌ Introduce timing attacks (especially in crypto operations)
- ❌ Use unwrap() or expect() in production code (handle errors properly)

#### Example: Secure Logging

```rust
// ❌ BAD: Logs sensitive data
error!("Failed to load CA key: {}", ca_key_content);

// ✅ GOOD: Logs error without exposing secrets
error!("Failed to load CA key from environment variable");
```

---

## Project Structure

```
derusted/
├── src/
│   ├── lib.rs                      # Public API exports
│   ├── mitm/
│   │   ├── ca_key_manager.rs       # CA key management
│   │   ├── certificate_authority.rs # Certificate generation + caching
│   │   ├── interceptor.rs          # MITM decision engine
│   │   ├── tls_config.rs           # TLS configuration
│   │   ├── logging.rs              # PII redaction
│   │   ├── log_storage.rs          # SQLite storage
│   │   ├── bypass.rs               # Smart bypass system
│   │   ├── pinning.rs              # Pinning detection
│   │   ├── http_parser.rs          # HTTP/1.1 parsing
│   │   ├── http2_mitm.rs           # HTTP/2 MITM
│   │   └── error.rs                # Error types
│   ├── connection_pool.rs          # Connection pooling
│   ├── destination_filter.rs       # SSRF protection
│   └── ...
│
├── docs/
│   ├── SECURITY_AUDIT.md           # Security audit report
│   ├── THREAT_MODEL.md             # Threat analysis
│   ├── CA_ROTATION.md              # Rotation procedures
│   └── CI_CD_NOTE.md               # CI/CD decision
│
├── tests/                          # Integration tests
├── Cargo.toml                      # Dependencies
├── README.md                       # Project documentation
├── CHANGELOG.md                    # Version history
└── CONTRIBUTING.md                 # This file
```

### Key Modules

- **`mitm/`** - Core MITM functionality (certificate generation, TLS, interception)
- **`connection_pool.rs`** - Upstream connection pooling for HTTP/1.1
- **`destination_filter.rs`** - SSRF protection (private IP blocking)

---

## Pull Request Process

### Before Submitting

1. **Create an issue first** (for non-trivial changes) to discuss the approach
2. **Branch naming**:
   - Features: `feature/description` (e.g., `feature/add-mtls-support`)
   - Bugs: `fix/description` (e.g., `fix/certificate-cache-leak`)
   - Docs: `docs/description` (e.g., `docs/update-readme`)

### Pull Request Checklist

Before submitting your PR, ensure:

- [ ] Code compiles without warnings (`RUSTFLAGS="-D warnings" cargo check --all-targets`)
- [ ] All tests pass (`cargo test --all`)
- [ ] Clippy lints pass (`cargo clippy --all-targets -- -D warnings`)
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] New tests added for new functionality
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Security implications considered and documented

### PR Description Template

```markdown
## Summary
Brief description of the change

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- List of changes made
- Each change on a new line

## Testing
How was this tested? Include:
- Manual testing steps
- Automated test coverage
- Performance impact (if applicable)

## Security Considerations
- Any security implications?
- New attack surface introduced?
- PII handling changes?

## Related Issues
Closes #123
```

### Review Process

1. **Automated checks** - CI runs tests, lints, and security scans
2. **Maintainer review** - At least one maintainer approval required
3. **Changes requested** - Address feedback and push updates
4. **Approval** - Maintainer merges PR

---

## Community

### Communication Channels

- **Issues**: https://github.com/your-org/derusted/issues
- **Discussions**: https://github.com/your-org/derusted/discussions
- **Security**: kumar.imlab@outlook.com (private)

### Getting Help

- Check existing issues and discussions
- Read the documentation in `docs/` and `README.md`
- Ask questions in GitHub Discussions

### Recognition

Contributors will be recognized in:
- Release notes (CHANGELOG.md)
- README.md contributors section (future)

---

## License

By contributing to Derusted, you agree that your contributions will be licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for full details.

---

## Questions?

If you have questions about contributing, feel free to:
- Open an issue with the "question" label
- Start a discussion on GitHub Discussions

Thank you for contributing to Derusted!

---

**Last Updated**: November 25, 2025
