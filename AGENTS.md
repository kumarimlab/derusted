# Repository Guidelines

## Project Structure & Module Organization
The core crate sits in `src/`: `server.rs`, `config.rs`, `mixed_content.rs`, and `mitm/*` implement proxy orchestration, while helper modules cover auth, rate limiting, upstream HTTP clients, and metrics. Integration suites reside in `tests/` (`integration_tests.rs`, `security_tests.rs`, `h1_connect_load.rs`, `h2_connect_load.rs`). The runnable sample lives in `examples/proxy_server.rs`, reusable configs in `config/`, CA installers in `scripts/`, and extended reference material inside `docs/` plus the untracked `pdocs/` notes.

## Build, Test, and Development Commands
- `cargo build` / `cargo build --release`: debug or optimized builds.
- `cargo check`: fast validation before reviews.
- `cargo fmt` then `cargo clippy --all-features --all-targets -- -D warnings`: enforce style and lints.
- `cargo test --workspace`, or `cargo test --test integration_tests` / `security_tests` / `http_end_to_end_tests` for targeted suites.
- `cargo run --example proxy_server` for manual proxy runs; `cargo run --release --bin h2_connect_load` or `h1_connect_load` for throughput harnesses.

## Coding Style & Naming Conventions
Use Rust’s default 4-space indentation and let `rustfmt` shape files. Keep modules and files in `snake_case`, public types/traits in `PascalCase`, and config constants (`PROXY_HOST`, etc.) in `SCREAMING_SNAKE_CASE`. Maintain rustdoc comments and `tracing` spans on exported APIs, prefer `Result<T, Error>` returns, and re-export only intentional entry points from `lib.rs`.

## Testing Guidelines
Pair new behavior with unit tests near the source file and integration coverage when it crosses network, TLS, or auth boundaries. Run `cargo test --workspace` before pushing; list any selective commands in the PR. For HTTP/2 Extended CONNECT, follow `tests/README.md`: boot the proxy with the documented TLS env vars, then run `cargo test --test h2_client_harness -- --nocapture`. Exercise `h*_connect_load.rs` when performance characteristics may shift.

## Commit & Pull Request Guidelines
Work on `feature/<scope>` or `fix/<scope>` branches. Commit messages stay imperative (e.g., “Add CA certificate generation with rcgen”), never reference AI tooling, and must not include `CLAUDE.md`, `pdocs/`, or generated certs. Before opening a PR, confirm `cargo fmt`, `cargo clippy -- -D warnings`, and relevant tests pass, then describe motivation, config toggles, and test evidence (logs, load numbers, or screenshots) plus link any tracking issue.

## Security & Configuration Tips
Use `.env.template` to seed runtime settings such as `PROXY_HOST`, `JWT_SECRET`, and `MIXED_CONTENT_POLICY`, and keep real dotenvs outside the repo. Copy `config/bypass.*.yaml` when defining new policies rather than modifying the samples. The CA helper scripts in `scripts/install-ca-*.sh` simplify local trust; run them locally but never commit resulting keys or certificates, and call out any operator-facing change in `docs/` or your PR notes.
