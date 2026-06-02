#!/bin/bash
# SessionStart hook for Claude Code on the web: warm the Rust workspace so
# `cargo test` / `cargo clippy` run without a cold dependency fetch+build.
# Idempotent and non-interactive. Runs only in the remote (web) environment.
set -euo pipefail

# Only run in Claude Code on the web; local sessions already have their toolchain.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

# Ensure rustfmt + clippy are present (no-ops if already installed).
rustup component add rustfmt clippy >/dev/null 2>&1 || true

# Fetch dependencies and pre-build the workspace (cached in the container image).
cargo fetch
cargo build --workspace --tests
