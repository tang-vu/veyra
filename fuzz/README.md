# Veyra fuzzing

These libFuzzer targets exercise two security-sensitive pure boundaries without network, persistent
state, credentials, or production data:

- `canonical_protocol` checks canonical JSON stability, digest encoding, and arbitrary JSON input;
- `resource_scope` checks component-aware filesystem and HTTP containment plus exact process and
  generic scopes.

Install the same pinned tools used by CI, then run either target from the repository root:

```sh
rustup toolchain install nightly-2026-08-20 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-08-20 fuzz run canonical_protocol -- -max_total_time=60 -max_len=4096 -rss_limit_mb=2048
cargo +nightly-2026-08-20 fuzz run resource_scope -- -max_total_time=60 -max_len=4096 -rss_limit_mb=2048
```

Pull requests and `main` receive a bounded smoke run; the weekly schedule spends five minutes on
each target. Local corpora, coverage data, and crash artifacts are intentionally ignored. If a crash
may cross a Veyra trust boundary, preserve it privately and follow [`SECURITY.md`](../SECURITY.md)
before opening a public issue or pull request.
