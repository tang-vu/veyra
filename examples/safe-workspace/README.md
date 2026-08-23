# Safe workspace demo

This example represents a small agent request to create `demo/hello.txt` inside the named `default`
workspace. [`principal.json`](principal.json) and [`intent.json`](intent.json) are valid protocol
documents. [`policy.example.json`](policy.example.json) explains the narrow capability policy the
real demo issues dynamically after a transaction ID exists.

From the repository root, execute the complete real flow without credentials:

```sh
cargo run --locked -p veyra-cli -- demo --json
```

To preserve all audit and recovery evidence:

```sh
cargo run --locked -p veyra-cli -- demo --directory ./safe-workspace-run --json
```

Then start a daemon against that preserved state:

```sh
cargo run --locked -p veyra-server -- \
  --data-directory ./safe-workspace-run/data \
  --workspace ./safe-workspace-run/workspace
```

In a second terminal, verify its audit chain:

```sh
cargo run --locked -p veyra-cli -- \
  --token-file ./safe-workspace-run/data/api-token \
  --api-url http://127.0.0.1:7843/v1/ \
  audit verify --json
```

The demo itself performs plan, preflight, capability evaluation, content-addressed approval,
execution, SHA-256 verification, receipt/audit inspection, and rollback.

For manual intent submission, start the daemon, register `principal.json`, and submit `intent.json`.
It will correctly stop at denial until a registered human issues a live capability. Use generated IDs
and short current timestamps when adapting `policy.example.json`; do not copy long-lived example
authority into production.
