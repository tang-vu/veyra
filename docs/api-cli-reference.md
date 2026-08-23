# Local API and CLI reference

## Transport and authentication

The standalone server defaults to `http://127.0.0.1:7843/v1/` and refuses a non-loopback listener.
Every route, including health, requires `Authorization: Bearer <token>`. `veyra init` creates the
token at `<data-directory>/api-token`; never pass it in a URL or commit it. Request bodies are limited
to 2 MiB and JSON types reject unknown fields where declared.

That bearer is an administrative root credential, not an end-user session token. Its holder can
register principals, issue/revoke capabilities, and submit an approval using any registered human
principal ID. V0.1 has no separate human-login or agent-token protocol, so keep the bearer inside a
trusted local controller and never expose it to a model or remote browser application.

Errors use:

```json
{ "error": { "code": "invalid_request", "message": "safe diagnostic" } }
```

Expected status classes are `400` malformed input, `401` token failure, `403` insufficient authority,
`404` absent object, `409` state/replay/revision conflict, and `500` trusted-core failure. Clients
must make decisions from status and `code`, not parse message text.

## API endpoints

All paths below are relative to `/v1/`.

| Method | Path                               | Request                                           | Success response                                          |
| ------ | ---------------------------------- | ------------------------------------------------- | --------------------------------------------------------- |
| GET    | `health`                           | —                                                 | API and protocol versions                                 |
| POST   | `principals`                       | `Principal`                                       | registered `Principal` (`201`)                            |
| POST   | `intents`                          | `Intent`                                          | intent, proposed plan, and transaction (`201`)            |
| GET    | `intents/{id}`                     | —                                                 | `Intent`                                                  |
| GET    | `plans/{id}`                       | —                                                 | latest proposed/preflighted `Plan`                        |
| GET    | `transactions`                     | —                                                 | latest `Transaction[]`                                    |
| GET    | `transactions/{id}`                | —                                                 | `Transaction`                                             |
| GET    | `transactions/{id}/bundle`         | —                                                 | causal aggregate for inspection                           |
| POST   | `transactions/{id}/preview`        | empty                                             | preview, policy decisions, approval requests, transaction |
| POST   | `transactions/{id}/run`            | empty                                             | execution/receipt/verification outcome                    |
| POST   | `transactions/{id}/rollback`       | empty                                             | compensation records and resulting transaction            |
| POST   | `approvals/{id}/grant`             | `{ "approver_id": UUID }`                         | grant and transaction outcome                             |
| POST   | `capabilities`                     | `{ "issuer_id": UUID, "capability": Capability }` | `Capability` (`201`)                                      |
| POST   | `capabilities/{id}/revoke`         | `{ "revoker_id": UUID }`                          | no body (`204`)                                           |
| GET    | `audit/events?transaction_id={id}` | —                                                 | redacted `AuditEvent[]`                                   |
| GET    | `audit/export?transaction_id={id}` | —                                                 | human-readable redacted text                              |
| GET    | `audit/verify`                     | —                                                 | sequence/hash verification result                         |
| GET    | `recovery`                         | —                                                 | conservative recovery classifications                     |
| POST   | `demo/seed`                        | `{ "content"?: string }`                          | real demo principals, capability, and submission (`201`)  |

The bundle contains transaction, intent, plan, policy decisions, requests, grants, executions,
receipts, verifications, compensations, and events from one consistent database read path. Serialized
record shapes live in the generated JSON Schemas.

Example:

```sh
curl -H "Authorization: Bearer $VEYRA_API_TOKEN" \
  http://127.0.0.1:7843/v1/transactions
```

The TypeScript equivalent is `new VeyraClient({ baseUrl, token })`; the SDK accepts only explicit
loopback HTTP hosts without URL credentials/query/fragment, refuses redirects, bounds request and
response bodies, applies a timeout, and redacts the bearer from surfaced errors. These client checks
reduce accidental credential disclosure; they do not reduce the bearer's authority.

## Server options

```text
veyra-server [--bind 127.0.0.1:7843]
             [--data-directory .veyra-data]
             [--workspace workspace]
             [--workspace-name default]
             [--planner-model MODEL]
             [--planner-endpoint HTTPS_URL]
             [--planner-api-key-environment NAME]
```

No model option means deterministic fixture planning. Data and workspace roots must be disjoint.

## CLI

Global options are `--api-url`, `--token-file`, and `--json`. The environment equivalents are
`VEYRA_API_URL` and `VEYRA_TOKEN_FILE`.

```text
veyra init [--data-directory PATH] [--workspace PATH]
veyra principal register FILE
veyra intent submit FILE
veyra intent show ID
veyra plan show ID
veyra tx list
veyra tx preview ID
veyra tx run ID
veyra tx inspect ID
veyra tx rollback ID
veyra approval grant REQUEST_ID --approver PRINCIPAL_ID
veyra capability issue FILE --issuer PRINCIPAL_ID
veyra audit verify
veyra audit export [--transaction TRANSACTION_ID]
veyra demo [--directory PATH]
```

`--json` emits compact JSON; otherwise output is pretty JSON. Input files must match the protocol
schema and use already registered/bound IDs. The complete no-key path is `veyra demo --json`.

Exit codes follow sysexits-style meanings: `0` success, `64` invalid input/JSON/URL, `69` daemon
unreachable, `70` other API/software failure, `75` transaction conflict, `77` authentication failure,
and `78` local configuration or filesystem failure.
