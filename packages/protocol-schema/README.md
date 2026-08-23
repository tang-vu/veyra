# @veyra/protocol-schema

Committed JSON Schemas generated from `veyra-protocol`, the authoritative Rust wire types.

Regenerate from the repository root:

```sh
cargo run -p veyra-protocol --example generate-schema -- packages/protocol-schema/schema
```

Every document carries `x-veyra-protocol: veyra.protocol/v1`. Do not hand-edit generated schema files.
