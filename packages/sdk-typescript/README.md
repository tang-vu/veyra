# `@veyra/sdk`

Typed ESM client for Veyra's authenticated loopback `/v1` API. It carries no authority logic;
the Rust kernel remains the sole policy and execution boundary.

```ts
import { VeyraClient } from "@veyra/sdk";

const veyra = new VeyraClient({
  baseUrl: "http://127.0.0.1:7843/v1/",
  token: process.env.VEYRA_API_TOKEN!,
});

const transactions = await veyra.listTransactions();
```

Treat the token as a local credential. Do not log it, embed it in a web deployment, or send it to a
non-loopback origin.
