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

Treat the token as an administrative root credential. Do not give it to a model, log it, embed it in
a web deployment, or send it to a non-loopback origin. The client rejects URL credentials,
query/fragment-bearing base URLs and redirects; it also bounds request/response sizes, defaults to a
60-second timeout, and redacts the token from surfaced errors.
