import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

const directory = resolve(import.meta.dirname, "../schema");

test("all generated schemas are valid JSON with stable protocol markers", async () => {
  const files = (await readdir(directory)).filter((file) => file.endsWith(".schema.json"));
  assert.equal(files.length, 16);
  for (const file of files) {
    const document = JSON.parse(await readFile(resolve(directory, file), "utf8"));
    assert.equal(document["x-veyra-protocol"], "veyra.protocol/v1");
    assert.match(document.$schema, /^https:\/\/json-schema\.org\//);
  }
});
