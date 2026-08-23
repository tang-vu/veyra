import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const directory = resolve(import.meta.dirname, "../schema");
const files = (await readdir(directory)).filter((file) =>
  file.endsWith(".schema.json"),
);

if (files.length !== 16) {
  throw new Error(`expected 16 generated schemas, found ${files.length}`);
}

for (const file of files) {
  const document = JSON.parse(await readFile(resolve(directory, file), "utf8"));
  if (document["x-veyra-protocol"] !== "veyra.protocol/v1") {
    throw new Error(`${file} has the wrong protocol marker`);
  }
  if (typeof document.$schema !== "string") {
    throw new Error(`${file} has no JSON Schema dialect`);
  }
}

console.log(`verified ${files.length} generated Veyra schemas`);
