import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repository = process.env.VEYRA_PACKAGE_SOURCE
  ? resolve(process.env.VEYRA_PACKAGE_SOURCE)
  : resolve(import.meta.dirname, "..");
const failures = [];
let checks = 0;

function check(condition, message) {
  checks += 1;
  if (!condition) {
    failures.push(message);
  }
}

const cargoArguments = [];
if (process.env.VEYRA_RUST_TOOLCHAIN) {
  cargoArguments.push(`+${process.env.VEYRA_RUST_TOOLCHAIN}`);
}
cargoArguments.push("metadata", "--no-deps", "--format-version", "1");
const metadataResult = spawnSync("cargo", cargoArguments, {
  cwd: repository,
  encoding: "utf8",
});
check(
  metadataResult.status === 0,
  `cargo metadata failed: ${(metadataResult.stderr || metadataResult.error?.message || "unknown error").trim()}`,
);

const expectedRustOrder = [
  "veyra-protocol",
  "veyra-executor",
  "veyra-journal",
  "veyra-policy",
  "veyra-core",
  "veyra-server",
  "veyra-cli",
];
const expectedNpmOrder = ["@veyra/protocol-schema", "@veyra/sdk"];
const workspaceVersion = JSON.parse(
  readFileSync(resolve(repository, "package.json"), "utf8"),
).version;

if (metadataResult.status === 0) {
  const metadata = JSON.parse(metadataResult.stdout);
  const workspaceMembers = new Set(metadata.workspace_members);
  const publishable = metadata.packages.filter(
    (package_) =>
      workspaceMembers.has(package_.id) &&
      (package_.publish === null || package_.publish.length > 0),
  );
  const byName = new Map(
    publishable.map((package_) => [package_.name, package_]),
  );
  check(
    expectedRustOrder.every((name) => byName.has(name)) &&
      byName.size === expectedRustOrder.length,
    "publishable Rust package set must match the reviewed seven-crate plan",
  );

  const position = new Map(
    expectedRustOrder.map((name, index) => [name, index]),
  );
  for (const [index, name] of expectedRustOrder.entries()) {
    const package_ = byName.get(name);
    if (!package_) {
      continue;
    }
    check(
      package_.version === workspaceVersion,
      `${name} must use workspace version ${workspaceVersion}`,
    );
    check(
      package_.publish === null || package_.publish.includes("crates-io"),
      `${name} must allow publication to crates.io`,
    );
    const internalDependencies = package_.dependencies.filter((dependency) =>
      position.has(dependency.name),
    );
    for (const dependency of internalDependencies) {
      check(
        position.get(dependency.name) < index,
        `${name} must be published after internal dependency ${dependency.name}`,
      );
      check(
        dependency.path !== null && dependency.path !== undefined,
        `${name} must develop against a local path for ${dependency.name}`,
      );
      check(
        dependency.req === `^${workspaceVersion}`,
        `${name} must publish ${dependency.name} with compatible version ^${workspaceVersion}`,
      );
    }
  }
}

const npmManifests = [
  "packages/protocol-schema/package.json",
  "packages/sdk-typescript/package.json",
].map((path) => JSON.parse(readFileSync(resolve(repository, path), "utf8")));
check(
  npmManifests.map(({ name }) => name).join("\n") ===
    expectedNpmOrder.join("\n"),
  "npm package order must keep protocol schema before the SDK",
);
for (const manifest of npmManifests) {
  check(manifest.private === false, `${manifest.name} must be public`);
  check(
    manifest.version === workspaceVersion,
    `${manifest.name} must use workspace version ${workspaceVersion}`,
  );
  check(
    manifest.publishConfig?.access === "public",
    `${manifest.name} must publish with public access`,
  );
  check(
    manifest.publishConfig?.provenance === true,
    `${manifest.name} must retain registry provenance`,
  );
}

if (failures.length > 0) {
  console.error(
    `Package publication plan failed with ${failures.length} problem(s):`,
  );
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  `Package publication plan passed: ${checks} checks; Rust order ${expectedRustOrder.join(" -> ")}; npm order ${expectedNpmOrder.join(" -> ")}.`,
);
