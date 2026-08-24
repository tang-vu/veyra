import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

const repository = resolve(import.meta.dirname, "..");
const failures = [];

function check(condition, message) {
  if (!condition) {
    failures.push(message);
  }
}

function run(command, arguments_, cwd = repository) {
  const result = spawnSync(command, arguments_, {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = (
      result.stderr ||
      result.stdout ||
      result.error?.message ||
      "unknown error"
    ).trim();
    throw new Error(`${command} ${arguments_.join(" ")} failed: ${detail}`);
  }
  return result.stdout;
}

const cargoPrefix = [];
if (process.env.VEYRA_RUST_TOOLCHAIN) {
  cargoPrefix.push(`+${process.env.VEYRA_RUST_TOOLCHAIN}`);
}

const rustPackages = [
  "veyra-cli",
  "veyra-core",
  "veyra-executor",
  "veyra-journal",
  "veyra-policy",
  "veyra-protocol",
  "veyra-server",
];

for (const packageName of rustPackages) {
  const output = run("cargo", [
    ...cargoPrefix,
    "package",
    "--package",
    packageName,
    "--allow-dirty",
    "--locked",
    "--list",
  ]);
  const files = output
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);

  for (const requiredFile of ["Cargo.toml", "LICENSE", "README.md"]) {
    check(
      files.includes(requiredFile),
      `${packageName} archive must contain ${requiredFile}`,
    );
  }
  check(
    files.some((file) => file.startsWith("src/")),
    `${packageName} archive must contain Rust sources`,
  );
  check(
    !files.some((file) =>
      /(^|\/)(target|node_modules|test-results|playwright-report|\.git)(\/|$)/.test(
        file,
      ),
    ),
    `${packageName} archive contains a local or generated directory`,
  );
  check(
    !files.some((file) =>
      /(^|\/)(\.env[^/]*|.*\.(db|sqlite|log))$/i.test(file),
    ),
    `${packageName} archive contains a credential-shaped or local-state file`,
  );
}

const bundledNpmCli = resolve(
  dirname(process.execPath),
  "node_modules/npm/bin/npm-cli.js",
);
const useBundledNpmCli =
  process.platform === "win32" && existsSync(bundledNpmCli);
const npmCommand = useBundledNpmCli ? process.execPath : "npm";
const npmArguments = useBundledNpmCli ? [bundledNpmCli] : [];
const npmPackages = [
  {
    directory: "packages/protocol-schema",
    name: "@veyra/protocol-schema",
    required: [
      "LICENSE",
      "README.md",
      "package.json",
      "fixtures/agent.principal.json",
      "schema/effect.schema.json",
    ],
    allowed: ["LICENSE", "README.md", "package.json", "fixtures/", "schema/"],
  },
  {
    directory: "packages/sdk-typescript",
    name: "@veyra/sdk",
    required: [
      "LICENSE",
      "README.md",
      "package.json",
      "dist/index.d.ts",
      "dist/index.js",
    ],
    allowed: ["LICENSE", "README.md", "package.json", "dist/"],
  },
];

for (const packageDefinition of npmPackages) {
  const output = run(
    npmCommand,
    [...npmArguments, "pack", "--dry-run", "--json"],
    resolve(repository, packageDefinition.directory),
  );
  const reports = JSON.parse(output);
  check(
    Array.isArray(reports) && reports.length === 1,
    `${packageDefinition.name} must produce exactly one npm pack report`,
  );
  if (!Array.isArray(reports) || reports.length !== 1) {
    continue;
  }

  const report = reports[0];
  const files = report.files.map((file) => file.path);
  check(
    report.name === packageDefinition.name,
    `${packageDefinition.directory} packed as unexpected name ${report.name}`,
  );
  for (const requiredFile of packageDefinition.required) {
    check(
      files.includes(requiredFile),
      `${packageDefinition.name} archive must contain ${requiredFile}`,
    );
  }
  for (const file of files) {
    check(
      packageDefinition.allowed.some(
        (allowed) =>
          (allowed.endsWith("/") && file.startsWith(allowed)) ||
          file === allowed,
      ),
      `${packageDefinition.name} archive contains unexpected file ${file}`,
    );
  }
}

if (failures.length > 0) {
  console.error(
    `Package archive gate failed with ${failures.length} problem(s):`,
  );
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  `Package archive gate passed: ${rustPackages.length} Rust crates and ${npmPackages.length} npm packages are self-contained and clean.`,
);
