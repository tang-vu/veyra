import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repository = resolve(import.meta.dirname, "..");
const failures = [];
let checks = 0;

function check(condition, message) {
  checks += 1;
  if (!condition) {
    failures.push(message);
  }
}

function repositoryPath(path) {
  return resolve(repository, path);
}

function readText(path) {
  return readFileSync(repositoryPath(path), "utf8");
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function normalized(text) {
  return text.replace(/\r\n/g, "\n").trimEnd();
}

function repositoryUrl(manifest) {
  return typeof manifest.repository === "string"
    ? manifest.repository
    : manifest.repository?.url;
}

function checkDiscoveryMetadata(manifest, label) {
  check(
    typeof manifest.description === "string" && manifest.description.length > 0,
    `${label} must have a description`,
  );
  check(manifest.license === "Apache-2.0", `${label} must use Apache-2.0`);
  check(
    repositoryUrl(manifest) === "git+https://github.com/tang-vu/veyra.git",
    `${label} must point at the canonical repository`,
  );
  check(
    manifest.homepage?.startsWith("https://github.com/tang-vu/veyra"),
    `${label} must have a canonical homepage`,
  );
  check(
    manifest.bugs?.url === "https://github.com/tang-vu/veyra/issues",
    `${label} must route bugs to the public issue tracker`,
  );
  check(
    Array.isArray(manifest.keywords) && manifest.keywords.length >= 3,
    `${label} must have at least three discovery keywords`,
  );
}

const requiredFiles = [
  ".github/ISSUE_TEMPLATE/bug_report.yml",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/feature_request.yml",
  ".github/ISSUE_TEMPLATE/question.yml",
  ".github/copilot-instructions.md",
  ".github/pull_request_template.md",
  ".github/workflows/ci.yml",
  ".github/workflows/codeql.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/release.yml",
  ".github/workflows/scorecard.yml",
  ".github/workflows/security.yml",
  "AGENTS.md",
  "CHANGELOG.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "LICENSE",
  "README.md",
  "RELEASING.md",
  "ROADMAP.md",
  "SECURITY.md",
  "SUPPORT.md",
  ".node-version",
  ".node-version-min",
  "Cargo.lock",
  "deny.toml",
  "docs/maintainers/repository-settings.md",
  "fuzz/.gitignore",
  "fuzz/Cargo.lock",
  "fuzz/Cargo.toml",
  "fuzz/README.md",
  "fuzz/fuzz_targets/canonical_protocol.rs",
  "fuzz/fuzz_targets/resource_scope.rs",
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "rust-toolchain.toml",
  "scripts/check-github.mjs",
  "scripts/check-packages.mjs",
];

for (const path of requiredFiles) {
  check(
    existsSync(repositoryPath(path)),
    `required OSS file is missing: ${path}`,
  );
}

check(
  !existsSync(repositoryPath("goal.md")),
  "goal.md is retired; use ROADMAP.md, CHANGELOG.md, and PROGRESS.md instead",
);

const agentInstructions = readText("AGENTS.md");
for (const marker of [
  "`goal.md` must not be recreated",
  "OSS change matrix",
  "pnpm oss:check",
  "`cargo-fuzz`",
  "Never push, publish, deploy",
]) {
  check(
    agentInstructions.includes(marker),
    `AGENTS.md is missing required maintainer rule: ${marker}`,
  );
}

check(
  readText(".github/copilot-instructions.md").includes("AGENTS.md"),
  ".github/copilot-instructions.md must delegate to the canonical AGENTS.md contract",
);

const privateAdvisoryUrl =
  /https:\/\/github\.com\/tang-vu\/veyra\/security\/advisories\/new(?=[\s)'"\]}]|$)/;
check(
  privateAdvisoryUrl.test(readText("SECURITY.md")),
  "SECURITY.md must link directly to GitHub private vulnerability reporting",
);

const advisoryTrackingUrl =
  /https:\/\/github\.com\/tang-vu\/veyra\/issues\/4(?=[\s)'"\]}]|$)/;
for (const path of [
  "deny.toml",
  "docs/security/threat-model.md",
  "ROADMAP.md",
]) {
  check(
    advisoryTrackingUrl.test(readText(path)),
    `${path} must retain the tracked disposition for RUSTSEC-2024-0429`,
  );
}

const rootManifest = readJson("package.json");
const workspaceVersion = rootManifest.version;
check(
  rootManifest.private === true,
  "the JavaScript workspace root must stay private",
);
check(
  /^\d+\.\d+\.\d+$/.test(workspaceVersion),
  "the workspace version must be a stable semantic version",
);
checkDiscoveryMetadata(rootManifest, "package.json");
check(
  rootManifest.scripts?.["oss:check"] === "node ./scripts/check-oss.mjs",
  "package.json must expose the deterministic oss:check script",
);
check(
  rootManifest.scripts?.["oss:host-check"] ===
    "node ./scripts/check-github.mjs",
  "package.json must expose the read-only oss:host-check script",
);
check(
  rootManifest.scripts?.["package:check"] ===
    "node ./scripts/check-packages.mjs",
  "package.json must expose the deterministic package:check script",
);

const rootLicense = normalized(readText("LICENSE"));
const publicJavaScriptPackages = [
  "packages/protocol-schema",
  "packages/sdk-typescript",
];

for (const packageDirectory of publicJavaScriptPackages) {
  const manifest = readJson(`${packageDirectory}/package.json`);
  const label = `${packageDirectory}/package.json`;
  check(
    manifest.version === workspaceVersion,
    `${label} version must match the workspace version`,
  );
  check(manifest.private === false, `${label} must explicitly be public`);
  checkDiscoveryMetadata(manifest, label);
  check(
    manifest.repository?.directory === packageDirectory.replaceAll("\\", "/"),
    `${label} must identify its monorepo directory`,
  );
  check(
    manifest.publishConfig?.access === "public",
    `${label} must publish with public access`,
  );
  check(
    manifest.publishConfig?.provenance === true,
    `${label} must request registry provenance`,
  );
  check(
    manifest.engines?.node === ">=22.0.0",
    `${label} must state the supported Node runtime`,
  );
  for (const script of ["build", "check", "lint", "test"]) {
    check(
      typeof manifest.scripts?.[script] === "string",
      `${label} must expose a ${script} script`,
    );
  }
  for (const packagedFile of ["README.md", "LICENSE"]) {
    check(
      manifest.files?.includes(packagedFile),
      `${label} must include ${packagedFile} in its package archive`,
    );
    check(
      existsSync(repositoryPath(`${packageDirectory}/${packagedFile}`)),
      `${packageDirectory}/${packagedFile} is missing`,
    );
  }
  check(
    normalized(readText(`${packageDirectory}/LICENSE`)) === rootLicense,
    `${packageDirectory}/LICENSE must match the root license`,
  );
}

const desktopManifest = readJson("apps/desktop/package.json");
const tauriConfiguration = readJson("apps/desktop/src-tauri/tauri.conf.json");
const nodeRuntimeVersion = normalized(readText(".node-version"));
const minimumNodeVersion = normalized(readText(".node-version-min"));
const nodeTypesVersion = desktopManifest.devDependencies?.["@types/node"] ?? "";
const overriddenNodeTypesVersion = readText("pnpm-workspace.yaml").match(
  /^\s*["']?@types\/node["']?:\s*["']?(\d+\.\d+\.\d+)["']?\s*$/m,
)?.[1];
const supportedNodeMajor =
  rootManifest.engines?.node?.match(/^>=(\d+)\.\d+\.\d+$/)?.[1];
check(
  desktopManifest.version === workspaceVersion,
  "apps/desktop/package.json version must match the workspace version",
);
check(
  tauriConfiguration.version === workspaceVersion,
  "the Tauri application version must match the workspace version",
);
check(
  /^\d+\.\d+\.\d+$/.test(nodeRuntimeVersion) &&
    /^\d+\.\d+\.\d+$/.test(minimumNodeVersion) &&
    /^\d+\.\d+\.\d+$/.test(nodeTypesVersion),
  "Node runtime pins and @types/node must use exact semantic versions",
);
check(
  minimumNodeVersion.split(".")[0] === supportedNodeMajor,
  ".node-version-min major must match the public minimum Node engine",
);
check(
  minimumNodeVersion.split(".")[0] === nodeTypesVersion.split(".")[0],
  "@types/node major must match the minimum supported Node major",
);
check(
  overriddenNodeTypesVersion === nodeTypesVersion,
  "the workspace must constrain transitive Node types to the reviewed direct version",
);
check(
  Number(nodeRuntimeVersion.split(".")[0]) >=
    Number(minimumNodeVersion.split(".")[0]),
  "the default Node runtime cannot be older than the minimum compatibility runtime",
);

const cargoArguments = [];
if (process.env.VEYRA_RUST_TOOLCHAIN) {
  cargoArguments.push(`+${process.env.VEYRA_RUST_TOOLCHAIN}`);
}
cargoArguments.push("metadata", "--no-deps", "--format-version", "1");
const cargoMetadata = spawnSync("cargo", cargoArguments, {
  cwd: repository,
  encoding: "utf8",
});
check(
  cargoMetadata.status === 0,
  `cargo metadata failed: ${(cargoMetadata.stderr || cargoMetadata.error?.message || "unknown error").trim()}`,
);

if (cargoMetadata.status === 0) {
  const metadata = JSON.parse(cargoMetadata.stdout);
  const workspaceMembers = new Set(metadata.workspace_members);
  const publishablePackages = metadata.packages.filter(
    (manifest) =>
      workspaceMembers.has(manifest.id) &&
      (manifest.publish === null || manifest.publish.length > 0),
  );

  check(
    publishablePackages.length === 7,
    `expected 7 publishable Rust crates, found ${publishablePackages.length}`,
  );

  for (const manifest of publishablePackages) {
    const label = `${manifest.name} Cargo package`;
    const packageReadme =
      typeof manifest.readme === "string"
        ? resolve(dirname(manifest.manifest_path), manifest.readme)
        : undefined;
    check(
      typeof manifest.description === "string" &&
        manifest.description.length > 0,
      `${label} must have a description`,
    );
    check(
      manifest.version === workspaceVersion,
      `${label} version must match the workspace version`,
    );
    check(manifest.license === "Apache-2.0", `${label} must use Apache-2.0`);
    check(
      manifest.repository === "https://github.com/tang-vu/veyra",
      `${label} must point at the canonical repository`,
    );
    check(manifest.authors.length > 0, `${label} must identify its authors`);
    check(
      packageReadme !== undefined && existsSync(packageReadme),
      `${label} must have an existing README`,
    );
    check(
      manifest.keywords.length >= 3,
      `${label} must have at least three discovery keywords`,
    );
    check(
      manifest.categories.length > 0,
      `${label} must have at least one crates.io category`,
    );
    check(
      typeof manifest.rust_version === "string",
      `${label} must state its minimum Rust version`,
    );

    const crateLicense = resolve(dirname(manifest.manifest_path), "LICENSE");
    check(existsSync(crateLicense), `${label} must ship a local LICENSE file`);
    if (existsSync(crateLicense)) {
      check(
        normalized(readFileSync(crateLicense, "utf8")) === rootLicense,
        `${relative(repository, crateLicense)} must match the root license`,
      );
    }
  }
}

const workflowDirectory = repositoryPath(".github/workflows");
const workflowFiles = readdirSync(workflowDirectory)
  .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
  .sort();
const codeqlActionReferences = [];

for (const file of workflowFiles) {
  const workflow = readFileSync(resolve(workflowDirectory, file), "utf8");
  const workflowLines = workflow.split(/\r?\n/);
  const topPermissionsIndex = workflowLines.findIndex(
    (line) => line === "permissions:",
  );
  check(
    topPermissionsIndex >= 0,
    `.github/workflows/${file} must declare top-level permissions`,
  );
  if (topPermissionsIndex >= 0) {
    const topPermissions = [];
    for (const line of workflowLines.slice(topPermissionsIndex + 1)) {
      if (line.trim() === "" || !/^\s/.test(line)) {
        break;
      }
      topPermissions.push(line);
    }
    check(
      !topPermissions.some((line) => /:\s*write\s*$/.test(line)),
      `.github/workflows/${file} must not grant write access at workflow scope`,
    );
  }
  check(
    !/^\s*pull_request_target:\s*$/m.test(workflow),
    `.github/workflows/${file} must not use the privileged pull_request_target trigger`,
  );

  const actionLines = workflowLines.filter((line) => /^\s*uses:\s*/.test(line));
  let checkoutCount = 0;
  for (const line of actionLines) {
    const match = line.match(/^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.+))?$/);
    check(
      Boolean(match),
      `.github/workflows/${file} has an unreadable uses line`,
    );
    if (!match) {
      continue;
    }

    const action = match[1].replace(/^['"]|['"]$/g, "");
    const versionComment = match[2] ?? "";
    if (action.startsWith("./")) {
      continue;
    }
    if (action.startsWith("docker://")) {
      check(
        /@sha256:[0-9a-f]{64}$/.test(action),
        `.github/workflows/${file} must pin ${action} by digest`,
      );
      continue;
    }

    check(
      /^[^@\s]+@[0-9a-f]{40}$/.test(action),
      `.github/workflows/${file} must pin ${action} to a full commit SHA`,
    );
    check(
      /\bv\d+\.\d+\.\d+\b/.test(versionComment),
      `.github/workflows/${file} must annotate ${action} with its release version`,
    );
    if (action.startsWith("actions/checkout@")) {
      checkoutCount += 1;
    }
    if (action.startsWith("github/codeql-action/")) {
      const [actionName, commitSha = ""] = action.split("@");
      const releaseVersion =
        versionComment.match(/\bv\d+\.\d+\.\d+\b/)?.[0] ?? "";
      codeqlActionReferences.push({ actionName, commitSha, releaseVersion });
    }
  }

  const hardenedCheckoutCount = (
    workflow.match(/persist-credentials:\s*false/g) ?? []
  ).length;
  check(
    hardenedCheckoutCount === checkoutCount,
    `.github/workflows/${file} must disable persisted credentials on every checkout`,
  );
}

for (const requiredAction of [
  "github/codeql-action/init",
  "github/codeql-action/autobuild",
  "github/codeql-action/analyze",
  "github/codeql-action/upload-sarif",
]) {
  check(
    codeqlActionReferences.filter(
      ({ actionName }) => actionName === requiredAction,
    ).length === 1,
    `${requiredAction} must appear exactly once across the hosted security workflows`,
  );
}
check(
  new Set(codeqlActionReferences.map(({ commitSha }) => commitSha)).size === 1,
  "all github/codeql-action components must use the same immutable release commit",
);
check(
  new Set(codeqlActionReferences.map(({ releaseVersion }) => releaseVersion))
    .size === 1,
  "all github/codeql-action components must carry the same release version comment",
);

const securityWorkflow = readText(".github/workflows/security.yml");
check(
  !/^\s*pull_request:\s*\n\s+(?:paths|paths-ignore):/m.test(securityWorkflow),
  "dependency security must report a result on every pull request so it can remain a required check",
);
check(
  securityWorkflow.includes("name: Review dependency changes"),
  "dependency security must retain the stable required-check name",
);

const fuzzManifest = readText("fuzz/Cargo.toml");
for (const marker of [
  'arbitrary = { version = "=1.4.2"',
  'libfuzzer-sys = "=0.4.13"',
  'name = "canonical_protocol"',
  'name = "resource_scope"',
]) {
  check(
    fuzzManifest.includes(marker),
    `fuzz/Cargo.toml is missing pinned harness contract: ${marker}`,
  );
}
for (const target of ["canonical_protocol", "resource_scope"]) {
  check(
    readText(`fuzz/fuzz_targets/${target}.rs`).includes("libfuzzer_sys"),
    `${target} must remain a real libFuzzer target`,
  );
}
const fuzzIgnore = readText("fuzz/.gitignore");
for (const localOutput of [
  "/artifacts/",
  "/corpus/",
  "/coverage/",
  "/target/",
]) {
  check(
    fuzzIgnore.includes(localOutput),
    `fuzz/.gitignore must exclude local output: ${localOutput}`,
  );
}

const fuzzWorkflow = readText(".github/workflows/fuzz.yml");
check(
  !/^\s*pull_request:\s*\n\s+(?:paths|paths-ignore):/m.test(fuzzWorkflow),
  "fuzzing must report a result on every pull request so it can remain a required check",
);
for (const marker of [
  "name: Fuzz security boundaries",
  "nightly-2026-08-20",
  "cargo install cargo-fuzz --version 0.13.2 --locked",
  "-max_len=4096",
  "-rss_limit_mb=2048",
  "fuzz run canonical_protocol",
  "fuzz run resource_scope",
]) {
  check(
    fuzzWorkflow.includes(marker),
    `fuzz workflow is missing bounded pinned behavior: ${marker}`,
  );
}

const dependabot = readText(".github/dependabot.yml");
check(
  /^\s+directory:\s+\/fuzz\s*$/m.test(dependabot),
  "Dependabot must monitor the isolated fuzz Cargo workspace",
);
check(
  dependabot.includes(
    'groups:\n      codeql-action:\n        patterns:\n          - "github/codeql-action/*"',
  ),
  "Dependabot must update the version-coupled CodeQL Action family atomically",
);
check(
  dependabot.includes(
    'dependency-name: "@types/node"\n        update-types:\n          - "version-update:semver-major"',
  ),
  "Dependabot must not advance Node type definitions beyond the pinned runtime major",
);

const ciWorkflow = readText(".github/workflows/ci.yml");
check(
  /^\s*push:\s*\n\s+branches:\s*\n\s+- main\s*$/m.test(ciWorkflow),
  "CI push runs must target main; pull_request covers contributor branches without duplicate builds",
);
for (const marker of [
  "name: JavaScript gate (Node 22)",
  "node-version-file: .node-version-min",
  "name: Verify minimum Node compatibility",
]) {
  check(
    ciWorkflow.includes(marker),
    `CI must retain minimum supported Node coverage: ${marker}`,
  );
}

const releaseWorkflow = readText(".github/workflows/release.yml");
const draftReleaseIndex = releaseWorkflow.indexOf("gh release create");
const publishReleaseIndex = releaseWorkflow.indexOf(
  'gh release edit "$GITHUB_REF_NAME" --draft=false',
);
check(
  draftReleaseIndex >= 0 &&
    releaseWorkflow
      .slice(
        draftReleaseIndex,
        releaseWorkflow.indexOf("\n", draftReleaseIndex),
      )
      .includes("--draft"),
  "release automation must attach every asset to a draft before immutable publication",
);
check(
  publishReleaseIndex > draftReleaseIndex,
  "release automation must publish only after the draft and its assets exist",
);

if (failures.length > 0) {
  console.error(`OSS gate failed with ${failures.length} problem(s):`);
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  `OSS gate passed: ${checks} assertions across community health, package metadata, licenses, AI guidance, and workflow pinning.`,
);
