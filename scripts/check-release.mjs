import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

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

const requireTag = process.argv.includes("--require-tag");
const suppliedTag = process.argv
  .slice(2)
  .find((argument) => argument !== "--require-tag");
const rootManifest = readJson("package.json");
const version = rootManifest.version;
const tag = suppliedTag ?? `v${version}`;

check(
  /^v\d+\.\d+\.\d+$/.test(tag),
  `release tag must be vX.Y.Z, received: ${tag}`,
);
check(
  tag === `v${version}`,
  `${tag} must match package.json version ${version}`,
);

for (const manifestPath of [
  "apps/desktop/package.json",
  "packages/protocol-schema/package.json",
  "packages/sdk-typescript/package.json",
]) {
  check(
    readJson(manifestPath).version === version,
    `${manifestPath} must match release version ${version}`,
  );
}

check(
  readJson("apps/desktop/src-tauri/tauri.conf.json").version === version,
  `apps/desktop/src-tauri/tauri.conf.json must match release version ${version}`,
);

const cargoManifest = readText("Cargo.toml");
const workspacePackage = cargoManifest.match(
  /\[workspace\.package\]([\s\S]*?)(?=\r?\n\[|$)/,
)?.[1];
check(Boolean(workspacePackage), "Cargo.toml must contain [workspace.package]");
check(
  new RegExp(`^version = "${version.replaceAll(".", "\\.")}"$`, "m").test(
    workspacePackage ?? "",
  ),
  `Cargo workspace version must match ${version}`,
);

const changelog = readText("CHANGELOG.md");
check(
  new RegExp(
    `^## \\[${version.replaceAll(".", "\\.")}\\] - \\d{4}-\\d{2}-\\d{2}$`,
    "m",
  ).test(changelog),
  `CHANGELOG.md must contain a dated [${version}] release section`,
);
check(
  changelog.includes(
    `[Unreleased]: https://github.com/tang-vu/veyra/compare/${tag}...HEAD`,
  ),
  `CHANGELOG.md must compare Unreleased changes from ${tag}`,
);
check(
  changelog.includes(
    `[${version}]: https://github.com/tang-vu/veyra/releases/tag/${tag}`,
  ),
  `CHANGELOG.md must link ${version} to its immutable GitHub Release`,
);

const releaseNotesPath = `docs/releases/${tag}.md`;
check(
  existsSync(repositoryPath(releaseNotesPath)),
  `${releaseNotesPath} must exist`,
);
if (existsSync(repositoryPath(releaseNotesPath))) {
  const releaseNotes = readText(releaseNotesPath);
  for (const marker of [
    `# Veyra ${tag}`,
    "## Verify the download",
    "## Security and trust boundary",
    "unsigned",
    "https://github.com/tang-vu/veyra/issues/4",
    "gh attestation verify",
  ]) {
    check(
      releaseNotes.includes(marker),
      `${releaseNotesPath} must disclose or document: ${marker}`,
    );
  }
}

if (requireTag) {
  check(
    process.env.GITHUB_REF === `refs/tags/${tag}`,
    `release workflow must run from refs/tags/${tag}`,
  );
  const head = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repository,
    encoding: "utf8",
  }).trim();
  const taggedCommit = execFileSync("git", ["rev-parse", `${tag}^{commit}`], {
    cwd: repository,
    encoding: "utf8",
  }).trim();
  check(
    taggedCommit === head,
    `${tag} must resolve to the checked-out commit ${head}`,
  );
  check(
    !process.env.GITHUB_SHA || process.env.GITHUB_SHA === head,
    "GITHUB_SHA must match the checked-out annotated tag commit",
  );
}

if (failures.length > 0) {
  console.error(`Release contract failed with ${failures.length} problem(s):`);
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`Release contract passed: ${checks} assertions for ${tag}.`);
