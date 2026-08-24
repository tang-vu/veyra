import { createReadStream, existsSync, lstatSync, readdirSync } from "node:fs";
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { relative, resolve, sep } from "node:path";

const repositoryRoot = process.env.VEYRA_RELEASE_SOURCE
  ? resolve(process.env.VEYRA_RELEASE_SOURCE)
  : resolve(import.meta.dirname, "..");
const tag = process.argv[2];
const dist = resolve(repositoryRoot, process.argv[3] ?? "dist");
const failures = [];

function check(condition, message) {
  if (!condition) {
    failures.push(message);
  }
}

function requiredEnvironment(name, pattern) {
  const value = process.env[name] ?? "";
  check(pattern.test(value), `${name} is missing or malformed`);
  return value;
}

async function sha256(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    digest.update(chunk);
  }
  return digest.digest("hex");
}

async function writeExclusive(path, contents, encoding) {
  const handle = await open(path, "wx", 0o644);
  try {
    await handle.writeFile(contents, { encoding });
    await handle.sync();
  } finally {
    await handle.close();
  }
}

check(/^v\d+\.\d+\.\d+$/.test(tag ?? ""), "tag must be vX.Y.Z");
const relativeDist = relative(repositoryRoot, dist);
check(
  relativeDist !== "" &&
    relativeDist !== ".." &&
    !relativeDist.startsWith(`..${sep}`),
  "output directory must stay inside the repository",
);
check(
  existsSync(dist) && lstatSync(dist).isDirectory(),
  "output directory must already exist",
);

const repository = requiredEnvironment(
  "GITHUB_REPOSITORY",
  /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
);
const releaseControlCommit = requiredEnvironment(
  "GITHUB_SHA",
  /^[a-f0-9]{40}$/,
);
const workflow = requiredEnvironment("GITHUB_WORKFLOW", /\S/);
const workflowRef = requiredEnvironment("GITHUB_WORKFLOW_REF", /\S/);
const eventName = requiredEnvironment("GITHUB_EVENT_NAME", /\S/);
const githubRef = requiredEnvironment("GITHUB_REF", /^refs\/(heads|tags)\//);
const runId = requiredEnvironment("GITHUB_RUN_ID", /^\d+$/);
const runAttemptText = requiredEnvironment("GITHUB_RUN_ATTEMPT", /^\d+$/);
const runAttempt = Number.parseInt(runAttemptText, 10);
check(runAttempt > 0, "GITHUB_RUN_ATTEMPT must be positive");
check(workflow === "Release artifacts", "unexpected release workflow identity");

let sourceCommit = "";
let checkedOutCommit = "";
let tagObjectType = "";
try {
  checkedOutCommit = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  }).trim();
  tagObjectType = execFileSync("git", ["cat-file", "-t", `refs/tags/${tag}`], {
    cwd: repositoryRoot,
    encoding: "utf8",
  }).trim();
  sourceCommit = execFileSync(
    "git",
    ["rev-parse", `refs/tags/${tag}^{commit}`],
    { cwd: repositoryRoot, encoding: "utf8" },
  ).trim();
} catch {
  failures.push(`${tag} must resolve to a local commit`);
}
check(
  /^[a-f0-9]{40}$/.test(sourceCommit),
  "source commit must be a full Git SHA",
);
check(tagObjectType === "tag", `${tag} must be an annotated tag`);
check(
  checkedOutCommit === sourceCommit,
  "checked-out source must match the annotated tag commit",
);

const releaseControlRoot = resolve(repositoryRoot, ".release-control");
const recovery = eventName === "workflow_dispatch";
check(
  eventName === "push" || recovery,
  "release manifest event must be push or workflow_dispatch",
);
check(
  recovery ? githubRef === "refs/heads/main" : githubRef === `refs/tags/${tag}`,
  "release manifest event ref does not match its release mode",
);
check(
  recovery ? existsSync(releaseControlRoot) : !existsSync(releaseControlRoot),
  "release-control checkout presence does not match its release mode",
);
let actualReleaseControlCommit = checkedOutCommit;
if (recovery && existsSync(releaseControlRoot)) {
  try {
    actualReleaseControlCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: releaseControlRoot,
      encoding: "utf8",
    }).trim();
  } catch {
    failures.push("release-control checkout must resolve to a Git commit");
  }
}
check(
  actualReleaseControlCommit === releaseControlCommit,
  "GITHUB_SHA must match the checked-out release-control commit",
);
check(
  workflowRef ===
    `${repository}/.github/workflows/release.yml@refs/${recovery ? "heads/main" : `tags/${tag}`}`,
  "GITHUB_WORKFLOW_REF must identify the expected release workflow ref",
);

const manifestName = `veyra-${tag}.release-manifest.json`;
const manifestPath = resolve(dist, manifestName);
const checksumPath = `${manifestPath}.sha256`;

const entries = existsSync(dist)
  ? readdirSync(dist, { withFileTypes: true })
  : [];
check(
  entries.every((entry) => entry.isFile()),
  "release asset directory must contain only regular files",
);
const names = entries
  .filter((entry) => entry.isFile())
  .map((entry) => entry.name)
  .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
check(names.length > 0, "release manifest requires at least one asset");

if (failures.length > 0) {
  console.error(`Release manifest failed with ${failures.length} problem(s):`);
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

const assets = [];
for (const name of names) {
  const path = resolve(dist, name);
  const size = lstatSync(path).size;
  assets.push({ name, sha256: await sha256(path), size });
}

const manifest = {
  schemaVersion: 1,
  repository,
  tag,
  sourceCommit,
  releaseControlCommit,
  workflow,
  workflowRef,
  eventName,
  githubRef,
  mode: recovery ? "recovery" : "tag",
  runId,
  runAttempt,
  assets,
};
const manifestContents = `${JSON.stringify(manifest, null, 2)}\n`;
const manifestDigest = createHash("sha256")
  .update(manifestContents, "utf8")
  .digest("hex");
await writeExclusive(manifestPath, manifestContents, "utf8");
await writeExclusive(
  checksumPath,
  `${manifestDigest}  ${manifestName}\n`,
  "ascii",
);

console.log(
  `Release manifest created: ${assets.length} assets, source ${sourceCommit}, control ${releaseControlCommit}.`,
);
