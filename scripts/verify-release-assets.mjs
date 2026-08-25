import {
  createReadStream,
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  artifactSbomSyftVersion,
  validateArtifactSbom,
} from "./check-artifact-sbom.mjs";

const canonicalRepository = "tang-vu/veyra";

const artifactSboms = [
  {
    file: "veyra-cli-linux-x86_64.spdx.json",
    sourceName: "veyra-cli-linux-x86_64",
    rootPackage: "veyra-cli",
  },
  {
    file: "veyra-server-linux-x86_64.spdx.json",
    sourceName: "veyra-server-linux-x86_64",
    rootPackage: "veyra-server",
  },
  {
    file: "veyra-cli-windows-x86_64.spdx.json",
    sourceName: "veyra-cli-windows-x86_64",
    rootPackage: "veyra-cli",
  },
  {
    file: "veyra-server-windows-x86_64.spdx.json",
    sourceName: "veyra-server-windows-x86_64",
    rootPackage: "veyra-server",
  },
  {
    file: "veyra-desktop-windows-x86_64.spdx.json",
    sourceName: "veyra-desktop-windows-x86_64",
    rootPackage: "veyra-desktop",
  },
];

async function sha256(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    digest.update(chunk);
  }
  return digest.digest("hex");
}

function packagePurls(package_) {
  return (package_?.externalRefs ?? [])
    .filter((reference) => reference.referenceType === "purl")
    .map((reference) => reference.referenceLocator);
}

function sameMembers(actual, expected) {
  return (
    actual.length === expected.length &&
    [...actual]
      .sort()
      .every((value, index) => value === [...expected].sort()[index])
  );
}

export async function verifyReleaseAssets({
  directory,
  tag,
  repository = canonicalRepository,
  expectedSourceCommit,
}) {
  const failures = [];
  let checks = 0;

  function check(condition, message) {
    checks += 1;
    if (!condition) {
      failures.push(message);
    }
  }

  check(/^v\d+\.\d+\.\d+$/.test(tag), "tag must be vX.Y.Z");
  check(
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository),
    "repository must be owner/name",
  );
  if (expectedSourceCommit !== undefined) {
    check(
      /^[a-f0-9]{40}$/.test(expectedSourceCommit),
      "expected source commit must be a full Git SHA",
    );
  }

  const root = resolve(directory);
  const entries = readdirSync(root, { withFileTypes: true });
  check(entries.length > 0, "release directory must not be empty");
  check(
    entries.every((entry) => entry.isFile()),
    "release directory must contain only regular files",
  );
  const names = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
  for (const name of names) {
    const path = resolve(root, name);
    check(
      basename(path) === name && lstatSync(path).isFile(),
      `release asset must be a direct regular file: ${name}`,
    );
  }

  const version = tag.slice(1);
  const manifestName = `veyra-${tag}.release-manifest.json`;
  const manifestChecksumName = `${manifestName}.sha256`;
  const repositorySbomName = `veyra-${tag}.spdx.json`;
  const requiredNames = [
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "RELEASE_NOTES.md",
    `Veyra_${version}_x64-setup.exe`,
    `Veyra_${version}_x64-setup.exe.sha256`,
    "veyra-linux-x86_64.tar.gz",
    "veyra-linux-x86_64.tar.gz.sha256",
    "veyra-windows-x86_64.zip",
    "veyra-windows-x86_64.zip.sha256",
    repositorySbomName,
    `${repositorySbomName}.sha256`,
    manifestName,
    manifestChecksumName,
  ];
  for (const name of requiredNames) {
    check(names.includes(name), `required release asset is missing: ${name}`);
  }

  const digests = new Map();
  for (const name of names) {
    digests.set(name, await sha256(resolve(root, name)));
  }

  const checksumNames = names.filter((name) => name.endsWith(".sha256"));
  check(checksumNames.length > 0, "release must contain checksum files");
  for (const checksumName of checksumNames) {
    const lines = readFileSync(resolve(root, checksumName), "ascii")
      .replaceAll("\r\n", "\n")
      .split("\n")
      .filter((line) => line.length > 0);
    check(
      lines.length === 1,
      `${checksumName} must contain exactly one checksum record`,
    );
    const match = lines[0]?.match(/^([a-f0-9]{64})  ([^/\\\r\n]+)$/);
    check(Boolean(match), `${checksumName} has malformed checksum syntax`);
    if (!match) {
      continue;
    }
    const [, digest, target] = match;
    const expectedTarget = checksumName.slice(0, -".sha256".length);
    check(
      target === expectedTarget,
      `${checksumName} must checksum only ${expectedTarget}`,
    );
    check(
      names.includes(target),
      `${checksumName} target is missing: ${target}`,
    );
    check(
      digests.get(target) === digest,
      `${checksumName} does not match ${target}`,
    );
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(resolve(root, manifestName), "utf8"));
  } catch (error) {
    failures.push(`release manifest is not valid JSON: ${error.message}`);
  }

  if (manifest) {
    check(
      manifest.schemaVersion === 1,
      "release manifest schemaVersion must be 1",
    );
    check(
      manifest.repository === repository,
      "release manifest repository mismatch",
    );
    check(manifest.tag === tag, "release manifest tag mismatch");
    check(
      /^[a-f0-9]{40}$/.test(manifest.sourceCommit ?? ""),
      "release manifest source commit must be a full Git SHA",
    );
    if (expectedSourceCommit !== undefined) {
      check(
        manifest.sourceCommit === expectedSourceCommit,
        "release manifest source commit does not match the annotated tag",
      );
    }
    check(
      /^[a-f0-9]{40}$/.test(manifest.releaseControlCommit ?? ""),
      "release manifest control commit must be a full Git SHA",
    );
    check(
      manifest.workflow === "Release artifacts",
      "release manifest workflow identity mismatch",
    );
    check(
      typeof manifest.runId === "string" && /^\d+$/.test(manifest.runId),
      "release manifest runId must be numeric text",
    );
    check(
      Number.isInteger(manifest.runAttempt) && manifest.runAttempt > 0,
      "release manifest runAttempt must be positive",
    );
    check(
      manifest.mode === "tag" || manifest.mode === "recovery",
      "release manifest mode must be tag or recovery",
    );
    if (manifest.mode === "tag") {
      check(manifest.eventName === "push", "tag mode must record a push event");
      check(
        manifest.githubRef === `refs/tags/${tag}`,
        "tag mode must record the exact tag ref",
      );
      check(
        manifest.workflowRef ===
          `${repository}/.github/workflows/release.yml@refs/tags/${tag}`,
        "tag mode workflow ref mismatch",
      );
      check(
        manifest.releaseControlCommit === manifest.sourceCommit,
        "tag mode source and release-control commits must match",
      );
    } else if (manifest.mode === "recovery") {
      check(
        manifest.eventName === "workflow_dispatch",
        "recovery mode must record workflow_dispatch",
      );
      check(
        manifest.githubRef === "refs/heads/main",
        "recovery mode must record protected main",
      );
      check(
        manifest.workflowRef ===
          `${repository}/.github/workflows/release.yml@refs/heads/main`,
        "recovery mode workflow ref mismatch",
      );
    }

    const assets = Array.isArray(manifest.assets) ? manifest.assets : [];
    check(
      Array.isArray(manifest.assets),
      "release manifest assets must be an array",
    );
    const assetNames = assets.map((asset) => asset.name);
    check(
      assetNames.every(
        (name) =>
          typeof name === "string" &&
          name.length > 0 &&
          name === basename(name) &&
          !name.includes("\\"),
      ),
      "release manifest asset names must be safe basenames",
    );
    check(
      new Set(assetNames).size === assetNames.length,
      "release manifest asset names must be unique",
    );
    check(
      assetNames.every(
        (name, index) => index === 0 || assetNames[index - 1] < name,
      ),
      "release manifest assets must be sorted by name",
    );
    check(
      !assetNames.includes(manifestName) &&
        !assetNames.includes(manifestChecksumName),
      "release manifest must not recursively inventory itself",
    );
    for (const asset of assets) {
      check(
        names.includes(asset.name),
        `manifest asset is missing: ${asset.name}`,
      );
      check(
        Number.isInteger(asset.size) && asset.size >= 0,
        `manifest asset size is invalid: ${asset.name}`,
      );
      check(
        /^[a-f0-9]{64}$/.test(asset.sha256 ?? ""),
        `manifest asset digest is invalid: ${asset.name}`,
      );
      if (names.includes(asset.name)) {
        check(
          lstatSync(resolve(root, asset.name)).size === asset.size,
          `manifest size mismatch: ${asset.name}`,
        );
        check(
          digests.get(asset.name) === asset.sha256,
          `manifest digest mismatch: ${asset.name}`,
        );
      }
    }
    check(
      sameMembers(names, [...assetNames, manifestName, manifestChecksumName]),
      "downloaded release assets must exactly match the manifest inventory plus its two files",
    );
  }

  let repositorySbom;
  try {
    repositorySbom = JSON.parse(
      readFileSync(resolve(root, repositorySbomName), "utf8"),
    );
  } catch (error) {
    failures.push(`repository SBOM is not valid JSON: ${error.message}`);
  }
  if (repositorySbom) {
    check(
      repositorySbom.spdxVersion === "SPDX-2.3",
      "repository SBOM must use SPDX 2.3",
    );
    check(
      repositorySbom.name === "veyra",
      "repository SBOM source name mismatch",
    );
    check(
      repositorySbom.creationInfo?.creators?.includes(
        `Tool: syft-${artifactSbomSyftVersion}`,
      ),
      `repository SBOM must identify pinned Syft ${artifactSbomSyftVersion}`,
    );
    const purls = (repositorySbom.packages ?? []).flatMap(packagePurls);
    check(
      purls.some((purl) => purl.startsWith("pkg:cargo/")),
      "repository SBOM must contain Cargo PURLs",
    );
    check(
      purls.some((purl) => purl.startsWith("pkg:npm/")),
      "repository SBOM must contain npm PURLs",
    );
  }

  const artifactSbomNames = names.filter(
    (name) => name.endsWith(".spdx.json") && name !== repositorySbomName,
  );
  if (artifactSbomNames.length === 0) {
    check(
      tag === "v0.1.0",
      "only the immutable v0.1.0 release may omit binary-scoped SBOMs",
    );
  } else {
    const expectedArtifactSbomNames = artifactSboms.map(({ file }) => file);
    check(
      sameMembers(artifactSbomNames, expectedArtifactSbomNames),
      "artifact SBOMs must be the complete reviewed CLI, daemon, and desktop set",
    );
    for (const definition of artifactSboms) {
      check(
        names.includes(`${definition.file}.sha256`),
        `artifact SBOM checksum is missing: ${definition.file}.sha256`,
      );
      if (!names.includes(definition.file)) {
        continue;
      }
      try {
        const result = await validateArtifactSbom({
          document: JSON.parse(
            readFileSync(resolve(root, definition.file), "utf8"),
          ),
          expectedSourceName: definition.sourceName,
          expectedRootPackage: definition.rootPackage,
          expectedVersion: version,
        });
        checks += result.checks;
      } catch (error) {
        failures.push(`${definition.file}: ${error.message}`);
      }
    }
  }

  if (failures.length > 0) {
    throw new Error(
      `Release asset verification failed with ${failures.length} problem(s):\n${failures
        .map((failure) => `- ${failure}`)
        .join("\n")}`,
    );
  }

  return { checks, artifactSbomCount: artifactSbomNames.length };
}

async function main() {
  const [tag, directory, repository, expectedSourceCommit] =
    process.argv.slice(2);
  if (!tag || !directory) {
    console.error(
      "usage: node scripts/verify-release-assets.mjs <vX.Y.Z> <directory> [owner/repository] [source-commit]",
    );
    process.exit(64);
  }
  const result = await verifyReleaseAssets({
    directory,
    tag,
    repository: repository ?? canonicalRepository,
    expectedSourceCommit,
  });
  const scope =
    result.artifactSbomCount === 0
      ? "legacy release without binary-scoped SBOMs"
      : `${result.artifactSbomCount} binary-scoped SBOMs`;
  console.log(`Release assets passed: ${result.checks} checks; ${scope}.`);
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
) {
  await main();
}
