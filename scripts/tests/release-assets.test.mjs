import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { validateArtifactSbom } from "../check-artifact-sbom.mjs";
import { verifyReleaseAssets } from "../verify-release-assets.mjs";

const tag = "v0.1.0";
const version = "0.1.0";
const sourceCommit = "a".repeat(40);
const controlCommit = "b".repeat(40);
const repository = "tang-vu/veyra";

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function write(path, contents) {
  writeFileSync(path, contents);
  return contents;
}

function spdxPackage(name, versionInfo, id) {
  return {
    name,
    SPDXID: id,
    versionInfo,
    supplier: "NOASSERTION",
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:cargo/${name}@${versionInfo}`,
      },
    ],
  };
}

function artifactSpdx(sourceName, rootPackage, artifactVersion = version) {
  const fileId = `SPDXRef-DocumentRoot-File-${sourceName}`;
  const rootId = `SPDXRef-Package-${rootPackage}`;
  const dependencyId = "SPDXRef-Package-serde";
  const document = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: sourceName,
    documentNamespace: `https://anchore.com/syft/file/${sourceName}-fixture`,
    creationInfo: {
      created: "2026-08-25T00:00:00Z",
      creators: ["Organization: Anchore, Inc", "Tool: syft-1.42.3"],
    },
    packages: [
      {
        name: sourceName,
        SPDXID: fileId,
        versionInfo: `v${artifactVersion}`,
        supplier: "NOASSERTION",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        checksums: [{ algorithm: "SHA256", checksumValue: "c".repeat(64) }],
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        copyrightText: "NOASSERTION",
        primaryPackagePurpose: "FILE",
      },
      spdxPackage(rootPackage, artifactVersion, rootId),
      spdxPackage("serde", "1.0.0", dependencyId),
    ],
    relationships: [
      {
        spdxElementId: fileId,
        relationshipType: "CONTAINS",
        relatedSpdxElement: rootId,
      },
      {
        spdxElementId: rootId,
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: dependencyId,
      },
    ],
  };
  if (rootPackage === "veyra-desktop") {
    const binaryIdentityId = "SPDXRef-Package-binary-Veyra";
    document.packages.splice(1, 0, {
      name: "Veyra",
      SPDXID: binaryIdentityId,
      versionInfo: artifactVersion,
      supplier: "Organization: veyra",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "SECURITY",
          referenceType: "cpe23Type",
          referenceLocator: `cpe:2.3:a:Veyra:Veyra:${artifactVersion}:*:*:*:*:*:*:*`,
        },
      ],
    });
    document.relationships.push({
      spdxElementId: fileId,
      relationshipType: "CONTAINS",
      relatedSpdxElement: binaryIdentityId,
    });
  }
  return document;
}

const artifactDefinitions = [
  ["veyra-cli-linux-x86_64.spdx.json", "veyra-cli-linux-x86_64", "veyra-cli"],
  [
    "veyra-server-linux-x86_64.spdx.json",
    "veyra-server-linux-x86_64",
    "veyra-server",
  ],
  [
    "veyra-cli-windows-x86_64.spdx.json",
    "veyra-cli-windows-x86_64",
    "veyra-cli",
  ],
  [
    "veyra-server-windows-x86_64.spdx.json",
    "veyra-server-windows-x86_64",
    "veyra-server",
  ],
  [
    "veyra-desktop-windows-x86_64.spdx.json",
    "veyra-desktop-windows-x86_64",
    "veyra-desktop",
  ],
];

function createFixture(artifactCount = 0, fixtureTag = tag) {
  const directory = mkdtempSync(join(tmpdir(), "veyra-release-assets-"));
  const fixtureVersion = fixtureTag.slice(1);
  const files = new Map([
    ["CHANGELOG.md", "# Changelog\n"],
    ["LICENSE", "Apache-2.0\n"],
    ["README.md", "# Veyra\n"],
    ["RELEASE_NOTES.md", `# Veyra ${fixtureTag}\n`],
    [`Veyra_${fixtureVersion}_x64-setup.exe`, "installer"],
    ["veyra-linux-x86_64.tar.gz", "linux archive"],
    ["veyra-windows-x86_64.zip", "windows archive"],
    [
      `veyra-${fixtureTag}.spdx.json`,
      `${JSON.stringify({
        spdxVersion: "SPDX-2.3",
        dataLicense: "CC0-1.0",
        SPDXID: "SPDXRef-DOCUMENT",
        name: "veyra",
        documentNamespace: "https://anchore.com/syft/dir/veyra-fixture",
        creationInfo: {
          created: "2026-08-25T00:00:00Z",
          creators: ["Organization: Anchore, Inc", "Tool: syft-1.42.3"],
        },
        packages: [
          spdxPackage("serde", "1.0.0", "SPDXRef-Cargo"),
          {
            ...spdxPackage("react", "19.0.0", "SPDXRef-Npm"),
            externalRefs: [
              {
                referenceCategory: "PACKAGE-MANAGER",
                referenceType: "purl",
                referenceLocator: "pkg:npm/react@19.0.0",
              },
            ],
          },
        ],
        relationships: [],
      })}\n`,
    ],
  ]);

  for (const [name, contents] of files) {
    write(join(directory, name), contents);
  }

  for (const name of [
    `Veyra_${fixtureVersion}_x64-setup.exe`,
    "veyra-linux-x86_64.tar.gz",
    "veyra-windows-x86_64.zip",
    `veyra-${fixtureTag}.spdx.json`,
  ]) {
    const contents = files.get(name);
    const checksum = `${digest(contents)}  ${name}\n`;
    files.set(`${name}.sha256`, checksum);
    write(join(directory, `${name}.sha256`), checksum);
  }

  for (const [name, sourceName, rootPackage] of artifactDefinitions.slice(
    0,
    artifactCount,
  )) {
    const contents = `${JSON.stringify(
      artifactSpdx(sourceName, rootPackage, fixtureVersion),
    )}\n`;
    files.set(name, contents);
    write(join(directory, name), contents);
    const checksum = `${digest(contents)}  ${name}\n`;
    files.set(`${name}.sha256`, checksum);
    write(join(directory, `${name}.sha256`), checksum);
  }

  const assets = [...files.entries()]
    .map(([name, contents]) => ({
      name,
      sha256: digest(contents),
      size: Buffer.byteLength(contents),
    }))
    .sort((left, right) => (left.name < right.name ? -1 : 1));
  const manifestName = `veyra-${fixtureTag}.release-manifest.json`;
  const manifest = `${JSON.stringify(
    {
      schemaVersion: 1,
      repository,
      tag: fixtureTag,
      sourceCommit,
      releaseControlCommit: controlCommit,
      workflow: "Release artifacts",
      workflowRef: `${repository}/.github/workflows/release.yml@refs/heads/main`,
      eventName: "workflow_dispatch",
      githubRef: "refs/heads/main",
      mode: "recovery",
      runId: "12345",
      runAttempt: 1,
      assets,
    },
    null,
    2,
  )}\n`;
  write(join(directory, manifestName), manifest);
  write(
    join(directory, `${manifestName}.sha256`),
    `${digest(manifest)}  ${manifestName}\n`,
  );
  return directory;
}

async function verify(directory) {
  return verifyReleaseAssets({
    directory,
    tag,
    repository,
    expectedSourceCommit: sourceCommit,
  });
}

test("accepts the published legacy evidence contract", async () => {
  const directory = createFixture();
  try {
    const result = await verify(directory);
    assert.equal(result.artifactSbomCount, 0);
    assert.ok(result.checks > 30);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a future release without binary-scoped SBOMs", async () => {
  const directory = createFixture(0, "v1.2.3");
  try {
    await assert.rejects(
      () =>
        verifyReleaseAssets({
          directory,
          tag: "v1.2.3",
          repository,
          expectedSourceCommit: sourceCommit,
        }),
      /only the immutable v0\.1\.0 release may omit binary-scoped SBOMs/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("accepts the complete binary-scoped SBOM set", async () => {
  const directory = createFixture(artifactDefinitions.length);
  try {
    const result = await verify(directory);
    assert.equal(result.artifactSbomCount, artifactDefinitions.length);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects an unclassified non-Cargo package in a binary SBOM", async () => {
  const document = artifactSpdx("veyra-cli-linux-x86_64", "veyra-cli");
  document.packages.push({
    name: "mystery-component",
    SPDXID: "SPDXRef-Package-mystery",
    versionInfo: version,
    externalRefs: [],
  });
  await assert.rejects(
    () =>
      validateArtifactSbom({
        document,
        expectedSourceName: "veyra-cli-linux-x86_64",
        expectedRootPackage: "veyra-cli",
        expectedVersion: version,
      }),
    /every dependency package must use a Cargo PURL/,
  );
});

test("rejects a binary SBOM whose expected root PURL is absent", async () => {
  const document = artifactSpdx("veyra-cli-linux-x86_64", "veyra-cli");
  document.packages.find(
    ({ name }) => name === "veyra-cli",
  ).externalRefs[0].referenceLocator = "pkg:cargo/another-cli@0.1.0";
  await assert.rejects(
    () =>
      validateArtifactSbom({
        document,
        expectedSourceName: "veyra-cli-linux-x86_64",
        expectedRootPackage: "veyra-cli",
        expectedVersion: version,
      }),
    /exactly one pkg:cargo\/veyra-cli@0\.1\.0 root package/,
  );
});

test("rejects a binary SBOM subject digest that does not match its bytes", async () => {
  const directory = mkdtempSync(join(tmpdir(), "veyra-artifact-sbom-"));
  const binaryPath = join(directory, "veyra");
  write(binaryPath, "exact binary bytes");
  try {
    await assert.rejects(
      () =>
        validateArtifactSbom({
          document: artifactSpdx("veyra-cli-linux-x86_64", "veyra-cli"),
          expectedSourceName: "veyra-cli-linux-x86_64",
          expectedRootPackage: "veyra-cli",
          expectedVersion: version,
          binaryPath,
        }),
      /subject digest must match the exact binary bytes/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects bytes changed after the manifest and checksum", async () => {
  const directory = createFixture();
  try {
    write(join(directory, "veyra-linux-x86_64.tar.gz"), "tampered");
    await assert.rejects(
      () => verify(directory),
      /does not match|digest mismatch/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a partial artifact SBOM rollout", async () => {
  const directory = createFixture(1);
  try {
    await assert.rejects(() => verify(directory), /complete reviewed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects an asset that is absent from the immutable manifest", async () => {
  const directory = createFixture();
  try {
    write(join(directory, "orphan.txt"), "not inventoried");
    await assert.rejects(() => verify(directory), /exactly match the manifest/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("fixture manifest remains parseable for regression diagnosis", () => {
  const directory = createFixture();
  try {
    const manifest = JSON.parse(
      readFileSync(
        join(directory, `veyra-${tag}.release-manifest.json`),
        "utf8",
      ),
    );
    assert.equal(manifest.assets.length, 12);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
