import { createReadStream, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const artifactSbomSyftVersion = "1.42.3";

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

export async function validateArtifactSbom({
  document,
  expectedSourceName,
  expectedRootPackage,
  expectedVersion,
  binaryPath,
}) {
  const failures = [];
  let checks = 0;

  function check(condition, message) {
    checks += 1;
    if (!condition) {
      failures.push(message);
    }
  }

  check(
    document !== null && typeof document === "object",
    "SBOM must be a JSON object",
  );
  check(document?.spdxVersion === "SPDX-2.3", "SBOM must use SPDX 2.3");
  check(document?.dataLicense === "CC0-1.0", "SBOM must use CC0-1.0");
  check(
    document?.name === expectedSourceName,
    `SBOM source name must be ${expectedSourceName}`,
  );
  check(
    typeof document?.documentNamespace === "string" &&
      document.documentNamespace.includes(expectedSourceName),
    "SBOM namespace must be derived from the stable artifact name",
  );
  check(
    document?.creationInfo?.creators?.includes(
      `Tool: syft-${artifactSbomSyftVersion}`,
    ),
    `SBOM must identify pinned Syft ${artifactSbomSyftVersion}`,
  );
  check(
    Array.isArray(document?.packages) && document.packages.length > 1,
    "SBOM must contain the binary subject and resolved Cargo packages",
  );

  const packages = Array.isArray(document?.packages) ? document.packages : [];
  const packageIds = packages.map((package_) => package_.SPDXID);
  check(
    packageIds.every(
      (identifier) =>
        typeof identifier === "string" && identifier.startsWith("SPDXRef-"),
    ) && new Set(packageIds).size === packageIds.length,
    "SBOM package SPDX identifiers must be present and unique",
  );

  const filePackages = packages.filter(
    (package_) => package_.primaryPackagePurpose === "FILE",
  );
  check(
    filePackages.length === 1,
    "SBOM must contain exactly one primary binary FILE package",
  );
  const filePackage = filePackages[0];
  check(
    filePackage?.name === expectedSourceName,
    "primary binary package name must match the SBOM source name",
  );
  check(
    filePackage?.versionInfo === `v${expectedVersion}`,
    `primary binary package version must be v${expectedVersion}`,
  );
  const subjectChecksums = (filePackage?.checksums ?? []).filter(
    (checksum) => checksum.algorithm === "SHA256",
  );
  check(
    subjectChecksums.length === 1 &&
      /^[a-f0-9]{64}$/.test(subjectChecksums[0]?.checksumValue ?? ""),
    "primary binary package must carry one lowercase SHA-256 digest",
  );

  const expectedRootPurl = `pkg:cargo/${expectedRootPackage}@${expectedVersion}`;
  const cargoPackages = packages.filter((package_) =>
    packagePurls(package_).some((purl) => purl.startsWith("pkg:cargo/")),
  );
  const binaryIdentityPackages = packages.filter(
    (package_) =>
      package_.primaryPackagePurpose !== "FILE" &&
      !cargoPackages.includes(package_),
  );
  const roots = packages.filter(
    (package_) =>
      package_.name === expectedRootPackage &&
      package_.versionInfo === expectedVersion &&
      packagePurls(package_).includes(expectedRootPurl),
  );
  check(
    roots.length === 1,
    `SBOM must contain exactly one ${expectedRootPurl} root package`,
  );
  check(
    binaryIdentityPackages.length <= 1 &&
      binaryIdentityPackages.every(
        (package_) =>
          package_.SPDXID?.startsWith("SPDXRef-Package-binary-") &&
          package_.versionInfo === expectedVersion &&
          (package_.externalRefs ?? []).some(
            (reference) =>
              reference.referenceCategory === "SECURITY" &&
              reference.referenceType === "cpe23Type" &&
              reference.referenceLocator?.startsWith("cpe:2.3:a:"),
          ),
      ),
    "every dependency package must use a Cargo PURL; at most one version-matched PE identity package is allowed",
  );

  check(
    Array.isArray(document?.relationships) && document.relationships.length > 0,
    "SBOM must retain dependency relationships",
  );
  const rootId = roots[0]?.SPDXID;
  check(
    typeof rootId === "string" &&
      document?.relationships?.some(
        (relationship) =>
          relationship.spdxElementId === filePackage?.SPDXID &&
          relationship.relatedSpdxElement === rootId &&
          relationship.relationshipType === "CONTAINS",
      ),
    "the primary binary must contain the expected root package",
  );
  check(
    binaryIdentityPackages.every((package_) =>
      document?.relationships?.some(
        (relationship) =>
          relationship.spdxElementId === filePackage?.SPDXID &&
          relationship.relatedSpdxElement === package_.SPDXID &&
          relationship.relationshipType === "CONTAINS",
      ),
    ),
    "the primary binary must contain every PE identity package",
  );

  if (binaryPath) {
    const binaryDigest = await sha256(binaryPath);
    check(
      binaryDigest === subjectChecksums[0]?.checksumValue,
      "SBOM subject digest must match the exact binary bytes",
    );
  }

  if (failures.length > 0) {
    throw new Error(
      `Artifact SBOM validation failed with ${failures.length} problem(s):\n${failures
        .map((failure) => `- ${failure}`)
        .join("\n")}`,
    );
  }

  return {
    checks,
    packageCount: cargoPackages.length,
    subjectSha256: subjectChecksums[0].checksumValue,
  };
}

export async function checkArtifactSbomFile({
  path,
  expectedSourceName,
  expectedRootPackage,
  expectedVersion,
  binaryPath,
}) {
  const document = JSON.parse(readFileSync(path, "utf8"));
  return validateArtifactSbom({
    document,
    expectedSourceName,
    expectedRootPackage,
    expectedVersion,
    binaryPath,
  });
}

async function main() {
  const [
    path,
    expectedSourceName,
    expectedRootPackage,
    expectedVersion,
    binary,
  ] = process.argv.slice(2);
  if (
    !path ||
    !expectedSourceName ||
    !expectedRootPackage ||
    !/^\d+\.\d+\.\d+$/.test(expectedVersion ?? "")
  ) {
    console.error(
      "usage: node scripts/check-artifact-sbom.mjs <sbom> <source-name> <root-package> <X.Y.Z> [binary]",
    );
    process.exit(64);
  }

  const result = await checkArtifactSbomFile({
    path: resolve(path),
    expectedSourceName,
    expectedRootPackage,
    expectedVersion,
    binaryPath: binary ? resolve(binary) : undefined,
  });
  console.log(
    `Artifact SBOM passed: ${result.checks} checks, ${result.packageCount} Cargo packages, subject ${result.subjectSha256}.`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
) {
  await main();
}
