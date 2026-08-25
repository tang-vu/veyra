# Releasing Veyra

Only maintainers authorized by [GOVERNANCE.md](GOVERNANCE.md) may publish a tag, package, or release.
Automated contributors may prepare a release change locally, but must never push a tag, publish a
package, change repository settings, or create a public release without explicit maintainer action.

## Prepare the release

1. Choose the semantic version and document any pre-1.0 compatibility break. Synchronize the
   workspace version in `Cargo.toml`, all four JavaScript workspace package versions, the Tauri version in
   `apps/desktop/src-tauri/tauri.conf.json`, and affected lockfiles.
2. Move completed entries from `Unreleased` to a dated changelog section and update comparison links.
3. For protocol, persistence, authority, or adapter-contract changes, finish the required VEP/ADR,
   migrations, schemas, compatibility fixtures, SDK types, threat model, and adversarial evals.
4. Regenerate `evals/results/latest.json` on the release revision. Review every environment-limited
   result and known limitation rather than converting it to a pass.
5. Run the complete local gate from a clean tree:

   ```sh
   corepack pnpm install --frozen-lockfile
   corepack pnpm oss:check
   corepack pnpm release:check
   bash ./scripts/verify.sh
   ```

   PowerShell maintainers use `./scripts/verify.ps1`. Also build and smoke-test the platform release
   artifacts described in `PROGRESS.md`.

6. Create `docs/releases/vX.Y.Z.md` with download verification, trust-boundary limitations,
   platform-signing status, package-registry status, open advisory disposition, and SBOM scope. The
   tag workflow prepends these curated notes to GitHub's generated change list and refuses a tag
   without them. These notes are dual-use GitHub Release metadata: use absolute, tag-pinned HTTPS
   links for repository documents and verify their rendered targets rather than relying on the
   source file's relative path context.
7. Review `npm pack --dry-run --json` for each public JavaScript package and `cargo package --list`
   for each publishable Rust crate. Every archive must contain its README and Apache-2.0 license and
   must not contain credentials, local databases, test output, or unrelated repository files.
   `corepack pnpm package:check` performs these checks for every current public archive.
8. Have another maintainer review security-sensitive releases when one is available.

## Tag and publish artifacts

Create an annotated tag from the reviewed release commit; use a signed tag when project signing
infrastructure is available:

```sh
git tag -a vX.Y.Z -m "Veyra vX.Y.Z"
git push origin vX.Y.Z
```

The tag workflow first rejects any version or release-note mismatch. It builds locked Linux and
Windows binaries plus the unsigned Windows desktop installer. Pinned `cargo-auditable` embeds Cargo
dependency metadata in each CLI and daemon and in the desktop build through Tauri's explicit Cargo
runner. The workflow extracts the exact desktop executable from the completed NSIS installer before
the full-SHA-pinned Anchore SBOM Action and pinned Syft version generate five binary-scoped SPDX 2.3
documents. The gate validates each expected root crate, Cargo PURLs, relationships, stable artifact
identity, and exact executable digest. It separately generates the multi-ecosystem repository
dependency snapshot and requires both Cargo and npm package URLs so a partial source scan cannot
silently pass.

Every SBOM has a sibling checksum and is attested in its build job. The desktop inventory describes
the installed Rust payload extracted from NSIS, not the NSIS bootstrapper or unreported native
toolchain components; see
[release evidence scope](docs/maintainers/release-evidence.md). Each packaged CLI/daemon archive must
also run its version probe, daemon help path, and deterministic reversible demo on its target runner.
The workflow then creates a draft GitHub Release with curated and generated notes, attaches every
archive, checksum, and SBOM, and only then publishes the immutable release. A failed draft must be
inspected before an authorized maintainer removes or replaces it; the workflow never edits a
published release. Package-registry publication remains separate and rehearsal-only until the
[trusted-publishing prerequisites](docs/maintainers/package-publishing.md) are satisfied.

The attestation step stays inside each build job, immediately after packaging, as required by
[GitHub's provenance guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Recover an unpublished tagged release

Use recovery only when an immutable annotated tag exists but the tag workflow failed before creating
a GitHub Release. Never delete, recreate, or move the tag. First confirm that no draft or published
release exists, fix the release workflow through the normal protected-main pull-request path, and run
a build-only dry run of that reviewed workflow:

```sh
gh release view vX.Y.Z --repo tang-vu/veyra
gh workflow run release.yml --repo tang-vu/veyra --ref main
```

The first command must report that the release does not exist. After the dry run passes, an
authorized maintainer may rebuild and publish the existing tag with:

```sh
gh workflow run release.yml --repo tang-vu/veyra --ref main -f release_tag=vX.Y.Z
```

Recovery is accepted only from `refs/heads/main`. Every build job checks out the supplied tag, and
the contract proves it is annotated and resolves to the exact detached checkout before builds start.
The release-control revision from protected `main` supplies the reviewed workflow and corrected
curated notes; product source, binaries, and dependency scan remain tag-scoped. Recovery reruns all
builds, target-platform smoke tests, checksums, and attestations rather than reusing unverifiable
partial output. It still refuses any existing release and preserves draft-first publication.

## Verify the published release

Download release assets on a clean machine and run the protected verifier with the annotated tag's
commit. Then independently verify provenance for primary artifacts:

```sh
gh release download vX.Y.Z --repo tang-vu/veyra --dir dist
node scripts/verify-release-assets.mjs vX.Y.Z dist tang-vu/veyra <annotated-tag-commit>
gh attestation verify ./dist/veyra-linux-x86_64.tar.gz \
  --repo tang-vu/veyra \
  --signer-workflow tang-vu/veyra/.github/workflows/release.yml \
  --deny-self-hosted-runners
gh attestation verify ./dist/veyra-vX.Y.Z.release-manifest.json \
  --repo tang-vu/veyra \
  --signer-workflow tang-vu/veyra/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

Confirm that the attested release manifest's `sourceCommit` resolves from the immutable tag and that
every listed digest matches its downloaded asset. Smoke-test `veyra demo --json`, daemon
authentication, and the supported desktop flow from the downloaded artifacts. Record any signing or
platform limitation in the release notes. Never replace an asset under an existing version; issue a
new patch release, and yank a registry package only when leaving it available would materially harm
users. The scheduled `Release consumer verification` workflow repeats tag, manifest, checksum,
attestation, binary-SBOM subject, Linux, and Windows checks against the latest public Release.
