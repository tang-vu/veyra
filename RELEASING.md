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
   without them.
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
Windows binaries plus the unsigned Windows desktop installer, generates an SPDX 2.3 repository
dependency snapshot from the exact checkout with the full-SHA-pinned Anchore SBOM Action and pinned
Syft version, verifies checksums, and creates GitHub/Sigstore provenance attestations at each build
boundary. The SBOM gate requires both Cargo and npm package URLs so a partial ecosystem scan cannot
silently pass. Each packaged CLI/daemon archive must also run its version probe, daemon help path,
and deterministic reversible demo on its target runner. The workflow then creates a draft GitHub
Release with curated and generated notes, attaches every archive, checksum, and SBOM, and only then
publishes the immutable release. A failed draft must be inspected before an authorized maintainer
removes or replaces it; the workflow never edits a published release. Package-registry publication
remains a separate, explicit maintainer action until trusted publishing is configured.

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

Download release assets on a clean machine, check every `.sha256` file, and verify provenance:

```sh
gh release download vX.Y.Z --repo tang-vu/veyra --dir dist
cd dist
for checksum in *.sha256; do sha256sum --check "$checksum"; done
gh attestation verify ./veyra-linux-x86_64.tar.gz --repo tang-vu/veyra
gh attestation verify ./veyra-vX.Y.Z.release-manifest.json --repo tang-vu/veyra
```

Confirm that the attested release manifest's `sourceCommit` resolves from the immutable tag and that
every listed digest matches its downloaded asset. Smoke-test `veyra demo --json`, daemon
authentication, and the supported desktop flow from the downloaded artifacts. Record any signing or
platform limitation in the release notes. Never replace an asset under an existing version; issue a
new patch release, and yank a registry package only when leaving it available would materially harm
users.
