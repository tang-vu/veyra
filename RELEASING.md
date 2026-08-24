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
   bash ./scripts/verify.sh
   ```

   PowerShell maintainers use `./scripts/verify.ps1`. Also build and smoke-test the platform release
   artifacts described in `PROGRESS.md`.

6. Review `npm pack --dry-run --json` for each public JavaScript package and `cargo package --list`
   for each publishable Rust crate. Every archive must contain its README and Apache-2.0 license and
   must not contain credentials, local databases, test output, or unrelated repository files.
   `corepack pnpm package:check` performs these checks for every current public archive.
7. Have another maintainer review security-sensitive releases when one is available.

## Tag and publish artifacts

Create an annotated tag from the reviewed release commit; use a signed tag when project signing
infrastructure is available:

```sh
git tag -a vX.Y.Z -m "Veyra vX.Y.Z"
git push origin vX.Y.Z
```

The tag workflow builds locked Linux and Windows binaries plus the unsigned Windows desktop
installer. It verifies checksums, creates GitHub/Sigstore build-provenance attestations, and then
creates the GitHub Release with archives and checksum files. Package-registry publication remains a
separate, explicit maintainer action until trusted publishing is configured.

The attestation step stays inside each build job, immediately after packaging, as required by
[GitHub's provenance guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Verify the published release

Download release assets on a clean machine, check every `.sha256` file, and verify provenance:

```sh
gh release download vX.Y.Z --repo tang-vu/veyra --dir dist
cd dist
for checksum in *.sha256; do sha256sum --check "$checksum"; done
gh attestation verify ./veyra-linux-x86_64.tar.gz --repo tang-vu/veyra
```

Smoke-test `veyra demo --json`, daemon authentication, and the supported desktop flow from the
downloaded artifacts. Record any signing or platform limitation in the release notes. Never replace
an asset under an existing version; issue a new patch release, and yank a registry package only when
leaving it available would materially harm users.
