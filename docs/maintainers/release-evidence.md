# Release evidence and consumer verification

Veyra publishes several complementary evidence layers. None of them alone proves that a binary is
safe, signed by a platform vendor, reproducible, or free from a compromised build dependency.

| Evidence           | What it binds                                                                                                           | What it does not claim                                                                   |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Sibling SHA-256    | Downloaded bytes to a small reviewable digest file                                                                      | Publisher identity                                                                       |
| Release manifest   | Every uploaded asset to the source tag, release-control commit, workflow, and run                                       | An independently trusted build                                                           |
| GitHub attestation | Archive, installer, SBOM, or manifest digest to the `release.yml` GitHub-hosted build identity                          | Windows platform signing or reproducibility                                              |
| Repository SBOM    | Cargo and npm dependencies discoverable in the exact source checkout                                                    | The dependency set linked into one executable                                            |
| Binary SBOM        | Cargo metadata embedded in one release executable and its exact file SHA-256                                            | NSIS bootstrapper, native libraries not represented by Cargo, or supply-chain prevention |
| Consumer workflow  | Public evidence validation, exact installed-payload digest binding, and extracted CLI/daemon execution on clean runners | External user adoption or every supported environment                                    |

The release build uses pinned [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable)
0.7.5 to embed dependency metadata in the CLI, daemon, and Windows desktop payload. The reviewed
release is maintained by the Rust Secure Code project, supports Linux/Windows/macOS, and is dual
MIT/Apache-2.0 licensed; it is a release-build tool and is not linked into Veyra. Its own locked
dependency set is honored during installation. Pinned Syft 1.42.3 reads each executable and emits
these five SPDX 2.3 documents:

```text
veyra-cli-linux-x86_64.spdx.json
veyra-server-linux-x86_64.spdx.json
veyra-cli-windows-x86_64.spdx.json
veyra-server-windows-x86_64.spdx.json
veyra-desktop-windows-x86_64.spdx.json
```

Each document has a sibling checksum and provenance attestation. The release gate requires the
expected root crate, Cargo PURLs, dependency relationships, stable artifact identity, and a primary
`FILE` package whose digest matches the exact executable. Post-publication verification extracts
both CLI/daemon archives and the NSIS installer and compares all five shipped payloads with those
subject digests.

On PE files, Syft may also emit one binary-identity package from the executable's version-resource
cataloger. The validator accepts it only when its normalized name is bound to the expected Veyra
binary and its metadata is either the expected version plus CPE references or Syft's explicit
`UNKNOWN` value with no references. Other non-Cargo packages remain a hard failure.

The desktop build passes Tauri an explicit auditable Cargo runner. After Tauri creates the installer,
the release job extracts its exact `veyra-desktop.exe` payload and scans those bytes; the public
consumer job independently repeats that extraction before checking the subject digest. The desktop
SBOM therefore binds the installed Rust payload, but it does not inventory the NSIS bootstrapper,
installer plug-ins, WebView runtime, or native components that Cargo metadata does not represent.
That limitation stays explicit until an installer-aware inventory is implemented. Stable Cargo
metadata can also include dependencies that were resolved for the workspace but not linked and does
not reliably enumerate statically linked C libraries. An SBOM is inventory evidence, not protection
from a malicious dependency.

## Verify a downloaded release

From a protected-main checkout containing the current verifier:

```sh
gh release download vX.Y.Z --repo tang-vu/veyra --dir dist
node scripts/verify-release-assets.mjs vX.Y.Z dist tang-vu/veyra <annotated-tag-commit>
```

The verifier rejects malformed or partial checksum sets, path-shaped manifest entries, missing or
orphaned assets, byte-size/digest drift, source/tag mismatch, invalid workflow mode, incomplete
binary SBOM rollout, and missing Cargo/npm scope. It accepts v0.1.0 as a documented legacy release
without binary-scoped SBOMs; immutable historical assets are never rewritten to retrofit evidence.

The `Release consumer verification` workflow performs the complete remote check on every newly
published release, every Monday, and on manual dispatch. It resolves the annotated tag through the
GitHub API, requires a public non-prerelease immutable Release, verifies the exact `release.yml`
signer while denying self-hosted build attestations, binds archive and installed desktop payloads to
binary SBOM subjects, and runs version, demo, unauthenticated-denial, and authenticated-health probes
from freshly downloaded Linux and Windows archives.

An unpublishing build-only dispatch uses a run-scoped `build-<run-id>` evidence identifier rather
than a branch name. This keeps SBOM paths stable and path-safe even when the source branch contains
slashes, while real tag and protected recovery runs retain their exact `vX.Y.Z` asset names.
