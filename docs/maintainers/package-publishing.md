# Package registry publication

Veyra's source archives are publication-ready, but registry publication is not active. As observed
on 2026-08-25, none of the seven `veyra-*` crates or the two `@veyra/*` npm packages existed in the
public registries. A `404` is not a reservation: only a real, recoverable maintainer account can
claim a name and own its recovery path.

The manual `Package publication rehearsal` workflow is deliberately read-only. It checks an exact
annotated tag with a public immutable GitHub Release, builds every package, inspects all archives,
validates the dependency-first publication plan, exercises the leaf Cargo dry run, and runs npm
publish dry runs. It has neither `id-token: write` nor registry credentials and contains no publish
operation.

Run it from protected `main` with:

```sh
gh workflow run publish-packages.yml --repo tang-vu/veyra --ref main -f release_tag=vX.Y.Z
```

## Package order

Cargo replaces local paths with registry dependencies when packaging. Internal crates must therefore
be published and become visible in this order:

```text
veyra-protocol
veyra-executor
veyra-journal
veyra-policy
veyra-core
veyra-server
veyra-cli
```

The executor, journal, and policy crates share the same dependency level; their displayed order is
fixed only to make automation deterministic. Wait until crates.io serves each version before
publishing a dependent crate. Publish npm packages in this order:

```text
@veyra/protocol-schema
@veyra/sdk
```

`scripts/check-package-publication.mjs` derives the current internal graph from Cargo metadata and
fails if this reviewed order, compatible version requirement, package set, public access, or npm
provenance setting drifts.

## One-time registry bootstrap

Bootstrap requires an authorized human because registry ownership, two-factor authentication,
durable email, and account recovery cannot be established from repository source.

1. Create or confirm recoverable crates.io and npm accounts with two-factor authentication. Confirm
   who owns the npm `@veyra` scope and every crate; do not use an untransferable automation account.
2. Run the protected rehearsal for the exact version. Confirm the tag is annotated, the GitHub
   Release is immutable, the release manifest resolves to the tag commit, and every package version
   matches it.
3. From a clean detached checkout of that tag, publish the first crate versions in the order above,
   waiting for each registry index entry. The initial crates.io publish requires an API token by
   registry design. Keep it in Cargo's local credential store, never in a command, issue, log, or
   repository file, and revoke it after trusted publishing succeeds.
4. Claim the two npm packages from the same checkout. Because a package must already exist before an
   npm trusted publisher can be configured, the initial publish is a one-time authenticated action.
   If it occurs outside supported CI, explicitly disable provenance for that bootstrap publish and
   record the exception; all later public releases must use trusted publishing and provenance.
5. Verify ownership, public visibility, archive contents, version, README, license, and install from
   each registry before changing automation.

Package versions are immutable. Never overwrite a version. Yank or deprecate only when leaving it
available would materially harm users, document why, and publish a corrected patch version.

## Activate trusted publishing after bootstrap

Activation is a separate protected pull request and host-settings change. Do not add registry writes
to the rehearsal until every prerequisite below is observed.

- Create a GitHub environment such as `package-publishing` only when its deployment policy and
  recovery owners are real. A sole maintainer must not invent a reviewer to simulate separation of
  duties.
- On each crates.io package, configure GitHub owner `tang-vu`, repository `veyra`, workflow filename
  `publish-packages.yml`, and the exact environment name if one is used. crates.io requires the crate
  to exist first. Its official authentication Action exchanges GitHub OIDC for a short-lived token.
- On each npm package, configure the same repository and workflow filename, plus the exact
  environment if used. npm requires a supported hosted runner, `id-token: write`, npm 11.5.1 or
  newer, and Node 22.14.0 or newer; the pinned Veyra Node/npm toolchain currently satisfies those
  runtime floors. Trusted publication of a public package from this public repository produces npm
  provenance automatically.
- Pin `rust-lang/crates-io-auth-action` to a reviewed full commit SHA with a release comment, add
  only that Action pattern to the repository's selected-Action allowlist, update the hosted OSS gate,
  and grant `id-token: write` only to the individual publish jobs.
- Make publish jobs prove the exact annotated tag, immutable GitHub Release, manifest source commit,
  synchronized package versions, and absence of that version in the target registry before the
  first write. Publish crates dependency-first and wait for index visibility. Never pass an npm
  long-lived token when OIDC is active.
- After one successful OIDC release, disable other publish methods where the registry supports it,
  revoke bootstrap tokens, and rerun the quarterly owner/recovery audit.

Current primary references are the official
[crates.io trusted-publishing guide](https://crates.io/docs/trusted-publishing),
[crates.io authentication Action](https://github.com/rust-lang/crates-io-auth-action), and
[npm trusted-publisher guide](https://docs.npmjs.com/trusted-publishers/). Recheck them before
activation because registry requirements and supported OIDC claims are version-sensitive.
