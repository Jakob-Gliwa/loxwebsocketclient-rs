# Releasing

Releases go to crates.io from CI only. No registry credential is stored
anywhere: the `publish` job in [.github/workflows/release.yml](.github/workflows/release.yml)
exchanges its GitHub OIDC identity for a crates.io token that expires after 30
minutes ([Trusted Publishing](https://crates.io/docs/trusted-publishing)).

## Cutting a release

1. Bump `version` in `Cargo.toml`.
2. `cargo update --workspace` so `Cargo.lock` records the new version, then run
   `cargo test --all-targets --locked` and `cargo test --doc --locked`.
3. Commit, push to `main`, wait for CI to go green.
4. Tag the commit CI validated and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "loxwebsocket X.Y.Z"
   git push origin vX.Y.Z
   ```

5. The tag starts the `Release` workflow. It re-runs the whole lint/test/MSRV
   matrix against the tagged commit, then stops in front of the `release`
   environment. Approve it under Actions, in the running workflow, via *Review
   deployments*.
6. The job refuses to continue if the tag and `Cargo.toml` disagree, then
   publishes and opens a GitHub Release for the tag.

## Checking the setup without releasing

Run `Release` manually with `dry_run: true` (Actions, *Release*, *Run
workflow*). It performs the OIDC exchange and `cargo publish --dry-run`, which
proves the trusted publisher configuration still works without burning a
version number. Worth doing after renaming anything the OIDC claim covers.

## One-time configuration

Already in place, recorded here because breaking it is easy and the error
messages are unhelpful:

- crates.io, crate `loxwebsocket`, Settings, Trusted Publishing: repository
  `Jakob-Gliwa/loxwebsocketclient-rs`, workflow filename `release.yml`,
  environment `release`. All three are matched against the OIDC claim, so
  renaming the workflow file or the environment stops publishing until the
  configuration is updated to match.
- GitHub, Settings, Environments, `release`: required reviewer, and deployments
  restricted to tags matching `v*`.

Version 0.1.0 was published once by hand with a temporary API token that was
revoked afterwards, because Trusted Publishing cannot create a crate that does
not exist yet — it only ever gets the `publish-update` scope.
