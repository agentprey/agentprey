# Release Checklist

Use this checklist before publishing any beta tag.

## Preflight

- [ ] `cargo fmt --manifest-path cli/Cargo.toml --all --check`
- [ ] `cargo clippy --manifest-path cli/Cargo.toml --all-targets -- -D warnings`
- [ ] `cargo test --manifest-path cli/Cargo.toml`
- [ ] `bash scripts/beta_smoke.sh`

## Artifacts

- [ ] Confirm `release.yml` matrix includes Linux, macOS, and Windows targets
- [ ] Confirm release archives are uploaded from GitHub Actions
- [ ] Confirm checksums or archive names match expected target triples

## Docs

- [ ] README install and quick verification steps are current
- [ ] `CHANGELOG.md` includes current beta notes
- [ ] `docs/known-limitations.md` reflects current scope

## Publish

- [ ] Tag release candidate (`v0.1.0-beta.x`) or stable (`v0.1.0`)
- [ ] Confirm prerelease behavior (`v*` with `-` publishes prerelease, stable tags publish full release)
- [ ] Create release notes and artifact links
- [ ] Open beta feedback issue and pin it in repository

## Crates.io Rollout

- [ ] Bump version in `cli/Cargo.toml` and update `CHANGELOG.md`
- [ ] Run `Publish Crate` workflow with `dry_run=true`
- [ ] Re-run `Publish Crate` workflow with `dry_run=false` after approval
- [ ] Verify published metadata with `cargo info agentprey`

## User Upgrade Path

- [ ] Add update command to release notes: `cargo install agentprey --locked --force`
- [ ] Add pinned version command for rollback guidance: `cargo install agentprey --locked --version <version> --force`
