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

- [ ] Tag release candidate (`v0.1.0-beta.x`)
- [ ] Create prerelease with notes and artifact links
- [ ] Open beta feedback issue and pin it in repository
