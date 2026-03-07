# Release Checklist

Use this checklist before publishing any beta tag or calling a release candidate credible.

## Automated verification

- [ ] `cargo fmt --manifest-path cli/Cargo.toml --all --check`
- [ ] `cargo clippy --manifest-path cli/Cargo.toml --all-targets -- -D warnings`
- [ ] `cargo test --manifest-path cli/Cargo.toml`
- [ ] `bash scripts/beta_smoke.sh`
- [ ] `bash scripts/openclaw_smoke.sh`
- [ ] `bash scripts/release_candidate_smoke.sh`
- [ ] Upload/share smoke decision is explicit:
  Run with `AGENTPREY_UPLOAD_SMOKE=1 AGENTPREY_API_KEY=... AGENTPREY_API_URL=... bash scripts/release_candidate_smoke.sh`
  or record an intentional skip for this release candidate.

## Manual product QA

- [ ] Replay demo page QA (`agentprey-web /scan`)
- [ ] Checkout success claim QA (`agentprey-web /checkout/success`)
- [ ] Recovery flow QA (`agentprey-web /recover`)
- [ ] Direct share link QA (`agentprey-web /reports/[share_id]`)
- [ ] TUI manual screenshot check from a real CLI scan
- [ ] HTTP scan artifact spot-check (`scan.json`, `scan.html`)
- [ ] OpenClaw local-path scan artifact spot-check

## Docs and release notes

- [ ] README install and quickstart steps are current
- [ ] `docs/known-limitations.md` reflects current scope
- [ ] Release notes include upload/share behavior and limitations
- [ ] Release notes include install command: `curl -fsSL https://agentprey.com/install | sh`
- [ ] Release notes include upgrade command: `cargo install agentprey --locked --force`
- [ ] Release notes include rollback guidance: `cargo install agentprey --locked --version <version> --force`

## Packaging and publish

- [ ] Confirm release workflow still builds Linux, macOS, and Windows artifacts
- [ ] Confirm release archives and `.sha256` checksum sidecars match expected target triples
- [ ] Tag release candidate (`v0.1.0-beta.x`) or stable (`v0.1.0`)
- [ ] Confirm prerelease behavior (`v*` with `-` publishes prerelease, stable tags publish full release)
- [ ] Open or refresh the beta feedback issue and pin it in the repository

## Crates.io rollout

- [ ] Bump version in `cli/Cargo.toml`
- [ ] Update `CHANGELOG.md`
- [ ] Run `Publish Crate` workflow with `dry_run=true`
- [ ] Re-run `Publish Crate` workflow with `dry_run=false` after approval
- [ ] Verify published metadata with `cargo info agentprey`
