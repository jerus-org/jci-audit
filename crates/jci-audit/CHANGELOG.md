<!-- LTex: Enabled=false -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-07-30

Summary: Added[5], Fixed[6]

### Added

 - feat: use the pcu library to commit and push the record
 - feat: record the release before the crate release
 - feat: commit and push the release record from the orb
 - feat: digest the dependency set, not the raw lockfile
 - feat: add verify command and record the policy digest

### Fixed

 - fix: accept the pcu stack's licenses in cargo-about
 - fix: give the pcu client the prlog setting it requires
 - fix: push the record with credentials the branch rules accept
 - fix: decode the signing key the way CI stores it
 - fix: read the calculated version under its real name
 - fix: seed the crate CHANGELOG.md

## [0.0.2] - 2026-07-28

Summary: Chore[1]

## [0.0.1] - 2026-07-28

Summary: Added[4], Changed[1], Chore[2], Documentation[1], Fixed[5]

### Added

 - feat: implement release gate with locked advisory snapshot
 - feat: implement prune stale-ignore detector
 - feat: implement check command
 - feat: implement sync and init commands

### Fixed

 - fix: add binstall signing scaffold for pubkey injection
 - fix: set initial version baseline to 0.0.0
 - fix(deps): update rust crate toml_edit to 0.25.13
 - fix(deps): update rust crate trycmd to 1.2.1
 - fix(deps): update rust crate clap to 4.6.4

### Changed

 - refactor: invoke tools as standalone binaries

[Unreleased]: https://github.com/jerus-org/jci-audit/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/jerus-org/jci-audit/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/jerus-org/jci-audit/releases/tag/v0.0.1

