# Pull Request Log

All notable pull requests merged into this workspace are recorded here. This log
tracks workspace-level changes (`v<VERSION>` tags); per-crate code changes are
tracked in each crate's `CHANGELOG.md` (`<crate>-v<VERSION>` tags).

## [Unreleased]

### Added

- add verify command and record the policy digest(pr [#21])
- digest the dependency set, not the raw lockfile(pr [#23])

## [0.0.1] - 2026-07-28

### Added

- scaffold jci-audit workspace (P0)(pr [#1])
- implement sync and init commands (P1)(pr [#3])
- implement check command (P1)(pr [#4])
- generate jci-audit orb with executor tools(pr [#12])
- implement prune stale-ignore detector (P2)(pr [#16])
- implement release gate with locked advisory snapshot (P3)(pr [#17])

### Changed

- docs-add missing PR #1 to PRLOG(pr [#5])
- refactor-invoke tools as standalone binaries(pr [#11])

### Fixed

- deps: lock file maintenance(pr [#9])
- deps: update rust crate clap to 4.6.4(pr [#6])
- deps: update rust crate trycmd to 1.2.1(pr [#7])
- deps: update rust crate toml_edit to 0.25.13(pr [#8])
- deps: update dependency toolkit to v7(pr [#10])
- deps: lock file maintenance(pr [#13])
- deps: update dependency gen-circleci-orb to v0.1.4(pr [#14])
- deps: update dependency orb-tools to v12.4.0(pr [#15])
- set initial version baseline to 0.0.0(pr [#18])
- add binstall signing scaffold for pubkey injection(pr [#19])
- seed the crate CHANGELOG.md(pr [#20])

[#1]: https://github.com/jerus-org/jci-audit/pull/1
[#3]: https://github.com/jerus-org/jci-audit/pull/3
[#4]: https://github.com/jerus-org/jci-audit/pull/4
[#5]: https://github.com/jerus-org/jci-audit/pull/5
[#9]: https://github.com/jerus-org/jci-audit/pull/9
[#6]: https://github.com/jerus-org/jci-audit/pull/6
[#7]: https://github.com/jerus-org/jci-audit/pull/7
[#8]: https://github.com/jerus-org/jci-audit/pull/8
[#10]: https://github.com/jerus-org/jci-audit/pull/10
[#11]: https://github.com/jerus-org/jci-audit/pull/11
[#12]: https://github.com/jerus-org/jci-audit/pull/12
[#13]: https://github.com/jerus-org/jci-audit/pull/13
[#14]: https://github.com/jerus-org/jci-audit/pull/14
[#15]: https://github.com/jerus-org/jci-audit/pull/15
[#16]: https://github.com/jerus-org/jci-audit/pull/16
[#17]: https://github.com/jerus-org/jci-audit/pull/17
[#18]: https://github.com/jerus-org/jci-audit/pull/18
[#19]: https://github.com/jerus-org/jci-audit/pull/19
[#20]: https://github.com/jerus-org/jci-audit/pull/20
[#21]: https://github.com/jerus-org/jci-audit/pull/21
[#23]: https://github.com/jerus-org/jci-audit/pull/23
[Unreleased]: https://github.com/jerus-org/jci-audit/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/jerus-org/jci-audit/releases/tag/v0.0.1
