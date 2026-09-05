# Pull Request Log

All notable pull requests merged into this workspace are recorded here. This log
tracks workspace-level changes (`v<VERSION>` tags); per-crate code changes are
tracked in each crate's `CHANGELOG.md` (`<crate>-v<VERSION>` tags).

## [Unreleased]

### Fixed

- deps: update dependency jci-audit to v0.1.7(pr [#147])

## [0.1.7] - 2026-09-05

### Fixed

- deps: update dependency jci-audit to v0.1.6(pr [#145])
- check aggregates failures, names licenses(pr [#146])

## [0.1.6] - 2026-09-04

### Added

- report accepted bans.skip exceptions (#49)(pr [#143])
- add --deny-unused-licenses flag(pr [#144])

### Changed

- docs-schedule #62 for v0.2.0(pr [#141])

## [0.1.5] - 2026-09-03

### Fixed

- deps: update dependency jci-audit to v0.1.4(pr [#139])
- reuse one tokio runtime per block_on client(pr [#140])

## [0.1.4] - 2026-09-03

### Changed

- chore-replace redundant method-call closures(pr [#137])

### Fixed

- deps: update dependency jci-audit to v0.1.3(pr [#132])
- accurate reason on the remote verify path(pr [#133])
- make manifest pubkey source opt-in(pr [#134])
- derive about.toml paths from cargo metadata(pr [#135])

## [0.1.3] - 2026-09-02

### Changed

- chore-group subcommand flags under headings(pr [#131])

### Fixed

- deps: update dependency jci-audit to v0.1.2(pr [#128])
- deps: lock file maintenance(pr [#129])
- deps: update dependency gen-circleci-orb to v0.1.10(pr [#130])

## [0.1.2] - 2026-09-01

### Added

- check runs cargo-about resolution too(pr [#122])

### Changed

- docs-confirm #75 phase 2 proven on v0.1.1(pr [#119])
- ci-dogfood jci-audit/check, drop licenses_policy(pr [#123])

### Fixed

- deps: update dependency jci-audit to v0.1.1(pr [#118])
- verify takes owner/repo/tag-prefix(pr [#125])

## [0.1.1] - 2026-08-29

### Added

- self-contained publish-record subcommand(pr [#112])

### Changed

- docs-mark #90 and OpenSSF Silver done in roadmap(pr [#99])
- docs-note 0.1.0 yank, add missing backlog issues(pr [#102])
- refactor-rename release subcommand to release-prep(pr [#104])
- refactor-verify fetches pubkey as a release asset(pr [#105])
- ci-sign and upload the release record (path A)(pr [#117])

### Fixed

- deps: lock file maintenance(pr [#106])
- deps: lock file maintenance(pr [#110])
- deps: update rust:1-slim-trixie docker digest to 17d1ba8(pr [#107])
- deps: update rust crate pcu-release-assets to 0.1.1(pr [#108])
- deps: update dependency jci-audit to v0.1.0(pr [#109])
- RUST_LOG="" no longer silences logging(pr [#113])
- verify's remote fetch works unauthenticated(pr [#114])
- deps: update jerusdp/ci-rust:rolling-6mo docker digest to a0be475(pr [#115])
- deps: update dependency toolkit to v7.4.0(pr [#116])

## [0.1.0] - 2026-08-25

### Added

- BREAKING: stop committing the release record to git(pr [#77])
- verify's no-checkout remote fetch path(pr [#87])

### Changed

- docs-add GOVERNANCE.md and issue/PR templates(pr [#65])
- docs-add SECURITY.md and assurance case(pr [#66])
- docs-add ROADMAP.md, architecture and design docs(pr [#67])
- docs-add RELEASING.md release verification guide(pr [#71])
- docs-add OpenSSF Best Practices evidence sheet(pr [#72])
- ci-enable draft-first GitHub releases(pr [#84])
- docs-add user guides; fix release --version flag bug(pr [#73])
- docs-track bin-only publish refactor in roadmap(pr [#91])
- refactor-publish jci-audit as bin-only(pr [#92])

### Fixed

- deps: update rust:1-slim-trixie docker digest to 8e8cf8f(pr [#68])
- deps: update dependency jci-audit to v0.0.7(pr [#69])
- deps: lock file maintenance(pr [#70])
- give -h a terse summary distinct from --help(pr [#79])
- deps: update jerusdp/ci-rust:rolling-6mo docker digest to 1fd59ba(pr [#81])
- deps: update dependency toolkit to v7.2.0(pr [#82])
- deps: update dependency gen-circleci-orb to v0.1.7(pr [#83])
- wire rsign into orb executor container(pr [#89])
- deps: lock file maintenance(pr [#85])
- deps: update dependency toolkit to v7.3.0(pr [#96])
- deps: update pinned containers(pr [#93])
- deps: update dependency gen-circleci-orb to v0.1.9(pr [#94])
- deps: update rust crate tokio to 1.53.1(pr [#95])
- deps: lock file maintenance(pr [#97])

## [0.0.6] - 2026-08-13

### Added

- derive about.toml license policy from deny.toml(pr [#64])

### Fixed

- schedule sonarcloud scan on main(pr [#61])

## [0.0.5] - 2026-08-12

### Added

- take pcu without its attestation features(pr [#47])
- summarise the tools' warnings in our own output(pr [#48])

### Fixed

- deps: lock file maintenance(pr [#50])
- deps: update dependency toolkit to v7.1.0(pr [#52])
- deps: lock file maintenance(pr [#51])
- deps: update pinned containers(pr [#53])
- deps: update dependency gen-circleci-orb to v0.1.6(pr [#54])
- deps: update dependency jci-audit to v0.0.5(pr [#55])
- deps: update rust crate clap to 4.6.6(pr [#56])
- deps: update rust crate thiserror to 2.0.20(pr [#57])
- deps: update dependency orb-tools to v12.5.0(pr [#58])
- deps: update rust crate pcu to 0.6.31(pr [#60])

## [0.0.4] - 2026-07-31

### Changed

- ci-gate on the licence policy, not on notice text(pr [#46])

### Fixed

- deps: update dependency jci-audit to v0.0.4(pr [#42])
- deps: update rust crate pcu to 0.6.30(pr [#43])
- deps: update rust crate tokio to 1.53.1(pr [#44])
- deps: update rust crate sha2 to 0.11.0(pr [#45])
- let verify reach commits it has not seen yet(pr [#41])

## [0.0.3] - 2026-07-31

### Changed

- docs-record the 0.0.3 attestation gap(pr [#38])

### Fixed

- stage the record relative to the repository(pr [#37])
- make the record commit idempotent(pr [#39])
- pin the attribution for the two vendored-source crates(pr [#40])

## [0.0.2] - 2026-07-30

### Added

- add verify command and record the policy digest(pr [#21])
- digest the dependency set, not the raw lockfile(pr [#23])
- commit and push the release record from the orb(pr [#24])
- record the release before the crate release(pr [#25])
- use the pcu library to commit and push the record(pr [#32])

### Fixed

- record the release with the binary being released(pr [#26])
- hand-roll the record job to escape the orb bootstrap(pr [#27])
- read the calculated version under its real name(pr [#28])
- give the executor a cargo toolchain(pr [#29])
- decode the signing key the way CI stores it(pr [#30])
- give the pcu client the prlog setting it requires(pr [#33])
- accept the pcu stack's licenses in cargo-about(pr [#34])

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
[#24]: https://github.com/jerus-org/jci-audit/pull/24
[#25]: https://github.com/jerus-org/jci-audit/pull/25
[#26]: https://github.com/jerus-org/jci-audit/pull/26
[#27]: https://github.com/jerus-org/jci-audit/pull/27
[#28]: https://github.com/jerus-org/jci-audit/pull/28
[#29]: https://github.com/jerus-org/jci-audit/pull/29
[#30]: https://github.com/jerus-org/jci-audit/pull/30
[#32]: https://github.com/jerus-org/jci-audit/pull/32
[#33]: https://github.com/jerus-org/jci-audit/pull/33
[#34]: https://github.com/jerus-org/jci-audit/pull/34
[#37]: https://github.com/jerus-org/jci-audit/pull/37
[#38]: https://github.com/jerus-org/jci-audit/pull/38
[#39]: https://github.com/jerus-org/jci-audit/pull/39
[#40]: https://github.com/jerus-org/jci-audit/pull/40
[#42]: https://github.com/jerus-org/jci-audit/pull/42
[#43]: https://github.com/jerus-org/jci-audit/pull/43
[#44]: https://github.com/jerus-org/jci-audit/pull/44
[#45]: https://github.com/jerus-org/jci-audit/pull/45
[#41]: https://github.com/jerus-org/jci-audit/pull/41
[#46]: https://github.com/jerus-org/jci-audit/pull/46
[#47]: https://github.com/jerus-org/jci-audit/pull/47
[#50]: https://github.com/jerus-org/jci-audit/pull/50
[#52]: https://github.com/jerus-org/jci-audit/pull/52
[#51]: https://github.com/jerus-org/jci-audit/pull/51
[#53]: https://github.com/jerus-org/jci-audit/pull/53
[#54]: https://github.com/jerus-org/jci-audit/pull/54
[#55]: https://github.com/jerus-org/jci-audit/pull/55
[#56]: https://github.com/jerus-org/jci-audit/pull/56
[#57]: https://github.com/jerus-org/jci-audit/pull/57
[#58]: https://github.com/jerus-org/jci-audit/pull/58
[#60]: https://github.com/jerus-org/jci-audit/pull/60
[#48]: https://github.com/jerus-org/jci-audit/pull/48
[#61]: https://github.com/jerus-org/jci-audit/pull/61
[#64]: https://github.com/jerus-org/jci-audit/pull/64
[#65]: https://github.com/jerus-org/jci-audit/pull/65
[#66]: https://github.com/jerus-org/jci-audit/pull/66
[#67]: https://github.com/jerus-org/jci-audit/pull/67
[#68]: https://github.com/jerus-org/jci-audit/pull/68
[#69]: https://github.com/jerus-org/jci-audit/pull/69
[#70]: https://github.com/jerus-org/jci-audit/pull/70
[#71]: https://github.com/jerus-org/jci-audit/pull/71
[#72]: https://github.com/jerus-org/jci-audit/pull/72
[#77]: https://github.com/jerus-org/jci-audit/pull/77
[#79]: https://github.com/jerus-org/jci-audit/pull/79
[#81]: https://github.com/jerus-org/jci-audit/pull/81
[#82]: https://github.com/jerus-org/jci-audit/pull/82
[#83]: https://github.com/jerus-org/jci-audit/pull/83
[#84]: https://github.com/jerus-org/jci-audit/pull/84
[#89]: https://github.com/jerus-org/jci-audit/pull/89
[#87]: https://github.com/jerus-org/jci-audit/pull/87
[#85]: https://github.com/jerus-org/jci-audit/pull/85
[#73]: https://github.com/jerus-org/jci-audit/pull/73
[#91]: https://github.com/jerus-org/jci-audit/pull/91
[#96]: https://github.com/jerus-org/jci-audit/pull/96
[#93]: https://github.com/jerus-org/jci-audit/pull/93
[#94]: https://github.com/jerus-org/jci-audit/pull/94
[#95]: https://github.com/jerus-org/jci-audit/pull/95
[#97]: https://github.com/jerus-org/jci-audit/pull/97
[#92]: https://github.com/jerus-org/jci-audit/pull/92
[#99]: https://github.com/jerus-org/jci-audit/pull/99
[#102]: https://github.com/jerus-org/jci-audit/pull/102
[#104]: https://github.com/jerus-org/jci-audit/pull/104
[#106]: https://github.com/jerus-org/jci-audit/pull/106
[#110]: https://github.com/jerus-org/jci-audit/pull/110
[#107]: https://github.com/jerus-org/jci-audit/pull/107
[#108]: https://github.com/jerus-org/jci-audit/pull/108
[#109]: https://github.com/jerus-org/jci-audit/pull/109
[#105]: https://github.com/jerus-org/jci-audit/pull/105
[#112]: https://github.com/jerus-org/jci-audit/pull/112
[#113]: https://github.com/jerus-org/jci-audit/pull/113
[#114]: https://github.com/jerus-org/jci-audit/pull/114
[#115]: https://github.com/jerus-org/jci-audit/pull/115
[#116]: https://github.com/jerus-org/jci-audit/pull/116
[#117]: https://github.com/jerus-org/jci-audit/pull/117
[#118]: https://github.com/jerus-org/jci-audit/pull/118
[#119]: https://github.com/jerus-org/jci-audit/pull/119
[#122]: https://github.com/jerus-org/jci-audit/pull/122
[#123]: https://github.com/jerus-org/jci-audit/pull/123
[#125]: https://github.com/jerus-org/jci-audit/pull/125
[#128]: https://github.com/jerus-org/jci-audit/pull/128
[#129]: https://github.com/jerus-org/jci-audit/pull/129
[#130]: https://github.com/jerus-org/jci-audit/pull/130
[#131]: https://github.com/jerus-org/jci-audit/pull/131
[#132]: https://github.com/jerus-org/jci-audit/pull/132
[#133]: https://github.com/jerus-org/jci-audit/pull/133
[#134]: https://github.com/jerus-org/jci-audit/pull/134
[#135]: https://github.com/jerus-org/jci-audit/pull/135
[#137]: https://github.com/jerus-org/jci-audit/pull/137
[#139]: https://github.com/jerus-org/jci-audit/pull/139
[#140]: https://github.com/jerus-org/jci-audit/pull/140
[#141]: https://github.com/jerus-org/jci-audit/pull/141
[#143]: https://github.com/jerus-org/jci-audit/pull/143
[#144]: https://github.com/jerus-org/jci-audit/pull/144
[#145]: https://github.com/jerus-org/jci-audit/pull/145
[#146]: https://github.com/jerus-org/jci-audit/pull/146
[#147]: https://github.com/jerus-org/jci-audit/pull/147
[Unreleased]: https://github.com/jerus-org/jci-audit/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/jerus-org/jci-audit/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/jerus-org/jci-audit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/jerus-org/jci-audit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/jerus-org/jci-audit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/jerus-org/jci-audit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/jerus-org/jci-audit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jerus-org/jci-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jerus-org/jci-audit/compare/v0.0.6...v0.1.0
[0.0.6]: https://github.com/jerus-org/jci-audit/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/jerus-org/jci-audit/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/jerus-org/jci-audit/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/jerus-org/jci-audit/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/jerus-org/jci-audit/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/jerus-org/jci-audit/releases/tag/v0.0.1
