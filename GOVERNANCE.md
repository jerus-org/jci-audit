<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Project Governance

This document describes how the **jci-audit** project is governed: its
decision-making model, the roles and responsibilities within the project, who holds
those roles, and how continuity of the project is assured.

## Governance model

jci-audit uses a **single-maintainer ("benevolent dictator")** governance model. The
maintainer is responsible for the overall direction of the project and has final
authority over decisions. This model suits the project's current size and scope. The
project is hosted within the [`jerus-org`](https://github.com/jerus-org) GitHub
organisation, which provides institutional continuity independent of any one
individual.

Decisions are made openly on GitHub (issues and pull requests). The maintainer seeks
consensus with contributors where practical; where consensus cannot be reached, the
maintainer decides. All substantive changes flow through pull requests and are
subject to the project's automated CI checks and review.

## Roles and responsibilities

| Role | Responsibilities | Who holds it |
|------|------------------|--------------|
| **Maintainer** | Sets roadmap and priorities; reviews and merges pull requests; cuts and signs releases of the crate and its generated orb; responds to security reports; administers CI/CD, secrets, and signing keys; upholds the Code of Conduct. | Jeremiah Russell ([@jerusdp](https://github.com/jerusdp)) |
| **Organisation owners** | Hold administrative ownership of the `jerus-org` GitHub organisation and the repository; can grant/restore access and appoint maintainers. Provide continuity if the maintainer becomes unavailable. | `jerus-org` organisation owners |
| **Contributors** | Anyone who reports issues, proposes changes, reviews pull requests, or improves documentation. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). | The community |

The current maintainer and code owner of record is `@jerusdp` (see
[`.github/CODEOWNERS`](.github/CODEOWNERS)). Community and conduct matters are handled
via `community@jerus.ie`.

## Decision making

- **Routine changes** (bug fixes, documentation, dependency updates) — merged by the
  maintainer after review and green CI.
- **Significant changes** (new features, breaking changes, changes to the advisory/
  license policy model, or the security posture) — discussed in an issue or pull
  request before implementation; the maintainer makes the final call.
- **Governance changes** — proposed via pull request to this document and approved by
  the maintainer / organisation owners.

## Access and continuity

Continuity of the project does not depend on any single individual's day-to-day
availability:

- The repository and its settings are owned by the **`jerus-org` GitHub
  organisation**. Organisation owners retain administrative access and can restore or
  delegate repository access within one week if the maintainer becomes unavailable.
- **Publishing rights** to the crate on crates.io and the orb on the CircleCI orb
  registry are held at the organisation/owner level so that releases can continue.
- **CI/CD, signing keys, and secrets** are managed through organisation-level
  contexts and documented processes rather than personal accounts, so that a
  successor maintainer can operate the release pipeline.

If the maintainer is unavailable for an extended period, organisation owners may
appoint an interim or replacement maintainer to keep the project active.

## Bus factor (known limitation)

The project currently has an effective **bus factor of one**: day-to-day maintenance
is performed by a single maintainer. The OpenSSF Best Practices *Silver* criterion
`bus_factor` recommends two or more people with significant knowledge of the project.
This is a recognised limitation, mitigated by:

- Organisation-level ownership and access (above), so the project can survive and be
  handed over even though a single person maintains it day to day.
- Heavily automated, documented CI/CD and release processes that reduce the tacit
  knowledge required to operate the project.
- Comprehensive documentation ([`docs/`](docs/), `README.md`,
  [CONTRIBUTING.md](CONTRIBUTING.md)).

The project actively welcomes additional maintainers to raise the bus factor (see
below).

## Becoming a maintainer

Contributors who demonstrate sustained, high-quality contributions and good judgement
— and who engage constructively with the community — may be invited by the maintainer
or organisation owners to become maintainers. There is no fixed quota; the goal is to
grow a healthy, resilient set of maintainers over time.

## Code of Conduct

All participants are expected to follow the project
[Code of Conduct](CODE_OF_CONDUCT.md). Enforcement is handled by the community leaders
at `community@jerus.ie`.
