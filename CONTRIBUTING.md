# Contributing to jci-audit

Thanks for your interest in contributing! This project is maintained by
[jerus-org](https://github.com/jerus-org).

## Ground rules

- Be respectful — see the [Code of Conduct](CODE_OF_CONDUCT.md).
- All changes go through a **pull request**; never commit directly to `main`.
- Discuss significant changes in an issue first.

## Development workflow

1. Fork and branch from the latest `main`
   (`feat/…`, `fix/…`, `docs/…`, `chore/…`, `refactor/…`).
2. **RED/GREEN TDD** — write a failing test that pins the behaviour before you
   implement it. Every bug fix ships with a regression test; every new feature
   ships with tests.
3. Keep the tree green:

   ```bash
   just fmt          # format (nightly rustfmt + stable check)
   just clippy       # cargo clippy --all --tests --all-features -- -D warnings
   just test         # clippy + check + doc + unit/CLI tests
   just audit        # cargo deny (advisories, bans, licenses, sources)
   just msrv         # verify the declared MSRV builds
   ```

4. Update `THIRD-PARTY-LICENSES.md` if dependencies changed (`just licenses`).

## Coding standards

- **Rust edition 2024**, MSRV **1.85**. Follow the
  [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- `rustfmt` (config in `rustfmt.toml` / `rustfmt-nightly.toml`) and `clippy`
  with `-D warnings` are enforced in CI.
- Put `#[cfg(test)]` modules at the end of the file.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
  `docs:`, `chore:`, `refactor:`, `test:`, and `security:` (which routes to the
  changelog's Security section — put the advisory id in the subject).
- First line under 50 characters.
- **Sign off every commit** with the DCO: `git commit -s`.

## Pull requests

- Fill in the PR description; link related issues.
- Ensure CI is green. Maintainers review and merge — please don't merge your own PR.
