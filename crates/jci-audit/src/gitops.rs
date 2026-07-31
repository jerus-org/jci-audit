//! Committing and pushing the release record.
//!
//! The record has to reach the branch **before** cargo-release runs: cargo-release
//! refuses to start on a dirty tree (a pre-created file is rejected whether staged
//! or not), so the record cannot simply be left for it to pick up. Making it a
//! commit of its own also puts it in the tagged tree, since the release commit
//! descends from it.
//!
//! This uses **pcu** — the same CI git client the organisation's other tools use —
//! rather than driving `git` and `gpg` directly. Two reasons, the second decisive:
//!
//! 1. It already handles the awkward parts: CI stores the signing key
//!    base64-encoded with literal `\n` escapes, which pcu's importer expands and
//!    decodes forgivingly.
//! 2. **A protected branch refuses a direct push** however much write access the
//!    pusher holds, accepting only a credential its rules permit to bypass them.
//!    pcu mints a GitHub App installation token when `PCU_APP_ID` and
//!    `PCU_PRIVATE_KEY` are present, which is what lands a commit on such a
//!    branch. A deploy key cannot, so `git push` is not an option here.
//!
//! pcu brings `rsa` into the graph through `openidconnect`, which carries
//! RUSTSEC-2023-0071. That advisory concerns private-key operations whose timing is
//! observable over a network: the git path never enters OIDC or sigstore, and a CLI
//! in CI is not a decryption oracle. It is suppressed in `deny.toml` with that
//! reasoning, and [`crate::prune`] will report the suppression as stale the moment
//! `rsa` leaves the graph. Tracked upstream as jerus-org/pcu#1028, which would let
//! this crate take pcu's git surface without `rsa` at all.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Names of the environment variables holding the signing material.
///
/// Only *names* are configured, never values, so nothing secret is passed on a
/// command line or committed. The defaults are deliberately generic — the tool
/// imposes no organisation's naming convention.
#[derive(Debug, Clone)]
pub struct SignEnvNames {
    pub gpg_key: String,
    pub gpg_trust: String,
    pub user_name: String,
    pub user_email: String,
    pub sign_key: String,
}

impl Default for SignEnvNames {
    fn default() -> Self {
        Self {
            gpg_key: "GPG_KEY".to_string(),
            gpg_trust: "GPG_TRUST".to_string(),
            user_name: "GIT_USER_NAME".to_string(),
            user_email: "GIT_USER_EMAIL".to_string(),
            sign_key: "GPG_SIGN_KEY".to_string(),
        }
    }
}

/// The signing material read from the environment.
#[derive(Debug, Clone)]
pub struct SigningIdentity {
    pub user_name: String,
    pub user_email: String,
    pub sign_key: String,
}

/// The commit message for a release record.
pub fn record_commit_message(version: &str) -> String {
    format!("chore: record security validation for {version}")
}

/// Read the signing identity, returning `None` unless the environment supplies it
/// in full — a partial identity would attribute the commit to whatever git happened
/// to be configured with, which is worse than an unsigned commit.
pub fn read_identity(names: &SignEnvNames) -> Option<SigningIdentity> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    Some(SigningIdentity {
        user_name: get(&names.user_name)?,
        user_email: get(&names.user_email)?,
        sign_key: get(&names.sign_key)?,
    })
}

/// pcu's configuration: the CircleCI variable names it expects, with
/// `PCU_APP_ID`/`PCU_PRIVATE_KEY` (or `GITHUB_TOKEN`) supplying the credential.
fn pcu_config() -> Result<config::Config> {
    let mut builder = config::Config::builder()
        .set_default("branch", "CIRCLE_BRANCH")?
        .set_default("default_branch", "main")?
        .set_default("username", "CIRCLE_PROJECT_USERNAME")?
        .set_default("reponame", "CIRCLE_PROJECT_REPONAME")?
        // Required even though nothing here touches a PR log: the client reads it
        // while building, regardless of command, and refuses to construct without
        // it. pcu's own default, and the file this workspace actually keeps.
        .set_default("prlog", "PRLOG.md")?
        // `push` is what populates `branch` from the variable named above —
        // `push_commit` pushes the local branch of that name. Any other value
        // leaves it unset and the push has no ref to send.
        .set_override("command", "push")?
        .add_source(config::Environment::with_prefix("PCU"));
    // A token is a fallback for environments without App credentials; note it has
    // no bypass authority on a protected branch.
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        builder = builder.set_default("pat", token)?;
    }
    Ok(builder.build()?)
}

/// Import the signing key named by `names.gpg_key`, reporting whether one was
/// available. pcu handles the base64 and the literal `\n` escapes CI introduces.
pub fn import_signing_key(names: &SignEnvNames) -> Result<bool> {
    let Ok(key) = std::env::var(&names.gpg_key) else {
        return Ok(false);
    };
    if key.trim().is_empty() {
        return Ok(false);
    }
    let trust = std::env::var(&names.gpg_trust).unwrap_or_default();
    pcu::import_gpg_key(&key, &trust)
        .map_err(|e| anyhow::anyhow!("could not import the key in {}: {e}", names.gpg_key))?;
    Ok(true)
}

/// Express `path` the way git matches it: relative to the repository root.
///
/// git resolves the entries handed to the index as pathspecs against the working
/// directory, and a pathspec matching nothing is **not** an error. So an absolute
/// path stages nothing, silently, and the commit that follows is empty. Release
/// 0.0.3 pushed exactly such a commit and reported success.
pub fn relative_to_repo(root: &Path, path: &Path) -> Result<PathBuf> {
    if path.is_relative() {
        return Ok(path.to_path_buf());
    }
    path.strip_prefix(root).map(Path::to_path_buf).map_err(|_| {
        anyhow::anyhow!(
            "'{}' is outside the repository at '{}', so git cannot stage it",
            path.display(),
            root.display()
        )
    })
}

/// Refuse to commit when staging produced nothing.
///
/// Without this, every way of staging nothing — a path git cannot match, a file
/// already committed, an ignore rule — ends in an empty commit that is pushed and
/// announced as though the record had been stored.
fn ensure_staged(count: usize, paths: &[&Path]) -> Result<()> {
    if count > 0 {
        return Ok(());
    }
    let wanted = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "nothing was staged, so there is no record to commit (expected: {wanted}).\n\n\
         The file was written but git matched nothing to add. Check that the path \
         is inside the repository and not excluded by .gitignore. Committing now \
         would push an empty commit and report a record that does not exist."
    )
}

/// Stage the given paths, commit them, and optionally push.
///
/// `root` is the repository root: the paths are made relative to it before
/// staging, because git will otherwise match none of them.
///
/// Signs when an identity is supplied. The identity is passed explicitly rather
/// than read from git config, which is not reliably visible to pcu's repo handle
/// in CI.
pub fn commit_and_push(
    root: &Path,
    paths: &[&Path],
    message: &str,
    identity: Option<&SigningIdentity>,
    push: bool,
) -> Result<()> {
    use pcu::GitOps;

    let relative = paths
        .iter()
        .map(|p| relative_to_repo(root, p))
        .collect::<Result<Vec<_>>>()?;
    let relative: Vec<&Path> = relative.iter().map(PathBuf::as_path).collect();

    let config = pcu_config()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = runtime
        .block_on(pcu::Client::new_with(&config))
        .map_err(|e| anyhow::anyhow!("could not create the pcu client: {e}"))?;

    client
        .stage_paths(&relative)
        .map_err(|e| anyhow::anyhow!("failed to stage the record: {e}"))?;

    // Staging reports success whether or not it matched anything, so ask git what
    // is actually in the index before making a commit that claims to carry it.
    let staged = client
        .repo_files_staged()
        .map_err(|e| anyhow::anyhow!("could not read the staged files: {e}"))?;
    ensure_staged(staged.len(), &relative)?;

    let sign = match identity {
        Some(id) => pcu::SignConfig::new(pcu::Sign::Gpg)
            .with_identity(&id.user_name, &id.user_email)
            .with_signing_key(&id.sign_key),
        None => pcu::SignConfig::new(pcu::Sign::None),
    };
    client
        .commit_staged(sign, message, "", None)
        .map_err(|e| anyhow::anyhow!("failed to commit the record: {e}"))?;

    if !push {
        return Ok(());
    }
    let committer = identity.map(|i| i.user_name.as_str()).unwrap_or_default();
    client
        .push_commit("", None, false, committer)
        .map_err(|e| push_failure(&e.to_string()))?;
    Ok(())
}

/// Explain a push failure. The two causes present alike and have different
/// remedies, so name them apart rather than guessing.
fn push_failure(err: &str) -> anyhow::Error {
    let ruleset = err.contains("GH013")
        || err.contains("rule violations")
        || err.contains("protected branch")
        || err.contains("must be made through a pull request");
    if ruleset {
        anyhow::anyhow!(
            "push refused by the branch's rules: {err}\n\n\
             Authorisation succeeded — the branch requires changes to arrive another \
             way, typically by pull request. Landing a commit here needs a credential \
             its rules permit to bypass them: supply PCU_APP_ID and PCU_PRIVATE_KEY so \
             a GitHub App token is used. A deploy key or personal token cannot bypass, \
             however much write access it carries."
        )
    } else {
        anyhow::anyhow!(
            "push refused: {err}\n\n\
             A standard CircleCI + GitHub checkout leaves a READ-ONLY deploy key, which \
             cannot push. Supply App credentials, or run this step in a job that already \
             holds write authorisation."
        )
    }
}

/// Refuse to proceed when the paths to commit are absent: the commit would be
/// empty and the release would continue as though a record had been made.
pub fn ensure_paths_exist(paths: &[&Path]) -> Result<()> {
    for path in paths {
        if !path.exists() {
            bail!("nothing to commit: '{}' does not exist", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn message_names_the_version() {
        let m = record_commit_message("1.2.0");
        assert!(m.contains("1.2.0"), "got {m}");
        assert!(m.starts_with("chore:"), "conventional commit: {m}");
    }

    #[test]
    fn identity_requires_every_part() {
        // A partial identity counts as absent: committing with whatever git was
        // configured with would misattribute the commit.
        let names = SignEnvNames {
            user_name: "JCI_TEST_ABSENT_NAME".into(),
            ..SignEnvNames::default()
        };
        assert!(read_identity(&names).is_none());
    }

    #[test]
    fn import_is_skipped_when_no_key_is_supplied() {
        let names = SignEnvNames {
            gpg_key: "JCI_TEST_ABSENT_KEY".into(),
            ..SignEnvNames::default()
        };
        assert!(!import_signing_key(&names).unwrap());
    }

    #[test]
    fn paths_are_made_relative_to_the_repository() {
        // git matches the entries given to the index as pathspecs resolved from
        // the working directory. An absolute path matches nothing — and matching
        // nothing is not an error — so it stages silently and commits nothing.
        let rel = relative_to_repo(
            Path::new("/home/ci/project"),
            Path::new("/home/ci/project/.security/release-0.0.3.json"),
        )
        .unwrap();
        assert_eq!(rel, PathBuf::from(".security/release-0.0.3.json"));
        assert!(rel.is_relative(), "must be relative for git to match it");
    }

    #[test]
    fn an_already_relative_path_is_left_alone() {
        let rel =
            relative_to_repo(Path::new("/home/ci/project"), Path::new(".security/x.json")).unwrap();
        assert_eq!(rel, PathBuf::from(".security/x.json"));
    }

    #[test]
    fn a_path_outside_the_repository_is_refused() {
        let err = relative_to_repo(Path::new("/home/ci/project"), Path::new("/etc/passwd"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside the repository"), "got: {err}");
    }

    #[test]
    fn committing_nothing_is_refused() {
        // The guard that matters. Release 0.0.3 staged nothing, committed an
        // empty commit, pushed it, and reported "committed the record and
        // pushed" — a silent success claiming work it had not done. Whatever the
        // cause, an empty stage must stop the release rather than decorate it.
        let path = PathBuf::from(".security/release-0.0.3.json");
        let err = ensure_staged(0, &[path.as_path()]).unwrap_err().to_string();
        assert!(err.contains("nothing was staged"), "got: {err}");
        assert!(
            err.contains(".security/release-0.0.3.json"),
            "must name what it expected to stage: {err}"
        );
        assert!(ensure_staged(1, &[path.as_path()]).is_ok());
    }

    #[test]
    fn missing_paths_are_refused_before_committing() {
        let missing = PathBuf::from("/definitely/not/here/release-9.9.9.json");
        let err = ensure_paths_exist(&[missing.as_path()]).unwrap_err();
        assert!(err.to_string().contains("nothing to commit"), "got: {err}");
    }

    #[test]
    fn existing_paths_pass_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("record.json");
        std::fs::write(&f, "{}").unwrap();
        assert!(ensure_paths_exist(&[f.as_path()]).is_ok());
    }

    #[test]
    fn push_failure_distinguishes_a_branch_rule_from_a_missing_credential() {
        // Observed live: the key authenticated and the ruleset refused the push.
        // Blaming a credential there sends the reader down the wrong path.
        let ruled =
            push_failure("remote: error: GH013: Repository rule violations found for main.")
                .to_string();
        assert!(
            ruled.contains("Authorisation succeeded"),
            "must not blame the credential: {ruled}"
        );
        assert!(ruled.contains("PCU_APP_ID"), "must name the fix: {ruled}");
        assert!(
            !ruled.contains("READ-ONLY"),
            "must not mention read-only: {ruled}"
        );

        let refused = push_failure("Permission denied (publickey)").to_string();
        assert!(refused.contains("READ-ONLY"), "got: {refused}");
    }

    #[test]
    fn pcu_config_builds_without_credentials_present() {
        // Construction must not require secrets; only the push does.
        assert!(pcu_config().is_ok());
    }

    #[test]
    fn pcu_config_supplies_every_setting_the_client_requires() {
        // `Client::new_with` reads each of these and refuses to build when one is
        // absent, whether or not the command uses it. `prlog` was missing, and it
        // failed only in CI — after the gate had passed and the record was
        // written, which is the most expensive place to discover it. Asserted key
        // by key so a future omission names itself.
        let cfg = pcu_config().expect("config must build");
        for key in ["command", "username", "reponame", "branch", "prlog"] {
            assert!(
                cfg.get::<String>(key).is_ok(),
                "pcu's client requires the '{key}' setting"
            );
        }
    }
}
