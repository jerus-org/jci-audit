//! Committing and pushing the release record, without linking a git library.
//!
//! The record has to reach `main` **before** cargo-release runs: cargo-release
//! refuses to start on a dirty tree (a pre-created file is rejected whether
//! staged or not), so the record cannot simply be left for it to pick up. Making
//! it a commit of its own also puts it in the tagged tree, since the release
//! commit descends from it.
//!
//! This is done by driving the `git` and `gpg` binaries, exactly as the rest of
//! the tool drives `cargo-audit` and `cargo-deny` — the orb executor already
//! carries git, gnupg and openssh-client. Linking a git/GitHub library instead
//! would pull a much larger dependency tree into a tool whose own output is a
//! security audit; the obvious candidate transitively carries an RSA advisory
//! that this crate would then have to suppress in its own `deny.toml`.
//!
//! **Credentials are ambient.** Nothing here mints or carries its own: the push
//! uses whatever authorisation the CI checkout already established. On the usual
//! read-only deploy key it fails, and says so with guidance rather than
//! attempting to work around a deliberate control.

use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::check::CommandRunner;

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

/// Decode a base64 signing key supplied through the environment.
///
/// CI stores multi-line values with **literal `\n` escape sequences**, and the
/// base64 itself is usually line-wrapped, so a strict decode fails on the
/// embedded whitespace. Expand the escapes first, then keep only base64
/// alphabet characters — the equivalent of `printf '%b' | base64 --decode
/// --ignore-garbage`, which is how the rest of the toolchain reads these values.
///
/// Escapes must be expanded BEFORE filtering: dropping the backslash of `\n`
/// would leave a bare `n`, which is itself a valid base64 character and would
/// silently corrupt the key.
pub fn decode_key(raw: &str) -> Result<Vec<u8>> {
    // Expand literal escape sequences first — see the note above on why order
    // matters here.
    let expanded = raw.replace("\\r\\n", "\n").replace("\\n", "\n");
    let cleaned: String = expanded
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        .collect();
    if cleaned.is_empty() {
        bail!("no base64 content found");
    }
    Ok(STANDARD.decode(&cleaned)?)
}

/// The commit message for a release record.
pub fn record_commit_message(version: &str) -> String {
    format!("chore: record security validation for {version}")
}

/// Read the signing identity, returning `None` when the environment does not
/// supply it — an unsigned commit is then made, which is the right behaviour for
/// a local run and fails visibly in CI where signatures are required.
pub fn read_identity(names: &SignEnvNames) -> Option<SigningIdentity> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    Some(SigningIdentity {
        user_name: get(&names.user_name)?,
        user_email: get(&names.user_email)?,
        sign_key: get(&names.sign_key)?,
    })
}

/// Import the GPG key named by `names.gpg_key` (base64-encoded) and its
/// ownertrust, so the commit can be signed.
///
/// Written to files under `work_dir` rather than piped, so no key material ever
/// appears in a command line, and removed immediately afterwards.
pub fn import_signing_key<R: CommandRunner>(
    runner: &R,
    names: &SignEnvNames,
    work_dir: &Path,
) -> Result<bool> {
    let Ok(key_b64) = std::env::var(&names.gpg_key) else {
        return Ok(false);
    };
    if key_b64.trim().is_empty() {
        return Ok(false);
    }

    let key = decode_key(&key_b64)
        .with_context(|| format!("could not decode the key in {}", names.gpg_key))?;

    std::fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create '{}'", work_dir.display()))?;
    let key_path = work_dir.join("signing-key.asc");
    std::fs::write(&key_path, key).context("failed to stage the signing key")?;

    let import = runner.run(
        "gpg",
        &["--batch", "--import", key_path.to_str().unwrap_or_default()],
        work_dir,
    );
    // Remove the key material before reacting to the result.
    let _ = std::fs::remove_file(&key_path);
    let import = import?;
    if !import.success {
        bail!("failed to import the signing key: {}", import.stderr.trim());
    }

    // Ownertrust is optional: without it gpg still signs, it just warns.
    if let Ok(trust) = std::env::var(&names.gpg_trust)
        && !trust.trim().is_empty()
    {
        let trust_path = work_dir.join("ownertrust.txt");
        std::fs::write(&trust_path, trust).context("failed to stage the ownertrust")?;
        let _ = runner.run(
            "gpg",
            &[
                "--batch",
                "--import-ownertrust",
                trust_path.to_str().unwrap_or_default(),
            ],
            work_dir,
        );
        let _ = std::fs::remove_file(&trust_path);
    }
    Ok(true)
}

/// Stage the given paths and create a commit.
///
/// Signs when an identity with a signing key is supplied. Always signs off
/// (DCO), matching the contribution requirements.
pub fn commit_paths<R: CommandRunner>(
    runner: &R,
    root: &Path,
    paths: &[&Path],
    message: &str,
    identity: Option<&SigningIdentity>,
) -> Result<()> {
    // Stage exactly the named paths — never a blanket add, which would sweep up
    // whatever else the job happens to have left in the tree.
    let mut add: Vec<String> = vec!["add".to_string(), "--".to_string()];
    add.extend(paths.iter().map(|p| p.display().to_string()));
    let add_refs: Vec<&str> = add.iter().map(String::as_str).collect();
    let staged = runner.run("git", &add_refs, root)?;
    if !staged.success {
        bail!("failed to stage the record: {}", staged.stderr.trim());
    }

    // Identity is supplied per-invocation with -c, so nothing is written to the
    // repository or global git config.
    let mut args: Vec<String> = Vec::new();
    if let Some(id) = identity {
        args.push("-c".into());
        args.push(format!("user.name={}", id.user_name));
        args.push("-c".into());
        args.push(format!("user.email={}", id.user_email));
        args.push("-c".into());
        args.push(format!("user.signingkey={}", id.sign_key));
    }
    args.push("commit".into());
    if identity.is_some() {
        args.push("-S".into());
    }
    args.push("--signoff".into());
    args.push("-m".into());
    args.push(message.to_string());

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let committed = runner.run("git", &arg_refs, root)?;
    if !committed.success {
        bail!("failed to commit the record: {}", committed.stderr.trim());
    }
    Ok(())
}

/// Push the current branch using whatever credentials the environment provides.
pub fn push<R: CommandRunner>(runner: &R, root: &Path) -> Result<()> {
    let pushed = runner.run("git", &["push"], root)?;
    if !pushed.success {
        bail!("{}", ambient_push_failure(&pushed.stderr));
    }
    Ok(())
}

/// Guidance shown when an ambient push is refused, so the cause is obvious.
pub fn ambient_push_failure(stderr: &str) -> String {
    format!(
        "push refused with the credentials the CI checkout provided: {}\n\
         \n\
         Nothing here carries credentials of its own. A standard CircleCI + GitHub \
         checkout leaves a READ-ONLY deploy key, which cannot push. Give the job \
         write authorisation — for example load a write key with add_ssh_keys, or \
         run the record step in a job that already has it — rather than weakening \
         the checkout's configuration.",
        stderr.trim()
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf};

    use super::*;
    use crate::check::ToolOutput;

    struct MockRunner {
        ok: bool,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl MockRunner {
        fn new(ok: bool) -> Self {
            Self {
                ok,
                calls: RefCell::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str], _cwd: &Path) -> Result<ToolOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(call);
            Ok(ToolOutput {
                success: self.ok,
                stdout: String::new(),
                stderr: if self.ok {
                    String::new()
                } else {
                    "remote: write access denied".to_string()
                },
            })
        }
    }

    fn identity() -> SigningIdentity {
        SigningIdentity {
            user_name: "A Bot".to_string(),
            user_email: "bot@example.com".to_string(),
            sign_key: "DEADBEEF".to_string(),
        }
    }

    #[test]
    fn decodes_plain_base64() {
        // "hello" == aGVsbG8=
        assert_eq!(decode_key("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn decodes_despite_wrapping_whitespace() {
        // Real newlines and spaces, as line-wrapped base64 arrives.
        assert_eq!(decode_key("aGVs\nbG8=").unwrap(), b"hello");
        assert_eq!(decode_key("aGVs bG8=").unwrap(), b"hello");
        assert_eq!(decode_key("  aGVsbG8=\n").unwrap(), b"hello");
    }

    #[test]
    fn decodes_despite_literal_escape_sequences() {
        // CI stores multi-line values with a literal backslash-n. Expanding
        // these BEFORE filtering matters: dropping only the backslash would
        // leave a bare `n`, a valid base64 character, silently corrupting the key.
        let with_escapes = "aGVs\\nbG8=";
        assert_eq!(decode_key(with_escapes).unwrap(), b"hello");
    }

    #[test]
    fn rejects_input_with_no_base64_content() {
        assert!(decode_key("!!! ???").is_err());
        assert!(decode_key("").is_err());
    }

    #[test]
    fn message_names_the_version() {
        let m = record_commit_message("1.2.0");
        assert!(m.contains("1.2.0"), "got {m}");
        assert!(m.starts_with("chore:"), "conventional commit: {m}");
    }

    #[test]
    fn commit_stages_only_the_given_paths() {
        let runner = MockRunner::new(true);
        let record = PathBuf::from(".security/release-1.2.0.json");
        commit_paths(
            &runner,
            Path::new("/repo"),
            &[record.as_path()],
            "msg",
            Some(&identity()),
        )
        .unwrap();

        let calls = runner.calls();
        let add = calls
            .iter()
            .find(|c| c[0] == "git" && c.contains(&"add".to_string()))
            .expect("no git add");
        assert!(
            add.contains(&record.display().to_string()),
            "must stage the record: {add:?}"
        );
        // Never a blanket add.
        assert!(!add.contains(&"-A".to_string()), "blanket add: {add:?}");
        assert!(!add.contains(&".".to_string()), "blanket add: {add:?}");
    }

    #[test]
    fn commit_is_signed_and_signed_off_when_identity_is_supplied() {
        let runner = MockRunner::new(true);
        commit_paths(
            &runner,
            Path::new("/repo"),
            &[Path::new("f")],
            "msg",
            Some(&identity()),
        )
        .unwrap();
        let calls = runner.calls();
        let commit = calls
            .iter()
            .find(|c| c.contains(&"commit".to_string()))
            .expect("no git commit");
        assert!(commit.contains(&"-S".to_string()), "must sign: {commit:?}");
        assert!(
            commit.contains(&"--signoff".to_string()) || commit.contains(&"-s".to_string()),
            "must sign off (DCO): {commit:?}"
        );
        // Identity is passed per-invocation, never written to global config.
        let joined = commit.join(" ");
        assert!(joined.contains("user.name=A Bot"), "{joined}");
        assert!(joined.contains("user.email=bot@example.com"), "{joined}");
        assert!(joined.contains("user.signingkey=DEADBEEF"), "{joined}");
    }

    #[test]
    fn commit_without_identity_is_unsigned() {
        let runner = MockRunner::new(true);
        commit_paths(&runner, Path::new("/repo"), &[Path::new("f")], "msg", None).unwrap();
        let calls = runner.calls();
        let commit = calls
            .iter()
            .find(|c| c.contains(&"commit".to_string()))
            .expect("no git commit");
        assert!(!commit.contains(&"-S".to_string()), "got {commit:?}");
    }

    #[test]
    fn failed_commit_is_an_error() {
        let runner = MockRunner::new(false);
        assert!(
            commit_paths(&runner, Path::new("/repo"), &[Path::new("f")], "m", None).is_err(),
            "a failing git commit must not be swallowed"
        );
    }

    #[test]
    fn push_failure_explains_the_read_only_key() {
        let runner = MockRunner::new(false);
        let err = push(&runner, Path::new("/repo")).unwrap_err().to_string();
        assert!(err.contains("READ-ONLY"), "got: {err}");
        assert!(
            err.contains("add_ssh_keys") || err.contains("write authorisation"),
            "must say how to fix it: {err}"
        );
    }

    #[test]
    fn identity_is_read_from_the_named_variables() {
        // Absent variables yield no identity rather than a broken half-config.
        let names = SignEnvNames {
            user_name: "JCI_TEST_ABSENT_NAME".into(),
            ..SignEnvNames::default()
        };
        assert!(read_identity(&names).is_none());
    }

    #[test]
    fn import_is_skipped_when_no_key_is_supplied() {
        let runner = MockRunner::new(true);
        let names = SignEnvNames {
            gpg_key: "JCI_TEST_ABSENT_KEY".into(),
            ..SignEnvNames::default()
        };
        let dir = tempfile::tempdir().unwrap();
        assert!(!import_signing_key(&runner, &names, dir.path()).unwrap());
        assert!(runner.calls().is_empty(), "must not invoke gpg");
    }
}
