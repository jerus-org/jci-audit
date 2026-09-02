//! `jci-audit publish-record` (jerus-org/jci-audit#75 phase 2, path B): a
//! fully self-contained way to sign and distribute a release record for a
//! consumer with no circleci-toolkit-style signing facility of their own.
//!
//! [`crate::release`] writes the record locally, unsigned. This module does
//! everything else in one process: generates an ephemeral minisign keypair,
//! signs the record, uploads the record/`.sig`/`.pub` to the named release,
//! and (with `--publish`) un-drafts it. The private key is generated, used,
//! and discarded inside this one call — it never crosses a job boundary,
//! encrypted or not, matching the maintainer's direction on PR review for
//! jerus-org/jci-audit#75 ("none of this secret information is being passed
//! around").
//!
//! jci-audit's own release pipeline does not use this path — it already
//! depends on circleci-toolkit for everything else, so it reuses the same
//! ephemeral key that signs the binary tarball (a stronger, crates.io-
//! anchored trust chain; see `docs/RELEASING.md`). This subcommand exists so
//! any other consumer of the generated orb, with no equivalent tooling, can
//! still produce a self-contained, verifiable record.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::check::CommandRunner;
use crate::remote::parse_pubkey_asset;

/// Where the signed record's three assets actually get uploaded to. A trait
/// so [`publish_record_with`] is testable without real network access.
pub(crate) trait AssetPublisher {
    /// Upload the file at `path` as `asset_name` on the release for `tag`.
    fn upload_asset(&self, tag: &str, path: &Path, asset_name: &str) -> Result<()>;
    /// Un-draft the release for `tag`.
    fn publish_release(&self, tag: &str) -> Result<()>;
}

/// What [`publish_record_with`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishRecordOutcome {
    /// The ephemeral pubkey generated for this record — printed so a caller
    /// can cross-check it against the uploaded `.pub` asset if they want to.
    pub(crate) pubkey: String,
    /// Names of the three assets uploaded, in upload order.
    pub(crate) uploaded: Vec<String>,
    /// Whether `--publish` un-drafted the release.
    pub(crate) published: bool,
}

const KEY_FILE_NAME: &str = "minisign.key";
const PUB_FILE_NAME: &str = "minisign.pub";

/// Ephemeral directory for the generated keypair and derived asset files.
/// Process-scoped so concurrent runs cannot collide; nothing here is
/// committed, and the private key is removed from it as soon as signing
/// finishes (success or failure).
pub(crate) fn work_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("jci-audit-publish-record-{}", std::process::id()))
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path '{}' is not valid UTF-8", path.display()))
}

/// Sign `record_path` with a freshly generated, one-use minisign keypair and
/// upload the record, its signature, and its pubkey to the release for
/// `tag`. `record_path` must already exist — this never re-runs the gate,
/// only distributes an already-produced record. `version` must be the
/// version `record_path` was actually written for — checked against its file
/// name before anything is signed, so a stale or mismatched `--record-path`
/// override fails loudly here instead of uploading the record under the
/// wrong asset name (silently making `verify <version>` find nothing,
/// later, with no clue why — the exact unverifiable-record failure mode
/// jerus-org/jci-audit#75 exists to prevent).
pub(crate) fn publish_record_with<R: CommandRunner, P: AssetPublisher>(
    runner: &R,
    publisher: &P,
    record_path: &Path,
    version: &str,
    tag: &str,
    work_dir: &Path,
    publish: bool,
) -> Result<PublishRecordOutcome> {
    if !record_path.is_file() {
        bail!(
            "no release record found at '{}' — run `jci-audit release-prep` first",
            record_path.display()
        );
    }
    let record_name = record_path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("'{}' has no valid file name", record_path.display()))?
        .to_string();
    let expected_name = format!("release-{version}.json");
    if record_name != expected_name {
        bail!(
            "'--record-path' points at '{record_name}', but the release version given is \
             '{version}' (expected file name '{expected_name}') — refusing to upload it under a \
             name that doesn't match the version, since `verify {version}` would then find \
             nothing"
        );
    }

    std::fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create '{}'", work_dir.display()))?;

    let key_path = work_dir.join(KEY_FILE_NAME);
    let pub_path = work_dir.join(PUB_FILE_NAME);
    let keygen = runner.run(
        "rsign",
        &[
            "generate",
            "-W",
            "-p",
            path_str(&pub_path)?,
            "-s",
            path_str(&key_path)?,
        ],
        work_dir,
    )?;
    if !keygen.success {
        bail!(
            "failed to generate an ephemeral signing key: {}",
            keygen.stderr.trim()
        );
    }

    let sig_name = format!("{record_name}.sig");
    let sig_path = work_dir.join(&sig_name);
    let sign = runner.run(
        "rsign",
        &[
            "sign",
            "-W",
            "-s",
            path_str(&key_path)?,
            "-x",
            path_str(&sig_path)?,
            path_str(record_path)?,
        ],
        work_dir,
    );
    // The private key must never outlive this one step, whether signing
    // succeeded or not — discard it before even inspecting the result.
    let _ = std::fs::remove_file(&key_path);
    let sign = sign?;
    if !sign.success {
        bail!("failed to sign the release record: {}", sign.stderr.trim());
    }

    let pub_text = std::fs::read_to_string(&pub_path)
        .with_context(|| format!("failed to read '{}'", pub_path.display()))?;
    let pubkey = parse_pubkey_asset(&pub_text).context("failed to extract the generated pubkey")?;
    let _ = std::fs::remove_file(&pub_path);

    let pub_name = format!("{record_name}.pub");
    let record_pub_path = work_dir.join(&pub_name);
    std::fs::write(&record_pub_path, format!("{pubkey}\n"))
        .with_context(|| format!("failed to write '{}'", record_pub_path.display()))?;

    publisher
        .upload_asset(tag, record_path, &record_name)
        .with_context(|| format!("failed to upload '{record_name}' to release '{tag}'"))?;
    publisher
        .upload_asset(tag, &sig_path, &sig_name)
        .with_context(|| format!("failed to upload '{sig_name}' to release '{tag}'"))?;
    publisher
        .upload_asset(tag, &record_pub_path, &pub_name)
        .with_context(|| format!("failed to upload '{pub_name}' to release '{tag}'"))?;

    let published = if publish {
        publisher
            .publish_release(tag)
            .with_context(|| format!("failed to publish release '{tag}'"))?;
        true
    } else {
        false
    };

    Ok(PublishRecordOutcome {
        pubkey,
        uploaded: vec![record_name, sig_name, pub_name],
        published,
    })
}

/// Real [`AssetPublisher`], backed by `pcu-release-assets`'s headless,
/// write-capable client (jerus-org/pcu#1059).
pub(crate) struct PcuAssetWriter {
    writer: pcu_release_assets::ReleaseAssetWriter,
}

impl PcuAssetWriter {
    pub(crate) fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        github_token: impl Into<String>,
    ) -> Self {
        Self {
            writer: pcu_release_assets::ReleaseAssetWriter::new(owner, repo, github_token),
        }
    }

    /// One call, one runtime — this is an occasional CLI invocation, not a
    /// server; there is no benefit to keeping a runtime alive across calls.
    fn block_on<F: std::future::Future>(fut: F) -> Result<F::Output> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to start an async runtime for the release-asset upload")
            .map(|rt| rt.block_on(fut))
    }
}

impl AssetPublisher for PcuAssetWriter {
    fn upload_asset(&self, tag: &str, path: &Path, asset_name: &str) -> Result<()> {
        Self::block_on(self.writer.upload_release_asset(tag, path, asset_name))?
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn publish_release(&self, tag: &str) -> Result<()> {
        Self::block_on(self.writer.publish_release(tag))?.map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::check::ToolOutput;

    const PUBKEY: &str = "RWSImK6yfWBJsXrcL0Pj4rGeuKAZBAHz1LtaE677qZGJ4Pd/O+L2A9vl";

    fn arg_after<'a>(args: &[&'a str], flag: &str) -> &'a str {
        let i = args
            .iter()
            .position(|a| *a == flag)
            .unwrap_or_else(|| panic!("no '{flag}' in {args:?}"));
        args[i + 1]
    }

    /// Simulates `rsign generate`/`rsign sign`'s real filesystem side
    /// effects (writing the keypair / signature files at the paths passed on
    /// the command line) so the orchestration under test — which reads those
    /// files back — is exercised the same way it would be against the real
    /// binary, without needing one installed.
    struct MockRunner {
        generate_ok: bool,
        sign_ok: bool,
        pubkey: String,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl MockRunner {
        fn ok() -> Self {
            Self {
                generate_ok: true,
                sign_ok: true,
                pubkey: PUBKEY.to_string(),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn generate_fails() -> Self {
            Self {
                generate_ok: false,
                ..Self::ok()
            }
        }

        fn sign_fails() -> Self {
            Self {
                sign_ok: false,
                ..Self::ok()
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str], _cwd: &Path) -> Result<ToolOutput> {
            assert_eq!(program, "rsign");
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(call);

            if args.contains(&"generate") {
                if self.generate_ok {
                    std::fs::write(
                        arg_after(args, "-p"),
                        format!(
                            "untrusted comment: minisign public key TEST\n{}\n",
                            self.pubkey
                        ),
                    )
                    .unwrap();
                    std::fs::write(arg_after(args, "-s"), "fake-private-key-material").unwrap();
                }
                return Ok(ToolOutput {
                    success: self.generate_ok,
                    stdout: String::new(),
                    stderr: if self.generate_ok {
                        String::new()
                    } else {
                        "key generation failed".to_string()
                    },
                });
            }
            if args.contains(&"sign") {
                if self.sign_ok {
                    std::fs::write(arg_after(args, "-x"), "fake-signature-bytes\n").unwrap();
                }
                return Ok(ToolOutput {
                    success: self.sign_ok,
                    stdout: String::new(),
                    stderr: if self.sign_ok {
                        String::new()
                    } else {
                        "signing failed".to_string()
                    },
                });
            }
            panic!("unexpected rsign invocation: {args:?}");
        }
    }

    struct MockPublisher {
        upload_ok: bool,
        publish_ok: bool,
        uploads: RefCell<Vec<(String, String, String)>>,
        publishes: RefCell<Vec<String>>,
    }

    impl MockPublisher {
        fn ok() -> Self {
            Self {
                upload_ok: true,
                publish_ok: true,
                uploads: RefCell::new(Vec::new()),
                publishes: RefCell::new(Vec::new()),
            }
        }

        fn upload_fails() -> Self {
            Self {
                upload_ok: false,
                ..Self::ok()
            }
        }

        fn publish_fails() -> Self {
            Self {
                publish_ok: false,
                ..Self::ok()
            }
        }
    }

    impl AssetPublisher for MockPublisher {
        fn upload_asset(&self, tag: &str, path: &Path, asset_name: &str) -> Result<()> {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            self.uploads
                .borrow_mut()
                .push((tag.to_string(), contents, asset_name.to_string()));
            if self.upload_ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!("upload failed"))
            }
        }

        fn publish_release(&self, tag: &str) -> Result<()> {
            self.publishes.borrow_mut().push(tag.to_string());
            if self.publish_ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!("publish failed"))
            }
        }
    }

    fn write_record(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, r#"{"schema_version":4}"#).unwrap();
        path
    }

    #[test]
    fn errors_when_no_local_record_exists() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("release-1.2.0.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        let err = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("release-prep"), "got: {err}");
    }

    #[test]
    fn errors_when_the_record_path_does_not_match_the_release_version() {
        // A mismatched --record-path/version pair (stale workspace artifact,
        // copy-paste version drift) would otherwise upload the
        // record under the wrong asset name, silently — `verify` for the
        // intended version would then find nothing and fail with no clue why.
        // Catch it loudly here instead, before any signing happens.
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.1.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        let err = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("release-1.2.1.json"), "got: {msg}");
        assert!(msg.contains("release-1.2.0.json"), "got: {msg}");
        assert!(msg.contains("1.2.0"), "got: {msg}");
        assert!(
            publisher.uploads.borrow().is_empty(),
            "must not sign or upload anything on a mismatched record path"
        );
    }

    #[test]
    fn signs_and_uploads_the_record_signature_and_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        let outcome = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap();

        assert_eq!(outcome.pubkey, PUBKEY);
        assert_eq!(
            outcome.uploaded,
            vec![
                "release-1.2.0.json".to_string(),
                "release-1.2.0.json.sig".to_string(),
                "release-1.2.0.json.pub".to_string(),
            ]
        );
        assert!(!outcome.published);

        let uploads = publisher.uploads.borrow();
        assert_eq!(uploads.len(), 3);
        assert_eq!(uploads[0].0, "myapp-v1.2.0");
        assert_eq!(uploads[0].2, "release-1.2.0.json");
        assert!(uploads[0].1.contains("schema_version"));
        assert_eq!(uploads[1].2, "release-1.2.0.json.sig");
        assert_eq!(uploads[1].1, "fake-signature-bytes\n");
        assert_eq!(uploads[2].2, "release-1.2.0.json.pub");
        assert_eq!(uploads[2].1, format!("{PUBKEY}\n"));

        assert!(
            publisher.publishes.borrow().is_empty(),
            "must not publish unless asked"
        );
    }

    #[test]
    fn the_private_key_is_removed_after_a_successful_sign() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap();

        assert!(!work.path().join(KEY_FILE_NAME).exists());
    }

    #[test]
    fn the_private_key_is_removed_even_when_signing_fails() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::sign_fails();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        let err = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("signing failed"), "got: {err}");
        assert!(!work.path().join(KEY_FILE_NAME).exists());
        assert!(
            publisher.uploads.borrow().is_empty(),
            "must not upload anything from a failed signature"
        );
    }

    #[test]
    fn a_failed_key_generation_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::generate_fails();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        let err = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("key generation failed"),
            "got: {err}"
        );
    }

    #[test]
    fn a_failed_upload_is_a_clear_error_and_stops_before_the_next_asset() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::upload_fails();
        let work = tempfile::tempdir().unwrap();

        let err = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("release-1.2.0.json"), "got: {err}");
        assert_eq!(
            publisher.uploads.borrow().len(),
            1,
            "must stop after the first failed upload, not try the rest"
        );
    }

    #[test]
    fn publish_true_un_drafts_the_release_after_all_uploads() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::ok();
        let work = tempfile::tempdir().unwrap();

        let outcome = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            true,
        )
        .unwrap();

        assert!(outcome.published);
        assert_eq!(publisher.uploads.borrow().len(), 3, "publish comes last");
        assert_eq!(
            *publisher.publishes.borrow(),
            vec!["myapp-v1.2.0".to_string()]
        );
    }

    #[test]
    fn a_failed_publish_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = write_record(dir.path(), "release-1.2.0.json");
        let runner = MockRunner::ok();
        let publisher = MockPublisher::publish_fails();
        let work = tempfile::tempdir().unwrap();

        let err = publish_record_with(
            &runner,
            &publisher,
            &record_path,
            "1.2.0",
            "myapp-v1.2.0",
            work.path(),
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("myapp-v1.2.0"), "got: {err}");
    }
}
