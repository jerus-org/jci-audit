//! Replacing a file without leaving a partial one on disk.
//!
//! For the files `wire-ci` rewrites wholesale that nobody could reconstruct:
//! `jci-audit.toml` and the consumer's `.circleci/config.yml`. Both hold
//! comments that exist in no other copy.
//!
//! Ported from `gen-circleci-orb`'s own `fs_atomic` module, which solves the
//! identical problem for the identical pair of file shapes (a config file
//! this tool owns, plus a consumer's `.circleci/config.yml` it only patches) —
//! see jerus-org/jci-audit#101's design plan for why atomic writes were
//! adopted here rather than a plain `std::fs::write` (this repo's other
//! write sites are a different, lower-stakes risk class: freshly scaffolded
//! or machine-regenerable files, not hand-authored ones with irreplaceable
//! comments).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Where new contents are staged before replacing `path`.
///
/// A sibling, because `rename` is only atomic within one filesystem.
///
/// The suffix is a v4 UUID, so concurrent writers cannot stage to one path: if
/// they did, the second would truncate the first's bytes and the first would
/// rename and report success having published the second's contents. Neither a
/// process id nor a clock reading is sufficient — containers sharing a
/// bind-mounted workspace number their processes independently, and can read
/// the same instant.
pub(crate) fn write_temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    path.with_file_name(name)
}

/// Write `content` to `path` by staging beside it and renaming over.
///
/// A reader sees the old contents or the new, never a mix, and an interruption
/// leaves the previous file intact.
///
/// The rename installs a new inode where an in-place write would reuse the
/// existing one, so permissions and symlinks are handled explicitly below.
/// Guarantees are strongest on Unix: elsewhere the mode carries only as far as
/// the platform models it, and the directory sync is skipped.
pub(crate) fn write_atomically(path: &Path, content: &str) -> Result<()> {
    // A symlink whose target no longer exists can't be resolved by
    // canonicalize either, so the "path doesn't exist yet" fallback below
    // would silently rename onto the link's own path — replacing the link
    // itself with a plain file, the opposite of "through a symlink, not
    // over it," rather than surfacing the broken link as the actual
    // problem.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        && std::fs::canonicalize(path).is_err()
    {
        anyhow::bail!(
            "{} is a symlink to a path that no longer exists; refusing to replace it",
            path.display()
        );
    }

    // Through a symlink, not over it: renaming onto the link's own path would
    // replace it and strand the file it pointed at.
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let existing = std::fs::metadata(&target).ok();

    // `rename` needs write permission on the directory, not on the file it
    // replaces, so a read-only target would otherwise be overwritten without a
    // word — where an in-place write refused. Someone who chmods a config to
    // stop tooling touching it means it.
    if existing
        .as_ref()
        .is_some_and(|m| m.permissions().readonly())
    {
        anyhow::bail!("{} is read-only; refusing to replace it", target.display());
    }

    let temp = write_temp_path(&target);
    if let Err(e) = stage(&temp, content.as_bytes()) {
        // The staged file may be partially written, and the next run stages
        // under a different name, so it would linger indefinitely.
        let _ = std::fs::remove_file(&temp);
        return Err(e)
            .with_context(|| format!("cannot stage the new contents at {}", temp.display()));
    }

    // The staged file is created at the umask default, so without this a write
    // silently widens a deliberately restricted target. Say so if it fails,
    // rather than publishing wider permissions in silence.
    if let Some(existing) = &existing
        && let Err(e) = std::fs::set_permissions(&temp, existing.permissions())
    {
        tracing::warn!(
            "could not carry {}'s permissions onto the replacement: {e}",
            target.display()
        );
    }

    if let Err(e) = std::fs::rename(&temp, &target) {
        // Best effort: the rename error is the one worth reporting.
        let _ = std::fs::remove_file(&temp);
        return Err(e).with_context(|| format!("cannot replace {}", target.display()));
    }

    // The rename is durable only once its directory entry is. Best effort: not
    // every platform opens a directory this way.
    if let Some(parent) = target.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Write the staged copy and get it to stable storage.
///
/// The sync must happen before the rename, or a crash can leave the rename's
/// metadata on disk without the data — a present, empty file, with the old
/// contents already unlinked.
fn stage(temp: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(temp)?;
    file.write_all(content)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_temporary_is_a_sibling_of_the_target() {
        let path = Path::new("/some/where/jci-audit.toml");
        let temp = write_temp_path(path);
        assert_eq!(temp.parent(), path.parent());
        assert_ne!(temp.file_name(), path.file_name());
    }

    /// Two writers must never stage to one path — the second would truncate the
    /// first's bytes, and the first would rename and publish the second's
    /// contents while reporting success.
    #[test]
    fn each_staging_path_is_distinct() {
        let path = Path::new("/some/where/jci-audit.toml");
        let paths: std::collections::HashSet<_> =
            (0..1000).map(|_| write_temp_path(path)).collect();
        assert_eq!(paths.len(), 1000, "staging paths must not repeat");
    }

    #[test]
    fn a_write_replaces_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.yml");
        std::fs::write(&path, "old").unwrap();

        write_atomically(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let entries = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(entries, 1, "the target should be the only file left");
    }

    #[test]
    fn a_write_creates_a_target_that_does_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.yml");

        write_atomically(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    /// Renaming onto a directory is the one way the staging write succeeds and
    /// the replace still fails.
    #[test]
    fn a_failed_replace_removes_the_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("occupied-by-a-directory");
        std::fs::create_dir(&target).unwrap();

        assert!(write_atomically(&target, "new contents").is_err());
        assert!(
            !write_temp_path(&target).exists(),
            "the staged file must not survive a failed replace"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_write_keeps_the_permissions_the_target_had() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.yml");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomically(&path, "new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    /// `rename` needs write permission on the directory, not on the file it
    /// replaces, so without an explicit check a read-only target is replaced
    /// silently — where an in-place write refused.
    #[cfg(unix)]
    #[test]
    fn a_read_only_target_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.yml");
        std::fs::write(&path, "old").unwrap();
        // 0o400, not 0o444: no bits for "others" (SonarQube rust:S2612) —
        // `Permissions::readonly()` only checks that no write bit is set
        // anywhere, so owner-read-only alone already exercises the same
        // refusal path this test is proving.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let err = write_atomically(&path, "new").unwrap_err().to_string();
        assert!(err.contains("read-only"), "got: {err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
    }

    /// A staging failure reports and leaves nothing behind.
    ///
    /// Induced with a missing parent directory. The `remove_file` on that path
    /// is belt-and-braces for a *partial* write — an I/O error after some bytes
    /// have landed — which cannot be induced without fault injection, so this
    /// covers the reporting and the absence of litter, not that branch.
    #[test]
    fn a_failed_stage_reports_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-directory").join("thing.yml");

        assert!(write_atomically(&path, "new").is_err());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "nothing should have been created"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_write_goes_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.yml");
        let link = dir.path().join("link.yml");
        std::fs::write(&real, "old").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomically(&link, "new").unwrap();

        assert!(
            std::fs::symlink_metadata(&link).unwrap().is_symlink(),
            "the symlink must survive the write"
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new");
    }

    /// A dangling symlink can't be canonicalized either — without an
    /// explicit check, the "path doesn't exist yet" fallback would rename
    /// onto the link's own path, silently replacing the broken link with a
    /// plain file instead of surfacing the real problem.
    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_refused_rather_than_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone.yml");
        let link = dir.path().join("link.yml");
        std::os::unix::fs::symlink(&missing, &link).unwrap();

        let err = write_atomically(&link, "new").unwrap_err().to_string();
        assert!(err.contains("no longer exists"), "got: {err}");
        assert!(
            std::fs::symlink_metadata(&link).unwrap().is_symlink(),
            "the broken symlink must survive, not be replaced by a plain file"
        );
    }
}
