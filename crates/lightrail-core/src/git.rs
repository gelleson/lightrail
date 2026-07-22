//! Current-checkout discovery through the external `git` executable.

use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::GitError;

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_WAIT_INTERVAL: Duration = Duration::from_millis(10);
const GIT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Git state that affects source selection and environment naming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitContext {
    repo_root: PathBuf,
    branch: String,
    commit: Option<String>,
    detached: bool,
    dirty: bool,
}

impl GitContext {
    /// Discovers the repository root and current checkout state from `start`.
    ///
    /// This intentionally delegates repository semantics to the user's Git
    /// executable rather than parsing `.git` files. A detached checkout is
    /// named `sha-<first 12 commit characters>`.
    ///
    /// # Errors
    ///
    /// Returns [`GitError`] when Git is unavailable, `start` is outside a
    /// working tree, a command fails, or required Git output is malformed.
    pub fn discover(start: impl AsRef<Path>) -> Result<Self, GitError> {
        let start = start.as_ref();
        let root_output = run_git(
            start,
            ["rev-parse", "--show-toplevel"],
            "finding repository root",
        )
        .map_err(|error| match error {
            GitError::CommandFailed { stderr, .. } => GitError::NotRepository {
                start: start.to_path_buf(),
                stderr,
            },
            other => other,
        })?;
        let repo_root = PathBuf::from(required_stdout(root_output, "finding repository root")?);

        let symbolic = run_git_allow_failure(
            &repo_root,
            ["symbolic-ref", "--quiet", "--short", "HEAD"],
            "finding current branch",
        )?;

        let (branch, detached, commit) = if symbolic.status.success() {
            (
                required_stdout(symbolic, "finding current branch")?,
                false,
                discover_attached_commit(&repo_root)?,
            )
        } else {
            let commit_output = run_git(
                &repo_root,
                ["rev-parse", "--verify", "HEAD"],
                "finding detached commit",
            )?;
            let commit =
                validate_commit(required_stdout(commit_output, "finding detached commit")?)?;
            (format!("sha-{}", &commit[..12]), true, Some(commit))
        };

        let status_output = run_git(
            &repo_root,
            ["status", "--porcelain", "--untracked-files=normal"],
            "checking working-tree status",
        )?;
        let dirty = !decode_stdout(status_output, "checking working-tree status")?.is_empty();

        Ok(Self {
            repo_root,
            branch,
            commit,
            detached,
            dirty,
        })
    }

    /// Returns the absolute Git worktree root.
    #[must_use]
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    /// Returns the raw branch name, or `sha-<12>` for detached HEAD.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Returns the full commit identifier when the repository has a commit.
    ///
    /// An attached, unborn branch has no commit and returns `None`.
    #[must_use]
    pub fn commit(&self) -> Option<&str> {
        self.commit.as_deref()
    }

    /// Returns whether HEAD is detached.
    #[must_use]
    pub const fn is_detached(&self) -> bool {
        self.detached
    }

    /// Returns whether tracked or untracked working-tree changes exist.
    ///
    /// Dirty state is informational and is deliberately excluded from
    /// [`crate::EnvironmentIdentity`].
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }
}

fn discover_attached_commit(repo_root: &Path) -> Result<Option<String>, GitError> {
    let output = run_git_allow_failure(
        repo_root,
        ["rev-parse", "--verify", "HEAD"],
        "finding current commit",
    )?;
    if output.status.success() {
        required_stdout(output, "finding current commit")
            .and_then(validate_commit)
            .map(Some)
    } else {
        Ok(None)
    }
}

fn run_git<I, S>(
    directory: &Path,
    arguments: I,
    operation: &'static str,
) -> Result<Output, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_git_allow_failure(directory, arguments, operation)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(GitError::CommandFailed {
            operation,
            status: output.status.code(),
            stderr: stderr_text(&output),
        })
    }
}

fn run_git_allow_failure<I, S>(
    directory: &Path,
    arguments: I,
    operation: &'static str,
) -> Result<Output, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .stdin(Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0");
    run_git_command(&mut command, operation, GIT_COMMAND_TIMEOUT)
}

fn run_git_command(
    command: &mut Command,
    operation: &'static str,
    timeout: Duration,
) -> Result<Output, GitError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| GitError::TimedOut {
            operation,
            timeout,
            cleanup: String::new(),
        })?;
    let mut stdout =
        tempfile::tempfile().map_err(|source| GitError::CommandIo { operation, source })?;
    let mut stderr =
        tempfile::tempfile().map_err(|source| GitError::CommandIo { operation, source })?;
    command
        .stdout(Stdio::from(
            stdout
                .try_clone()
                .map_err(|source| GitError::CommandIo { operation, source })?,
        ))
        .stderr(Stdio::from(
            stderr
                .try_clone()
                .map_err(|source| GitError::CommandIo { operation, source })?,
        ));

    let mut child = command.spawn().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            GitError::Unavailable(source)
        } else {
            GitError::CommandIo { operation, source }
        }
    })?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                return Err(terminate_timed_out_git(&mut child, operation, timeout));
            }
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(GIT_WAIT_INTERVAL.min(remaining));
            }
            Err(source) => {
                let cleanup = terminate_git(&mut child);
                let source = match cleanup {
                    None => source,
                    Some(cleanup) => io::Error::new(
                        source.kind(),
                        format!("{source}; process cleanup also failed: {cleanup}"),
                    ),
                };
                return Err(GitError::CommandIo { operation, source });
            }
        }
    };

    let stdout = read_captured_output(&mut stdout, operation)?;
    let stderr = read_captured_output(&mut stderr, operation)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn terminate_timed_out_git(
    child: &mut std::process::Child,
    operation: &'static str,
    timeout: Duration,
) -> GitError {
    let cleanup = terminate_git(child).map_or_else(String::new, |error| {
        format!("; process cleanup also failed: {error}")
    });
    GitError::TimedOut {
        operation,
        timeout,
        cleanup,
    }
}

fn terminate_git(child: &mut std::process::Child) -> Option<io::Error> {
    let kill_error = child.kill().err();
    let deadline = Instant::now() + GIT_CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return kill_error,
            Ok(None) if Instant::now() >= deadline => {
                return Some(kill_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out while reaping terminated Git process",
                    )
                }));
            }
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(GIT_WAIT_INTERVAL.min(remaining));
            }
            Err(wait_error) => {
                return Some(match kill_error {
                    None => wait_error,
                    Some(kill_error) => io::Error::new(
                        wait_error.kind(),
                        format!("kill failed: {kill_error}; reap failed: {wait_error}"),
                    ),
                });
            }
        }
    }
}

fn read_captured_output(
    output: &mut std::fs::File,
    operation: &'static str,
) -> Result<Vec<u8>, GitError> {
    output
        .seek(SeekFrom::Start(0))
        .and_then(|_| {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).map(|_| bytes)
        })
        .map_err(|source| GitError::CommandIo { operation, source })
}

fn required_stdout(output: Output, operation: &'static str) -> Result<String, GitError> {
    let value = decode_stdout(output, operation)?;
    if value.is_empty() {
        Err(GitError::EmptyOutput { operation })
    } else {
        Ok(value)
    }
}

fn decode_stdout(output: Output, operation: &'static str) -> Result<String, GitError> {
    String::from_utf8(output.stdout)
        .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|source| GitError::InvalidUtf8 { operation, source })
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

fn validate_commit(commit: String) -> Result<String, GitError> {
    if commit.len() >= 12 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(commit.to_ascii_lowercase())
    } else {
        Err(GitError::InvalidCommit(commit))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[cfg(target_os = "linux")]
    use std::ffi::OsString;

    fn git(directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .output()
            .expect("git must be installed for core Git tests");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Git test output is UTF-8")
            .trim()
            .to_owned()
    }

    fn repository() -> TempDir {
        let temp = tempfile::tempdir().expect("temporary repository");
        git(temp.path(), &["init", "--quiet"]);
        git(temp.path(), &["config", "user.name", "Lightrail Test"]);
        git(
            temp.path(),
            &["config", "user.email", "lightrail@example.invalid"],
        );
        fs::write(temp.path().join("compose.yaml"), "services: {}\n").expect("fixture");
        git(temp.path(), &["add", "compose.yaml"]);
        git(temp.path(), &["commit", "--quiet", "-m", "initial"]);
        temp
    }

    #[test]
    fn discovers_root_branch_commit_and_dirty_state() {
        let temp = repository();
        git(temp.path(), &["checkout", "--quiet", "-b", "feature/login"]);
        let nested = temp.path().join("a/b");
        fs::create_dir_all(&nested).expect("nested directory");

        let clean = GitContext::discover(&nested).expect("clean context");
        assert_eq!(clean.repo_root(), temp.path().canonicalize().expect("root"));
        assert_eq!(clean.branch(), "feature/login");
        assert!(clean.commit().is_some());
        assert!(!clean.is_detached());
        assert!(!clean.is_dirty());

        fs::write(temp.path().join("untracked.txt"), "dirty\n").expect("dirty fixture");
        let dirty = GitContext::discover(&nested).expect("dirty context");
        assert_eq!(dirty.branch(), clean.branch());
        assert_eq!(dirty.commit(), clean.commit());
        assert!(dirty.is_dirty());
    }

    #[test]
    fn detached_head_uses_twelve_commit_characters() {
        let temp = repository();
        let commit = git(temp.path(), &["rev-parse", "HEAD"]).to_ascii_lowercase();
        git(temp.path(), &["checkout", "--quiet", "--detach", "HEAD"]);
        fs::write(temp.path().join("dirty.txt"), "included in build\n").expect("dirty fixture");

        let context = GitContext::discover(temp.path()).expect("detached context");

        assert!(context.is_detached());
        assert!(context.is_dirty());
        assert_eq!(context.branch(), format!("sha-{}", &commit[..12]));
        assert_eq!(context.commit(), Some(commit.as_str()));
    }

    #[test]
    fn reports_non_repository_as_a_typed_error() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let error = GitContext::discover(temp.path()).expect_err("not a repository");

        assert!(matches!(error, GitError::NotRepository { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_git_command_terminates_and_reaps_on_timeout() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let pid_file = temp.path().join("git-command.pid");
        let mut command = Command::new("sh");
        command.args([
            OsString::from("-c"),
            OsString::from("echo $$ > \"$1\"; exec sleep 30"),
            OsString::from("sh"),
            pid_file.as_os_str().to_owned(),
        ]);

        let error = run_git_command(
            &mut command,
            "testing bounded Git execution",
            Duration::from_millis(200),
        )
        .expect_err("the command must time out");
        assert!(matches!(
            error,
            GitError::TimedOut {
                operation: "testing bounded Git execution",
                timeout,
                ..
            } if timeout == Duration::from_millis(200)
        ));

        let pid = fs::read_to_string(pid_file)
            .expect("child publishes its PID")
            .trim()
            .parse::<u32>()
            .expect("child PID");
        assert!(
            !PathBuf::from(format!("/proc/{pid}")).exists(),
            "timed-out Git process {pid} was not reaped"
        );
    }
}
