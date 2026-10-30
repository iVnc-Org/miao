use super::Connection;
use crate::error::{AppError, AppResult};
use std::{
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::Stdio,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::{timeout, Duration},
};

pub fn random_id() -> AppResult<String> {
    let mut bytes = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

struct Credentials(PathBuf);
impl Drop for Credentials {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn tail(mut pipe: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = pipe.read(&mut chunk).await?;
        if n == 0 {
            return Ok(result);
        }
        result.extend_from_slice(&chunk[..n]);
        if result.len() > 131072 {
            result.drain(..result.len() - 131072);
        }
    }
}

#[derive(Clone, Copy)]
pub enum Operation {
    Inspect,
    Launch,
    Poll,
}

impl Operation {
    fn timeout_message(self) -> &'static str {
        match self {
            Self::Inspect => "VPS environment inspection timed out; check SSH connectivity and retry",
            Self::Launch => "VPS deployment launch timed out; remote outcome unknown, reconnect to inspect before retrying",
            Self::Poll => "VPS deployment status check timed out; reconnect to inspect the remote task before retrying deployment",
        }
    }
}

pub async fn script(
    connection: &Connection,
    body: &str,
    seconds: u64,
    operation: Operation,
) -> AppResult<Vec<u8>> {
    let directory = std::env::temp_dir().join(format!(
        "miao-vps-ssh-{}-{}",
        std::process::id(),
        random_id()?
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let _credentials = Credentials(directory.clone());
    let create = |name: &str, content: &str, mode: u32| -> AppResult<PathBuf> {
        let path = directory.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)?;
        file.write_all(content.as_bytes())?;
        Ok(path)
    };
    // Fail before authentication if accepted host keys cannot be persisted.
    // OpenSSH otherwise may connect successfully despite failing to save TOFU.
    let account = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .map_err(|_| AppError::message("Unable to resolve SSH account"))?
        .ok_or_else(|| AppError::message("SSH account has no home directory"))?;
    let ssh_dir = account.dir.join(".ssh");
    if !ssh_dir.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(&ssh_dir)?;
    }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory_metadata = std::fs::symlink_metadata(&ssh_dir)?;
    if directory_metadata.file_type().is_symlink()
        || directory_metadata.uid() != nix::unistd::geteuid().as_raw()
        || directory_metadata.mode() & 0o022 != 0
    {
        return Err(AppError::message("Unsafe SSH directory"));
    }
    let known_hosts = ssh_dir.join("known_hosts");
    let known_file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&known_hosts)?;
    if known_file.metadata()?.uid() != nix::unistd::geteuid().as_raw() {
        return Err(AppError::message("Unsafe SSH known_hosts ownership"));
    }
    known_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut command = Command::new("ssh");
    command
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
    command.args([
        "-F",
        "/dev/null",
        "-T",
        "-p",
        &connection.ssh_port.to_string(),
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "NumberOfPasswordPrompts=1",
    ]);
    match connection.auth.as_str() {
        "password" => {
            create("password", &connection.secret, 0o600)?;
            // Directory generated locally; quote even when TMPDIR contains shell metacharacters.
            let password = super::quote(
                directory
                    .join("password")
                    .to_str()
                    .ok_or_else(|| AppError::message("Invalid temporary directory"))?,
            );
            let askpass = create("askpass", &format!("#!/bin/sh\ncat {password}\n"), 0o700)?;
            command
                .env("SSH_ASKPASS", askpass)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("DISPLAY", "miao:0")
                .args([
                    "-o",
                    "PreferredAuthentications=password,keyboard-interactive",
                    "-o",
                    "PubkeyAuthentication=no",
                ]);
        }
        "private_key" => {
            let path = create("key", &connection.secret, 0o600)?;
            command
                .arg("-i")
                .arg(path)
                .args(["-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]);
        }
        "local_key" => {
            command.args(["-o", "BatchMode=yes"]);
        }
        _ => return Err(AppError::message("Unsupported authentication")),
    }
    // OpenSSH known_hosts preserves TOFU across restarts; changed keys fail closed.
    command
        .args(["-o", "LogLevel=ERROR"])
        .arg(format!("{}@{}", connection.user, connection.host))
        .args(["sh", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    execute(&mut command, body, Duration::from_secs(seconds), operation).await
}

// Keep transport I/O independent of SSH credential setup so EOF and timeout
// behavior can be exercised without connecting to a VPS.
async fn execute(
    command: &mut Command,
    body: &str,
    duration: Duration,
    operation: Operation,
) -> AppResult<Vec<u8>> {
    let mut child = command
        .spawn()
        .map_err(|_| AppError::message("SSH client unavailable"))?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let result = timeout(duration, async {
        tokio::join!(
            async move {
                // ChildStdin::shutdown is a no-op on Unix. Owning the pipe in
                // this future closes it on success, write failure or cancellation.
                let result = stdin.write_all(body.as_bytes()).await;
                drop(stdin);
                result
            },
            tail(stdout),
            tail(stderr),
            child.wait()
        )
    })
    .await;
    match result {
        Ok((sent, out, err, status)) => {
            let status = status?;
            if !status.success() {
                let err = String::from_utf8_lossy(&err?).to_lowercase();
                let code = if err.contains("permission denied") {
                    "SSH authentication rejected"
                } else if err.contains("host key verification failed")
                    || err.contains("identification has changed")
                {
                    "SSH host key changed; verify fingerprint using the VPS console"
                } else if err.contains("connection refused") {
                    "SSH connection refused; check SSH port"
                } else if err.contains("resolve hostname") {
                    "SSH DNS resolution failed"
                } else {
                    "SSH/remote operation failed; inspect VPS connectivity and prerequisites"
                };
                return Err(AppError::message(code));
            }
            sent?;
            Ok(out?)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err(AppError::message(operation.timeout_message()))
        }
    }
}
use std::os::unix::fs::DirBuilderExt;

/// Only remove our private directories owned by this account whose creating
/// process no longer exists. Never follow symlinks or delete another live job.
pub fn cleanup_credentials() {
    use std::os::unix::fs::MetadataExt;
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name
                .strip_prefix("miao-vps-ssh-")
                .or_else(|| name.strip_prefix("miao-vps-check-"))
            else {
                continue;
            };
            let Some((pid, id)) = rest.split_once('-') else {
                continue;
            };
            if pid.parse::<u32>().is_err()
                || id.len() != 48
                || !id.bytes().all(|c| c.is_ascii_hexdigit())
                || std::path::Path::new(&format!("/proc/{pid}")).exists()
            {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir()
                    && !entry.path().is_symlink()
                    && meta.uid() == nix::unistd::geteuid().as_raw()
                    && meta.mode() & 0o777 == 0o700
                {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(program: &str) -> Command {
        let mut command = Command::new("sh");
        command
            .args(["-c", program])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    #[tokio::test]
    async fn closes_input_after_sending_script() {
        for operation in [Operation::Inspect, Operation::Launch, Operation::Poll] {
            let output = execute(
                &mut shell("sh -s; printf EOF_RECEIVED"),
                "printf SCRIPT_COMPLETED\n",
                Duration::from_secs(3),
                operation,
            )
            .await
            .unwrap();
            assert_eq!(output, b"SCRIPT_COMPLETEDEOF_RECEIVED");
        }
    }

    #[tokio::test]
    async fn drains_both_outputs_while_sending_large_input() {
        // Fill both output pipes before reading a body larger than the input
        // pipe. Sequential writing/reading would deadlock here.
        let program =
            "head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2; cat >/dev/null; printf DONE";
        let output = execute(
            &mut shell(program),
            &"x".repeat(262144),
            Duration::from_secs(3),
            Operation::Inspect,
        )
        .await
        .unwrap();
        assert_eq!(output.len(), 131072);
        assert!(output.ends_with(b"DONE"));
    }

    #[tokio::test]
    async fn closed_input_returns_error_without_waiting_for_timeout() {
        let error = execute(
            &mut shell("exec 0<&-; exit 0"),
            &"x".repeat(262144),
            Duration::from_secs(3),
            Operation::Inspect,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::Io(_)));
    }

    #[tokio::test]
    async fn timeout_kills_and_reaps_child_and_identifies_operation() {
        for operation in [Operation::Inspect, Operation::Launch, Operation::Poll] {
            let path = std::env::temp_dir().join(format!("miao-ssh-test-{}", random_id().unwrap()));
            let mut command = shell("echo $$ > \"$1\"; exec sleep 60");
            command.arg("test").arg(&path);
            let error = execute(&mut command, "", Duration::from_millis(300), operation)
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), operation.timeout_message());
            let pid: i32 = std::fs::read_to_string(&path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_eq!(unsafe { nix::libc::kill(pid, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(nix::libc::ESRCH)
            );
            std::fs::remove_file(path).unwrap();
        }
    }
}
