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

pub async fn script(connection: &Connection, body: &str, seconds: u64) -> AppResult<Vec<u8>> {
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
    let mut child = command
        .spawn()
        .map_err(|_| AppError::message("SSH client unavailable"))?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let result = timeout(Duration::from_secs(seconds), async {
        tokio::join!(
            async {
                stdin.write_all(body.as_bytes()).await?;
                stdin.shutdown().await
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
            Err(AppError::message(
                "SSH timed out; remote outcome unknown, reconnect to inspect before retrying",
            ))
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
