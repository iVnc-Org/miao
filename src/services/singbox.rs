use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::error::{AppError, AppResult};
use crate::state::{AppState, SingBoxProcess};

#[cfg(target_arch = "x86_64")]
const SING_BOX_BINARY: &[u8] = include_bytes!("../../embedded/sing-box-amd64");

#[cfg(target_arch = "aarch64")]
const SING_BOX_BINARY: &[u8] = include_bytes!("../../embedded/sing-box-arm64");

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported architecture: only x86_64 and aarch64 are supported. Please add support for your target architecture in embedded/ directory.");

const IP_RULE_BINARY: &[u8] = include_bytes!("../../embedded/geoip-cn.srs");
const SITE_RULE_BINARY: &[u8] = include_bytes!("../../embedded/geosite-geolocation-cn.srs");

pub fn get_sing_box_home() -> PathBuf {
    crate::embedding::runtime_dir()
}

pub fn extract_sing_box() -> AppResult<PathBuf> {
    let sing_box_home = get_sing_box_home();
    if !sing_box_home.exists() {
        fs::create_dir_all(&sing_box_home)
            .map_err(|e| AppError::context("Failed to create sing-box home directory", e))?;
    }

    let sing_box_path = sing_box_home.join("sing-box");
    let ip_rule_path = sing_box_home.join("chinaip.srs");
    let site_rule_path = sing_box_home.join("chinasite.srs");

    // Serialise extraction; rename replaces an old executable without truncating
    // an inode that a running sing-box process may still be using.
    static EXTRACTION_LOCK: Mutex<()> = Mutex::new(());
    let _guard = EXTRACTION_LOCK
        .lock()
        .map_err(|_| AppError::message("Core extraction lock poisoned"))?;
    sync_embedded_file(&sing_box_path, SING_BOX_BINARY, 0o755)?;
    sync_embedded_file(&ip_rule_path, IP_RULE_BINARY, 0o644)?;
    sync_embedded_file(&site_rule_path, SITE_RULE_BINARY, 0o644)?;
    let dashboard_dir = sing_box_home.join("dashboard");
    if !dashboard_dir.exists() {
        fs::create_dir_all(&dashboard_dir)
            .map_err(|e| AppError::context("Failed to create sing-box dashboard directory", e))?;
    }

    Ok(sing_box_home)
}

fn sync_embedded_file(path: &std::path::Path, bytes: &[u8], mode: u32) -> AppResult<()> {
    let matches = match fs::read(path) {
        Ok(existing) => Sha256::digest(&existing) == Sha256::digest(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(AppError::context("Failed to read embedded runtime file", e)),
    };
    if matches {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        return Ok(());
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AppError::message("System clock precedes Unix epoch"))?
        .as_nanos();
    let temporary = path.with_extension(format!("{}.{nonce}.new", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| AppError::context("Failed to create embedded runtime file", e))?;
    let result = (|| -> AppResult<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e| AppError::context("Failed to replace embedded runtime file", e))?;
    info!(file = ?path, "Updated embedded runtime file");
    Ok(())
}

/// 在停止运行中的实例前验证 sing-box 配置，避免不必要的服务中断
pub async fn validate_sing_box_config() -> AppResult<()> {
    let _ = extract_sing_box()?;
    let sing_box_home = get_sing_box_home();
    let sing_box_path = sing_box_home.join("sing-box");
    let config_path = sing_box_home.join("config.json");

    let output = tokio::process::Command::new(&sing_box_path)
        .current_dir(&sing_box_home)
        .arg("check")
        .arg("-c")
        .arg(&config_path)
        .output()
        .await
        .map_err(|e| AppError::context("Failed to run sing-box config check", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::message(format!(
            "Config validation failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// 判断 sing-box 是否仍在运行。
///
/// 顺带回收已退出的子进程句柄（把 `sing_process` 置空），所以这是一次带副作用的查询，
/// 语义变更必须集中在这里改，不要再复制到调用方。
pub async fn sing_box_is_running(state: &Arc<AppState>) -> bool {
    let mut lock = state.sing_process.lock().await;

    match &mut *lock {
        Some(proc) => match proc.child.try_wait() {
            Ok(Some(_)) => {
                *lock = None;
                false
            }
            Ok(None) => true,
            Err(_) => false,
        },
        None => false,
    }
}

fn startup_output_details(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = stdout.trim();
    let stderr = stderr.trim();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (true, false) => stderr.to_string(),
        (false, true) => stdout.to_string(),
        (false, false) => format!("stderr: {stderr}\nstdout: {stdout}"),
    }
}

fn forward_child_output(child: &mut tokio::process::Child) {
    if let Some(mut stdout) = child.stdout.take() {
        tokio::spawn(async move {
            let mut destination = io::stdout();
            if let Err(error) = io::copy(&mut stdout, &mut destination).await {
                warn!(error = %error, "Failed to forward sing-box stdout");
            }
        });
    }

    if let Some(mut stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut destination = io::stderr();
            if let Err(error) = io::copy(&mut stderr, &mut destination).await {
                warn!(error = %error, "Failed to forward sing-box stderr");
            }
        });
    }
}

pub async fn start_sing_internal(state: &Arc<AppState>) -> AppResult<()> {
    let _ = extract_sing_box()?;

    let mut lock = state.sing_process.lock().await;
    if let Some(ref mut proc) = *lock {
        if proc
            .child
            .try_wait()
            .map_err(|e| {
                AppError::context("Failed to check whether sing-box is already running", e)
            })?
            .is_none()
        {
            return Err(AppError::AlreadyRunning);
        }
    }

    let sing_box_home = get_sing_box_home();
    let sing_box_path = sing_box_home.join("sing-box");
    let config_path = sing_box_home.join("config.json");

    info!(binary = ?sing_box_path, config = ?config_path, "Starting sing-box");

    let mut child = tokio::process::Command::new(&sing_box_path)
        .current_dir(&sing_box_home)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AppError::context("Failed to spawn sing-box process", e))?;

    let pid = child.id();
    info!(pid = pid, "sing-box process spawned");

    sleep(Duration::from_millis(500)).await;
    if let Some(exit_status) = child
        .try_wait()
        .map_err(|e| AppError::context("Failed to check sing-box startup status", e))?
    {
        let code = exit_status.code().unwrap_or(-1);
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| AppError::context("Failed to collect sing-box startup output", e))?;
        let details = startup_output_details(&output.stdout, &output.stderr);
        let suffix = if details.is_empty() {
            String::new()
        } else {
            format!(": {details}")
        };
        return Err(AppError::message(format!(
            "sing-box exited immediately with code {code}{suffix}"
        )));
    }

    forward_child_output(&mut child);
    *lock = Some(SingBoxProcess {
        child,
        started_at: Instant::now(),
    });
    drop(lock);

    Ok(())
}

pub async fn stop_sing_internal(state: &Arc<AppState>) {
    let mut lock = state.sing_process.lock().await;
    if let Some(ref mut proc) = *lock {
        if proc.child.try_wait().ok().flatten().is_none() {
            if let Some(pid) = proc.child.id() {
                // 发送 SIGTERM 信号请求进程优雅退出
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);

                // 使用 timeout 等待进程退出，避免忙等待
                let wait_result =
                    tokio::time::timeout(Duration::from_secs(3), proc.child.wait()).await;

                match wait_result {
                    Ok(Ok(_)) => {
                        // 进程正常退出
                    }
                    _ => {
                        // 超时或等待失败，强制杀死进程
                        let _ = proc.child.start_kill();
                        let _ = proc.child.wait().await;
                    }
                }
            }
        }
    }
    *lock = None;
}

#[cfg(test)]
mod tests {
    use super::{startup_output_details, sync_embedded_file};

    #[test]
    fn core_replacement_preserves_old_inode_and_updates_contents() {
        let dir = std::env::temp_dir().join(format!("miao-extraction-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core");
        let old_link = dir.join("old-core");
        std::fs::write(&path, b"old").unwrap();
        let _ = std::fs::remove_file(&old_link);
        std::fs::hard_link(&path, &old_link).unwrap();
        sync_embedded_file(&path, b"new", 0o755).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read(&old_link).unwrap(), b"old");
        sync_embedded_file(&path, b"new", 0o755).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_output_details_prefers_stderr() {
        assert_eq!(
            startup_output_details(b"", b"listen tcp 0.0.0.0:50000: address already in use\n"),
            "listen tcp 0.0.0.0:50000: address already in use"
        );
    }

    #[test]
    fn startup_output_details_preserves_both_streams() {
        assert_eq!(
            startup_output_details(b"startup context\n", b"fatal error\n"),
            "stderr: fatal error\nstdout: startup context"
        );
    }
}
