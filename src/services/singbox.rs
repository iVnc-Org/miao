use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration};
use tracing::info;

use super::routing::{self, EffectiveRouting, RuntimePhase};
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
    fs::set_permissions(&sing_box_home, fs::Permissions::from_mode(0o700))?;

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

    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(&sing_box_path)
            .current_dir(&sing_box_home)
            .env_remove("DISABLE_NFTABLES")
            .kill_on_drop(true)
            .arg("check")
            .arg("-c")
            .arg(&config_path)
            .output(),
    )
    .await
    .map_err(|_| AppError::message("CONFIG_CHECK_TIMEOUT: sing-box check exceeded 10 seconds"))?
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
/// try_wait 回收子进程；保留退出句柄，交给生命周期锁下的清理收回防火墙规则。
pub async fn sing_box_is_running(state: &Arc<AppState>) -> bool {
    let mut lock = state.sing_process.lock().await;

    match &mut *lock {
        Some(proc) => match proc.child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        },
        None => false,
    }
}

#[cfg(test)]
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

#[derive(Default)]
pub struct ChildOutput {
    tail: Mutex<VecDeque<u8>>,
    started: AtomicBool,
}

impl ChildOutput {
    fn append(&self, bytes: &[u8]) {
        let mut tail = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        tail.extend(bytes);
        let excess = tail.len().saturating_sub(64 * 1024);
        tail.drain(..excess);
        if String::from_utf8_lossy(tail.make_contiguous()).contains("sing-box started (") {
            self.started.store(true, Ordering::SeqCst);
        }
    }
    pub fn text(&self) -> String {
        let mut tail = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(tail.make_contiguous())
            .trim()
            .to_string()
    }
}

fn capture_child_output(child: &mut tokio::process::Child) -> Arc<ChildOutput> {
    let output = Arc::new(ChildOutput::default());
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    tokio::spawn(async move {
        let mut destination = io::stderr();
        while let Some(bytes) = receiver.recv().await {
            let _ = destination.write_all(&bytes).await;
        }
    });
    fn capture(
        reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
        output: Arc<ChildOutput>,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            let mut reader = reader;
            let mut bytes = [0u8; 4096];
            loop {
                match reader.read(&mut bytes).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        output.append(&bytes[..count]);
                        let _ = sender.try_send(bytes[..count].to_vec());
                    }
                }
            }
        });
    }
    if let Some(stdout) = child.stdout.take() {
        capture(stdout, output.clone(), sender.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        capture(stderr, output.clone(), sender);
    }
    output
}

pub async fn start_sing_internal(state: &Arc<AppState>) -> AppResult<()> {
    let _lifecycle = state.sing_lifecycle.lock().await;
    let _ = extract_sing_box()?;
    if sing_box_is_running(state).await {
        return Err(AppError::AlreadyRunning);
    }
    if let Some(error) = stop_locked(state).await {
        return Err(AppError::message(error));
    }
    let (mut config, mut plan, epoch) = routing::read_plan().await?;
    routing::check_current(state, epoch)?;
    if plan.effective != EffectiveRouting::None {
        super::openwrt::check_net_admin()?;
        if !super::openwrt::tun_available()? {
            return Err(AppError::message(
                "TUN_UNAVAILABLE: host preparation is required before activation",
            ));
        }
    }
    let result = async {
        for attempt in 0..2 {
            routing::check_current(state, epoch)?;
            routing::status(state, RuntimePhase::Starting, Some(plan.clone()), None);
            validate_sing_box_config().await?;
            routing::check_current(state, epoch)?;
            let tun = config["inbounds"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|inbound| inbound["type"] == "tun")
                .and_then(|inbound| inbound["interface_name"].as_str())
                .unwrap_or("sing-tun");
            let routes = super::route_cleanup::RouteOwnership::before(&config, &plan).await?;
            super::firewall::Fw3Rules::cleanup_stale().await?;
            let firewall = super::firewall::Fw3Rules::install(&plan, tun).await?;
            if let Err(error) = routing::check_current(state, epoch) {
                if let Some(firewall) = firewall {
                    let _ = firewall.cleanup().await;
                }
                return Err(error);
            }
            let mut command = tokio::process::Command::new(get_sing_box_home().join("sing-box"));
            command
                .current_dir(get_sing_box_home())
                .env_remove("DISABLE_NFTABLES")
                .kill_on_drop(true)
                .arg("run")
                .arg("-c")
                .arg(get_sing_box_home().join("config.json"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // A dead manager must not leave an unmanaged core routing the host.
            let parent_pid = std::process::id() as nix::libc::pid_t;
            unsafe {
                command.pre_exec(move || {
                    if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGTERM) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if nix::libc::getppid() != parent_pid {
                        return Err(std::io::Error::other("Miao exited before core spawn"));
                    }
                    Ok(())
                });
            }
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    if let Some(firewall) = firewall {
                        let _ = firewall.cleanup().await;
                    }
                    return Err(AppError::context("Failed to spawn sing-box", error));
                }
            };
            let pid = child
                .id()
                .ok_or_else(|| AppError::message("sing-box PID unavailable"))?;
            let output = capture_child_output(&mut child);
            *state.sing_process.lock().await = Some(SingBoxProcess {
                child,
                pid,
                started_at: Instant::now(),
                firewall: firewall.clone(),
                routes: routes.clone(),
                output: output.clone(),
            });
            match wait_for_ready(state, &config, &plan, epoch, pid, &output).await {
                Ok(()) => {
                    if let Some(routes) = &routes {
                        routes.capture(pid).await?;
                    }
                    routing::check_current(state, epoch)?;
                    if plan.effective == EffectiveRouting::Nftables {
                        routing::remember_nft_rules(true);
                    }
                    if let Some(firewall) = firewall {
                        firewall.watch();
                    }
                    routing::status(state, RuntimePhase::Ready, Some(plan.clone()), None);
                    watch_child(state, epoch, pid);
                    return Ok(());
                }
                Err(error) => {
                    let _ = stop_locked(state).await;
                    let details = output.text();
                    if attempt == 0
                        && plan.requested == crate::models::TunRouting::Auto
                        && plan.effective == EffectiveRouting::Nftables
                        && known_nft_failure(&details)
                        && routing::is_current(state, epoch)
                    {
                        routing::remember_nft_rules(false);
                        plan.effective = EffectiveRouting::PolicyRoute;
                        plan.reason = Some(
                            "nftables 基础查询成功，但内核不支持启动所需规则；已回退到兼容策略路由"
                                .into(),
                        );
                        routing::apply(&mut config, &plan)?;
                        routing::write_config(&config, &plan, epoch).await?;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        Err(AppError::message(
            "START_FAILED: routing fallback exhausted",
        ))
    }
    .await;
    if let Err(error) = &result {
        let _ = stop_locked(state).await;
        if routing::is_current(state, epoch) {
            routing::status(
                state,
                RuntimePhase::Failed,
                Some(plan),
                Some(error.to_string()),
            );
        }
    }
    result
}

fn known_nft_failure(details: &str) -> bool {
    (details.contains("auto-redirect: missing nftables support")
        || details.contains("setup nftables"))
        && [
            "invalid argument",
            "operation not supported",
            "protocol not supported",
            "no such file or directory",
        ]
        .iter()
        .any(|message| details.contains(message))
}

async fn wait_for_ready(
    state: &Arc<AppState>,
    config: &serde_json::Value,
    plan: &routing::RoutingPlan,
    epoch: u64,
    pid: u32,
    output: &ChildOutput,
) -> AppResult<()> {
    let controller = config["experimental"]["clash_api"]["external_controller"]
        .as_str()
        .unwrap_or("127.0.0.1:6262");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(250))
        .build()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let socks = config["inbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|inbound| inbound["tag"] == "socks-in");
    let mut consecutive = 0;
    let mut route_checked = plan.effective != EffectiveRouting::PolicyRoute;
    loop {
        routing::check_current(state, epoch)?;
        {
            let mut slot = state.sing_process.lock().await;
            let process = slot
                .as_mut()
                .filter(|process| process.pid == pid)
                .ok_or_else(|| AppError::message("START_CANCELLED: child process replaced"))?;
            if let Some(exit) = process.child.try_wait()? {
                drop(slot);
                sleep(Duration::from_millis(25)).await;
                return Err(AppError::message(format!(
                    "sing-box exited during startup with code {}: {}",
                    exit.code().unwrap_or(-1),
                    output.text()
                )));
            }
        }
        let started = output.started.load(Ordering::SeqCst);
        let api_ready = started
            && client
                .get(format!("http://{controller}/version"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
        let mut tun_ready = true;
        for inbound in config["inbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|inbound| inbound["type"] == "tun")
        {
            let name = inbound["interface_name"].as_str().unwrap_or("sing-tun");
            tun_ready &= std::path::Path::new("/sys/class/net").join(name).exists();
            if started && !route_checked {
                if let Some(ip) =
                    super::openwrt::find_command(&super::openwrt::command_search_dirs(), "ip")
                {
                    let route = super::openwrt::command_output(
                        &ip,
                        &["-4", "route", "get", "198.19.255.254"],
                        Duration::from_secs(2),
                    )
                    .await?;
                    route_checked = route.status.success()
                        && String::from_utf8_lossy(&route.stdout)
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .windows(2)
                            .any(|pair| pair == ["dev", name]);
                } else {
                    route_checked = true;
                } // The core's post-start receipt remains required.
            }
        }
        let socks_ready = if let Some(socks) = socks {
            let host = match socks["listen"].as_str().unwrap_or("127.0.0.1") {
                "0.0.0.0" => "127.0.0.1",
                "::" => "::1",
                host => host,
            };
            tokio::time::timeout(
                Duration::from_millis(150),
                tokio::net::TcpStream::connect((
                    host,
                    socks["listen_port"].as_u64().unwrap_or(1080) as u16,
                )),
            )
            .await
            .is_ok_and(|result| result.is_ok())
        } else {
            false
        };
        if api_ready && tun_ready && route_checked && socks_ready {
            consecutive += 1;
            if consecutive >= 2 {
                return Ok(());
            }
        } else {
            consecutive = 0;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AppError::message(format!(
                "READY_TIMEOUT: core data plane did not become ready within 8 seconds: {}",
                output.text()
            )));
        }
        sleep(Duration::from_millis(75)).await;
    }
}

fn watch_child(state: &Arc<AppState>, _epoch: u64, pid: u32) {
    let state = Arc::downgrade(state);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(500)).await;
            let Some(state) = state.upgrade() else {
                break;
            };
            let Ok(_lifecycle) = state.sing_lifecycle.try_lock() else {
                continue;
            };
            let mut slot = state.sing_process.lock().await;
            let Some(process) = slot.as_mut().filter(|process| process.pid == pid) else {
                break;
            };
            if let Ok(Some(exit)) = process.child.try_wait() {
                let process = slot.take().unwrap();
                drop(slot);
                let mut cleanup_errors = Vec::new();
                if let Some(firewall) = process.firewall {
                    if let Err(error) = firewall.cleanup().await {
                        cleanup_errors.push(error.to_string());
                    }
                }
                if let Some(routes) = process.routes {
                    if let Err(error) = routes.cleanup().await {
                        tracing::error!(%error, "Failed to clean core network resources");
                        cleanup_errors.push(error.to_string());
                    }
                }
                if !state.shutting_down.load(Ordering::SeqCst)
                    && state
                        .runtime_status
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .phase
                        == RuntimePhase::Ready
                {
                    routing::status(
                        &state,
                        RuntimePhase::Failed,
                        None,
                        Some(format!(
                            "CORE_EXITED: code {}: {}{}",
                            exit.code().unwrap_or(-1),
                            process.output.text(),
                            if cleanup_errors.is_empty() {
                                String::new()
                            } else {
                                format!("; network cleanup failed: {}", cleanup_errors.join("; "))
                            }
                        )),
                    );
                }
                break;
            }
        }
    });
}

pub async fn stop_sing_internal(state: &Arc<AppState>) {
    let epoch = state.runtime_epoch.load(Ordering::SeqCst);
    let _lifecycle = state.sing_lifecycle.lock().await;
    let mut error = stop_locked(state).await;
    if error.is_none() {
        error = super::route_cleanup::RouteOwnership::recover()
            .await
            .err()
            .map(|error| error.to_string());
    }
    if error.is_none() {
        error = super::firewall::Fw3Rules::cleanup_stale()
            .await
            .err()
            .map(|error| error.to_string());
    }
    if routing::is_current(state, epoch) {
        routing::status(
            state,
            if error.is_some() {
                RuntimePhase::Failed
            } else {
                RuntimePhase::Stopped
            },
            None,
            error,
        );
    }
}

async fn stop_locked(state: &Arc<AppState>) -> Option<String> {
    let mut failure = None;
    let process = state.sing_process.lock().await.take();
    if let Some(mut process) = process {
        if process.child.try_wait().ok().flatten().is_none() {
            if let Some(pid) = process.child.id() {
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }
            if tokio::time::timeout(Duration::from_secs(3), process.child.wait())
                .await
                .is_err()
            {
                let _ = process.child.start_kill();
                let _ = process.child.wait().await;
            }
        }
        if let Some(firewall) = process.firewall {
            if let Err(error) = firewall.cleanup().await {
                tracing::error!(%error, "Failed to clean core firewall resources");
                failure = Some(error.to_string());
            }
        }
        if let Some(routes) = process.routes {
            if let Err(error) = routes.cleanup().await {
                tracing::error!(%error, "Failed to clean core network resources");
                failure = Some(error.to_string());
            }
        }
    }
    failure
}

#[cfg(test)]
mod tests {
    use super::{startup_output_details, sync_embedded_file};

    #[test]
    fn only_unsupported_nftables_failures_allow_automatic_retry() {
        assert!(super::known_nft_failure(
            "auto-redirect: missing nftables support: netlink receive: invalid argument"
        ));
        assert!(super::known_nft_failure(
            "auto-redirect: setup nftables: operation not supported"
        ));
        assert!(!super::known_nft_failure(
            "auto-redirect: missing nftables support: operation not permitted"
        ));
        assert!(!super::known_nft_failure("decode config: invalid argument"));
        assert!(!super::known_nft_failure(
            "listen tcp: address already in use"
        ));
    }

    #[test]
    fn core_log_capture_is_bounded_and_remembers_the_start_receipt() {
        let output = super::ChildOutput::default();
        output.append(b"sing-box start");
        output.append(b"ed (0.01s)\n");
        output.append(&vec![b'x'; 100_000]);
        assert!(output.started.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(output.text().len(), 64 * 1024);
    }

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
