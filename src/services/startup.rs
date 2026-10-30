//! One-shot CLI startup orchestration. SSH credentials never enter persisted state.
use super::{
    config::{gen_config, save_config_cache, save_config_to, SubFetchPolicy},
    proxy::{load_last_proxy, save_last_proxy},
    runtime::{load_runtime_state, save_running_state},
    singbox::{
        get_sing_box_home, sing_box_is_running, start_sing_internal, stop_sing_internal,
        validate_sing_box_config,
    },
    vps::{self, Connection, Job},
};
use crate::{
    error::{AppError, AppResult},
    models::{Config, LastProxy, ProxyMode, DEFAULT_SOCKS_LISTEN, DEFAULT_SOCKS_PORT},
    state::AppState,
};
use serde_json::Value;
use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

pub fn normalize_mode(config: &mut Config, mode: ProxyMode) -> AppResult<()> {
    config.mode = mode;
    match mode {
        ProxyMode::Process => {
            config.tun_process = config.tun_process.normalized().map_err(AppError::message)?;
            config
                .tun_process
                .validate_active()
                .map_err(AppError::message)?;
        }
        ProxyMode::Pool => config.share = config.share.normalized().map_err(AppError::message)?,
        ProxyMode::Global => {}
    }
    Ok(())
}

fn allowed(state: &AppState) -> AppResult<()> {
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err(AppError::message(
            "Miao is shutting down; inspect the remote task after restart",
        ));
    }
    if state.startup_cancelled.load(Ordering::SeqCst) {
        return Err(AppError::message(
            "CLI startup superseded by a web action; node retained, automatic activation cancelled",
        ));
    }
    Ok(())
}

pub async fn run(
    state: Arc<AppState>,
    mode: ProxyMode,
    request: Option<Connection>,
) -> AppResult<()> {
    allowed(&state)?;
    let mut candidate = state.config.read().await.clone();
    normalize_mode(&mut candidate, mode)?;
    // Do local prerequisite work before changing any remote service.
    if mode != ProxyMode::Pool {
        super::openwrt::check_and_install_openwrt_dependencies().await?;
    }
    allowed(&state)?;
    if let Some(request) = request {
        // Keep a previously running proxy available during a potentially long
        // remote deployment. This only uses existing caches and never refreshes subscriptions.
        resume_baseline(&state).await?;
        if !std::path::Path::new("/dev/net/tun").exists() {
            return Err(AppError::message(
                "Global mode requires /dev/net/tun; enable TUN before VPS deployment",
            ));
        }
        let _lock = state.config_update.lock().await;
        allowed(&state)?;
        if !sing_box_is_running(&state).await {
            check_local_ports(&candidate)?;
        }
        drop(_lock);
        let mut ssh = tokio::process::Command::new("ssh");
        ssh.arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let status = tokio::time::timeout(Duration::from_secs(5), ssh.status())
            .await
            .map_err(|_| {
                AppError::message(
                    "Local SSH client check timed out; VPS deployment was not started",
                )
            })?
            .map_err(|_| {
                AppError::message(
                    "OpenSSH client is required on the Miao host; VPS deployment was not started",
                )
            })?;
        if !status.success() {
            return Err(AppError::message(
                "Local SSH client check failed; VPS deployment was not started",
            ));
        }
        eprintln!("[VPS] 本机前提检查通过，开始部署/恢复……");
        run_vps(&state, request).await
    } else {
        activate(&state, mode, None).await?;
        eprintln!("[代理] 已启动 {mode:?} 模式；运行状态已保存");
        Ok(())
    }
}

async fn resume_baseline(state: &Arc<AppState>) -> AppResult<()> {
    let _lock = state.config_update.lock().await;
    allowed(state)?;
    let config = state.config.read().await.clone();
    if !load_runtime_state().await.running
        || sing_box_is_running(state).await
        || (config.nodes.is_empty() && config.subs.is_empty())
    {
        return Ok(());
    }
    eprintln!("[代理] 正在从本地缓存恢复原代理，部署期间保持可用……");
    let restored: AppResult<()> = async {
        if super::config::restore_config_from_cache(&config)
            .await
            .is_err()
        {
            gen_config(&config, state, SubFetchPolicy::CacheOnly).await?;
        }
        allowed(state)?;
        start_sing_internal(state).await?;
        super::proxy::restore_last_proxy(state).await;
        Ok(())
    }
    .await;
    if let Err(error) = restored {
        // An unusable old subscription must not prevent provisioning a new node.
        eprintln!("[代理] 原代理未能恢复，将继续 VPS 引导；本机启动条件仍须检查：{error}");
    }
    Ok(())
}

fn check_local_ports(config: &Config) -> AppResult<()> {
    let listen = config
        .socks_listen
        .as_deref()
        .unwrap_or(DEFAULT_SOCKS_LISTEN);
    let port = config.socks_port.unwrap_or(DEFAULT_SOCKS_PORT);
    let mut reservations = Vec::new();
    for (host, port) in [(listen, port), ("127.0.0.1", 6262)] {
        reservations.push(std::net::TcpListener::bind((host, port)).map_err(|_| {
            AppError::message(format!(
                "Local proxy port {host}:{port} is unavailable; VPS deployment was not started"
            ))
        })?);
    }
    Ok(())
}

fn matching(job: &Job, req: &Connection) -> bool {
    job.host == req.host
        && job.ssh_port == req.ssh_port
        && job.listen_port == req.listen_port
        && job.node_host == req.node_host
        && job.node_port == req.node_port
}

fn needs_reconciliation(job: &Job) -> bool {
    // A confirmed failure or completed rollback can be retried as a new task.
    // Unknown outcomes and saved-but-unverified nodes must inspect the old task.
    ![
        "success",
        "proxy_ready",
        "proxy_failed",
        "activation_cancelled",
        "error",
        "rolled_back",
    ]
    .contains(&job.stage.as_str())
}

fn reusable(job: &Job, config: &Config) -> Option<Value> {
    if ![
        "success",
        "proxy_ready",
        "proxy_failed",
        "activation_cancelled",
        "proxy_starting",
    ]
    .contains(&job.stage.as_str())
    {
        return None;
    }
    config
        .nodes
        .iter()
        .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
        .find(|node| {
            node["tag"].as_str() == job.tag.as_deref()
                && job.tag.is_some()
                && node["type"] == "hysteria2"
                && node["server"] == job.node_host
                && node["server_port"] == job.node_port
                && node["tls"]["enabled"] == true
                && node["tls"]["insecure"] == false
        })
}

async fn run_vps(state: &Arc<AppState>, mut req: Connection) -> AppResult<()> {
    req.validate()?;
    eprintln!(
        "[VPS] 目标 root@{}:{}；认证：{}",
        req.host,
        req.ssh_port,
        if req.auth == "local_key" {
            "Miao 主机 SSH 密钥"
        } else {
            "SSH 密码"
        }
    );
    let existing = vps::jobs(state)
        .await?
        .into_iter()
        .find(|job| matching(job, &req));
    let config = state.config.read().await.clone();
    let mut job = if let Some((job, node)) = existing
        .as_ref()
        .and_then(|job| reusable(job, &config).map(|node| (job, node)))
    {
        eprintln!("[VPS] 复用已保存节点，正在验证连接；不会重复安装");
        let mut saved = job.clone();
        saved.active = true;
        vps::activation_stage(state, &mut saved, "verifying_connection").await?;
        let verified = vps::verify_node(&node).await;
        saved.active = false;
        if verified.is_err() {
            vps::activation_stage(state, &mut saved, "connectivity_failed").await?;
            return Err(AppError::message("Saved VPS node failed connectivity verification; inspect UDP 543/firewall or recover it in the web panel"));
        }
        vps::activation_stage(state, &mut saved, "success").await?;
        saved
    } else {
        if let Some(job) = existing {
            if needs_reconciliation(&job) {
                req.id = job.id;
                eprintln!("[VPS] 核查已有远程任务，不重复启动安装");
            }
        }
        let mut events = state.vps_progress.subscribe();
        let initial = vps::start(state.clone(), req).await?;
        eprintln!(
            "[VPS] 任务 {}；SSH {}:{}；退出后可在 Web 核查此任务",
            initial.id, initial.host, initial.ssh_port
        );
        monitor(state, initial, &mut events).await?
    };
    if job.stage != "success" && reusable(&job, &*state.config.read().await).is_none() {
        return Err(AppError::message(format!("VPS task stopped at {}; inspect task {} in the web panel. Deployment was not automatically repeated", job.stage, job.id)));
    }
    let tag = job
        .tag
        .clone()
        .ok_or_else(|| AppError::message("VPS task returned no node"))?;
    job.active = true;
    vps::activation_stage(state, &mut job, "proxy_starting").await?;
    eprintln!("[代理] 节点连接已验证，正在启用全局代理并选择 VPS 节点……");
    let result = activate(state, ProxyMode::Global, Some(&tag)).await;
    job.active = false;
    match result {
        Ok(()) => {
            vps::activation_stage(state, &mut job, "proxy_ready").await?;
            eprintln!("[完成] VPS 节点已选中，实际代理请求验证通过，全局代理已启用");
            Ok(())
        }
        Err(error) => {
            job.events.push(error.to_string());
            let phase = if state.startup_cancelled.load(Ordering::SeqCst) {
                "activation_cancelled"
            } else {
                "proxy_failed"
            };
            vps::activation_stage(state, &mut job, phase).await?;
            Err(error)
        }
    }
}

async fn monitor(
    state: &Arc<AppState>,
    mut job: Job,
    events: &mut tokio::sync::broadcast::Receiver<Job>,
) -> AppResult<Job> {
    let mut progress = Progress::default();
    loop {
        for line in progress.lines(&job, Instant::now()) {
            eprintln!("{line}");
        }
        if !job.active {
            return Ok(job);
        }
        if state.shutting_down.load(Ordering::SeqCst) {
            return Err(AppError::message(format!(
                "Remote task {} may continue; inspect it after restart",
                job.id
            )));
        }
        // Snapshot fallback handles lagged receivers, missed final notifications,
        // and provides a bounded wakeup for shutdown detection.
        match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Ok(update)) if update.id == job.id => job = update,
            _ => {
                if let Some(update) = vps::jobs(state).await?.into_iter().find(|j| j.id == job.id) {
                    job = update;
                }
                if job.active && !state.vps_active.load(Ordering::SeqCst) {
                    return Err(AppError::message(format!("VPS task {} result could not be persisted; inspect the original remote task before retrying", job.id)));
                }
            }
        }
    }
}

/// Set the selector default before TUN is started, not just via a later API call.
pub(super) fn pin_selector(config: &mut Value, tag: &str) -> AppResult<()> {
    let selector = config["outbounds"]
        .as_array_mut()
        .and_then(|items| {
            items
                .iter_mut()
                .find(|v| v["tag"] == "proxy" && v["type"] == "selector")
        })
        .ok_or_else(|| AppError::message("Proxy selector missing"))?;
    if !selector["outbounds"]
        .as_array()
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(tag)))
    {
        return Err(AppError::message(
            "Selected node is missing from generated config",
        ));
    }
    selector["default"] = Value::String(tag.into());
    Ok(())
}

async fn prepare(
    state: &Arc<AppState>,
    config: &Config,
    tag: Option<&str>,
    required: bool,
) -> AppResult<()> {
    let policy = if required {
        SubFetchPolicy::CacheOnly
    } else {
        SubFetchPolicy::CacheOrBootstrap
    };
    gen_config(config, state, policy).await?;
    if let Some(tag) = tag {
        let path = get_sing_box_home().join("config.json");
        let mut value: Value = serde_json::from_slice(&tokio::fs::read(&path).await?)?;
        // Missing historical selections can be ignored; an explicit VPS target cannot.
        if required
            || value["outbounds"][0]["outbounds"]
                .as_array()
                .is_some_and(|nodes| nodes.iter().any(|v| v.as_str() == Some(tag)))
        {
            pin_selector(&mut value, tag)?;
        }
        super::write_file_atomic(
            &path,
            &serde_json::to_string(&value)?,
            "selected proxy config",
        )
        .await?;
    }
    validate_sing_box_config().await
}

async fn select(state: &Arc<AppState>, tag: &str) -> AppResult<()> {
    let url = "http://127.0.0.1:6262/proxies/proxy";
    state
        .http_client
        .put(url)
        .timeout(Duration::from_secs(5))
        .json(&serde_json::json!({"name":tag}))
        .send()
        .await?
        .error_for_status()?;
    let selected: Value = state
        .http_client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if selected["now"] != tag {
        return Err(AppError::message("Proxy node selection was not applied"));
    }
    Ok(())
}

fn socks_url(config: &Config) -> String {
    let host = match config
        .socks_listen
        .as_deref()
        .unwrap_or(DEFAULT_SOCKS_LISTEN)
    {
        "0.0.0.0" => "127.0.0.1",
        "::" => "::1",
        host => host,
    };
    let port = config.socks_port.unwrap_or(DEFAULT_SOCKS_PORT);
    if host.contains(':') {
        format!("socks5h://[{host}]:{port}")
    } else {
        format!("socks5h://{host}:{port}")
    }
}

async fn verify_main(config: &Config) -> AppResult<()> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(socks_url(config))?)
        .timeout(Duration::from_secs(20))
        .build()?;
    if client
        .get("https://www.gstatic.com/generate_204")
        .send()
        .await?
        .status()
        .as_u16()
        != 204
    {
        return Err(AppError::message("Main proxy connectivity check failed"));
    }
    Ok(())
}

async fn activate(state: &Arc<AppState>, mode: ProxyMode, tag: Option<&str>) -> AppResult<()> {
    let _lock = state.config_update.lock().await;
    allowed(state)?;
    let old = state.config.read().await.clone();
    let old_running = sing_box_is_running(state).await;
    let old_intent = load_runtime_state().await;
    let old_selection = load_last_proxy().await;
    let mut candidate = old.clone();
    normalize_mode(&mut candidate, mode)?;
    if candidate.nodes.is_empty() && candidate.subs.is_empty() {
        return Err(AppError::message(
            "No nodes configured; add nodes in the web panel before starting this mode",
        ));
    }
    // Restore the old selection synchronously for ordinary explicit starts.
    let selected = tag.or_else(|| {
        old_selection
            .as_ref()
            .filter(|p| p.group == "proxy")
            .map(|p| p.name.as_str())
    });
    let mut runtime_changed = false;
    let result: AppResult<()> = async {
        prepare(state, &candidate, selected, tag.is_some()).await?;
        allowed(state)?;
        runtime_changed = true;
        if old_running {
            stop_sing_internal(state).await;
        }
        start_sing_internal(state).await?;
        if let Some(tag) = tag {
            select(state, tag).await?;
            verify_main(&candidate).await?;
        }
        allowed(state)?;
        save_config_to(&state.config_path, &candidate).await?;
        if let Some(tag) = tag {
            save_last_proxy(&LastProxy {
                group: "proxy".into(),
                name: tag.into(),
            })
            .await?;
        }
        save_running_state(true).await?;
        *state.config.write().await = candidate.clone();
        save_config_cache(&candidate).await;
        *state.config_source.lock().await = Some("generated".into());
        *state.config_warning.lock().await = None;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        // Never leave a partially enabled new global route after a failed CLI start.
        if runtime_changed {
            stop_sing_internal(state).await;
        }
        *state.config.write().await = old.clone();
        // Persistence failures must not prevent an independent runtime rollback.
        let mut rollback_errors = Vec::new();
        if let Err(error) = save_config_to(&state.config_path, &old).await {
            rollback_errors.push(format!("configuration: {error}"));
        }
        let selection_result = match old_selection {
            Some(ref proxy) => save_last_proxy(proxy).await,
            None => super::proxy::clear_last_proxy().await,
        };
        if let Err(error) = selection_result {
            rollback_errors.push(format!("selection: {error}"));
        }
        if let Err(error) = super::runtime::save_runtime_state(old_intent).await {
            rollback_errors.push(format!("runtime state: {error}"));
        }
        if !old.nodes.is_empty() || !old.subs.is_empty() {
            // Rollback must use local caches, never refresh subscriptions.
            match gen_config(&old, state, SubFetchPolicy::CacheOnly).await {
                Ok(_)
                    if (runtime_changed || !old_running)
                        && (old_running || old_intent.running)
                        && !state.shutting_down.load(Ordering::SeqCst) =>
                {
                    match start_sing_internal(state).await {
                        Ok(()) => super::proxy::restore_last_proxy(state).await,
                        Err(error) => rollback_errors.push(format!("core restart: {error}")),
                    }
                }
                Ok(_) => {}
                Err(error) => rollback_errors.push(format!("core configuration: {error}")),
            }
        }
        let rollback: AppResult<()> = if rollback_errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::message(rollback_errors.join("; ")))
        };
        return Err(match rollback {
            Ok(()) => AppError::context("CLI startup failed; previous state restored", error),
            Err(rollback) => AppError::message(format!(
                "CLI startup failed: {error}; rollback failed: {rollback}"
            )),
        });
    }
    Ok(())
}

fn phase(stage: &str) -> &str {
    match stage {
        "starting" => "准备部署",
        "inspecting" => "检查 SSH 和远程环境",
        "reconnecting" | "checking" => "核查远程任务",
        "waiting_for_deployment" => "其他 Miao 正在部署，最多等待 120 秒，随后重新检查",
        "recovering_existing" => "复用已有 Miao 节点，保留密码和证书，不重启服务",
        "installing_dependencies" => "安装依赖",
        "downloading" => "下载 Hysteria2",
        "verifying_download" => "校验下载",
        "preparing" => "准备配置和证书",
        "backing_up" => "备份已有部署",
        "activating" => "激活远程服务",
        "checking_service" => "检查远程服务",
        "repairing" => "修复已有服务",
        "remote_ready" => "远程节点就绪",
        "saving_node" => "保存节点",
        "verifying_connection" => "验证实际代理连接",
        "success" => "节点部署完成，连接验证通过",
        "connectivity_failed" => {
            "节点已保存，连接验证失败；检查 UDP 543、安全组、防火墙及 NAT 映射"
        }
        "rolling_back" => "远程正在回滚",
        "rolled_back" => "远程部署失败，已回滚",
        "unknown" => "远程结果未知，请核查原任务，勿重复部署",
        "recovery_required" => "远程需要手工恢复，请保留备份",
        "error" => "环境检查或远程执行失败",
        _ => stage,
    }
}

#[derive(Default)]
struct Progress {
    events: Vec<String>,
    stage: String,
    downloaded: u64,
    last_download: Option<Instant>,
}
impl Progress {
    fn lines(&mut self, job: &Job, now: Instant) -> Vec<String> {
        let mut lines = Vec::new();
        // Find the overlap also when the server trims its bounded event history.
        let overlap = (0..=self.events.len().min(job.events.len()))
            .rev()
            .find(|n| self.events[self.events.len() - n..] == job.events[..*n])
            .unwrap_or(0);
        for event in &job.events[overlap..] {
            lines.push(format!(
                "[VPS] {}",
                phase(event)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect::<String>()
            ));
        }
        if job.stage != self.stage && job.events.last() != Some(&job.stage) {
            lines.push(format!(
                "[VPS] {}",
                phase(&job.stage)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect::<String>()
            ));
        }
        if job.downloaded != self.downloaded
            && (job.stage != "downloading"
                || self
                    .last_download
                    .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1)))
        {
            let total = if job.total > 0 {
                format!(
                    " / {} KiB ({}%)",
                    job.total / 1024,
                    job.downloaded
                        .saturating_mul(100)
                        .checked_div(job.total)
                        .unwrap_or(0)
                        .min(100)
                )
            } else {
                String::new()
            };
            lines.push(format!(
                "[VPS] 下载：{} KiB{total} · {}",
                job.downloaded / 1024,
                if job.source == "proxy" {
                    "代理下载"
                } else {
                    "直接下载"
                }
            ));
            self.downloaded = job.downloaded;
            self.last_download = Some(now);
        }
        self.events = job.events.clone();
        self.stage = job.stage.clone();
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn queued_web_stop_cancels_startup_before_waiting_for_config_lock() {
        let state = crate::test_support::app_state(Config::default());
        let lock = state.config_update.lock().await;
        let stop_state = state.clone();
        let task = tokio::spawn(async move {
            crate::handlers::service::stop_service(axum::extract::State(stop_state)).await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.startup_cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(allowed(&state).is_err());
        assert!(!task.is_finished());
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        drop(lock);
    }

    #[test]
    fn retry_known_failures_but_reconcile_uncertain_remote_outcomes() {
        for phase in ["error", "rolled_back", "success", "proxy_failed"] {
            assert!(!needs_reconciliation(&Job {
                stage: phase.into(),
                ..Default::default()
            }));
        }
        for phase in [
            "unknown",
            "recovery_required",
            "connectivity_failed",
            "downloading",
        ] {
            assert!(needs_reconciliation(&Job {
                stage: phase.into(),
                ..Default::default()
            }));
        }
    }

    #[test]
    fn occupied_local_proxy_port_blocks_remote_deployment_preflight() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = Config {
            socks_port: Some(listener.local_addr().unwrap().port()),
            ..Default::default()
        };
        assert!(check_local_ports(&config)
            .unwrap_err()
            .to_string()
            .contains("VPS deployment was not started"));
    }

    #[test]
    fn pins_exact_node_before_core_start_and_rejects_missing_target() {
        let mut config =
            json!({"outbounds":[{"type":"selector","tag":"proxy","outbounds":["old","new"]}]});
        pin_selector(&mut config, "new").unwrap();
        assert_eq!(config["outbounds"][0]["default"], "new");
        assert!(pin_selector(&mut config, "missing").is_err());
        assert!(pin_selector(&mut json!({}), "new").is_err());
    }

    #[test]
    fn reuses_only_verified_jobs_with_the_same_secure_node_endpoint() {
        let mut job = Job {
            host: "vps.example.com".into(),
            ssh_port: 22,
            listen_port: 543,
            node_host: "vps.example.com".into(),
            node_port: 543,
            tag: Some("node".into()),
            stage: "proxy_ready".into(),
            ..Default::default()
        };
        let mut config = Config { nodes: vec![json!({"type":"hysteria2", "tag":"node", "server":"vps.example.com", "server_port":543,
            "tls":{"enabled":true,"insecure":false}}).to_string()], ..Default::default() };
        assert!(reusable(&job, &config).is_some());
        for phase in [
            "success",
            "proxy_failed",
            "activation_cancelled",
            "proxy_starting",
        ] {
            job.stage = phase.into();
            assert!(reusable(&job, &config).is_some());
        }
        job.stage = "connectivity_failed".into();
        assert!(reusable(&job, &config).is_none());
        job.stage = "success".into();
        config.nodes[0] = config.nodes[0].replace("vps.example.com", "other.example.com");
        assert!(reusable(&job, &config).is_none());
        config.nodes.clear();
        assert!(reusable(&job, &config).is_none());
        let mut req = Connection {
            host: "vps.example.com".into(),
            auth: "local_key".into(),
            ..Default::default()
        };
        req.validate().unwrap();
        assert!(matching(&job, &req));
        req.ssh_port = 2222;
        assert!(!matching(&job, &req));
        req.ssh_port = 22;
        req.node_port = 443;
        assert!(!matching(&job, &req));
    }

    #[test]
    fn progress_keeps_history_deduplicates_throttles_and_handles_trimmed_events() {
        let now = Instant::now();
        let mut progress = Progress::default();
        let mut job = Job {
            stage: "downloading".into(),
            events: vec!["starting".into(), "downloading".into()],
            downloaded: 1024,
            total: 4096,
            source: "proxy".into(),
            ..Default::default()
        };
        let lines = progress.lines(&job, now);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("准备部署"));
        assert!(lines[2].contains("25%"));
        assert!(progress.lines(&job, now).is_empty());
        job.downloaded = 2048;
        assert!(progress
            .lines(&job, now + Duration::from_millis(500))
            .is_empty());
        assert!(progress.lines(&job, now + Duration::from_secs(1))[0].contains("50%"));
        job.events = vec!["downloading".into(), "saving_node".into()];
        job.stage = "saving_node".into();
        assert_eq!(progress.lines(&job, now).len(), 1);
        job.events.push("safe\u{1b}[31m\nerror".into());
        assert!(progress
            .lines(&job, now)
            .iter()
            .all(|line| !line.contains('\u{1b}') && !line.contains('\n')));
    }

    #[tokio::test]
    async fn monitor_subscribes_before_updates_and_receives_terminal_snapshot() {
        let state = crate::test_support::app_state(Config::default());
        let mut events = state.vps_progress.subscribe();
        let job = Job {
            id: "test".into(),
            active: true,
            stage: "starting".into(),
            ..Default::default()
        };
        let mut done = job.clone();
        done.active = false;
        done.stage = "success".into();
        assert!(state.vps_progress.send(done).is_ok());
        let result =
            tokio::time::timeout(Duration::from_secs(1), monitor(&state, job, &mut events))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(result.stage, "success");
        assert!(!result.active);
    }

    #[tokio::test]
    async fn web_stop_or_shutdown_prevents_cli_activation_before_any_core_changes() {
        let state = crate::test_support::app_state(Config::default());
        state.startup_cancelled.store(true, Ordering::SeqCst);
        assert!(activate(&state, ProxyMode::Global, Some("node"))
            .await
            .unwrap_err()
            .to_string()
            .contains("superseded"));
        state.startup_cancelled.store(false, Ordering::SeqCst);
        state.shutting_down.store(true, Ordering::SeqCst);
        assert!(activate(&state, ProxyMode::Global, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("shutting down"));
    }

    #[test]
    fn normalizes_modes_and_formats_local_proxy_addresses() {
        let mut config = Config::default();
        assert!(normalize_mode(&mut config, ProxyMode::Process).is_err());
        config.tun_process.r#match.names.push("curl".into());
        for mode in [ProxyMode::Global, ProxyMode::Process, ProxyMode::Pool] {
            normalize_mode(&mut config, mode).unwrap();
            assert_eq!(config.mode, mode);
        }
        config.socks_listen = Some("0.0.0.0".into());
        assert_eq!(socks_url(&config), "socks5h://127.0.0.1:1080");
        config.socks_listen = Some("::".into());
        assert_eq!(socks_url(&config), "socks5h://[::1]:1080");
    }
}
