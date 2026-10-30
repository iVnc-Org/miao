mod auth;
mod build_info;
mod error;
mod handlers;
mod models;
mod paths;
mod responses;
mod router;
mod services;
mod state;
#[cfg(test)]
mod test_support;
mod validation;

use crate::build_info::current_version;
use crate::error::{AppError, AppResult};
use nix::unistd::Uid;
use std::{fs, net::IpAddr, sync::Arc};
use tracing::{error, info, warn};

use models::{Config, ProxyMode, DEFAULT_PORT, DEFAULT_SOCKS_LISTEN, DEFAULT_SOCKS_PORT};
use services::{
    config::{
        gen_config, migrate_legacy_subscription_nodes, restore_config_from_cache,
        save_config_cache, save_config_to, SubFetchPolicy,
    },
    openwrt::check_and_install_openwrt_dependencies,
    proxy::restore_last_proxy,
    runtime::{load_runtime_state_report, save_running_state},
    singbox::{extract_sing_box, start_sing_internal, stop_sing_internal},
    sub_nodes::hydrate_sub_status,
};
use state::AppState;

#[derive(Default, PartialEq, Eq)]
struct CliOptions {
    password: Option<String>,
    config_path: Option<std::path::PathBuf>,
    password_command: bool,
    show_help: bool,
    show_version: bool,
    socks_listen: Option<String>,
    socks_port: Option<u16>,
    mode: Option<ProxyMode>,
    no_start: bool,
    vps_host: Option<String>,
    vps_ssh_port: Option<u16>,
    vps_password: Option<String>,
}

impl std::fmt::Debug for CliOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliOptions")
            .field("password_command", &self.password_command)
            .finish_non_exhaustive()
    }
}

fn print_help() {
    let version = current_version();
    println!(
        r#"miao {version}

Usage:
  miao [OPTIONS]
  miao [--config PATH] password set [PASSWORD]

Without startup options: first run starts the panel only; later runs restore saved state.

Options:
  -h, --help                    Show this help message
  -V, --version                 Show version information
      --config <PATH>           Configuration file path
      --password <PASSWORD>     Set persistent panel password and start
      --mode <MODE>             Start proxy: global, process, pool
      --no-start                Start panel only; persist stopped state
      --vps-host <HOST>         Deploy/recover VPS and select it (--mode global)
      --vps-ssh-port <PORT>     VPS SSH port (default: 22; root user)
      --vps-password <PASSWORD> SSH password; omitted uses local SSH keys
                               Password arguments may appear in shell history/process listings
      --socks-listen <ADDR>     SOCKS5 listen address (default: {DEFAULT_SOCKS_LISTEN})
      --socks-port <PORT>       SOCKS5 listen port (default: {DEFAULT_SOCKS_PORT})

Examples:
  miao --mode global
  miao --mode global --vps-host 154.202.118.100
  miao --mode global --vps-host 154.202.118.100 --vps-ssh-port 22 --vps-password 'secret'
  miao --no-start
  miao --socks-listen 0.0.0.0 --socks-port 1080
  miao --socks-listen=0.0.0.0 --socks-port=1080
"#
    );
}

fn parse_cli_args<I, S>(args: I) -> AppResult<CliOptions>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut options = CliOptions::default();
    let mut args = args.into_iter().map(Into::into).skip(1).peekable();
    while let Some(arg) = args.next() {
        let (key, inline) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
        if ["--mode", "--vps-host", "--vps-ssh-port", "--vps-password"].contains(&key) {
            let value = match inline {
                Some(value) => value.to_owned(),
                None => args
                    .next()
                    .ok_or_else(|| AppError::message(format!("{key} requires a value")))?,
            };
            let duplicate = match key {
                "--mode" => options.mode.is_some(),
                "--vps-host" => options.vps_host.is_some(),
                "--vps-ssh-port" => options.vps_ssh_port.is_some(),
                _ => options.vps_password.is_some(),
            };
            if duplicate || value.trim().is_empty() {
                return Err(AppError::message(format!(
                    "{key} must be specified once with a non-empty value"
                )));
            }
            match key {
                "--mode" => {
                    options.mode = Some(match value.as_str() {
                        "global" => ProxyMode::Global,
                        "process" => ProxyMode::Process,
                        "pool" => ProxyMode::Pool,
                        _ => {
                            return Err(AppError::message("--mode must be global, process or pool"))
                        }
                    })
                }
                "--vps-host" => {
                    validation::Validator::server_address(&value).map_err(AppError::message)?;
                    options.vps_host = Some(value);
                }
                "--vps-ssh-port" => {
                    options.vps_ssh_port = Some(
                        value
                            .parse::<u16>()
                            .ok()
                            .filter(|p| *p > 0)
                            .ok_or_else(|| {
                                AppError::message("--vps-ssh-port must be between 1 and 65535")
                            })?,
                    )
                }
                _ => options.vps_password = Some(value),
            }
            continue;
        }
        match arg.as_str() {
            "--no-start" => {
                if options.no_start {
                    return Err(AppError::message("--no-start specified more than once"));
                }
                options.no_start = true;
            }
            "-h" | "--help" => options.show_help = true,
            "-V" | "--version" => options.show_version = true,
            "--config" => {
                let path = args
                    .next()
                    .filter(|v| !v.trim().is_empty())
                    .ok_or_else(|| AppError::message("--config requires a path"))?;
                options.config_path = Some(path.into());
            }
            "--password" => {
                if options.password.is_some() {
                    return Err(AppError::message("Password specified more than once"));
                }
                options.password = Some(
                    args.next()
                        .ok_or_else(|| AppError::message("--password requires a value"))?,
                );
            }
            "password" => {
                if options.password_command || args.next().as_deref() != Some("set") {
                    return Err(AppError::message("Usage: miao password set [PASSWORD]"));
                }
                options.password_command = true;
                if args.peek().is_some_and(|v| !v.starts_with('-')) {
                    if options.password.is_some() {
                        return Err(AppError::message("Password specified more than once"));
                    }
                    options.password = args.next();
                }
            }
            "--socks-listen" => {
                options.socks_listen =
                    Some(parse_socks_listen(&args.next().ok_or_else(|| {
                        AppError::message("--socks-listen requires an address")
                    })?)?)
            }
            "--socks-port" => {
                options.socks_port =
                    Some(parse_socks_port(&args.next().ok_or_else(|| {
                        AppError::message("--socks-port requires a port")
                    })?)?)
            }
            _ if arg.starts_with("--config=") => {
                let path = &arg[9..];
                if path.trim().is_empty() {
                    return Err(AppError::message("--config requires a path"));
                }
                options.config_path = Some(path.into());
            }
            _ if arg.starts_with("--password=") => {
                if options.password.is_some() {
                    return Err(AppError::message("Password specified more than once"));
                }
                options.password = Some(arg[11..].into());
            }
            _ if arg.starts_with("--socks-listen=") => {
                options.socks_listen = Some(parse_socks_listen(&arg[15..])?)
            }
            _ if arg.starts_with("--socks-port=") => {
                options.socks_port = Some(parse_socks_port(&arg[13..])?)
            }
            _ => return Err(AppError::message("Unknown argument. Use --help for usage.")),
        }
    }

    if options.no_start && (options.mode.is_some() || options.vps_host.is_some()) {
        return Err(AppError::message(
            "--no-start cannot be combined with --mode or VPS deployment",
        ));
    }
    if options.vps_host.is_some() && options.mode != Some(ProxyMode::Global) {
        return Err(AppError::message(
            "VPS deployment requires explicit --mode global",
        ));
    }
    if options.vps_host.is_none()
        && (options.vps_ssh_port.is_some() || options.vps_password.is_some())
    {
        return Err(AppError::message("VPS SSH options require --vps-host"));
    }
    if options.password_command
        && (options.mode.is_some() || options.no_start || options.vps_host.is_some())
    {
        return Err(AppError::message(
            "password set cannot be combined with startup options",
        ));
    }
    Ok(options)
}

fn parse_socks_listen(value: &str) -> AppResult<String> {
    if value.trim().is_empty() {
        return Err(AppError::message("--socks-listen cannot be empty"));
    }

    value
        .parse::<IpAddr>()
        .map_err(|_| AppError::message("--socks-listen must be an IP address"))?;
    Ok(value.to_string())
}

fn parse_socks_port(value: &str) -> AppResult<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| AppError::message("--socks-port must be between 1 and 65535"))?;
    if port == 0 {
        return Err(AppError::message(
            "--socks-port must be between 1 and 65535",
        ));
    }
    Ok(port)
}

fn apply_cli_overrides(config: &mut Config, options: &CliOptions) {
    if let Some(socks_listen) = &options.socks_listen {
        config.socks_listen = Some(socks_listen.clone());
    }
    if let Some(socks_port) = options.socks_port {
        config.socks_port = Some(socks_port);
    }
}

fn browser_launch_env() -> Vec<(String, String)> {
    let mut envs = Vec::new();

    for key in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"] {
        if let Ok(value) = std::env::var(key) {
            envs.push((key.to_string(), value));
        }
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok().or_else(|| {
        std::env::var("SUDO_UID")
            .ok()
            .map(|uid| format!("/run/user/{uid}"))
    });

    if let Some(runtime_dir) = runtime_dir {
        envs.push(("XDG_RUNTIME_DIR".to_string(), runtime_dir.clone()));

        let bus_address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .ok()
            .unwrap_or_else(|| format!("unix:path={runtime_dir}/bus"));
        envs.push(("DBUS_SESSION_BUS_ADDRESS".to_string(), bus_address));
    } else if let Ok(bus_address) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        envs.push(("DBUS_SESSION_BUS_ADDRESS".to_string(), bus_address));
    }

    envs
}

async fn open_onboarding_browser(url: String) {
    let has_graphical_session =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    if !has_graphical_session {
        return;
    }

    let launch_env = browser_launch_env();
    let sudo_user = std::env::var("SUDO_USER")
        .ok()
        .filter(|user| !user.is_empty());
    let use_runuser = sudo_user.is_some();
    let mut command = if let Some(sudo_user) = sudo_user {
        let mut command = tokio::process::Command::new("runuser");
        command.arg("-u").arg(sudo_user).arg("--").arg("env");
        for (key, value) in &launch_env {
            command.arg(format!("{key}={value}"));
        }
        command.arg("xdg-open");
        command
    } else {
        tokio::process::Command::new("xdg-open")
    };

    command.arg(&url);
    if !use_runuser {
        command.envs(launch_env);
    }

    match command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
    {
        Ok(status) if status.success() => {}
        Ok(status) => warn!(
            url = %url,
            status = ?status.code(),
            "Failed to auto-open onboarding URL in browser"
        ),
        Err(err) => warn!(url = %url, error = %err, "Failed to launch browser opener"),
    }
}

fn config_declares_key(content: &str, key: &str) -> bool {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return false;
    };

    value
        .as_mapping()
        .is_some_and(|mapping| mapping.contains_key(key))
}

fn migrate_proxy_mode(config: &mut Config, mode_declared: bool) -> (bool, Option<String>) {
    let legacy_process = config.tun_process.legacy_enabled;
    let legacy_pool = config.share.legacy_enabled;
    config.tun_process.legacy_enabled = false;
    config.share.legacy_enabled = false;

    if mode_declared {
        return (false, None);
    }

    config.mode = if legacy_pool {
        ProxyMode::Pool
    } else if legacy_process {
        ProxyMode::Process
    } else {
        ProxyMode::Global
    };

    let warning = if legacy_process && legacy_pool {
        Some("检测到旧配置同时启用了进程代理和分享模式，已迁移为代理池模式".to_string())
    } else {
        None
    };
    (true, warning)
}

fn config_backup_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".bak");
    backup.into()
}

#[tokio::main]
async fn main() -> AppResult<()> {
    // 初始化结构化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli_options = parse_cli_args(std::env::args())?;

    if cli_options.show_help {
        print_help();
        return Ok(());
    }

    if cli_options.show_version {
        println!("miao {}", current_version());
        return Ok(());
    }

    if !Uid::effective().is_root() {
        error!("This application must be run as root");
        std::process::exit(1);
    }

    if cli_options.password_command || cli_options.password.is_some() {
        let password = match &cli_options.password {
            Some(value) => value.clone(),
            None => auth::prompt_password()?,
        };
        let resolution = paths::resolve_config_path_with(cli_options.config_path.clone())?;
        auth::set_password(&resolution.path, &password, None)?;
        if cli_options.password_command {
            println!("Panel password updated.");
            return Ok(());
        }
    }

    paths::prepare_data_dir().await?;

    if let Ok(current_exe) = std::env::current_exe() {
        let backup_path = format!("{}.bak", current_exe.display());
        if std::path::Path::new(&backup_path).exists() {
            let _ = fs::remove_file(&backup_path);
        }
    }

    info!("Reading configuration...");
    let config_resolution = paths::resolve_config_path_with(cli_options.config_path.clone())?;
    let config_path = config_resolution.path.clone();
    info!(
        config_path = ?config_path,
        source = ?config_resolution.source,
        "Resolved configuration path"
    );

    let (mut config, mut migration_warning): (Config, Option<String>) =
        match tokio::fs::read_to_string(&config_path).await {
            Ok(content) => {
                let mode_declared = config_declares_key(&content, "mode");
                let mut config: Config = serde_yaml::from_str(&content)?;
                let (migrated, warning) = migrate_proxy_mode(&mut config, mode_declared);
                if migrated {
                    let backup_path = config_backup_path(&config_path);
                    tokio::fs::copy(&config_path, &backup_path)
                        .await
                        .map_err(|error| {
                            AppError::context(
                                "Failed to back up config before mode migration",
                                error,
                            )
                        })?;
                    save_config_to(&config_path, &config).await?;
                    info!(config_path = ?config_path, backup_path = ?backup_path, mode = ?config.mode, "Migrated legacy proxy mode configuration");
                    if let Some(message) = &warning {
                        warn!("{message}");
                    }
                }
                (config, warning)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    config_path = ?config_path,
                    "No config file found, using in-memory default configuration"
                );
                (Config::default(), None)
            }
            Err(e) => return Err(e.into()),
        };
    apply_cli_overrides(&mut config, &cli_options);
    if let Err(error) = migrate_legacy_subscription_nodes(&config).await {
        warn!(error = %error, "Failed to import subscription nodes from legacy config cache");
    }
    let (runtime_state, runtime_warning) = load_runtime_state_report().await;
    if let Some(warning) = runtime_warning {
        migration_warning = Some(match migration_warning {
            Some(previous) => format!("{previous}; {warning}"),
            None => warning,
        });
    }
    let port = config.port.unwrap_or(DEFAULT_PORT);
    let socks_listen = config
        .socks_listen
        .as_deref()
        .unwrap_or(DEFAULT_SOCKS_LISTEN);
    let socks_port = config.socks_port.unwrap_or(DEFAULT_SOCKS_PORT);
    let subs_count = config.subs.len();
    let nodes_count = config.nodes.len();

    info!(
        port = port,
        socks_listen = socks_listen,
        socks_port = socks_port,
        subs = subs_count,
        nodes = nodes_count,
        "Configuration loaded"
    );

    let _ = extract_sing_box()?;

    // 初始化应用状态
    let app_state = Arc::new(
        AppState::with_config_path(config.clone(), config_path)
            .map_err(|e| AppError::context("Failed to create HTTP client", e))?,
    );
    *app_state.config_warning.lock().await = migration_warning.clone();
    let state_for_init = app_state.clone();
    services::version::watch_upgrade_recovery(app_state.clone());

    // Start web server immediately so the panel is accessible during initialization
    let app = router::build_router(app_state.clone());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!(port = port, url = %format!("http://localhost:{}", port), "Miao panel started");

    // Auto-open browser for onboarding when no subs/nodes configured
    if config.subs.is_empty() && config.nodes.is_empty() {
        let url = format!("http://localhost:{}", port);
        tokio::spawn(async move {
            open_onboarding_browser(url).await;
        });
    }

    services::vps::recover_jobs(&app_state).await;
    if cli_options.no_start {
        save_running_state(false).await?;
    }
    let requested_mode = cli_options.mode;
    let no_start = cli_options.no_start;
    let startup_request = cli_options.vps_host.map(|host| services::vps::Connection {
        host,
        ssh_port: cli_options.vps_ssh_port.unwrap_or(22),
        auth: if cli_options.vps_password.is_some() {
            "password"
        } else {
            "local_key"
        }
        .into(),
        secret: cli_options.vps_password.unwrap_or_default(),
        ..Default::default()
    });

    // Background: generate config, check dependencies, and start sing-box
    tokio::spawn(async move {
        let config_update = state_for_init.config_update.lock().await;
        // Remote provisioning runs separately and commits against the latest config.
        let config = state_for_init.config.read().await.clone();

        // 用本地缓存回填订阅状态。必须在下面两个提前返回之前做——服务处于停止
        // 状态时恰恰最需要它，否则面板上订阅节点数会是 0。
        if let Err(e) = services::sub_nodes::migrate_local_subscriptions().await {
            error!(error = %e, "Failed to migrate local subscription parsing, keeping cache");
        }
        hydrate_sub_status(&state_for_init, &config.subs).await;

        if let Some(mode) = requested_mode {
            drop(config_update);
            if let Err(error) =
                services::startup::run(state_for_init.clone(), mode, startup_request).await
            {
                eprintln!("[失败] {error}\n[面板] 服务继续运行，可在 Web 查看节点和 VPS 任务");
                *state_for_init.config_warning.lock().await = Some(error.to_string());
            }
            state_for_init
                .initializing
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return;
        }

        if config.subs.is_empty() && config.nodes.is_empty() {
            info!("No subscriptions or nodes configured, waiting for onboarding");
            state_for_init
                .initializing
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return;
        }

        if no_start || !runtime_state.running {
            info!("Previous runtime state was stopped, not starting sing-box");
            state_for_init
                .initializing
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return;
        }

        info!("Preparing initial sing-box config...");
        match restore_config_from_cache(&config).await {
            Ok(_) => {
                info!("Using cached config for initial startup");
                *state_for_init.config_source.lock().await = Some("cache".to_string());
                *state_for_init.config_warning.lock().await =
                    Some("当前使用上次成功生成的缓存配置，订阅未在启动时自动刷新".to_string());
            }
            Err(cache_err) => {
                info!(error = %cache_err, "No matching config cache available, generating config");
                // 开机自启不主动刷订阅：链接几分钟就失效，抓也是白抓。
                // 只有节点缓存彻底为空时才做一次首装抓取。
                match gen_config(&config, &state_for_init, SubFetchPolicy::CacheOrBootstrap).await {
                    Ok(outcome) => {
                        if outcome.has_sub_nodes() || config.subs.is_empty() {
                            save_config_cache(&config).await;
                        } else if !config.subs.is_empty() {
                            *state_for_init.config_warning.lock().await =
                                Some("订阅节点缓存为空，请点击刷新订阅".to_string());
                        }
                        *state_for_init.config_source.lock().await = Some("generated".to_string());
                        if outcome.has_sub_nodes() || config.subs.is_empty() {
                            *state_for_init.config_warning.lock().await = migration_warning.clone();
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to generate config");
                        *state_for_init.config_warning.lock().await =
                            Some("无法生成配置且无匹配缓存，请添加有效订阅或手动节点".to_string());
                        state_for_init
                            .initializing
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
            }
        }

        // 依赖安装会跑 opkg/apk 且没有超时，软件源不可达时会一直卡着，
        // 所以先放锁，别让整个面板的配置类接口陪着一起卡死。
        drop(config_update);

        info!("Checking dependencies...");
        if let Err(e) = check_and_install_openwrt_dependencies().await {
            error!("Failed to check or install OpenWrt dependencies: {}", e);
        }

        // 重新拿锁：下面还要写 runtime.json 和配置缓存，这两个都是从配置派生的持久状态。
        // 放锁期间用户可能已经改过模式或订阅，所以快照也要重新取。
        let config_update = state_for_init.config_update.lock().await;
        let config = state_for_init.config.read().await.clone();

        if state_for_init
            .startup_cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
            || state_for_init
                .shutting_down
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            state_for_init
                .initializing
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return;
        }
        match start_sing_internal(&state_for_init).await {
            Ok(_) => {
                info!("sing-box started successfully");
                if let Err(e) = save_running_state(true).await {
                    error!(error = %e, "Failed to save runtime state after startup");
                }
                save_config_cache(&config).await;
                // Restore under the configuration lock so a delayed task cannot
                // overwrite a newer CLI or web node selection.
                restore_last_proxy(&state_for_init).await;
            }
            Err(e) => error!("Failed to start sing-box: {}", e),
        }
        drop(config_update);
        state_for_init
            .initializing
            .store(false, std::sync::atomic::Ordering::Relaxed);
    });

    let vps_state = app_state.clone();
    tokio::spawn(async move {
        while vps_state
            .initializing
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        if requested_mode.is_none() && !no_start {
            services::vps::initialize_legacy(vps_state).await;
        }
    });
    let state_for_shutdown = app_state.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(state_for_shutdown))
    .await?;
    Ok(())
}

async fn shutdown_signal(state: Arc<AppState>) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.expect("failed to install Ctrl+C handler");
        }
        _ = sigterm.recv() => {}
    }

    state
        .shutting_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    if let Ok(jobs) = services::vps::jobs(&state).await {
        for job in jobs.iter().filter(|job| job.active) {
            eprintln!("[VPS] 本机退出不保证远程任务终止；任务 {}，目标 {}:{}。重启后请核查原任务，勿重复部署。", job.id, job.host, job.ssh_port);
        }
    }
    let _config_update = state.config_update.lock().await;
    info!("Shutting down, stopping sing-box...");
    stop_sing_internal(&state).await;
}

#[cfg(test)]
mod tests {
    use super::{config_declares_key, migrate_proxy_mode, parse_cli_args};
    use crate::models::{Config, ProxyMode};

    #[test]
    fn cli_modes_and_minimal_vps_options() {
        for (name, mode) in [
            ("global", ProxyMode::Global),
            ("process", ProxyMode::Process),
            ("pool", ProxyMode::Pool),
        ] {
            let opts = parse_cli_args(["miao", "--mode", name]).unwrap();
            assert_eq!(opts.mode, Some(mode));
        }
        let opts = parse_cli_args([
            "miao",
            "--mode=global",
            "--vps-host=154.202.118.100",
            "--vps-ssh-port=2222",
            "--vps-password",
            "中文 $ ' secret",
        ])
        .unwrap();
        assert_eq!(opts.vps_ssh_port, Some(2222));
        assert_eq!(opts.vps_password.as_deref(), Some("中文 $ ' secret"));
        assert!(!format!("{opts:?}").contains("secret"));
        let opts =
            parse_cli_args(["miao", "--mode", "global", "--vps-host", "2001:db8::1"]).unwrap();
        assert!(opts.vps_password.is_none());
        assert!(parse_cli_args(["miao"]).unwrap().mode.is_none());
        assert!(parse_cli_args(["miao", "--no-start"]).unwrap().no_start);
    }

    #[test]
    fn cli_rejects_ambiguous_startup_requests_without_echoing_secrets() {
        for args in [
            vec!["--mode", "invalid"],
            vec!["--mode"],
            vec!["--mode=global", "--mode=pool"],
            vec!["--no-start", "--mode=global"],
            vec!["--no-start", "--no-start"],
            vec!["--vps-host=154.202.118.100"],
            vec!["--mode=pool", "--vps-host=154.202.118.100"],
            vec!["--vps-ssh-port=22"],
            vec!["--vps-password=topsecret"],
            vec![
                "--mode=global",
                "--vps-host=154.202.118.100",
                "--vps-password=",
            ],
            vec![
                "--mode=global",
                "--vps-host=154.202.118.100",
                "--vps-ssh-port=0",
            ],
            vec![
                "--mode=global",
                "--vps-host=154.202.118.100",
                "--vps-ssh-port=65536",
            ],
            vec!["password", "set", "topsecret", "--mode=global"],
        ] {
            let error = parse_cli_args(std::iter::once("miao").chain(args)).unwrap_err();
            assert!(!error.to_string().contains("topsecret"));
        }
    }

    #[test]
    fn config_declares_top_level_key() {
        let yaml = r#"
port: 6161
mode: global
subs: []
"#;

        assert!(config_declares_key(yaml, "mode"));
    }

    #[test]
    fn config_declares_key_ignores_nested_key() {
        let yaml = r#"
custom_rules:
  - '{"mode":"global"}'
"#;

        assert!(!config_declares_key(yaml, "mode"));
    }

    #[test]
    fn config_declares_key_handles_invalid_yaml() {
        assert!(!config_declares_key("mode: [", "mode"));
    }

    #[test]
    fn cli_password_commands_preserve_values_and_config_paths() {
        let options = parse_cli_args([
            "miao",
            "--config",
            "/tmp/instance.yaml",
            "password",
            "set",
            "中文 $ ' pass",
        ])
        .unwrap();
        assert!(options.password_command);
        assert_eq!(options.password.as_deref(), Some("中文 $ ' pass"));
        assert_eq!(
            options.config_path.unwrap(),
            std::path::PathBuf::from("/tmp/instance.yaml")
        );
        let options = parse_cli_args(["miao", "--password", "--config"]).unwrap();
        assert_eq!(options.password.as_deref(), Some("--config"));
        assert!(options.config_path.is_none());
        let options = parse_cli_args(["miao", "password", "set", "--config=/tmp/x.yaml"]).unwrap();
        assert!(options.password_command);
        assert!(options.password.is_none());
        assert!(parse_cli_args(["miao", "password", "set", "a", "b"]).is_err());
        assert!(parse_cli_args(["miao", "password", "set", "a", "--password=b"]).is_err());
    }
    #[test]
    fn cli_accepts_config_path_forms() {
        assert!(parse_cli_args(["miao", "--config", "/tmp/miao.yaml"]).is_ok());
        assert!(parse_cli_args(["miao", "--config=/tmp/miao.yaml"]).is_ok());
    }

    #[test]
    fn cli_rejects_missing_config_path() {
        let error = parse_cli_args(["miao", "--config"]).unwrap_err();
        assert_eq!(error.to_string(), "--config requires a path");

        let error = parse_cli_args(["miao", "--config="]).unwrap_err();
        assert_eq!(error.to_string(), "--config requires a path");
    }

    #[test]
    fn legacy_mode_migration_prefers_pool_and_warns_on_conflict() {
        let mut config = Config::default();
        config.tun_process.legacy_enabled = true;
        config.share.legacy_enabled = true;

        let (migrated, warning) = migrate_proxy_mode(&mut config, false);

        assert!(migrated);
        assert_eq!(config.mode, ProxyMode::Pool);
        assert!(warning.is_some());
        assert!(!config.tun_process.legacy_enabled);
        assert!(!config.share.legacy_enabled);
    }

    #[test]
    fn explicit_mode_wins_over_legacy_flags() {
        let mut config = Config {
            mode: ProxyMode::Process,
            ..Default::default()
        };
        config.share.legacy_enabled = true;

        let (migrated, warning) = migrate_proxy_mode(&mut config, true);

        assert!(!migrated);
        assert!(warning.is_none());
        assert_eq!(config.mode, ProxyMode::Process);
    }
}
