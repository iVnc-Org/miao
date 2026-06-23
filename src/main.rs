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

use crate::build_info::{git_commit_short, VERSION};
use crate::error::{AppError, AppResult};
use nix::unistd::Uid;
use std::{fs, net::IpAddr, sync::Arc};
use tracing::{error, info, warn};

use models::{Config, DEFAULT_PORT, DEFAULT_SOCKS_LISTEN, DEFAULT_SOCKS_PORT};
use services::{
    config::{gen_config, restore_config_from_cache, save_config_cache},
    openwrt::check_and_install_openwrt_dependencies,
    proxy::restore_last_proxy,
    singbox::{extract_sing_box, start_sing_internal, stop_sing_internal},
    vps::ensure_vps_hysteria_node,
};
use state::AppState;

#[derive(Debug, Default, PartialEq, Eq)]
struct CliOptions {
    show_help: bool,
    show_version: bool,
    socks_listen: Option<String>,
    socks_port: Option<u16>,
}

fn print_help() {
    println!(
        r#"miao v{VERSION}

Usage:
  miao [OPTIONS]

Options:
  -h, --help                    Show this help message
  -V, --version                 Show version information
      --socks-listen <ADDR>     SOCKS5 listen address (default: {DEFAULT_SOCKS_LISTEN})
      --socks-port <PORT>       SOCKS5 listen port (default: {DEFAULT_SOCKS_PORT})

Examples:
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
    let mut args = args.into_iter().map(Into::into).skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => options.show_help = true,
            "-V" | "--version" => options.show_version = true,
            "--socks-listen" => {
                let value = args
                    .next()
                    .ok_or_else(|| AppError::message("--socks-listen requires an address"))?;
                options.socks_listen = Some(parse_socks_listen(&value)?);
            }
            "--socks-port" => {
                let value = args
                    .next()
                    .ok_or_else(|| AppError::message("--socks-port requires a port"))?;
                options.socks_port = Some(parse_socks_port(&value)?);
            }
            _ if arg.starts_with("--socks-listen=") => {
                let value = arg.trim_start_matches("--socks-listen=");
                options.socks_listen = Some(parse_socks_listen(value)?);
            }
            _ if arg.starts_with("--socks-port=") => {
                let value = arg.trim_start_matches("--socks-port=");
                options.socks_port = Some(parse_socks_port(value)?);
            }
            _ => {
                return Err(AppError::message(format!(
                    "Unknown argument: {arg}. Use --help for usage."
                )));
            }
        }
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

fn config_declares_route_mode(content: &str) -> bool {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return false;
    };

    value
        .as_mapping()
        .is_some_and(|mapping| mapping.contains_key("route_mode"))
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
        match git_commit_short() {
            Some(commit) => println!("miao v{} ({})", VERSION, commit),
            None => println!("miao v{}", VERSION),
        }
        return Ok(());
    }

    if !Uid::effective().is_root() {
        error!("This application must be run as root");
        std::process::exit(1);
    }

    if let Ok(current_exe) = std::env::current_exe() {
        let backup_path = format!("{}.bak", current_exe.display());
        if std::path::Path::new(&backup_path).exists() {
            let _ = fs::remove_file(&backup_path);
        }
    }

    info!("Reading configuration...");
    let config_resolution = paths::resolve_config_path()?;
    let config_path = config_resolution.path.clone();
    info!(
        config_path = ?config_path,
        source = ?config_resolution.source,
        "Resolved configuration path"
    );

    let mut config: Config = match tokio::fs::read_to_string(&config_path).await {
        Ok(content) => {
            let route_mode_declared = config_declares_route_mode(&content);
            let mut config: Config = serde_yaml::from_str(&content)?;
            if route_mode_declared {
                info!(
                    config_path = ?config_path,
                    "Ignoring route_mode from configuration file; route mode is session-only"
                );
                config.route_mode = Default::default();
            }
            config
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                config_path = ?config_path,
                "No config file found, using in-memory default configuration"
            );
            Config::default()
        }
        Err(e) => return Err(e.into()),
    };
    apply_cli_overrides(&mut config, &cli_options);
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
    let state_for_init = app_state.clone();

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

    // Background: generate config, check dependencies, and start sing-box
    tokio::spawn(async move {
        let mut config = config;

        match ensure_vps_hysteria_node(&mut config, &state_for_init.config_path).await {
            Ok(_) => {
                *state_for_init.config.write().await = config.clone();
            }
            Err(e) => {
                error!(error = %e, "Failed to provision VPS from vps_ip");
                *state_for_init.config_warning.lock().await =
                    Some(format!("VPS 自动部署失败: {}", e));
            }
        }

        if config.subs.is_empty() && config.nodes.is_empty() {
            info!("No subscriptions or nodes configured, waiting for onboarding");
            state_for_init
                .initializing
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return;
        }

        info!("Preparing initial sing-box config...");
        let mut started_from_cache = false;
        let mut all_subs_failed = false;

        match restore_config_from_cache(&config).await {
            Ok(_) => {
                info!("Using cached config for initial startup");
                started_from_cache = true;
                *state_for_init.config_source.lock().await = Some("cache".to_string());
                *state_for_init.config_warning.lock().await =
                    Some("当前使用上次成功生成的缓存配置，订阅未在启动时自动刷新".to_string());
            }
            Err(cache_err) => {
                info!(error = %cache_err, "No matching config cache available, generating config");
                match gen_config(&config, &state_for_init).await {
                    Ok(has_sub_nodes) => {
                        if has_sub_nodes || config.subs.is_empty() {
                            save_config_cache(&config).await;
                        } else if !config.subs.is_empty() {
                            all_subs_failed = true;
                        }
                        *state_for_init.config_source.lock().await = Some("generated".to_string());
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

        info!("Checking dependencies...");
        if let Err(e) = check_and_install_openwrt_dependencies().await {
            error!("Failed to check or install OpenWrt dependencies: {}", e);
        }

        match start_sing_internal(&state_for_init).await {
            Ok(_) => {
                info!("sing-box started successfully");
                save_config_cache(&config).await;
                if all_subs_failed {
                    warn!("所有订阅获取失败，请检查当前订阅");
                    *state_for_init.config_warning.lock().await =
                        Some("所有订阅获取失败，请检查当前订阅".to_string());
                } else if !started_from_cache {
                    *state_for_init.config_warning.lock().await = None;
                }
                let state_for_proxy = state_for_init.clone();
                tokio::spawn(async move {
                    restore_last_proxy(&state_for_proxy).await;
                });
            }
            Err(e) => error!("Failed to start sing-box: {}", e),
        }
        state_for_init
            .initializing
            .store(false, std::sync::atomic::Ordering::Relaxed);
    });

    let state_for_shutdown = app_state.clone();
    axum::serve(listener, app)
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

    info!("Shutting down, stopping sing-box...");
    stop_sing_internal(&state).await;
}

#[cfg(test)]
mod tests {
    use super::config_declares_route_mode;

    #[test]
    fn config_declares_route_mode_when_top_level_key_exists() {
        let yaml = r#"
port: 6161
route_mode: global
subs: []
"#;

        assert!(config_declares_route_mode(yaml));
    }

    #[test]
    fn config_declares_route_mode_ignores_nested_key() {
        let yaml = r#"
custom_rules:
  - '{"route_mode":"global"}'
"#;

        assert!(!config_declares_route_mode(yaml));
    }

    #[test]
    fn config_declares_route_mode_handles_invalid_yaml() {
        assert!(!config_declares_route_mode("route_mode: ["));
    }
}
