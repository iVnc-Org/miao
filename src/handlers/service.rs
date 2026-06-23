use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc, time::Instant};
use tokio::time::Duration;

use crate::error::AppError;
use crate::models::{
    ApiResponse, ConnectivityResult, RouteMode, RouteModeRequest, StatusData,
    DEFAULT_SOCKS_LISTEN, DEFAULT_SOCKS_PORT,
};
use crate::responses::{status_error, success, success_no_data, HandlerResult};
use crate::services::{
    config::{apply_runtime_config_change, gen_config, restore_config_from_cache, save_config_cache},
    proxy::restore_last_proxy,
    singbox::{get_sing_box_home, start_sing_internal, stop_sing_internal},
};
use crate::state::AppState;

pub async fn get_status(State(state): State<Arc<AppState>>) -> Json<ApiResponse<StatusData>> {
    // 快速获取进程状态并立即释放锁
    let (running, pid, uptime_secs) = {
        let mut lock = state.sing_process.lock().await;

        if let Some(ref mut proc) = *lock {
            match proc.child.try_wait() {
                Ok(Some(_)) => {
                    *lock = None;
                    (false, None, None)
                }
                Ok(None) => {
                    let uptime = proc.started_at.elapsed().as_secs();
                    (true, proc.child.id(), Some(uptime))
                }
                Err(_) => (false, None, None),
            }
        } else {
            (false, None, None)
        }
    }; // sing_process 锁在此处释放

    let initializing = state
        .initializing
        .load(std::sync::atomic::Ordering::Relaxed);
    let warning = state.config_warning.lock().await.clone();
    let config_source = state.config_source.lock().await.clone();
    let route_mode = state
        .route_mode_override
        .read()
        .await
        .unwrap_or(RouteMode::default());

    success(
        if running { "running" } else { "stopped" },
        StatusData {
            running,
            initializing,
            route_mode,
            pid,
            uptime_secs,
            warning,
            config_source,
        },
    )
}

pub async fn start_service(State(state): State<Arc<AppState>>) -> HandlerResult {
    let config_path = get_sing_box_home().join("config.json");
    if !config_path.exists() {
        let config = state.config.read().await.clone();
        match restore_config_from_cache(&config).await {
            Ok(_) => {
                *state.config_source.lock().await = Some("cache".to_string());
                *state.config_warning.lock().await =
                    Some("当前使用上次成功生成的缓存配置，订阅未在启动时自动刷新".to_string());
            }
            Err(cache_err) => match gen_config(&config, &state).await {
                Ok(has_sub_nodes) => {
                    *state.config_source.lock().await = Some("generated".to_string());
                    if has_sub_nodes || config.subs.is_empty() {
                        save_config_cache(&config).await;
                        *state.config_warning.lock().await = None;
                    } else if !config.subs.is_empty() {
                        *state.config_warning.lock().await =
                            Some("所有订阅获取失败，请检查当前订阅".to_string());
                    }
                }
                Err(generate_err) => {
                    return Err(status_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to prepare sing-box config: cache restore failed: {}; regenerate failed: {}",
                            cache_err, generate_err
                        ),
                    ));
                }
            },
        }
    }

    match start_sing_internal(&state).await {
        Ok(_) => {
            let state_for_proxy = state.clone();
            tokio::spawn(async move {
                restore_last_proxy(&state_for_proxy).await;
            });
            Ok(success_no_data("sing-box started successfully"))
        }
        Err(AppError::AlreadyRunning) => Err(status_error(
            StatusCode::BAD_REQUEST,
            "sing-box is already running",
        )),
        Err(e) => Err(status_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to start: {}", e),
        )),
    }
}

pub async fn stop_service(State(state): State<Arc<AppState>>) -> Json<ApiResponse<()>> {
    stop_sing_internal(&state).await;
    success_no_data("sing-box stopped")
}

async fn sing_box_is_running(state: &Arc<AppState>) -> bool {
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

pub async fn set_route_mode(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RouteModeRequest>,
) -> HandlerResult {
    let _config_update = state.config_update.lock().await;
    let was_running = sing_box_is_running(&state).await;
    let old_config = state.config.read().await.clone();
    let current_route_mode = state
        .route_mode_override
        .read()
        .await
        .unwrap_or(RouteMode::default());

    if current_route_mode == req.route_mode {
        return Ok(success_no_data("Route mode unchanged"));
    }

    let mut old_runtime_config = old_config.clone();
    old_runtime_config.route_mode = current_route_mode;
    let mut new_runtime_config = old_config.clone();
    new_runtime_config.route_mode = req.route_mode;

    let result = apply_runtime_config_change(
        &state,
        &old_runtime_config,
        &new_runtime_config,
        was_running,
    )
    .await;

    match result {
        Ok(_) if was_running => Ok(success_no_data(
            "Route mode updated for current session and sing-box restarted",
        )),
        Ok(_) => Ok(success_no_data("Route mode updated for current session")),
        Err(e) => Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

#[derive(Deserialize)]
pub(crate) struct ConnectivityRequest {
    url: String,
}

pub async fn test_connectivity(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectivityRequest>,
) -> Json<ApiResponse<ConnectivityResult>> {
    let start = Instant::now();
    let (socks_listen, socks_port) = {
        let config = state.config.read().await;
        (
            config
                .socks_listen
                .clone()
                .unwrap_or_else(|| DEFAULT_SOCKS_LISTEN.to_string()),
            config.socks_port.unwrap_or(DEFAULT_SOCKS_PORT),
        )
    };
    let proxy_url = socks_proxy_url(&socks_listen, socks_port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .proxy(reqwest::Proxy::all(proxy_url).expect("valid local socks proxy URL"))
        .build();

    let result = match client {
        Ok(client) => match client.head(&req.url).send().await {
            Ok(_) => ConnectivityResult {
                name: String::new(),
                url: req.url,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                success: true,
            },
            Err(_) => ConnectivityResult {
                name: String::new(),
                url: req.url,
                latency_ms: None,
                success: false,
            },
        },
        Err(_) => ConnectivityResult {
            name: String::new(),
            url: req.url,
            latency_ms: None,
            success: false,
        },
    };

    success("Test completed", result)
}

fn socks_proxy_url(listen: &str, port: u16) -> String {
    let host = if listen == "0.0.0.0" {
        DEFAULT_SOCKS_LISTEN
    } else if listen == "::" {
        "::1"
    } else {
        listen
    };

    if host
        .parse::<IpAddr>()
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false)
    {
        format!("socks5h://[{host}]:{port}")
    } else {
        format!("socks5h://{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;

    use super::{get_status, socks_proxy_url};
    use crate::models::{Config, RouteMode};
    use crate::test_support::app_state;

    #[tokio::test]
    async fn get_status_reports_stopped_when_no_process_exists() {
        let state = app_state(Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
            route_mode: Default::default(),
            vps_ip: None,
        });

        let axum::response::Json(response) = get_status(State(state)).await;

        assert!(response.success);
        assert_eq!(response.message, "stopped");
        let data = response.data.unwrap();
        assert!(!data.running);
        assert!(data.pid.is_none());
        assert!(data.uptime_secs.is_none());
    }

    #[test]
    fn socks_proxy_url_handles_wildcard_and_ipv6_listeners() {
        assert_eq!(socks_proxy_url("0.0.0.0", 1080), "socks5h://127.0.0.1:1080");
        assert_eq!(socks_proxy_url("::", 1080), "socks5h://[::1]:1080");
        assert_eq!(socks_proxy_url("::1", 1080), "socks5h://[::1]:1080");
    }

    #[tokio::test]
    async fn get_status_reports_route_mode_override_without_mutating_config() {
        let state = app_state(Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
            route_mode: RouteMode::Rule,
            vps_ip: None,
        });
        *state.route_mode_override.write().await = Some(RouteMode::Global);

        let axum::response::Json(response) = get_status(State(state.clone())).await;

        let data = response.data.unwrap();
        assert_eq!(data.route_mode, RouteMode::Global);
        assert_eq!(state.config.read().await.route_mode, RouteMode::Rule);
    }

    #[tokio::test]
    async fn get_status_ignores_persisted_route_mode_without_override() {
        let state = app_state(Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
            route_mode: RouteMode::Global,
            vps_ip: None,
        });

        let axum::response::Json(response) = get_status(State(state)).await;

        let data = response.data.unwrap();
        assert_eq!(data.route_mode, RouteMode::Tunnel);
    }
}
