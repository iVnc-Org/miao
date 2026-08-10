use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc, time::Instant};
use tokio::time::Duration;

use crate::error::AppError;
use crate::models::{
    ApiResponse, ConnectivityResult, ModeRequest, ProxyMode, StatusData, DEFAULT_SOCKS_LISTEN,
    DEFAULT_SOCKS_PORT,
};
use crate::responses::{status_error, success, success_no_data, HandlerResult};
use crate::services::{
    config::{
        apply_persistent_config_change, gen_config, restore_config_from_cache, save_config_cache,
        SubFetchPolicy,
    },
    proxy::restore_last_proxy,
    runtime::save_running_state,
    singbox::{get_sing_box_home, sing_box_is_running, start_sing_internal, stop_sing_internal},
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
    let mode = state.config.read().await.mode;

    success(
        if running { "running" } else { "stopped" },
        StatusData {
            running,
            initializing,
            mode,
            pid,
            uptime_secs,
            warning,
            config_source,
        },
    )
}

pub async fn start_service(State(state): State<Arc<AppState>>) -> HandlerResult {
    // 与其它会重新生成配置的 handler 共用同一把锁：start 也可能走到 gen_config，
    // 不持锁会和并发的配置变更互相覆盖生成产物与端口分配账本。
    let _config_update = state.config_update.lock().await;
    let config_path = get_sing_box_home().join("config.json");
    if !config_path.exists() {
        let config = state.config.read().await.clone();
        match restore_config_from_cache(&config).await {
            Ok(_) => {
                *state.config_source.lock().await = Some("cache".to_string());
                *state.config_warning.lock().await =
                    Some("当前使用上次成功生成的缓存配置，订阅未在启动时自动刷新".to_string());
            }
            // 缓存未命中时才生成。只有订阅节点缓存也是空的（首装/用户清了缓存）
            // 才会真的联网抓一次，否则一律复用已存节点。
            Err(cache_err) => {
                match gen_config(&config, &state, SubFetchPolicy::CacheOrBootstrap).await {
                    Ok(outcome) => {
                        *state.config_source.lock().await = Some("generated".to_string());
                        if outcome.has_sub_nodes() || config.subs.is_empty() {
                            save_config_cache(&config).await;
                            *state.config_warning.lock().await = None;
                        } else if !config.subs.is_empty() {
                            *state.config_warning.lock().await =
                                Some("订阅节点缓存为空，请点击刷新订阅".to_string());
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
                }
            }
        }
    }

    match start_sing_internal(&state).await {
        Ok(_) => {
            if let Err(e) = save_running_state(true).await {
                return Err(status_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to save runtime state: {}", e),
                ));
            }
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

pub async fn stop_service(State(state): State<Arc<AppState>>) -> HandlerResult {
    let _config_update = state.config_update.lock().await;
    stop_sing_internal(&state).await;
    if let Err(e) = save_running_state(false).await {
        return Err(status_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save runtime state: {}", e),
        ));
    }
    Ok(success_no_data("sing-box stopped"))
}

pub async fn set_mode(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ModeRequest>,
) -> HandlerResult {
    let _config_update = state.config_update.lock().await;
    let was_running = sing_box_is_running(&state).await;
    let old_config = state.config.read().await.clone();

    if old_config.mode == req.mode {
        return Ok(success_no_data("Proxy mode unchanged"));
    }

    let mut new_config = old_config.clone();
    new_config.mode = req.mode;
    match req.mode {
        ProxyMode::Global => {}
        ProxyMode::Process => {
            let process_proxy = new_config
                .tun_process
                .normalized()
                .map_err(|error| status_error(StatusCode::BAD_REQUEST, error))?;
            process_proxy
                .validate_active()
                .map_err(|error| status_error(StatusCode::BAD_REQUEST, error))?;
            new_config.tun_process = process_proxy;
        }
        ProxyMode::Pool => {
            let pool = new_config
                .share
                .normalized()
                .map_err(|error| status_error(StatusCode::BAD_REQUEST, error))?;
            new_config.share = pool;
        }
    }

    let result = apply_persistent_config_change(
        &state,
        &old_config,
        &new_config,
        was_running,
        SubFetchPolicy::CacheOnly,
    )
    .await;

    match result {
        Ok(_) if was_running => Ok(success_no_data("Proxy mode updated and sing-box restarted")),
        Ok(_) => Ok(success_no_data("Proxy mode updated")),
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
    use crate::models::{Config, ProxyMode};
    use crate::test_support::app_state;

    #[tokio::test]
    async fn get_status_reports_stopped_when_no_process_exists() {
        let state = app_state(Config::default());

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
    async fn get_status_reports_persisted_proxy_mode() {
        let state = app_state(Config {
            mode: ProxyMode::Pool,
            ..Default::default()
        });

        let axum::response::Json(response) = get_status(State(state)).await;

        let data = response.data.unwrap();
        assert_eq!(data.mode, ProxyMode::Pool);
    }
}
