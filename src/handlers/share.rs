use axum::{extract::State, http::StatusCode, response::Json};
use std::sync::Arc;

use crate::{
    handlers::apply_config_section,
    models::{ApiResponse, PoolConfig, ProxyMode, ShareEndpoint},
    responses::{status_error, success, HandlerResult},
    services::{
        config::{extract_share_bindings_from_sing_box, read_existing_sing_box_config},
        share_ports::build_share_socks_url,
        singbox::sing_box_is_running,
    },
    state::AppState,
};

pub async fn get_share(State(state): State<Arc<AppState>>) -> Json<ApiResponse<PoolConfig>> {
    let config = state.config.read().await;
    success("Share config loaded", config.share.clone())
}

pub async fn set_share(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PoolConfig>,
) -> HandlerResult {
    let share = req
        .normalized()
        .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;
    if state.config.read().await.mode == ProxyMode::Pool {
        share
            .validate_active()
            .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;
    }

    apply_config_section(
        &state,
        "Share config",
        share,
        |config| &config.share,
        |config, value| config.share = value,
    )
    .await
}

pub async fn get_share_endpoints(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<ShareEndpoint>>> {
    let config = state.config.read().await;
    if config.mode != ProxyMode::Pool {
        return success("Share endpoints", Vec::new());
    }

    // 以已生成的 sing-box 配置为准，而不是分配账本：账本可能领先于实际部署
    // （比如一次失败的应用被回滚了），照账本报端口会让用户复制到没人监听的地址。
    // 同理，服务没跑的时候不报端口——read_existing_sing_box_config 会回退到缓存文件，
    // 那是"下次会部署什么"，不是"现在有什么在监听"。
    if !sing_box_is_running(&state).await {
        return success("Share endpoints", Vec::new());
    }

    let Ok(sing_box_config) = read_existing_sing_box_config().await else {
        return success("Share endpoints", Vec::new());
    };

    let endpoints = extract_share_bindings_from_sing_box(&sing_box_config)
        .into_iter()
        .map(|(tag, port)| ShareEndpoint {
            url: build_share_socks_url(
                &config.share.listen,
                port,
                &config.share.username,
                &config.share.password,
            ),
            tag,
            port,
            listen: config.share.listen.clone(),
        })
        .collect();

    success("Share endpoints", endpoints)
}

#[cfg(test)]
mod tests {
    use axum::{extract::State, response::Json};

    use super::{get_share, get_share_endpoints};
    use crate::{
        models::{Config, PoolConfig, ProxyMode},
        test_support::app_state,
    };

    fn config_with_share(share: PoolConfig) -> Config {
        Config {
            mode: ProxyMode::Pool,
            share,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn get_share_returns_config_value() {
        let state = app_state(config_with_share(PoolConfig {
            legacy_enabled: false,
            listen: "0.0.0.0".to_string(),
            base_port: 13000,
            username: "alice".to_string(),
            password: "secret".to_string(),
        }));

        let Json(response) = get_share(State(state)).await;
        assert!(response.success);
        let config = response.data.unwrap();
        assert_eq!(config.base_port, 13000);
        assert_eq!(config.username, "alice");
    }

    #[tokio::test]
    async fn get_share_endpoints_empty_when_disabled() {
        let state = app_state(Config::default());

        let Json(response) = get_share_endpoints(State(state)).await;
        assert!(response.success);
        assert!(response.data.unwrap().is_empty());
    }
}
