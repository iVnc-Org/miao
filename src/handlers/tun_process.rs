use axum::{extract::State, http::StatusCode, response::Json};
use std::sync::Arc;

use crate::{
    handlers::apply_config_section,
    models::{ApiResponse, ProcessProxyConfig, ProxyMode},
    responses::{status_error, success, HandlerResult},
    state::AppState,
};

pub async fn get_tun_process(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<ProcessProxyConfig>> {
    let config = state.config.read().await;

    success("TUN process config loaded", config.tun_process.clone())
}

pub async fn set_tun_process(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProcessProxyConfig>,
) -> HandlerResult {
    let tun_process = req
        .normalized()
        .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;
    if state.config.read().await.mode == ProxyMode::Process {
        tun_process
            .validate_active()
            .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;
    }

    apply_config_section(
        &state,
        "TUN process config",
        tun_process,
        |config| &config.tun_process,
        |config, value| config.tun_process = value,
    )
    .await
}

#[cfg(test)]
mod tests {
    use axum::{extract::State, response::Json};

    use super::get_tun_process;
    use crate::{
        models::{Config, ProcessListMode, ProcessMatch, ProcessProxyConfig},
        test_support::app_state,
    };

    #[tokio::test]
    async fn get_tun_process_returns_config_value() {
        let state = app_state(Config {
            tun_process: ProcessProxyConfig {
                legacy_enabled: false,
                mode: ProcessListMode::Whitelist,
                r#match: ProcessMatch {
                    names: vec!["curl".to_string()],
                    paths: vec![],
                    path_regex: vec![],
                },
                dns_follow_process: true,
                bypass_action: Default::default(),
            },
            ..Default::default()
        });

        let Json(response) = get_tun_process(State(state)).await;

        assert!(response.success);
        let config = response.data.unwrap();
        assert_eq!(config.r#match.names, vec!["curl"]);
    }
}
