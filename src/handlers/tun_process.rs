use axum::{extract::State, http::StatusCode, response::Json};
use std::sync::Arc;

use crate::{
    handlers::apply_config_section,
    models::{ApiResponse, TunProcessConfig},
    responses::{status_error, success, HandlerResult},
    state::AppState,
};

pub async fn get_tun_process(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<TunProcessConfig>> {
    let config = state.config.read().await;

    success("TUN process config loaded", config.tun_process.clone())
}

pub async fn set_tun_process(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TunProcessConfig>,
) -> HandlerResult {
    let tun_process = req
        .normalized()
        .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;

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
        models::{Config, TunProcessConfig, TunProcessMatch, TunProcessMode},
        test_support::app_state,
    };

    #[tokio::test]
    async fn get_tun_process_returns_config_value() {
        let state = app_state(Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            vps_ip: None,
            nodes: vec![],
            custom_rules: vec![],
            tun_process: TunProcessConfig {
                enabled: true,
                mode: TunProcessMode::ProcessOnly,
                r#match: TunProcessMatch {
                    names: vec!["curl".to_string()],
                    paths: vec![],
                    path_regex: vec![],
                },
                dns_follow_process: true,
                bypass_action: Default::default(),
            },
            share: Default::default(),
            route_mode: Default::default(),
        });

        let Json(response) = get_tun_process(State(state)).await;

        assert!(response.success);
        let config = response.data.unwrap();
        assert!(config.enabled);
        assert_eq!(config.r#match.names, vec!["curl"]);
    }
}
