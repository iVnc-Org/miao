use axum::{extract::State, http::StatusCode, response::Json};
use std::sync::Arc;

use crate::{
    models::{ApiResponse, TunProcessConfig},
    responses::{status_error, success, success_no_data, HandlerResult},
    services::config::apply_persistent_config_change,
    state::AppState,
};

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

    let _config_update = state.config_update.lock().await;
    let was_running = sing_box_is_running(&state).await;
    let old_config = state.config.read().await.clone();

    if old_config.tun_process == tun_process {
        return Ok(success_no_data("TUN process config unchanged"));
    }

    let mut new_config = old_config.clone();
    new_config.tun_process = tun_process;

    match apply_persistent_config_change(&state, &old_config, &new_config, was_running).await {
        Ok(_) if was_running => Ok(success_no_data(
            "TUN process config saved and sing-box restarted",
        )),
        Ok(_) => Ok(success_no_data("TUN process config saved")),
        Err(e) => Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
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
            route_mode: Default::default(),
        });

        let Json(response) = get_tun_process(State(state)).await;

        assert!(response.success);
        let config = response.data.unwrap();
        assert!(config.enabled);
        assert_eq!(config.r#match.names, vec!["curl"]);
    }
}
