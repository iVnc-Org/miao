use crate::{
    models::{ApiResponse, TunConfig},
    responses::{status_error, success, success_no_data, HandlerResult},
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use std::sync::Arc;

pub async fn get(State(state): State<Arc<AppState>>) -> Json<ApiResponse<TunConfig>> {
    success("TUN routing config", state.config.read().await.tun.clone())
}

#[derive(Deserialize)]
pub struct TunUpdate {
    #[serde(default)]
    lan_interfaces: Option<Vec<String>>,
}

pub async fn set(
    State(state): State<Arc<AppState>>,
    Json(update): Json<TunUpdate>,
) -> HandlerResult {
    // Old clients may send only the obsolete routing choice. That is a no-op,
    // rather than a request to clear an existing trusted LAN configuration.
    let Some(lan_interfaces) = update.lan_interfaces else {
        return Ok(success_no_data("Traffic routing adapts automatically"));
    };
    let config = TunConfig {
        lan_interfaces,
        ..Default::default()
    }
    .normalized()
    .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;
    super::apply_config_section(
        &state,
        "TUN routing",
        config,
        |config| &config.tun,
        |config, tun| config.tun = tun,
    )
    .await
}
