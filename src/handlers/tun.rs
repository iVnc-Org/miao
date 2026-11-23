use crate::{
    models::{ApiResponse, TunConfig},
    responses::{status_error, success, HandlerResult},
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

pub async fn get(State(state): State<Arc<AppState>>) -> Json<ApiResponse<TunConfig>> {
    success("TUN routing config", state.config.read().await.tun.clone())
}

pub async fn set(
    State(state): State<Arc<AppState>>,
    Json(config): Json<TunConfig>,
) -> HandlerResult {
    let config = config
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
