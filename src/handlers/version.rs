use axum::{extract::State, response::Json};
use serde::Deserialize;
use std::sync::Arc;

use crate::models::{ApiResponse, VersionInfo};
use crate::responses::{error, success};
use crate::services::version::get_version_info;
use crate::state::AppState;

#[derive(Deserialize, Default)]
pub struct UpgradeRequest {
    pub github_proxy: Option<String>,
}

pub async fn get_version(State(state): State<Arc<AppState>>) -> Json<ApiResponse<VersionInfo>> {
    success("Version info", get_version_info(&state).await)
}

pub async fn get_upgrade(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<crate::services::version::UpgradeStatus>> {
    match crate::services::version::upgrade_status(&state).await {
        Ok(status) => success("Upgrade status", status),
        Err(e) => error(e.to_string()),
    }
}

pub async fn upgrade(
    State(state): State<Arc<AppState>>,
    body: Option<Json<UpgradeRequest>>,
) -> Json<ApiResponse<crate::services::version::UpgradeStatus>> {
    let proxy = body.and_then(|Json(request)| request.github_proxy);
    match crate::services::version::start_upgrade(state, proxy) {
        Ok(status) => success("Upgrade started", status),
        Err(e) => error(e.to_string()),
    }
}

pub async fn cancel_upgrade(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<crate::services::version::UpgradeStatus>> {
    match crate::services::version::cancel_upgrade(&state).await {
        Ok(status) => success("Upgrade cancellation requested", status),
        Err(e) => error(e.to_string()),
    }
}
