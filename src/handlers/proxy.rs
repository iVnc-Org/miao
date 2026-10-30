use crate::state::AppState;
use axum::{extract::State, response::Json};
use std::sync::{atomic::Ordering, Arc};

use crate::models::{ApiResponse, LastProxy};
use crate::responses::{error, success_no_data};
use crate::services::proxy::save_last_proxy;

pub async fn set_last_proxy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LastProxy>,
) -> Json<ApiResponse<()>> {
    state.startup_cancelled.store(true, Ordering::SeqCst);
    let _lock = state.config_update.lock().await;
    match save_last_proxy(&req).await {
        Ok(_) => success_no_data("Last proxy saved"),
        Err(e) => error(format!("Failed to save: {}", e)),
    }
}
