use crate::{
    responses::{status_error, success, HandlerResult},
    services::vps::{self, Connection, Job},
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

pub async fn list(State(state): State<Arc<AppState>>) -> HandlerResult<Vec<Job>> {
    Ok(success(
        "VPS tasks",
        vps::jobs(&state)
            .await
            .map_err(|e| status_error(StatusCode::INTERNAL_SERVER_ERROR, e))?,
    ))
}
pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> HandlerResult<Job> {
    let jobs = vps::jobs(&state)
        .await
        .map_err(|e| status_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let job = jobs
        .into_iter()
        .find(|job| job.id == id)
        .ok_or_else(|| status_error(StatusCode::NOT_FOUND, "Task not found"))?;
    Ok(success("VPS task", job))
}
pub async fn preflight(Json(req): Json<Connection>) -> HandlerResult<serde_json::Value> {
    Ok(success(
        "VPS inspection",
        vps::preflight(req)
            .await
            .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?,
    ))
}
pub async fn start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Connection>,
) -> HandlerResult<Job> {
    if state
        .initializing
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err(status_error(StatusCode::CONFLICT, "Miao initializing"));
    }
    Ok(success(
        "VPS task accepted",
        vps::start(state, req)
            .await
            .map_err(|e| status_error(StatusCode::CONFLICT, e))?,
    ))
}

pub async fn no_store(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store".parse().unwrap(),
    );
    response
}
