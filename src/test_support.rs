use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, Request},
    Router,
};
use serde_json::Value;

use crate::{models::Config, router::build_router, state::AppState};

pub fn app_state(config: Config) -> Arc<AppState> {
    let config_path = std::env::temp_dir().join(format!(
        "miao-test-config-{}-{}.yaml",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    Arc::new(
        AppState::with_config_path(config, config_path).expect("Failed to create AppState in test"),
    )
}

pub async fn reset_version_cache(state: &Arc<AppState>) {
    state
        .version_cache
        .store(Arc::new(crate::state::VersionCache {
            release: None,
            fetched_at: None,
        }));
}

pub async fn test_app(config: Config) -> Router {
    let state = app_state(config);
    reset_version_cache(&state).await;
    authenticated_router(state).await
}

// Existing management tests exercise authenticated routes through real login,
// without adding any authentication bypass to production code.
pub async fn authenticated_router(state: Arc<AppState>) -> Router {
    use tower::ServiceExt;
    crate::auth::set_password(&state.config_path, "test-panel-password", None).unwrap();
    let app = build_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("host", "localhost:6161")
        .header("origin", "http://localhost:6161")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"password":"test-panel-password"}"#))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let data = response_json(response).await;
    let csrf = data["data"]["csrf"].as_str().unwrap().to_string();
    app.layer(axum::middleware::from_fn(
        move |mut request: Request<Body>, next: axum::middleware::Next| {
            let cookie = cookie.clone();
            let csrf = csrf.clone();
            async move {
                request
                    .headers_mut()
                    .insert("cookie", cookie.parse().unwrap());
                request
                    .headers_mut()
                    .insert("x-miao-csrf", csrf.parse().unwrap());
                request
                    .headers_mut()
                    .entry("host")
                    .or_insert("localhost:6161".parse().unwrap());
                request
                    .headers_mut()
                    .entry("origin")
                    .or_insert("http://localhost:6161".parse().unwrap());
                next.run(request).await
            }
        },
    ))
}

pub fn empty_request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

pub fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub async fn response_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
