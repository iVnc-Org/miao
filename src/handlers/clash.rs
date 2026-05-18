use axum::{
    body::Body,
    extract::{
        ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, Method, Response, StatusCode},
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};
use tracing::warn;

use crate::models::LastProxy;
use crate::services::proxy::save_last_proxy;
use crate::state::AppState;

const CLASH_API_BASE: &str = "http://127.0.0.1:6262";
const CLASH_WS_BASE: &str = "ws://127.0.0.1:6262";

#[derive(Deserialize)]
pub struct DelayQuery {
    timeout: Option<u64>,
    url: Option<String>,
}

fn clash_error(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "success": false, "message": message.into() }).to_string(),
        ))
        .unwrap()
}

async fn clash_request(
    state: Arc<AppState>,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Response<Body> {
    let url = format!("{CLASH_API_BASE}{path}");
    let mut request = state.http_client.request(method, &url);
    if let Some(body) = body {
        request = request.json(&body);
    }

    match request.send().await {
        Ok(upstream) => {
            let status = upstream.status();
            let content_type = upstream
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            match upstream.bytes().await {
                Ok(bytes) => Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(bytes))
                    .unwrap(),
                Err(err) => clash_error(
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to read clash response: {err}"),
                ),
            }
        }
        Err(err) => clash_error(
            StatusCode::BAD_GATEWAY,
            format!("Failed to reach clash controller: {err}"),
        ),
    }
}

pub async fn get_proxies(State(state): State<Arc<AppState>>) -> Response<Body> {
    clash_request(state, Method::GET, "/proxies", None).await
}

pub async fn switch_proxy(
    State(state): State<Arc<AppState>>,
    Path(group): Path<String>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> Response<Body> {
    let selected_name = selected_proxy_name(&body).map(str::to_string);
    let path = format!("/proxies/{}", urlencoding::encode(&group));
    let response = clash_request(state, Method::PUT, &path, Some(body)).await;

    if response.status().is_success() {
        if let Some(name) = selected_name {
            let proxy = LastProxy {
                group: group.clone(),
                name,
            };
            if let Err(err) = save_last_proxy(&proxy).await {
                warn!("failed to save selected proxy: {}", err);
            }
        }
    }

    response
}

fn selected_proxy_name(body: &serde_json::Value) -> Option<&str> {
    body.get("name").and_then(|name| name.as_str())
}

pub async fn test_proxy_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Response<Body> {
    let timeout = query.timeout.unwrap_or(3000);
    let url = query
        .url
        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string());
    let path = format!(
        "/proxies/{}/delay?timeout={}&url={}",
        urlencoding::encode(&name),
        timeout,
        urlencoding::encode(&url)
    );
    clash_request(state, Method::GET, &path, None).await
}

#[cfg(test)]
mod tests {
    use super::selected_proxy_name;
    use serde_json::json;

    #[test]
    fn selected_proxy_name_reads_name_from_switch_body() {
        let body = json!({"name": "node-a"});

        assert_eq!(selected_proxy_name(&body), Some("node-a"));
    }

    #[test]
    fn selected_proxy_name_ignores_missing_or_non_string_name() {
        assert_eq!(selected_proxy_name(&json!({})), None);
        assert_eq!(selected_proxy_name(&json!({"name": 123})), None);
    }
}

pub async fn traffic_ws(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(proxy_traffic_ws)
}

async fn proxy_traffic_ws(client_socket: WebSocket) {
    let upstream = match connect_async(format!("{CLASH_WS_BASE}/traffic")).await {
        Ok((stream, _)) => stream,
        Err(_) => return,
    };

    let (mut client_tx, mut client_rx) = client_socket.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();

    let client_to_upstream = async {
        while let Some(Ok(msg)) = client_rx.next().await {
            let forwarded = match msg {
                AxumWsMessage::Text(text) => TungsteniteMessage::Text(text.to_string().into()),
                AxumWsMessage::Binary(data) => TungsteniteMessage::Binary(data),
                AxumWsMessage::Ping(data) => TungsteniteMessage::Ping(data),
                AxumWsMessage::Pong(data) => TungsteniteMessage::Pong(data),
                AxumWsMessage::Close(frame) => {
                    let _ = upstream_tx.close().await;
                    let _ = frame;
                    break;
                }
            };
            if upstream_tx.send(forwarded).await.is_err() {
                break;
            }
        }
    };

    let upstream_to_client = async {
        while let Some(Ok(msg)) = upstream_rx.next().await {
            let forwarded = match msg {
                TungsteniteMessage::Text(text) => AxumWsMessage::Text(text.to_string().into()),
                TungsteniteMessage::Binary(data) => AxumWsMessage::Binary(data),
                TungsteniteMessage::Ping(data) => AxumWsMessage::Ping(data),
                TungsteniteMessage::Pong(data) => AxumWsMessage::Pong(data),
                TungsteniteMessage::Close(frame) => {
                    let close_frame = frame.map(|frame| axum::extract::ws::CloseFrame {
                        code: frame.code.into(),
                        reason: frame.reason.to_string().into(),
                    });
                    let _ = client_tx.send(AxumWsMessage::Close(close_frame)).await;
                    break;
                }
                TungsteniteMessage::Frame(_) => continue,
            };
            if client_tx.send(forwarded).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = client_to_upstream => {}
        _ = upstream_to_client => {}
    }
}
