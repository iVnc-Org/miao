use axum::{extract::State, http::StatusCode, response::Json};
use std::{sync::Arc, time::Duration};

use crate::{
    handlers::apply_config_section,
    models::{
        ApiResponse, PoolConfig, ProxyMode, ShareEndpoint, ShareTestRequest, ShareTestResult,
    },
    responses::{status_error, success, HandlerResult},
    services::{
        config::{extract_share_bindings_from_sing_box, read_existing_sing_box_config},
        share_ports::build_share_socks_url,
        singbox::sing_box_is_running,
    },
    state::AppState,
};

const SHARE_TEST_TARGET: &str = "http://3.0.3.0/";
const SHARE_TEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SHARE_TEST_BODY_BYTES: usize = 256 * 1024;

pub async fn get_share(State(state): State<Arc<AppState>>) -> Json<ApiResponse<PoolConfig>> {
    let config = state.config.read().await;
    success("Share config loaded", config.share.clone())
}

pub async fn set_share(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PoolConfig>,
) -> HandlerResult {
    let share = req
        .normalized()
        .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?;

    apply_config_section(
        &state,
        "Share config",
        share,
        |config| &config.share,
        |config, value| config.share = value,
    )
    .await
}

pub async fn get_share_endpoints(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<ShareEndpoint>>> {
    let config = state.config.read().await;
    if config.mode != ProxyMode::Pool {
        return success("Share endpoints", Vec::new());
    }

    // 以已生成的 sing-box 配置为准，而不是分配账本：账本可能领先于实际部署
    // （比如一次失败的应用被回滚了），照账本报端口会让用户复制到没人监听的地址。
    // 同理，服务没跑的时候不报端口——read_existing_sing_box_config 会回退到缓存文件，
    // 那是"下次会部署什么"，不是"现在有什么在监听"。
    if !sing_box_is_running(&state).await {
        return success("Share endpoints", Vec::new());
    }

    let Ok(sing_box_config) = read_existing_sing_box_config().await else {
        return success("Share endpoints", Vec::new());
    };

    let endpoints = extract_share_bindings_from_sing_box(&sing_box_config)
        .into_iter()
        .map(|(tag, port)| ShareEndpoint {
            url: build_share_socks_url(
                &config.share.listen,
                port,
                &config.share.username,
                &config.share.password,
            ),
            tag,
            port,
            listen: config.share.listen.clone(),
        })
        .collect();

    success("Share endpoints", endpoints)
}

pub async fn test_share_endpoint(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ShareTestRequest>,
) -> HandlerResult<ShareTestResult> {
    let pool = {
        let config = state.config.read().await;
        if config.mode != ProxyMode::Pool {
            return Err(status_error(
                StatusCode::BAD_REQUEST,
                "Proxy pool mode is not active",
            ));
        }
        config.share.clone()
    };

    if !sing_box_is_running(&state).await {
        return Err(status_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy service is not running",
        ));
    }

    let sing_box_config = read_existing_sing_box_config()
        .await
        .map_err(|e| status_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let endpoint_exists = extract_share_bindings_from_sing_box(&sing_box_config)
        .iter()
        .any(|(tag, port)| tag == &req.tag && *port == req.port);
    if !endpoint_exists {
        return Err(status_error(
            StatusCode::BAD_REQUEST,
            "Proxy pool endpoint is stale or unavailable",
        ));
    }

    let proxy_url = share_test_proxy_url(&pool, req.port);
    let mut proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| {
        status_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to configure proxy test: {e}"),
        )
    })?;
    if pool.has_auth() {
        proxy = proxy.basic_auth(&pool.username, &pool.password);
    }
    let client = reqwest::Client::builder()
        .timeout(SHARE_TEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .proxy(proxy)
        .build()
        .map_err(|e| {
            status_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create proxy test client: {e}"),
            )
        })?;

    let mut response = client
        .get(SHARE_TEST_TARGET)
        .header(reqwest::header::USER_AGENT, "curl/8.0.0")
        .send()
        .await
        .map_err(|e| {
            status_error(
                StatusCode::BAD_GATEWAY,
                format!("Proxy test request failed: {e}"),
            )
        })?;
    let status = response.status();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        status_error(
            StatusCode::BAD_GATEWAY,
            format!("Failed to read proxy test response: {e}"),
        )
    })? {
        if body_bytes.len().saturating_add(chunk.len()) > MAX_SHARE_TEST_BODY_BYTES {
            return Err(status_error(
                StatusCode::BAD_GATEWAY,
                "Proxy test response exceeded 256 KiB",
            ));
        }
        body_bytes.extend_from_slice(&chunk);
    }

    Ok(success(
        "Proxy endpoint test completed",
        ShareTestResult {
            tag: req.tag,
            status_code: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_string(),
            body: parse_share_test_body(&body_bytes),
        },
    ))
}

fn share_test_proxy_url(pool: &PoolConfig, port: u16) -> String {
    let host = match pool.listen.as_str() {
        "0.0.0.0" => "127.0.0.1",
        "::" => "::1",
        listen => listen,
    };
    build_share_socks_url(host, port, "", "")
}

fn parse_share_test_body(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| {
        serde_json::json!({
            "raw": String::from_utf8_lossy(bytes)
        })
    })
}

#[cfg(test)]
mod tests {
    use axum::{extract::State, response::Json};

    use serde_json::json;

    use super::{get_share, get_share_endpoints, parse_share_test_body, share_test_proxy_url};
    use crate::{
        models::{Config, PoolConfig, ProxyMode},
        test_support::app_state,
    };

    fn config_with_share(share: PoolConfig) -> Config {
        Config {
            mode: ProxyMode::Pool,
            share,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn get_share_returns_config_value() {
        let state = app_state(config_with_share(PoolConfig {
            legacy_enabled: false,
            listen: "0.0.0.0".to_string(),
            base_port: 13000,
            username: "alice".to_string(),
            password: "secret".to_string(),
        }));

        let Json(response) = get_share(State(state)).await;
        assert!(response.success);
        let config = response.data.unwrap();
        assert_eq!(config.base_port, 13000);
        assert_eq!(config.username, "alice");
    }

    #[tokio::test]
    async fn get_share_endpoints_empty_when_disabled() {
        let state = app_state(Config::default());

        let Json(response) = get_share_endpoints(State(state)).await;
        assert!(response.success);
        assert!(response.data.unwrap().is_empty());
    }

    #[test]
    fn share_test_proxy_url_uses_a_local_address_for_wildcard_listeners() {
        let mut pool = PoolConfig::default();
        assert_eq!(
            share_test_proxy_url(&pool, 50000),
            "socks5://127.0.0.1:50000"
        );

        pool.listen = "::".to_string();
        assert_eq!(share_test_proxy_url(&pool, 50000), "socks5://[::1]:50000");

        pool.listen = "192.168.1.20".to_string();
        assert_eq!(
            share_test_proxy_url(&pool, 50000),
            "socks5://192.168.1.20:50000"
        );
    }

    #[test]
    fn share_test_body_is_always_returned_as_json() {
        assert_eq!(
            parse_share_test_body(br#"{"status":"ok","ip":"3.0.3.0"}"#),
            json!({"status": "ok", "ip": "3.0.3.0"})
        );
        assert_eq!(
            parse_share_test_body(b"plain text"),
            json!({"raw": "plain text"})
        );
    }
}
