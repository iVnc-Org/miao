use std::sync::Arc;

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::handlers::{
    clash::{get_proxies, switch_proxy, test_proxy_delay, traffic_ws},
    nodes::{add_node, delete_node, get_node_inventory, get_nodes, update_node},
    proxy::set_last_proxy,
    service::{get_status, set_mode, start_service, stop_service, test_connectivity},
    share::{get_share, get_share_endpoints, set_share, test_share_endpoint},
    static_assets::{serve_favicon, serve_index},
    subs::{add_sub, add_sub_content, delete_sub, get_subs, refresh_subs, replace_sub},
    tun_process::{get_tun_process, set_tun_process},
    version::{get_version, upgrade},
};
use crate::state::AppState;

pub fn build_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/favicon.svg", get(serve_favicon))
        .route("/api/status", get(get_status))
        .route("/api/service/start", post(start_service))
        .route("/api/service/stop", post(stop_service))
        .route("/api/mode", post(set_mode))
        .route("/api/tun-process", get(get_tun_process))
        .route("/api/tun-process", post(set_tun_process))
        .route("/api/share", get(get_share))
        .route("/api/share", post(set_share))
        .route("/api/share/endpoints", get(get_share_endpoints))
        .route("/api/share/test", post(test_share_endpoint))
        .route("/api/connectivity", post(test_connectivity))
        .route("/api/version", get(get_version))
        .route("/api/upgrade", post(upgrade))
        .route("/api/subs", get(get_subs))
        .route("/api/subs", post(add_sub))
        .route("/api/subs/content", post(add_sub_content))
        .route("/api/subs", put(replace_sub))
        .route("/api/subs", delete(delete_sub))
        .route("/api/subs/refresh", post(refresh_subs))
        .route("/api/nodes", get(get_nodes))
        .route("/api/nodes", post(add_node))
        .route("/api/nodes", put(update_node))
        .route("/api/nodes", delete(delete_node))
        .route("/api/proxies", get(get_node_inventory))
        .route("/api/clash/proxies", get(get_proxies))
        .route("/api/clash/proxies/{group}", put(switch_proxy))
        .route("/api/clash/proxies/{name}/delay", get(test_proxy_delay))
        .route("/api/clash/traffic", get(traffic_ws))
        .route("/api/last-proxy", post(set_last_proxy))
        .with_state(app_state)
}

#[cfg(test)]
mod tests {
    use axum::http::{header::CONTENT_TYPE, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;

    use crate::{
        models::Config,
        test_support::{empty_request, json_request, response_json, response_text, test_app},
    };

    #[tokio::test]
    async fn router_serves_index_page() {
        let app = test_app(Config::default()).await;

        let response = app.oneshot(empty_request("GET", "/")).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("Miao 控制面板"));
    }

    #[tokio::test]
    async fn router_serves_favicon_with_svg_content_type() {
        let app = test_app(Config::default()).await;

        let response = app
            .oneshot(empty_request("GET", "/favicon.svg"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "image/svg+xml"
        );
        let body = response_text(response).await;
        assert!(body.contains("<svg"));
    }

    #[tokio::test]
    async fn router_returns_status_payload() {
        let app = test_app(Config::default()).await;

        let response = app
            .oneshot(empty_request("GET", "/api/status"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "stopped");
        assert_eq!(json["data"]["running"], false);
        assert_eq!(json["data"]["mode"], "global");
    }

    #[tokio::test]
    async fn router_rejects_proxy_pool_tests_outside_pool_mode() {
        let app = test_app(Config::default()).await;

        let response = app
            .oneshot(json_request(
                "POST",
                "/api/share/test",
                json!({"tag": "node-a", "port": 50000}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Proxy pool mode is not active");
    }

    #[tokio::test]
    async fn router_requires_a_running_service_for_proxy_pool_tests() {
        let app = test_app(Config {
            mode: crate::models::ProxyMode::Pool,
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "POST",
                "/api/share/test",
                json!({"tag": "node-a", "port": 50000}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Proxy service is not running");
    }

    #[tokio::test]
    async fn router_returns_version_build_info() {
        let app = test_app(Config::default()).await;

        let response = app
            .oneshot(empty_request("GET", "/api/version"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["success"], true);
        assert!(json["data"]["current"].as_str().unwrap().starts_with('v'));
        assert!(json["data"].get("commit_short").is_some());
        assert!(json["data"].get("commit_full").is_some());
        assert!(json["data"].get("commit_url").is_some());
    }

    #[tokio::test]
    async fn router_returns_node_list_payload() {
        let app = test_app(Config {
            nodes: vec![ r#"{"type":"hysteria2","tag":"router-node","server":"node.example.com","server_port":443,"password":"secret","up_mbps":40,"down_mbps":350,"tls":{"enabled":true,"server_name":"sni.example.com","insecure":true}}"#.to_string(), ],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(empty_request("GET", "/api/nodes"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Nodes loaded");
        assert_eq!(json["data"][0]["tag"], "router-node");
        assert_eq!(json["data"][0]["server"], "node.example.com");
        assert_eq!(json["data"][0]["sni"], "sni.example.com");
        assert_eq!(json["data"][0]["outbound"]["password"], "secret");
    }

    #[tokio::test]
    async fn router_returns_persistent_proxy_inventory() {
        let app = test_app(Config {
            nodes: vec![
                r#"{"type":"socks","tag":"inventory-node","server":"127.0.0.1","server_port":1081}"#
                    .to_string(),
            ],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(empty_request("GET", "/api/proxies"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Proxy inventory loaded");
        assert_eq!(json["data"]["nodes"][0]["tag"], "inventory-node");
    }

    #[tokio::test]
    async fn router_accepts_the_persisted_mode_contract() {
        let app = test_app(Config::default()).await;

        let response = app
            .oneshot(json_request(
                "POST",
                "/api/mode",
                json!({ "mode": "global" }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Proxy mode unchanged");
    }

    #[tokio::test]
    async fn router_returns_subscription_list_payload() {
        let app = test_app(Config {
            subs: vec!["https://example.com/subscription".to_string()],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(empty_request("GET", "/api/subs"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Subscriptions loaded");
        assert_eq!(json["data"][0]["url"], "https://example.com/subscription");
        assert_eq!(json["data"][0]["local"], false);
        assert_eq!(json["data"][0]["node_count"], 0);
    }

    #[tokio::test]
    async fn router_rejects_empty_pasted_subscription_content() {
        let app = test_app(Config::default()).await;

        let response = app
            .oneshot(json_request(
                "POST",
                "/api/subs/content",
                json!({ "content": "  ", "name": "Local" }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Subscription content cannot be empty");
    }

    #[tokio::test]
    async fn router_rejects_duplicate_subscription_with_bad_request() {
        let app = test_app(Config {
            subs: vec!["https://example.com/subscription".to_string()],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "POST",
                "/api/subs",
                json!({ "url": "https://example.com/subscription" }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Subscription already exists");
    }

    #[tokio::test]
    async fn router_exposes_atomic_subscription_replacement() {
        let app = test_app(Config {
            subs: vec!["https://example.com/subscription".to_string()],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "PUT",
                "/api/subs",
                json!({
                    "old_url": "https://example.com/subscription",
                    "new_url": "ftp://example.com/replacement"
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert!(json["message"].as_str().unwrap().contains("HTTP"));
    }

    #[tokio::test]
    async fn router_returns_not_found_when_deleting_missing_subscription() {
        let app = test_app(Config {
            subs: vec!["https://example.com/subscription".to_string()],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "DELETE",
                "/api/subs",
                json!({ "url": "https://example.com/missing" }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Subscription not found");
    }

    #[tokio::test]
    async fn router_rejects_duplicate_node_with_bad_request() {
        let app = test_app(Config {
            nodes: vec![ r#"{"type":"hysteria2","tag":"router-node","server":"node.example.com","server_port":443,"password":"password123","up_mbps":40,"down_mbps":350,"tls":{"enabled":true,"insecure":true}}"#.to_string(), ],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "POST",
                "/api/nodes",
                json!({
                    "tag": "router-node",
                    "server": "node.example.com",
                    "server_port": 443,
                    "password": "password123"
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert!(json["message"].as_str().unwrap().contains("重复"));
    }

    #[tokio::test]
    async fn router_returns_not_found_when_updating_missing_node() {
        let app = test_app(Config {
            nodes: vec![
                r#"{"type":"socks","tag":"router-node","server":"127.0.0.1","server_port":1080}"#
                    .to_string(),
            ],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "PUT",
                "/api/nodes",
                json!({
                    "original_tag": "missing-node",
                    "node_type": "socks",
                    "tag": "updated-node",
                    "server": "127.0.0.1",
                    "server_port": 1081
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Node not found");
    }

    #[tokio::test]
    async fn router_rejects_node_update_with_duplicate_tag() {
        let app = test_app(Config {
            nodes: vec![
                r#"{"type":"socks","tag":"first-node","server":"127.0.0.1","server_port":1080}"#
                    .to_string(),
                r#"{"type":"socks","tag":"second-node","server":"127.0.0.1","server_port":1081}"#
                    .to_string(),
            ],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "PUT",
                "/api/nodes",
                json!({
                    "original_tag": "first-node",
                    "node_type": "socks",
                    "tag": "SECOND-NODE",
                    "server": "127.0.0.1",
                    "server_port": 1082
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert!(json["message"].as_str().unwrap().contains("重复"));
    }

    #[tokio::test]
    async fn router_returns_not_found_when_deleting_missing_node() {
        let app = test_app(Config {
            nodes: vec![ r#"{"type":"hysteria2","tag":"router-node","server":"node.example.com","server_port":443,"password":"secret","up_mbps":40,"down_mbps":350,"tls":{"enabled":true,"insecure":true}}"#.to_string(), ],
            ..Default::default()
        })
        .await;

        let response = app
            .oneshot(json_request(
                "DELETE",
                "/api/nodes",
                json!({ "tag": "missing-node" }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["success"], false);
        assert_eq!(json["message"], "Node not found");
    }
}
