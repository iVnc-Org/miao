use crate::{
    responses::{status_error, success, HandlerResult},
    services::vps::{self, Connection, Job},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};

// Remote HTTP is supported explicitly; the token controls permission, not
// transport encryption. Never trust forwarded headers to grant local access.
fn access_context(
    headers: &HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    write: bool,
) -> Result<bool, String> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host_url = url::Url::parse(&format!("http://{host}")).map_err(|_| "Invalid Host")?;
    let local_host = host_url.host_str().is_some_and(|s| {
        s == "localhost"
            || s.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    let forwarded = [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    ]
    .iter()
    .any(|name| headers.contains_key(*name));
    let local = local_host && !forwarded && peer.is_some_and(|p| p.0.ip().is_loopback());
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !["same-origin", "none"].contains(&site) {
            return Err("Cross-site VPS access denied".into());
        }
    }
    if write || !local {
        let origin = headers
            .get("origin")
            .or_else(|| if write { None } else { headers.get("referer") })
            .and_then(|v| v.to_str().ok())
            .ok_or("Origin or same-origin Referer required")?;
        let url = url::Url::parse(origin).map_err(|_| "Invalid Origin")?;
        if !["http", "https"].contains(&url.scheme()) {
            return Err("HTTP or HTTPS Origin required".into());
        }
        if url.host_str() != host_url.host_str()
            || url.port_or_known_default()
                != Some(
                    host_url
                        .port()
                        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 }),
                )
        {
            return Err("Origin/Host mismatch".into());
        }
    }
    Ok(local)
}
fn configured_token() -> Option<String> {
    std::env::var("MIAO_VPS_TOKEN")
        .ok()
        .filter(|s| s.len() >= 32)
}
fn check_token(headers: &HeaderMap, local: bool, expected: Option<&str>) -> Result<(), String> {
    if local {
        return Ok(());
    }
    let expected = expected
        .ok_or("Remote VPS API disabled; configure MIAO_VPS_TOKEN (at least 32 characters)")?;
    let actual = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if Sha256::digest(actual.as_bytes()) != Sha256::digest(expected.as_bytes()) {
        return Err("VPS access token missing or invalid".into());
    }
    Ok(())
}
fn authorized(
    headers: &HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    write: bool,
) -> Result<(), String> {
    let local = access_context(headers, peer, write)?;
    check_token(headers, local, configured_token().as_deref())
}

// Public capability summary: no jobs, credentials, paths or token values.
pub async fn access(
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> HandlerResult<serde_json::Value> {
    let local = access_context(&headers, peer.map(|v| v.0), false).map_err(denied)?;
    let token = configured_token();
    Ok(success(
        "VPS access",
        serde_json::json!({
            "local": local,
            "token_configured": token.is_some(),
            "authorized": check_token(&headers, local, token.as_deref()).is_ok(),
        }),
    ))
}
fn denied<T: serde::Serialize>(
    message: String,
) -> (StatusCode, Json<crate::models::ApiResponse<T>>) {
    status_error(StatusCode::FORBIDDEN, message)
}
pub async fn list(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> HandlerResult<Vec<Job>> {
    authorized(&headers, peer.map(|v| v.0), false).map_err(denied)?;
    Ok(success(
        "VPS tasks",
        vps::jobs(&state)
            .await
            .map_err(|e| status_error(StatusCode::INTERNAL_SERVER_ERROR, e))?,
    ))
}
pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> HandlerResult<Job> {
    authorized(&headers, peer.map(|v| v.0), false).map_err(denied)?;
    let jobs = vps::jobs(&state)
        .await
        .map_err(|e| status_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let job = jobs
        .into_iter()
        .find(|job| job.id == id)
        .ok_or_else(|| status_error(StatusCode::NOT_FOUND, "Task not found"))?;
    Ok(success("VPS task", job))
}
pub async fn preflight(
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(req): Json<Connection>,
) -> HandlerResult<serde_json::Value> {
    authorized(&headers, peer.map(|v| v.0), true).map_err(denied)?;
    Ok(success(
        "VPS inspection",
        vps::preflight(req)
            .await
            .map_err(|e| status_error(StatusCode::BAD_REQUEST, e))?,
    ))
}
pub async fn start(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(req): Json<Connection>,
) -> HandlerResult<Job> {
    authorized(&headers, peer.map(|v| v.0), true).map_err(denied)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_requires_actual_loopback_peer_and_matching_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:6161".parse().unwrap());
        headers.insert("origin", "http://localhost:6161".parse().unwrap());
        assert!(authorized(
            &headers,
            Some(ConnectInfo("127.0.0.1:1234".parse().unwrap())),
            true
        )
        .is_ok());
        assert!(authorized(&headers, None, true).is_err());
        headers.insert("x-forwarded-for", "198.51.100.10".parse().unwrap());
        assert!(authorized(
            &headers,
            Some(ConnectInfo("127.0.0.1:1234".parse().unwrap())),
            true
        )
        .is_err());
        headers.remove("x-forwarded-for");
        headers.insert("origin", "http://evil.example".parse().unwrap());
        assert!(authorized(
            &headers,
            Some(ConnectInfo("127.0.0.1:1234".parse().unwrap())),
            true
        )
        .is_err());
    }
    #[test]
    fn remote_transport_and_token_matrix() {
        let token = "a".repeat(32);
        for (host, origin) in [
            ("192.168.1.10:6161", "http://192.168.1.10:6161"),
            ("panel.example", "https://panel.example"),
            ("panel.example:8443", "https://panel.example:8443"),
            ("[2001:db8::1]:6161", "http://[2001:db8::1]:6161"),
        ] {
            let mut h = HeaderMap::new();
            h.insert("host", host.parse().unwrap());
            h.insert("origin", origin.parse().unwrap());
            // Even an HTTPS reverse proxy with a loopback peer requires a token.
            h.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
            let local = access_context(
                &h,
                Some(ConnectInfo("127.0.0.1:1234".parse().unwrap())),
                true,
            )
            .unwrap();
            assert!(!local);
            assert!(check_token(&h, local, None).is_err());
            assert!(check_token(&h, local, Some(&token)).is_err());
            h.insert("authorization", "Bearer wrong".parse().unwrap());
            assert!(check_token(&h, local, Some(&token)).is_err());
            h.insert("authorization", format!("Bearer {token}").parse().unwrap());
            assert!(check_token(&h, local, Some(&token)).is_ok());
            h.remove("origin");
            h.insert("referer", format!("{origin}/").parse().unwrap());
            assert!(access_context(&h, None, false).is_ok());
            assert!(access_context(&h, None, true).is_err());
            h.insert("origin", "http://evil.example".parse().unwrap());
            assert!(access_context(&h, None, true).is_err());
            h.insert("origin", origin.parse().unwrap());
            h.insert("sec-fetch-site", "cross-site".parse().unwrap());
            assert!(access_context(&h, None, true).is_err());
        }
        let mut h = HeaderMap::new();
        h.insert("host", "localhost:6161".parse().unwrap());
        h.insert("origin", "http://localhost:6161".parse().unwrap());
        assert!(!access_context(
            &h,
            Some(ConnectInfo("198.51.100.1:1".parse().unwrap())),
            true
        )
        .unwrap());
        h.insert("forwarded", "for=127.0.0.1".parse().unwrap());
        assert!(
            !access_context(&h, Some(ConnectInfo("127.0.0.1:1".parse().unwrap())), true).unwrap()
        );
        h.insert("origin", "http://localhost:6162".parse().unwrap());
        assert!(access_context(&h, None, true).is_err());
        h.insert("origin", "ftp://localhost:6161".parse().unwrap());
        assert!(access_context(&h, None, true).is_err());
    }
    #[tokio::test]
    async fn remote_requests_cannot_bypass_authorization_on_any_sensitive_route() {
        use tower::ServiceExt;
        let router =
            crate::router::build_router(crate::test_support::app_state(Default::default()));
        for (method, uri) in [
            ("GET", "/api/vps/deployments"),
            ("GET", "/api/vps/deployments/example"),
            ("POST", "/api/vps/preflight"),
            ("POST", "/api/vps/deployments"),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "192.168.1.10:6161")
                .header("origin", "http://192.168.1.10:6161")
                .header("authorization", "Bearer invalid")
                .header("content-type", "application/json")
                .extension(ConnectInfo(
                    "192.168.1.20:1234".parse::<SocketAddr>().unwrap(),
                ))
                .body(axum::body::Body::from("{}".to_owned()))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
        }
    }
    #[tokio::test]
    async fn access_summary_contains_only_capabilities_and_is_not_cached() {
        use tower::ServiceExt;
        let state = crate::test_support::app_state(Default::default());
        let router = crate::router::build_router(state);
        let request = axum::http::Request::builder()
            .uri("/api/vps/access")
            .header("host", "localhost:6161")
            .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let data = &value["data"];
        assert_eq!(data["local"], true);
        assert_eq!(data["authorized"], true);
        assert_eq!(data.as_object().unwrap().len(), 3);
    }
    #[tokio::test]
    async fn router_requires_transport_identity_and_prevents_cached_task_responses() {
        use tower::ServiceExt;
        let state = crate::test_support::app_state(Default::default());
        let router = crate::router::build_router(state);
        let request = axum::http::Request::builder()
            .uri("/api/vps/deployments")
            .header("host", "localhost:6161")
            .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let request = axum::http::Request::builder()
            .uri("/api/vps/deployments")
            .header("host", "localhost:6161")
            .extension(ConnectInfo(
                "198.51.100.1:1234".parse::<SocketAddr>().unwrap(),
            ))
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
}
