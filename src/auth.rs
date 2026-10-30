//! Single administrator authentication. Passwords intentionally stored as plaintext,
//! as requested; never serialize Credentials into responses or logs.
use crate::{
    error::{AppError, AppResult},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
#[derive(Default)]
pub struct Auth {
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<HashMap<std::net::IpAddr, (Instant, u32)>>,
}
#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub csrf: String,
    revision: String,
    expires: Instant,
}
#[derive(Serialize, Deserialize)]
struct Credentials {
    password: String,
    revision: String,
}
pub fn auth_path(config: &Path) -> PathBuf {
    config.with_extension("auth.json")
}
fn random() -> AppResult<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}
fn equal(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
}
fn secure_open(path: &Path, create: bool) -> AppResult<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != nix::unistd::Uid::effective().as_raw()
        || m.mode() & 0o077 != 0
        || m.len() > 65536
    {
        return Err(AppError::message(
            "Unsafe panel authentication file permissions or ownership",
        ));
    }
    Ok(f)
}
fn read(config: &Path) -> AppResult<Option<Credentials>> {
    let path = auth_path(config);
    let mut file = match secure_open(&path, false) {
        Ok(f) => f,
        Err(e) if !path.exists() && fs::symlink_metadata(&path).is_err() => {
            let _ = e;
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    let credentials: Credentials = serde_json::from_str(&value)
        .map_err(|_| AppError::message("Invalid panel authentication file"))?;
    validate_password(&credentials.password)?;
    if credentials.revision.len() != 64 {
        return Err(AppError::message("Invalid credential revision"));
    }
    Ok(Some(credentials))
}
fn validate_password(password: &str) -> AppResult<()> {
    if password.is_empty() || password.len() > 4096 || password.chars().any(char::is_control) {
        return Err(AppError::message(
            "Password must contain 1–4096 bytes without control characters",
        ));
    }
    Ok(())
}
/// All writers share the same flock and compare current password under that lock.
pub fn set_password(config: &Path, password: &str, current: Option<&str>) -> AppResult<()> {
    write_password(config, password, current, false)
}
fn write_password(
    config: &Path,
    password: &str,
    current: Option<&str>,
    initial_only: bool,
) -> AppResult<()> {
    validate_password(password)?;
    let path = auth_path(config);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
    }
    let lock_path = path.with_extension("json.lock");
    let lock = secure_open(&lock_path, true)?;
    let _lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| AppError::message(format!("Cannot lock authentication file: {e}")))?;
    let existing = read(config);
    if initial_only {
        if existing?.is_some() {
            return Err(AppError::message("Panel password is already configured"));
        }
    } else if let Some(current) = current {
        let credentials =
            existing?.ok_or_else(|| AppError::message("Panel password is not configured"))?;
        if !equal(current, &credentials.password) {
            return Err(AppError::message("Current password is incorrect"));
        }
    } else {
        // CLI can repair corrupt content, but must never replace a symlink or unsafe file.
        if fs::symlink_metadata(&path).is_ok() {
            secure_open(&path, false)?;
        }
    }
    let credentials = Credentials {
        password: password.into(),
        revision: random()?,
    };
    let temp = path.with_extension(format!("json.tmp.{}", random()?));
    let result = (|| -> AppResult<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        f.write_all(serde_json::to_string(&credentials)?.as_bytes())?;
        f.sync_all()?;
        fs::rename(&temp, &path)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
use std::os::unix::fs::DirBuilderExt;
/// Internal upgrade exec restores persisted state, never replaying one-shot CLI intent or secrets.
pub fn restart_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut result = Vec::new();
    let mut args = args.into_iter().skip(1);
    while let Some(arg) = args.next() {
        let transient = [
            "--password",
            "--mode",
            "--vps-host",
            "--vps-ssh-port",
            "--vps-password",
        ];
        if transient.contains(&arg.as_str()) {
            args.next();
            continue;
        }
        if arg == "--no-start"
            || transient
                .iter()
                .any(|key| arg.starts_with(&format!("{key}=")))
        {
            continue;
        }
        let has_value = ["--config", "--socks-port", "--socks-listen"].contains(&arg.as_str());
        result.push(arg);
        if has_value {
            if let Some(value) = args.next() {
                result.push(value);
            }
        }
    }
    result
}
pub fn prompt_password() -> AppResult<String> {
    use std::os::fd::AsRawFd;
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| AppError::message("No terminal; pass a password explicitly"))?;
    struct Restore(i32, nix::libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                nix::libc::tcsetattr(self.0, nix::libc::TCSANOW, &self.1);
            }
        }
    }
    let fd = tty.as_raw_fd();
    let mut old = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::tcgetattr(fd, &mut old) } != 0 {
        return Err(AppError::message("Cannot configure terminal"));
    }
    let _restore = Restore(fd, old);
    let mut settings = old;
    settings.c_lflag &= !(nix::libc::ECHO | nix::libc::ICANON | nix::libc::ISIG);
    settings.c_cc[nix::libc::VMIN] = 1;
    settings.c_cc[nix::libc::VTIME] = 0;
    if unsafe { nix::libc::tcsetattr(fd, nix::libc::TCSANOW, &settings) } != 0 {
        return Err(AppError::message("Cannot disable terminal echo"));
    }
    let mut get = |prompt: &str| -> AppResult<String> {
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        let mut value = Vec::new();
        loop {
            let mut b = [0];
            if tty.read(&mut b)? == 0 {
                return Err(AppError::message("Password input interrupted"));
            }
            if b[0] == b'\n' || b[0] == b'\r' {
                break;
            }
            if b[0] == 3 || b[0] == 4 {
                return Err(AppError::message("Password input interrupted"));
            }
            if b[0] == 127 || b[0] == 8 {
                while let Some(last) = value.pop() {
                    if last & 0xc0 != 0x80 {
                        break;
                    }
                }
                continue;
            }
            value.push(b[0]);
            if value.len() > 4096 {
                return Err(AppError::message("Password too long"));
            }
        }
        tty.write_all(b"\n")?;
        String::from_utf8(value).map_err(|_| AppError::message("Password must be UTF-8"))
    };
    let first = get("New panel password: ")?;
    let second = get("Confirm password: ")?;
    if first != second {
        return Err(AppError::message("Passwords do not match"));
    }
    validate_password(&first)?;
    Ok(first)
}
fn cookie_name(state: &AppState) -> String {
    format!(
        "miao_session_{}",
        &hex::encode(Sha256::digest(
            state.config_path.as_os_str().as_encoded_bytes()
        ))[..12]
    )
}
fn cookie<'a>(state: &AppState, headers: &'a HeaderMap) -> Option<&'a str> {
    let prefix = format!("{}=", cookie_name(state));
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|v| v.strip_prefix(&prefix))
}
pub fn session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let id = cookie(state, headers)?;
    let credentials = read(&state.config_path).ok()??;
    let mut sessions = state.auth.sessions.lock().unwrap();
    sessions.retain(|_, s| s.expires > Instant::now() && s.revision == credentials.revision);
    sessions.get(id).cloned()
}
pub fn valid_session(state: &AppState, id: &str) -> bool {
    let mut headers = HeaderMap::new();
    if let Ok(value) = format!("{}={id}", cookie_name(state)).parse() {
        headers.insert("cookie", value);
    }
    session(state, &headers).is_some()
}
fn same_origin(headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !["same-origin", "none"].contains(&v))
    {
        return false;
    }
    let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    let Ok(expected) = url::Url::parse(&format!("{}://{host}", url.scheme())) else {
        return false;
    };
    ["http", "https"].contains(&url.scheme())
        && url.origin() == expected.origin()
        && url.username().is_empty()
        && url.password().is_none()
}
fn error(status: StatusCode, message: &str) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({"success":false,"message":message})),
    )
        .into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
pub async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let public = matches!(
        (request.method(), path),
        (&Method::GET, "/")
            | (&Method::GET, "/favicon.svg")
            | (&Method::GET, "/api/auth/status")
            | (&Method::POST, "/api/auth/login")
            | (&Method::POST, "/api/auth/setup")
    );
    if !public {
        let Some(session) = session(&state, request.headers()) else {
            return error(StatusCode::UNAUTHORIZED, "Login required");
        };
        let websocket = request
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if websocket
            || !matches!(
                *request.method(),
                Method::GET | Method::HEAD | Method::OPTIONS
            )
        {
            if !same_origin(request.headers()) {
                return error(StatusCode::FORBIDDEN, "Cross-site request denied");
            }
            if !websocket
                && request
                    .headers()
                    .get("x-miao-csrf")
                    .and_then(|v| v.to_str().ok())
                    != Some(session.csrf.as_str())
            {
                return error(StatusCode::FORBIDDEN, "Invalid CSRF token");
            }
        }
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response.headers_mut().insert(
        "x-frame-options",
        if state.embedded { "SAMEORIGIN" } else { "DENY" }
            .parse()
            .unwrap(),
    );
    response
}
pub async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let credentials = match read(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Panel authentication file cannot be read; repair with miao password set",
            )
        }
    };
    let s = session(&state, &headers);
    let config = state.config.read().await;
    let socks_listen = config
        .socks_listen
        .clone()
        .unwrap_or_else(|| crate::models::DEFAULT_SOCKS_LISTEN.into());
    let socks_port = config
        .socks_port
        .unwrap_or(crate::models::DEFAULT_SOCKS_PORT);
    drop(config);
    let proxy_running = crate::services::singbox::sing_box_is_running(&state).await;
    Json(serde_json::json!({"success":true,"data":{
        "configured":credentials.is_some(), "authenticated":s.is_some(), "csrf":s.map(|s|s.csrf),
        "service":"miao", "service_pid":std::process::id(), "embedded":state.embedded,
        "integration_version":crate::embedding::INTEGRATION_VERSION,
        "initializing":state.initializing.load(std::sync::atomic::Ordering::Relaxed),
        "proxy_running":proxy_running, "socks_listen":socks_listen, "socks_port":socks_port
    }}))
    .into_response()
}
#[derive(Deserialize)]
pub struct Login {
    password: String,
}
pub async fn login(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> Response {
    if !same_origin(&headers) {
        return error(StatusCode::FORBIDDEN, "Cross-site request denied");
    }
    let ip = peer
        .map(|p| p.0 .0.ip())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    {
        let mut attempts = state.auth.attempts.lock().unwrap();
        attempts.retain(|_, (time, _)| time.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 4096 && !attempts.contains_key(&ip) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts; retry in one minute",
            );
        }
        let entry = attempts.entry(ip).or_insert((Instant::now(), 0));
        if entry.1 >= 10 {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts; retry in one minute",
            );
        }
        entry.1 += 1;
    }
    let credentials = match read(&state.config_path) {
        Ok(Some(c)) => c,
        _ => {
            return error(
                StatusCode::UNAUTHORIZED,
                "Set the panel password using miao password set",
            )
        }
    };
    if !equal(&body.password, &credentials.password) {
        return error(StatusCode::UNAUTHORIZED, "Incorrect password");
    }
    state.auth.attempts.lock().unwrap().remove(&ip);
    issue_session(&state, &headers, credentials)
}
fn issue_session(state: &AppState, headers: &HeaderMap, credentials: Credentials) -> Response {
    let (Ok(id), Ok(csrf)) = (random(), random()) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Cannot create session");
    };
    let s = Session {
        id: id.clone(),
        csrf: csrf.clone(),
        revision: credentials.revision,
        expires: Instant::now() + TTL,
    };
    {
        let mut sessions = state.auth.sessions.lock().unwrap();
        sessions.retain(|_, existing| {
            existing.expires > Instant::now() && existing.revision == s.revision
        });
        if sessions.len() >= 256 {
            return error(StatusCode::TOO_MANY_REQUESTS, "Too many active sessions");
        }
        sessions.insert(id.clone(), s);
    }
    let secure = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("https://"));
    let mut response =
        Json(serde_json::json!({"success":true,"data":{"csrf":csrf}})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        format!(
            "{}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            cookie_name(state),
            TTL.as_secs(),
            if secure { "; Secure" } else { "" }
        )
        .parse()
        .unwrap(),
    );
    response
}
#[derive(Deserialize)]
pub struct InitialPassword {
    password: String,
    confirm_password: String,
}
pub async fn setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InitialPassword>,
) -> Response {
    if !same_origin(&headers) {
        return error(StatusCode::FORBIDDEN, "Cross-site request denied");
    }
    if body.password != body.confirm_password || validate_password(&body.password).is_err() {
        return error(
            StatusCode::BAD_REQUEST,
            "Passwords must match and be non-empty without control characters (max 4096 bytes)",
        );
    }
    let path = state.config_path.clone();
    let password = body.password.clone();
    let result =
        tokio::task::spawn_blocking(move || write_password(&path, &password, None, true)).await;
    match result {
        Ok(Ok(())) => {
            // A CLI reset may have raced after initialization. Never authorize a
            // session for credentials different from those submitted here.
            match read(&state.config_path) {
                Ok(Some(credentials)) if equal(&credentials.password, &body.password) => {
                    issue_session(&state, &headers, credentials)
                }
                _ => error(
                    StatusCode::CONFLICT,
                    "Password changed; sign in with the current password",
                ),
            }
        }
        Ok(Err(e)) if e.to_string() == "Panel password is already configured" => {
            error(StatusCode::CONFLICT, "Panel password is already configured")
        }
        _ => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Cannot initialize panel password; check authentication file permissions",
        ),
    }
}
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = cookie(&state, &headers) {
        state.auth.sessions.lock().unwrap().remove(id);
    }
    let mut r = Json(serde_json::json!({"success":true})).into_response();
    r.headers_mut().insert(
        "set-cookie",
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            cookie_name(&state)
        )
        .parse()
        .unwrap(),
    );
    r
}
#[derive(Deserialize)]
pub struct PasswordChange {
    current_password: String,
    new_password: String,
}
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasswordChange>,
) -> Response {
    let path = state.config_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        set_password(&path, &body.new_password, Some(&body.current_password))
    })
    .await;
    match result {
        Ok(Ok(()))=> {state.auth.sessions.lock().unwrap().clear(); Json(serde_json::json!({"success":true})).into_response()},
        Ok(Err(_))=>error(StatusCode::BAD_REQUEST,"Current password is incorrect or new password is invalid; check authentication file permissions"),
        Err(_)=>error(StatusCode::INTERNAL_SERVER_ERROR,"Password update failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    fn state() -> Arc<AppState> {
        let path = std::env::temp_dir()
            .join(format!("miao-auth-{}", random().unwrap()))
            .join("config.yaml");
        Arc::new(AppState::with_config_path(Default::default(), path).unwrap())
    }
    fn req(
        method: &str,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: serde_json::Value,
    ) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "panel.example:6161")
            .header("origin", "http://panel.example:6161")
            .header("content-type", "application/json");
        if let Some(cookie) = cookie {
            r = r.header("cookie", cookie);
        }
        if let Some(csrf) = csrf {
            r = r.header("x-miao-csrf", csrf);
        }
        r.body(Body::from(body.to_string())).unwrap()
    }
    async fn sign_in(app: &axum::Router, password: &str) -> (String, String) {
        let response = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/auth/login",
                None,
                None,
                serde_json::json!({"password":password}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("HttpOnly"));
        let value = crate::test_support::response_json(response).await;
        (cookie, value["data"]["csrf"].as_str().unwrap().into())
    }
    #[tokio::test]
    async fn embedded_identity_frames_and_authentication_remain_consistent() {
        for embedded in [false, true] {
            let path = std::env::temp_dir()
                .join(format!("miao-embedding-auth-{}", random().unwrap()))
                .join("config.yaml");
            let config = crate::models::Config {
                socks_listen: Some("127.0.0.1".into()),
                socks_port: Some(19080),
                ..Default::default()
            };
            let state = Arc::new(AppState::with_embedding(config, path.clone(), embedded).unwrap());
            let app = crate::router::build_router(state.clone());
            let response = app
                .clone()
                .oneshot(req(
                    "GET",
                    "/api/auth/status",
                    None,
                    None,
                    serde_json::json!({}),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.headers()["x-frame-options"],
                if embedded { "SAMEORIGIN" } else { "DENY" }
            );
            let status = crate::test_support::response_json(response).await;
            assert_eq!(status["data"]["service_pid"], std::process::id());
            assert_eq!(status["data"]["embedded"], embedded);
            assert_eq!(
                status["data"]["integration_version"],
                crate::embedding::INTEGRATION_VERSION
            );
            assert_eq!(status["data"]["socks_port"], 19080);
            assert_eq!(status["data"]["proxy_running"], false);
            assert_eq!(
                app.clone()
                    .oneshot(req("GET", "/api/status", None, None, serde_json::json!({})))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            set_password(&state.config_path, "embedded-test-password", None).unwrap();
            let (cookie, csrf) = sign_in(&app, "embedded-test-password").await;
            if embedded {
                let response = app
                    .clone()
                    .oneshot(req(
                        "POST",
                        "/api/upgrade",
                        Some(&cookie),
                        Some(&csrf),
                        serde_json::json!({}),
                    ))
                    .await
                    .unwrap();
                let result = crate::test_support::response_json(response).await;
                assert_eq!(result["success"], false);
                assert!(result.to_string().contains("managed by iVnc"));
                let info = crate::services::version::get_version_info(&state).await;
                assert_eq!(info.managed_by.as_deref(), Some("ivnc"));
                assert!(!state.upgrading.load(std::sync::atomic::Ordering::SeqCst));
            }
            let mut cross_site = req(
                "POST",
                "/api/auth/logout",
                Some(&cookie),
                Some(&csrf),
                serde_json::json!({}),
            );
            cross_site
                .headers_mut()
                .insert("origin", "https://foreign.example".parse().unwrap());
            assert_eq!(
                app.clone().oneshot(cross_site).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }

    #[tokio::test]
    async fn all_management_routes_require_login_including_loopback_and_vps() {
        let state = state();
        let app = crate::router::build_router(state.clone());
        for (method, path) in [
            ("GET", "/api/status"),
            ("GET", "/api/nodes"),
            ("GET", "/api/subs"),
            ("GET", "/api/share/endpoints"),
            ("POST", "/api/upgrade"),
            ("GET", "/api/upgrade"),
            ("POST", "/api/vps/preflight"),
            ("POST", "/api/vps/deployments"),
            ("GET", "/api/vps/deployments"),
            ("GET", "/api/clash/proxies"),
            ("GET", "/api/clash/traffic"),
        ] {
            let mut request = req(method, path, None, None, serde_json::json!({}));
            request
                .extensions_mut()
                .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
        let status = crate::test_support::response_json(
            app.clone()
                .oneshot(req(
                    "GET",
                    "/api/auth/status",
                    None,
                    None,
                    serde_json::json!({}),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status["data"]["configured"], false);
        assert!(status.to_string().find("password").is_none());
        set_password(&state.config_path, "first-password", None).unwrap();
        let (cookie, csrf) = sign_in(&app, "first-password").await;
        let r = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/vps/deployments",
                Some(&cookie),
                None,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let mut websocket = req(
            "GET",
            "/api/clash/traffic",
            Some(&cookie),
            None,
            serde_json::json!({}),
        );
        websocket
            .headers_mut()
            .insert("upgrade", "WebSocket".parse().unwrap());
        websocket
            .headers_mut()
            .insert("origin", "http://evil.example".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(websocket).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/service/stop",
                Some(&cookie),
                None,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let mut request = req(
            "POST",
            "/api/auth/logout",
            Some(&cookie),
            Some(&csrf),
            serde_json::json!({}),
        );
        request
            .headers_mut()
            .insert("origin", "http://evil.example".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/auth/logout",
                Some(&cookie),
                Some(&csrf),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "GET",
                    "/api/nodes",
                    Some(&cookie),
                    None,
                    serde_json::json!({})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let _ = fs::remove_dir_all(state.config_path.parent().unwrap());
    }
    #[tokio::test]
    async fn cli_and_web_password_changes_invalidate_sessions_and_never_return_passwords() {
        let state = state();
        set_password(&state.config_path, "old", None).unwrap();
        let app = crate::router::build_router(state.clone());
        let (cookie, csrf) = sign_in(&app, "old").await;
        let id = cookie.split_once('=').unwrap().1;
        assert!(valid_session(&state, id));
        let r = app
            .clone()
            .oneshot(req(
                "PUT",
                "/api/auth/password",
                Some(&cookie),
                Some(&csrf),
                serde_json::json!({"current_password":"wrong","new_password":"new"}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(valid_session(&state, id));
        let r=app.clone().oneshot(req("PUT","/api/auth/password",Some(&cookie),Some(&csrf),serde_json::json!({"current_password":"old","new_password":"new '中文 & $ password"}))).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(!valid_session(&state, id));
        let (cookie, _) = sign_in(&app, "new '中文 & $ password").await;
        set_password(&state.config_path, "cli-password", None).unwrap();
        assert!(!valid_session(&state, cookie.split_once('=').unwrap().1));
        sign_in(&app, "cli-password").await;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(auth_path(&state.config_path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(set_password(&state.config_path, "", None).is_err());
        let _ = fs::remove_dir_all(state.config_path.parent().unwrap());
    }
    #[tokio::test]
    async fn session_expiry_restart_corruption_and_unsafe_files_fail_closed() {
        let state = state();
        set_password(&state.config_path, "password", None).unwrap();
        let app = crate::router::build_router(state.clone());
        let (cookie, _) = sign_in(&app, "password").await;
        let id = cookie.split_once('=').unwrap().1;
        let restarted =
            AppState::with_config_path(Default::default(), state.config_path.clone()).unwrap();
        assert!(!valid_session(&restarted, id));
        state
            .auth
            .sessions
            .lock()
            .unwrap()
            .get_mut(id)
            .unwrap()
            .expires = Instant::now();
        assert!(!valid_session(&state, id));
        let (cookie, _) = sign_in(&app, "password").await;
        fs::write(auth_path(&state.config_path), "broken").unwrap();
        assert!(!valid_session(&state, cookie.split_once('=').unwrap().1));
        set_password(&state.config_path, "repaired", None).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            auth_path(&state.config_path),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(read(&state.config_path).is_err());
        assert!(set_password(&state.config_path, "x", None).is_err());
        fs::remove_file(auth_path(&state.config_path)).unwrap();
        std::os::unix::fs::symlink("/dev/null", auth_path(&state.config_path)).unwrap();
        assert!(set_password(&state.config_path, "x", None).is_err());
        fs::remove_file(auth_path(&state.config_path)).unwrap();
        nix::unistd::mkfifo(
            &auth_path(&state.config_path),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        assert!(read(&state.config_path).is_err());
        assert!(set_password(&state.config_path, "x", None).is_err());
        let _ = fs::remove_dir_all(state.config_path.parent().unwrap());
    }
    #[tokio::test]
    async fn login_limits_and_csrf_origin_validation_cover_proxy_and_ipv6() {
        let state = state();
        set_password(&state.config_path, "password", None).unwrap();
        let app = crate::router::build_router(state.clone());
        for _ in 0..10 {
            assert_eq!(
                app.clone()
                    .oneshot(req(
                        "POST",
                        "/api/auth/login",
                        None,
                        None,
                        serde_json::json!({"password":"wrong"})
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "POST",
                    "/api/auth/login",
                    None,
                    None,
                    serde_json::json!({"password":"password"})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        state.auth.attempts.lock().unwrap().clear();
        let mut r = req(
            "POST",
            "/api/auth/login",
            None,
            None,
            serde_json::json!({"password":"password"}),
        );
        r.headers_mut()
            .insert("host", "[2001:db8::1]:8443".parse().unwrap());
        r.headers_mut()
            .insert("origin", "https://[2001:db8::1]:8443".parse().unwrap());
        let response = app.clone().oneshot(r).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("; Secure"));
        let mut h = HeaderMap::new();
        h.insert("host", "panel.example".parse().unwrap());
        h.insert("origin", "https://panel.example".parse().unwrap());
        h.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        assert!(same_origin(&h));
        h.insert("origin", "https://panel.example:8443".parse().unwrap());
        assert!(!same_origin(&h));
        let _ = fs::remove_dir_all(state.config_path.parent().unwrap());
    }
    #[tokio::test]
    async fn browser_initialization_validates_confirms_and_logs_in_exactly_once() {
        let state = state();
        let app = crate::router::build_router(state.clone());
        let body =
            serde_json::json!({"password":"initial ' 中文", "confirm_password":"initial ' 中文"});
        let mut cross = req("POST", "/api/auth/setup", None, None, body.clone());
        cross
            .headers_mut()
            .insert("origin", "http://evil.example".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(cross).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "POST",
                    "/api/auth/setup",
                    None,
                    None,
                    serde_json::json!({"password":"a","confirm_password":"b"})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(read(&state.config_path).unwrap().is_none());
        let response = app
            .clone()
            .oneshot(req("POST", "/api/auth/setup", None, None, body.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "GET",
                    "/api/nodes",
                    Some(&cookie),
                    None,
                    serde_json::json!({})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(req("POST", "/api/auth/setup", None, None, body))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        set_password(&state.config_path, "cli-reset", None).unwrap();
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "POST",
                    "/api/auth/setup",
                    None,
                    None,
                    serde_json::json!({"password":"attacker","confirm_password":"attacker"})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            read(&state.config_path).unwrap().unwrap().password,
            "cli-reset"
        );
        fs::write(auth_path(&state.config_path), "corrupt").unwrap();
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "POST",
                    "/api/auth/setup",
                    None,
                    None,
                    serde_json::json!({"password":"attacker","confirm_password":"attacker"})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let _ = fs::remove_dir_all(state.config_path.parent().unwrap());
    }
    #[test]
    fn concurrent_initialization_has_only_one_winner() {
        let state = state();
        let path = state.config_path.clone();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    write_password(&path, &format!("initial-{i}"), None, true).is_ok()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().unwrap().then_some(()))
                .count(),
            1
        );
        assert!(read(&path)
            .unwrap()
            .unwrap()
            .password
            .starts_with("initial-"));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
    #[test]
    fn internal_restart_drops_only_startup_password_arguments() {
        let args = [
            "miao",
            "--config",
            "--password=filename",
            "--password",
            "--config",
            "--socks-port",
            "1080",
        ];
        assert_eq!(
            restart_args(args.map(String::from)),
            vec!["--config", "--password=filename", "--socks-port", "1080"]
        );
    }
    #[test]
    fn internal_restart_does_not_replay_cli_deployment_or_mode_intent() {
        let args = [
            "miao",
            "--config",
            "--mode=filename",
            "--mode",
            "global",
            "--vps-host=example.com",
            "--vps-ssh-port",
            "22",
            "--vps-password",
            "--no-start",
            "--password=secret",
            "--no-start",
            "--socks-port=1080",
        ];
        assert_eq!(
            restart_args(args.map(String::from)),
            vec!["--config", "--mode=filename", "--socks-port=1080"]
        );
    }

    #[test]
    fn concurrent_writers_preserve_atomic_valid_credentials() {
        let state = state();
        let path = state.config_path.clone();
        set_password(&path, "initial", None).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    set_password(&path, &format!("password-{i}"), None).unwrap()
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(read(&path)
            .unwrap()
            .unwrap()
            .password
            .starts_with("password-"));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
