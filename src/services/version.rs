use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    sync::{atomic::Ordering, Arc},
    time::Instant,
};

use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::build_info::{current_version, git_commit_full, git_commit_short, git_commit_url};
use crate::error::{AppError, AppResult};
use crate::models::{GitHubAsset, GitHubCommit, GitHubRelease, VersionInfo};
use crate::services::singbox::{
    get_sing_box_home, sing_box_is_running, start_sing_internal, stop_sing_internal,
};
use crate::state::{AppState, VersionCache};

const GITHUB_PROXY_PREFIX: &str = "https://httptunnel.top/gh/";

const RELEASE_REPO: &str = "iVnc-Org/miao";
const RELEASE_API_URL: &str = "https://api.github.com/repos/iVnc-Org/miao/releases/tags/latest";
const RELEASE_COMMIT_API_URL: &str = "https://api.github.com/repos/iVnc-Org/miao/commits/latest";
const RELEASE_DOWNLOAD_BASE: &str = "https://github.com/iVnc-Org/miao/releases/download/latest";

const CACHE_TTL: Duration = Duration::from_secs(300);
const DOWNLOAD_MAX_ATTEMPTS: u32 = 3;
const DOWNLOAD_RETRY_BASE_MS: u64 = 500;

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UpgradeStatus {
    pub id: String,
    pub active: bool,
    pub stage: String,
    pub target: String,
    pub downloaded: u64,
    pub total: u64,
    pub events: Vec<String>,
}

static STATUS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn status_path(state: &AppState) -> std::path::PathBuf {
    state.config_path.with_extension("upgrade.json")
}

fn update_status(
    state: &AppState,
    change: impl FnOnce(&mut UpgradeStatus),
) -> AppResult<UpgradeStatus> {
    let _lock = STATUS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = status_path(state);
    let mut status: UpgradeStatus = fs::read(&path)
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default();
    change(&mut status);
    let temp = path.with_extension("upgrade.json.tmp");
    fs::write(&temp, serde_json::to_vec(&status)?)?;
    fs::rename(temp, path)?;
    Ok(status)
}

fn stage(state: &AppState, message: &str) -> AppResult<()> {
    update_status(state, |s| {
        s.stage = message.into();
        s.events.push(message.into());
        if s.events.len() > 80 {
            s.events.remove(0);
        }
    })?;
    Ok(())
}

pub async fn upgrade_status(state: &Arc<AppState>) -> AppResult<UpgradeStatus> {
    let status: UpgradeStatus = match fs::read(status_path(state)) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => UpgradeStatus::default(),
        Err(e) => return Err(e.into()),
    };
    if !status.active
        || state.upgrading.load(Ordering::SeqCst)
        || state.initializing.load(Ordering::SeqCst)
    {
        return Ok(status);
    }
    let restored = sing_box_is_running(state).await;
    update_status(state, |s| {
        if state.upgrading.load(Ordering::SeqCst) || !s.active {
            return;
        }
        s.active = false;
        s.stage = if s.stage == "Restarting" && s.target == current_version() && restored {
            "Upgrade complete".into()
        } else {
            "Upgrade interrupted, rolled back, or core recovery failed".into()
        };
        s.events.push(s.stage.clone());
    })
}

/// Finalize recovery even when no browser is connected.
pub fn watch_upgrade_recovery(state: Arc<AppState>) {
    tokio::spawn(async move {
        for _ in 0..600 {
            if !state.initializing.load(Ordering::SeqCst) {
                if let Err(e) = upgrade_status(&state).await {
                    warn!(error = %e, "Failed to reconcile upgrade status");
                }
                return;
            }
            sleep(Duration::from_secs(1)).await;
        }
        let _ = update_status(&state, |s| {
            if s.active && !state.upgrading.load(Ordering::SeqCst) {
                s.active = false;
                s.stage = "Upgrade failed: core recovery timed out".into();
                s.events.push(s.stage.clone());
            }
        });
    });
}

pub fn start_upgrade(state: Arc<AppState>) -> AppResult<UpgradeStatus> {
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err(AppError::message("Miao is shutting down"));
    }
    if state.initializing.load(Ordering::SeqCst) {
        return Err(AppError::message("Service is still initializing"));
    }
    if state
        .upgrading
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(AppError::message("Upgrade already in progress"));
    }
    if state.vps_active.load(Ordering::SeqCst) {
        state.upgrading.store(false, Ordering::SeqCst);
        return Err(AppError::message("VPS deployment in progress"));
    }
    let initial = update_status(&state, |s| {
        *s = UpgradeStatus {
            id: format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
            ),
            active: true,
            stage: "Checking release".into(),
            events: vec!["Checking release".into()],
            ..Default::default()
        }
    });
    if initial.is_err() {
        state.upgrading.store(false, Ordering::SeqCst);
        return initial;
    }
    tokio::spawn(async move {
        match upgrade_binary(&state).await {
            Ok(message) if message == "Already up to date" => {
                let _ = stage(&state, &message);
                let _ = update_status(&state, |s| s.active = false);
                state.upgrading.store(false, Ordering::SeqCst);
            }
            Ok(_) => {} // Keep the guard until exec; the new process reconciles persisted state.
            Err(e) => {
                let _ = stage(&state, &format!("Upgrade failed: {e}"));
                let _ = update_status(&state, |s| s.active = false);
                state.upgrading.store(false, Ordering::SeqCst);
            }
        }
    });
    initial
}

async fn accessible_get(client: &reqwest::Client, url: &str) -> AppResult<reqwest::Response> {
    accessible_get_with_proxy(client, url, GITHUB_PROXY_PREFIX).await
}

async fn accessible_get_with_proxy(
    client: &reqwest::Client,
    url: &str,
    proxy: &str,
) -> AppResult<reqwest::Response> {
    // GET validates the actual resource; many release servers do not implement HEAD reliably.
    if url.starts_with(proxy) {
        return Ok(client
            .get(url)
            .header("User-Agent", "miao")
            .timeout(Duration::from_secs(120))
            .send()
            .await?
            .error_for_status()?);
    }
    match tokio::time::timeout(
        Duration::from_secs(8),
        client
            .get(url)
            .header("User-Agent", "miao")
            .timeout(Duration::from_secs(120))
            .send(),
    )
    .await
    {
        Ok(Ok(response)) if response.status().is_success() => Ok(response),
        _ => Ok(client
            .get(format!("{proxy}{url}"))
            .header("User-Agent", "miao")
            .timeout(Duration::from_secs(120))
            .send()
            .await?
            .error_for_status()?),
    }
}

/// 解析 `sha256sum` 输出首行：`<64 hex>[  *]<filename>`
fn parse_sha256sum_line(line: &str) -> AppResult<String> {
    let line = line.trim();
    let hex = line
        .split_whitespace()
        .next()
        .ok_or_else(|| AppError::message("checksum file is empty"))?;
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::message(format!(
            "invalid SHA256 in checksum file (first token): {line}"
        )));
    }
    Ok(hex.to_ascii_lowercase())
}

async fn fetch_checksum_hex(client: &reqwest::Client, url: &str) -> AppResult<String> {
    let text = accessible_get(client, url).await?.text().await?;

    let first = text.lines().next().unwrap_or("").trim();
    parse_sha256sum_line(first)
}

async fn fetch_checksum_hex_retried(client: &reqwest::Client, url: &str) -> AppResult<String> {
    let mut last_err: Option<AppError> = None;
    for attempt in 0..DOWNLOAD_MAX_ATTEMPTS {
        if attempt > 0 {
            sleep(Duration::from_millis(
                DOWNLOAD_RETRY_BASE_MS * (1 << (attempt - 1)),
            ))
            .await;
            warn!(
                attempt = attempt + 1,
                max = DOWNLOAD_MAX_ATTEMPTS,
                "retrying checksum download"
            );
        }
        let attempt_url = if attempt > 0 {
            format!("{GITHUB_PROXY_PREFIX}{url}")
        } else {
            url.into()
        };
        match fetch_checksum_hex(client, &attempt_url).await {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("checksum retry loop"))
}

/// 流式下载到临时文件并增量 SHA256；成功时文件已关闭且校验通过。
async fn download_binary_streaming_once(
    client: &reqwest::Client,
    url: &str,
    expected_size: u64,
    expected_hex: &str,
    temp_path: &Path,
    state: &Arc<AppState>,
) -> AppResult<()> {
    let response = accessible_get(client, url).await?;
    let source =
        if response.url().host_str() == Some("httptunnel.top") || url.starts_with(GITHUB_PROXY_PREFIX) {
            "httptunnel.top/gh"
        } else {
            "GitHub"
        };
    stage(state, &format!("Downloading binary via {source}"))?;

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(temp_path)
        .await
        .map_err(|e| AppError::context("Failed to create temp file", e))?;

    if expected_size == 0 {
        warn!("Asset size is 0; size validation will be skipped");
    }

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut last_logged_percent = 0u8;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes =
            chunk_result.map_err(|e| AppError::context("Download stream error", e))?;
        let n = chunk.len() as u64;
        if expected_size > 0 && downloaded + n > expected_size {
            let _ = tokio::fs::remove_file(temp_path).await;
            return Err(AppError::message(format!(
                "Download exceeds expected size ({expected_size} bytes)"
            )));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| AppError::context("Failed to write temp file", e))?;
        downloaded += n;

        if expected_size > 0 {
            let percent = ((downloaded as f64 / expected_size as f64) * 100.0) as u8;
            if percent >= last_logged_percent + 10 {
                info!(
                    percent = percent,
                    downloaded = downloaded,
                    total = expected_size,
                    "Download progress"
                );
                last_logged_percent = percent;
                update_status(state, |s| {
                    s.downloaded = downloaded;
                    s.total = expected_size;
                })?;
            }
        }
    }

    update_status(state, |s| {
        s.downloaded = downloaded;
        s.total = expected_size;
    })?;
    file.shutdown()
        .await
        .map_err(|e| AppError::context("Failed to finalize temp file", e))?;
    drop(file);

    if expected_size > 0 && downloaded != expected_size {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(AppError::message(format!(
            "Downloaded file size mismatch: expected {} bytes, got {} bytes",
            expected_size, downloaded
        )));
    }

    let actual_hex = hex::encode(hasher.finalize());
    if actual_hex != expected_hex {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(AppError::message(format!(
            "SHA256 mismatch: expected {expected_hex} (from checksum file), got {actual_hex}"
        )));
    }

    info!(
        sha256 = %actual_hex,
        bytes = downloaded,
        "Downloaded binary SHA256 matches release checksum"
    );
    Ok(())
}

async fn download_binary_streaming_retried(
    client: &reqwest::Client,
    url: &str,
    expected_size: u64,
    expected_hex: &str,
    temp_path: &Path,
    state: &Arc<AppState>,
) -> AppResult<()> {
    let mut last_err: Option<AppError> = None;
    for attempt in 0..DOWNLOAD_MAX_ATTEMPTS {
        if attempt > 0 {
            let _ = tokio::fs::remove_file(temp_path).await;
            sleep(Duration::from_millis(
                DOWNLOAD_RETRY_BASE_MS * (1 << (attempt - 1)),
            ))
            .await;
            warn!(
                attempt = attempt + 1,
                max = DOWNLOAD_MAX_ATTEMPTS,
                "retrying binary download"
            );
        }
        let attempt_url = if attempt > 0 {
            format!("{GITHUB_PROXY_PREFIX}{url}")
        } else {
            url.into()
        };
        if attempt > 0 {
            stage(state, "Retrying binary download via httptunnel.top/gh")?;
        }
        match download_binary_streaming_once(
            client,
            &attempt_url,
            expected_size,
            expected_hex,
            temp_path,
            state,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    let _ = tokio::fs::remove_file(temp_path).await;
    Err(last_err.expect("binary download retry loop"))
}

async fn fetch_release_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> AppResult<T> {
    let first =
        async { Ok::<T, AppError>(accessible_get(client, url).await?.json::<T>().await?) }.await;
    match first {
        Ok(value) => Ok(value),
        Err(_) => Ok(accessible_get(client, &format!("{GITHUB_PROXY_PREFIX}{url}"))
            .await?
            .json::<T>()
            .await?),
    }
}

async fn fetch_latest_release_uncached(client: &reqwest::Client) -> AppResult<GitHubRelease> {
    fetch_release_json(client, RELEASE_API_URL).await
}

async fn fetch_latest_commit_short(client: &reqwest::Client) -> AppResult<String> {
    let commit: GitHubCommit = fetch_release_json(client, RELEASE_COMMIT_API_URL).await?;
    Ok(normalize_commit_id(&commit.sha))
}

async fn resolve_latest_version(client: &reqwest::Client, release: &GitHubRelease) -> String {
    let from_release = release_version_label(release);
    if looks_like_commit_id(&from_release) {
        return from_release;
    }
    match fetch_latest_commit_short(client).await {
        Ok(commit) if !commit.is_empty() => commit,
        Ok(_) => from_release,
        Err(e) => {
            warn!(error = %e, "Failed to resolve latest commit from GitHub");
            from_release
        }
    }
}

async fn fetch_latest_release(
    client: &reqwest::Client,
    state: &Arc<AppState>,
) -> AppResult<GitHubRelease> {
    let cache = state.version_cache.load();
    if let (Some(release), Some(fetched_at)) = (&cache.release, cache.fetched_at) {
        if fetched_at.elapsed() < CACHE_TTL {
            return Ok(release.clone());
        }
    }
    drop(cache);

    let release = fetch_latest_release_uncached(client).await?;
    state.version_cache.store(Arc::new(VersionCache {
        release: Some(release.clone()),
        fetched_at: Some(Instant::now()),
    }));
    Ok(release)
}

async fn invalidate_release_cache(state: &Arc<AppState>) {
    state.version_cache.store(Arc::new(VersionCache {
        release: None,
        fetched_at: None,
    }));
}

pub async fn get_version_info(state: &Arc<AppState>) -> VersionInfo {
    let base = current_version_info();
    if !sing_box_is_running(state).await {
        return base;
    }

    let asset_name = current_arch_asset_name().unwrap_or("");

    match fetch_latest_release(&state.http_client, state).await {
        Ok(release) => {
            let latest = resolve_latest_version(&state.http_client, &release).await;
            let has_update = release_is_newer_than_current(&base.current, &latest);
            let download_url = if asset_name.is_empty() {
                None
            } else {
                Some(fixed_download_url(asset_name))
            };

            VersionInfo {
                latest: Some(latest),
                has_update,
                download_url,
                ..base
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to fetch latest release from GitHub");
            base
        }
    }
}

fn current_version_info() -> VersionInfo {
    VersionInfo {
        current: current_version(),
        sing_box_version: env!("SING_BOX_VERSION").into(),
        sing_box_revision: env!("SING_BOX_REVISION").into(),
        sing_box_tags: env!("SING_BOX_TAGS").into(),
        commit_short: git_commit_short(),
        commit_full: git_commit_full(),
        commit_url: git_commit_url(),
        latest: None,
        has_update: false,
        download_url: None,
    }
}

fn get_temp_binary_path() -> String {
    let pid = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("/tmp/miao-new-{}-{}", pid, timestamp)
}

fn checksum_asset_name(binary_asset_name: &str) -> String {
    format!("{binary_asset_name}.sha256")
}

fn find_binary_and_checksum_assets<'a>(
    release: &'a GitHubRelease,
    asset_name: &str,
) -> AppResult<(&'a GitHubAsset, &'a GitHubAsset)> {
    let sum_name = checksum_asset_name(asset_name);
    let binary = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| AppError::message("No binary found for current architecture"))?;
    let checksum = release.assets.iter().find(|a| a.name == sum_name).ok_or_else(|| {
        AppError::message(format!(
            "Release is missing checksum asset {sum_name}; upgrade requires a release that publishes .sha256 files"
        ))
    })?;
    Ok((binary, checksum))
}

fn fixed_download_url(asset_name: &str) -> String {
    format!("{RELEASE_DOWNLOAD_BASE}/{asset_name}")
}

fn normalize_commit_id(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("commit:")
        .trim()
        .chars()
        .take(7)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn looks_like_commit_id(value: &str) -> bool {
    let trimmed = value.trim();
    (7..=40).contains(&trimmed.len()) && trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

fn release_version_label(release: &GitHubRelease) -> String {
    release
        .target_commitish
        .as_deref()
        .filter(|value| looks_like_commit_id(value))
        .map(normalize_commit_id)
        .unwrap_or_else(|| normalize_commit_id(&release.tag_name))
}

/// 当前运行 commit 与 latest 发布的 commit 比较；不同即视为可更新。
fn release_is_newer_than_current(current: &str, release_version: &str) -> bool {
    let current_id = normalize_commit_id(current);
    let latest_id = normalize_commit_id(release_version);
    if current_id.is_empty() || current_id == "unknown" || latest_id.is_empty() {
        return false;
    }
    current_id != latest_id
}

/// 对已通过 SHA256 校验的临时文件 chmod 并执行 `--version` 核对。
async fn verify_temp_binary_executable(temp_path: &Path, tag_name: &str) -> AppResult<()> {
    std::fs::set_permissions(temp_path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| AppError::context("Failed to chmod temp binary", e))?;

    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(temp_path)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| AppError::message("New binary --version timed out"))?
    .map_err(|e| AppError::context("Failed to run new binary --version", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::message(format!(
            "New binary --version exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout_version_matches_release(&stdout, tag_name) {
        return Err(AppError::message(format!(
            "New binary --version output does not match release {}: {}",
            tag_name,
            stdout.trim()
        )));
    }
    Ok(())
}

fn stdout_version_matches_release(stdout: &str, tag_name: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    if !lower.contains("miao") {
        return false;
    }
    let tag_trim = tag_name.trim();
    let no_v = tag_trim.strip_prefix('v').unwrap_or(tag_trim);
    stdout.contains(tag_trim) || stdout.contains(no_v)
}

pub async fn upgrade_binary(state: &Arc<AppState>) -> AppResult<String> {
    invalidate_release_cache(state).await;
    let release = fetch_latest_release(&state.http_client, state).await?;
    let current = current_version();
    let latest = resolve_latest_version(&state.http_client, &release).await;

    if !release_is_newer_than_current(&current, &latest) {
        return Ok("Already up to date".to_string());
    }

    let asset_name =
        current_arch_asset_name().ok_or_else(|| AppError::message("Unsupported architecture"))?;
    let (binary_asset, _checksum_asset) = find_binary_and_checksum_assets(&release, asset_name)?;
    let binary_url = fixed_download_url(asset_name);
    let checksum_url = format!("{}.sha256", binary_url);

    update_status(state, |s| {
        s.target = latest.clone();
        s.total = binary_asset.size;
    })?;
    stage(
        state,
        "Checking download access and checksum (GitHub, fallback httptunnel.top/gh)",
    )?;
    let expected_hex = fetch_checksum_hex_retried(&state.http_client, &checksum_url).await?;

    let temp_path = get_temp_binary_path();
    let temp_path = Path::new(&temp_path);

    info!(
        from_version = %current,
        to_version = %latest,
        repo = RELEASE_REPO,
        binary_url = %binary_url,
        size_bytes = binary_asset.size,
        "starting upgrade download"
    );

    stage(state, "Downloading binary (GitHub, fallback httptunnel.top/gh)")?;
    download_binary_streaming_retried(
        &state.http_client,
        &binary_url,
        binary_asset.size,
        &expected_hex,
        temp_path,
        state,
    )
    .await?;

    stage(state, "Verifying SHA256 and executable version")?;
    if let Err(e) = verify_temp_binary_executable(temp_path, &latest).await {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(e);
    }

    let current_exe = std::env::current_exe()?;

    stage(state, "Backing up and installing binary")?;
    let backup_path = format!("{}.bak", current_exe.display());
    fs::rename(&current_exe, &backup_path)
        .map_err(|e| AppError::context("Failed to backup current binary", e))?;

    if let Err(e) = fs::copy(temp_path, &current_exe) {
        let _ = fs::rename(&backup_path, &current_exe);
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(AppError::context("Failed to install new binary", e));
    }
    if let Err(e) = fs::set_permissions(&current_exe, fs::Permissions::from_mode(0o755)) {
        let _ = fs::remove_file(&current_exe);
        let _ = fs::rename(&backup_path, &current_exe);
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(AppError::context(
            "Failed to set permissions on new binary",
            e,
        ));
    }
    let _ = tokio::fs::remove_file(temp_path).await;

    info!(
        from_version = %current,
        to_version = %latest,
        "upgrade binary installed; restarting process"
    );

    stage(state, "Stopping sing-box")?;
    stop_sing_internal(state).await;
    if let Err(e) = stage(state, "Restarting") {
        let _ = fs::rename(&backup_path, &current_exe);
        let _ = start_sing_internal(state).await;
        return Err(e);
    }
    let new_version = latest;
    let sing_box_home = get_sing_box_home();
    tokio::spawn(async move {
        sleep(Duration::from_millis(500)).await;

        let files_to_remove = ["sing-box", "chinaip.srs", "chinasite.srs"];
        for file in &files_to_remove {
            let path = sing_box_home.join(file);
            if path.exists() {
                info!("Removing old file: {:?}", path);
                let _ = fs::remove_file(&path);
            }
        }

        let args = crate::auth::restart_args(std::env::args());
        let err = std::process::Command::new(&current_exe)
            .args(&args)
            .exec();

        error!("Failed to exec new binary: {}", err);
        error!("Attempting to restore from backup...");

        if fs::rename(&backup_path, &current_exe).is_ok() {
            let _ = fs::set_permissions(&current_exe, fs::Permissions::from_mode(0o755));
            error!("Restored from backup, restarting with old version...");
            let _ = std::process::Command::new(&current_exe)
                .args(&args)
                .exec();
        }
        let diag = format!(
            "miao upgrade failure: exec and backup restore both failed.\nbinary: {:?}\nbackup: {}\n",
            current_exe, backup_path
        );
        let _ = std::fs::write("/tmp/miao-upgrade-failure.log", &diag);
        error!("Diagnostics written to /tmp/miao-upgrade-failure.log");
        error!("Failed to restore from backup, manual intervention required");
        std::process::exit(1);
    });

    Ok(new_version)
}

fn current_arch_asset_name() -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Some("miao-rust-linux-amd64")
    } else if cfg!(target_arch = "aarch64") {
        Some("miao-rust-linux-arm64")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        current_arch_asset_name, fixed_download_url, normalize_commit_id, parse_sha256sum_line,
        release_is_newer_than_current, release_version_label, stdout_version_matches_release,
        GitHubRelease,
    };

    #[test]
    fn normalize_commit_id_uses_short_prefix() {
        assert_eq!(normalize_commit_id("ABCDEF1234567890"), "abcdef1");
        assert_eq!(normalize_commit_id("commit:abc1234"), "abc1234");
    }

    #[test]
    fn release_version_label_prefers_commitish() {
        let release = GitHubRelease {
            tag_name: "latest".to_string(),
            target_commitish: Some("ABCDEF1234567890".to_string()),
            assets: vec![],
        };
        assert_eq!(release_version_label(&release), "abcdef1");
    }

    #[test]
    fn release_is_newer_than_current_compares_commit_ids() {
        assert!(release_is_newer_than_current("abc1234", "def5678"));
        assert!(!release_is_newer_than_current("ABCDEF1", "abcdef123"));
        assert!(!release_is_newer_than_current("unknown", "def5678"));
    }

    #[test]
    fn parse_sha256sum_line_accepts_gnu_format() {
        let line = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd  miao-rust-linux-amd64";
        let h = parse_sha256sum_line(line).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("abcdabcd"));
    }

    #[test]
    fn parse_sha256sum_line_accepts_star_filename() {
        let line = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd *miao-rust-linux-amd64";
        assert!(parse_sha256sum_line(line).unwrap().starts_with("abcd"));
    }

    #[test]
    fn stdout_version_matches_release_requires_miao_and_tag_or_version() {
        assert!(stdout_version_matches_release("miao abc1234\n", "abc1234"));
        assert!(stdout_version_matches_release(
            "miao-rust abc1234\n",
            "abc1234"
        ));
        assert!(!stdout_version_matches_release(
            "other abc1234\n",
            "abc1234"
        ));
    }

    #[test]
    fn fixed_download_url_uses_latest_tag() {
        assert_eq!(
            fixed_download_url("miao-rust-linux-amd64"),
            "https://github.com/iVnc-Org/miao/releases/download/latest/miao-rust-linux-amd64"
        );
        assert_eq!(
            fixed_download_url("miao-rust-linux-arm64"),
            "https://github.com/iVnc-Org/miao/releases/download/latest/miao-rust-linux-arm64"
        );
    }

    #[test]
    fn current_arch_asset_name_matches_supported_targets() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(current_arch_asset_name(), Some("miao-rust-linux-amd64"));
        } else if cfg!(target_arch = "aarch64") {
            assert_eq!(current_arch_asset_name(), Some("miao-rust-linux-arm64"));
        } else {
            assert_eq!(current_arch_asset_name(), None);
        }
    }
    #[tokio::test]
    async fn inaccessible_resource_uses_proxy_and_preserves_full_url() {
        use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/binary", get(|| async { StatusCode::FORBIDDEN }))
            .fallback(|uri: axum::http::Uri| async move {
                if uri.path().starts_with("/gh/http://127.0.0.1:") {
                    (StatusCode::OK, "proxied binary").into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = super::accessible_get_with_proxy(
            &reqwest::Client::new(),
            &format!("{base}/binary"),
            &format!("{base}/gh/"),
        )
        .await
        .unwrap();
        assert_eq!(response.text().await.unwrap(), "proxied binary");
        server.abort();
    }

    #[tokio::test]
    async fn refresh_recovers_persisted_progress_and_detects_interruption() {
        use std::sync::atomic::Ordering;
        let state = crate::test_support::app_state(crate::models::Config::default());
        state.initializing.store(false, Ordering::SeqCst);
        state.upgrading.store(true, Ordering::SeqCst);
        super::update_status(&state, |s| {
            s.id = "job-1".into();
            s.active = true;
            s.stage = "Downloading".into();
            s.downloaded = 1024;
            s.total = 2048;
        })
        .unwrap();
        let status = super::upgrade_status(&state).await.unwrap();
        assert!(status.active);
        assert_eq!(status.downloaded, 1024);
        assert!(super::start_upgrade(state.clone()).is_err());
        // A fresh process loads the same file, but has no live download task.
        let restarted = std::sync::Arc::new(
            crate::state::AppState::with_config_path(
                crate::models::Config::default(),
                state.config_path.clone(),
            )
            .unwrap(),
        );
        restarted.initializing.store(false, Ordering::SeqCst);
        let status = super::upgrade_status(&restarted).await.unwrap();
        assert!(!status.active);
        assert!(status.stage.contains("interrupted"));
        std::fs::remove_file(super::status_path(&state)).unwrap();
    }

    #[tokio::test]
    async fn download_validates_bytes_and_rejects_corruption() {
        use axum::{routing::get, Router};
        use sha2::{Digest, Sha256};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/binary", listener.local_addr().unwrap());
        let app = Router::new().route("/binary", get(|| async { "binary data" }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = crate::test_support::app_state(crate::models::Config::default());
        let path = state.config_path.with_extension("binary");
        let checksum = hex::encode(Sha256::digest(b"binary data"));
        super::download_binary_streaming_once(
            &reqwest::Client::new(),
            &url,
            11,
            &checksum,
            &path,
            &state,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"binary data");
        let status: super::UpgradeStatus =
            serde_json::from_slice(&std::fs::read(super::status_path(&state)).unwrap()).unwrap();
        assert_eq!(status.downloaded, 11);
        let result = super::download_binary_streaming_once(
            &reqwest::Client::new(),
            &url,
            11,
            &"0".repeat(64),
            &path,
            &state,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("SHA256 mismatch"));
        assert!(!path.exists());
        std::fs::remove_file(super::status_path(&state)).unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn matching_version_without_healthy_core_is_not_success() {
        use std::sync::atomic::Ordering;
        let state = crate::test_support::app_state(crate::models::Config::default());
        state.initializing.store(false, Ordering::SeqCst);
        super::update_status(&state, |s| {
            s.active = true;
            s.stage = "Restarting".into();
            s.target = crate::build_info::current_version();
        })
        .unwrap();
        let status = super::upgrade_status(&state).await.unwrap();
        assert!(!status.active);
        assert!(status.stage.contains("recovery failed"));
        std::fs::remove_file(super::status_path(&state)).unwrap();
    }
    #[tokio::test]
    async fn upgrade_does_not_start_during_vps_deployment() {
        use super::start_upgrade;
        use std::sync::atomic::Ordering;
        let state = crate::test_support::app_state(crate::models::Config::default());
        state.initializing.store(false, Ordering::SeqCst);
        state.vps_active.store(true, Ordering::SeqCst);
        let error = start_upgrade(state.clone())
            .err().expect("deployment must block upgrade");
        assert!(error.to_string().contains("VPS deployment"));
        assert!(!state.upgrading.load(Ordering::SeqCst));
    }
}
