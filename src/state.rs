use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

use crate::models::{Config, GitHubRelease, SubStatus};

/// 应用状态容器 - 包含所有运行时状态
/// 通过依赖注入传递，避免全局静态变量
pub struct AppState {
    pub embedded: bool,
    pub auth: crate::auth::Auth,
    pub config: RwLock<Config>, // 使用 RwLock 支持并发读
    pub config_path: PathBuf,
    pub config_update: Mutex<()>,
    pub sing_process: Mutex<Option<SingBoxProcess>>,
    pub sub_status: Mutex<HashMap<String, SubStatus>>,
    pub config_warning: Mutex<Option<String>>,
    pub config_source: Mutex<Option<String>>,
    pub initializing: AtomicBool,
    pub http_client: reqwest::Client,
    pub version_cache: ArcSwap<VersionCache>, // 使用 ArcSwap 实现无锁读取
    pub shutting_down: AtomicBool,
    pub vps_active: AtomicBool,
    /// A web action supersedes this process's one-time CLI startup intent.
    pub startup_cancelled: AtomicBool,
    pub vps_progress: tokio::sync::broadcast::Sender<crate::services::vps::Job>,
    pub upgrading: AtomicBool, // 防止并发升级
    pub upgrade_attempt: AtomicU64,
    /// `Some(attempt)` asks that attempt to stop before installation.
    pub upgrade_cancel: StdMutex<Option<u64>>,
}

impl AppState {
    /// 创建新的应用状态实例
    #[cfg(test)]
    pub fn new(config: Config) -> Result<Self, reqwest::Error> {
        Self::with_config_path(config, PathBuf::from("config.yaml"))
    }

    pub fn with_config_path(config: Config, config_path: PathBuf) -> Result<Self, reqwest::Error> {
        Self::with_embedding(config, config_path, false)
    }

    pub fn with_embedding(
        config: Config,
        config_path: PathBuf,
        embedded: bool,
    ) -> Result<Self, reqwest::Error> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            embedded,
            auth: crate::auth::Auth::default(),
            config: RwLock::new(config),
            config_path,
            config_update: Mutex::new(()),
            sing_process: Mutex::new(None),
            sub_status: Mutex::new(HashMap::new()),
            config_warning: Mutex::new(None),
            config_source: Mutex::new(None),
            initializing: AtomicBool::new(true),
            http_client,
            version_cache: ArcSwap::new(Arc::new(VersionCache {
                release: None,
                fetched_at: None,
            })),
            shutting_down: AtomicBool::new(false),
            vps_active: AtomicBool::new(false),
            startup_cancelled: AtomicBool::new(false),
            vps_progress: tokio::sync::broadcast::channel(128).0,
            upgrading: AtomicBool::new(false),
            upgrade_attempt: AtomicU64::new(0),
            upgrade_cancel: StdMutex::new(None),
        })
    }
}

pub struct SingBoxProcess {
    pub child: tokio::process::Child,
    pub started_at: Instant,
}

/// 版本信息缓存
#[derive(Clone)]
pub struct VersionCache {
    pub release: Option<GitHubRelease>,
    pub fetched_at: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_new_creates_valid_instance() {
        let config = Config {
            port: Some(8080),
            socks_port: Some(1080),
            subs: vec!["https://example.com/sub".to_string()],
            ..Default::default()
        };

        let state = AppState::new(config.clone()).unwrap();

        // 验证状态正确初始化
        assert!(state
            .initializing
            .load(std::sync::atomic::Ordering::Relaxed));

        // 验证配置被正确存储
        let locked_config = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { state.config.read().await.clone() });
        assert_eq!(locked_config.port, Some(8080));
        assert_eq!(locked_config.subs.len(), 1);
        assert_eq!(state.config_path, PathBuf::from("config.yaml"));
    }

    #[test]
    fn version_cache_starts_empty() {
        let config = Config::default();

        let state = AppState::new(config).unwrap();
        let cache = state.version_cache.load();

        assert!(cache.release.is_none());
        assert!(cache.fetched_at.is_none());
    }
}
