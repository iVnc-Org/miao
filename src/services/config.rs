use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::error::{AppError, AppResult};
use crate::models::{
    BypassAction, Config, NodeInfo, ProcessListMode, ProcessMatch, ProcessProxyConfig, ProxyMode,
    DEFAULT_SOCKS_LISTEN, DEFAULT_SOCKS_PORT,
};
use crate::paths::{data_dir, data_file};
use crate::services::{
    proxy::restore_last_proxy,
    share_ports::{
        allocate_share_ports, load_share_port_map, reserved_system_ports, save_share_port_map,
        share_inbound_tag, SharePortMap,
    },
    singbox::{
        get_sing_box_home, sing_box_is_running, start_sing_internal, stop_sing_internal,
        validate_sing_box_config,
    },
    sub_nodes::{
        hydrate_sub_status, load_sub_nodes, save_sub_nodes, StoredNode, SubNodeStore,
    },
    subscription::fetch_sub,
    write_file_atomic,
};
use crate::state::AppState;

const CONFIG_CACHE_FILE: &str = "config.json";
const CONFIG_CACHE_META_FILE: &str = "config.meta.json";
const CONFIG_CACHE_SCHEMA_VERSION: u32 = 7;
const MAX_CONCURRENT_SUBS: usize = 5;

#[derive(Serialize, Deserialize)]
struct ConfigCacheMeta {
    fingerprint: String,
}

pub fn get_config_cache_path() -> PathBuf {
    data_file(CONFIG_CACHE_FILE)
}

fn get_config_cache_meta_path() -> PathBuf {
    data_file(CONFIG_CACHE_META_FILE)
}

fn config_cache_fingerprint(config: &Config) -> AppResult<String> {
    let value = serde_json::json!({
        "schema_version": CONFIG_CACHE_SCHEMA_VERSION,
        "socks_listen": &config.socks_listen,
        "socks_port": config.socks_port,
        "mode": &config.mode,
        "subs": &config.subs,
        "nodes": &config.nodes,
        "custom_rules": &config.custom_rules,
        "tun_process": &config.tun_process,
        "share": &config.share,
    });
    let bytes = serde_json::to_vec(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn normalize_cached_sing_box_config(mut config: serde_json::Value) -> serde_json::Value {
    if config["route"]["default_domain_resolver"] == "cfdns" {
        config["route"]["default_domain_resolver"] = serde_json::Value::String("local".to_string());
    }
    config
}

pub async fn save_config_to(path: &Path, config: &Config) -> AppResult<()> {
    let yaml = serde_yaml::to_string(config)?;
    if let Ok(existing) = tokio::fs::read_to_string(path).await {
        if existing == yaml {
            info!(config_path = ?path, "Config file already up to date, skipping write");
            return Ok(());
        }
    }

    write_file_atomic(path, &yaml, "config file").await
}

pub async fn save_config_cache(config: &Config) {
    let config_path = get_sing_box_home().join("config.json");
    let cache_path = get_config_cache_path();
    let meta_path = get_config_cache_meta_path();

    if let Err(e) = tokio::fs::create_dir_all(data_dir()).await {
        error!("Failed to create config cache directory: {}", e);
        return;
    }

    if let Err(e) = tokio::fs::copy(&config_path, &cache_path).await {
        error!("Failed to save config cache: {}", e);
        return;
    }

    let meta = match config_cache_fingerprint(config)
        .map(|fingerprint| ConfigCacheMeta { fingerprint })
        .and_then(|meta| serde_json::to_string(&meta).map_err(AppError::from))
    {
        Ok(meta) => meta,
        Err(e) => {
            error!("Failed to build config cache metadata: {}", e);
            return;
        }
    };

    if let Err(e) = write_file_atomic(&meta_path, &meta, "config cache meta").await {
        error!("Failed to save config cache metadata: {}", e);
        return;
    }

    info!(cache = ?cache_path, "Config cache saved");
}

async fn clear_generated_config_state() {
    for path in [
        get_sing_box_home().join("config.json"),
        get_config_cache_path(),
        get_config_cache_meta_path(),
    ] {
        let _ = tokio::fs::remove_file(path).await;
    }
}

async fn restore_subscription_nodes(snapshot: &SubNodeStore) -> AppResult<()> {
    if load_sub_nodes().await != *snapshot {
        save_sub_nodes(snapshot).await?;
    }
    Ok(())
}

async fn apply_no_node_config(
    state: &Arc<AppState>,
    old_config: &Config,
    new_config: Config,
    previous_sub_nodes: &SubNodeStore,
    stop_runtime: bool,
) -> AppResult<()> {
    let mut retained_sub_nodes = previous_sub_nodes.clone();
    retained_sub_nodes.retain_urls(&new_config.subs);
    if retained_sub_nodes != *previous_sub_nodes {
        save_sub_nodes(&retained_sub_nodes).await?;
    }

    if let Err(save_error) = save_config_to(&state.config_path, &new_config).await {
        let restore_error = restore_subscription_nodes(previous_sub_nodes).await.err();
        hydrate_sub_status(state, &old_config.subs).await;
        return match restore_error {
            None => Err(AppError::context(
                "Failed to persist config change; restored subscription cache",
                save_error,
            )),
            Some(restore_error) => Err(AppError::message(format!(
                "Failed to persist config change: {}. Subscription cache rollback failed: {}",
                save_error, restore_error
            ))),
        };
    }

    if stop_runtime {
        stop_sing_internal(state).await;
    }
    clear_generated_config_state().await;
    {
        let mut status_map = state.sub_status.lock().await;
        status_map.retain(|url, _| new_config.subs.contains(url));
    }
    *state.config.write().await = new_config;
    *state.config_source.lock().await = None;
    *state.config_warning.lock().await = None;
    Ok(())
}

pub async fn restore_config_from_cache(config: &Config) -> AppResult<()> {
    let cache = get_config_cache_path();
    if !cache.exists() {
        return Err(AppError::message("No cached config available"));
    }

    let meta_path = get_config_cache_meta_path();
    let meta_content = tokio::fs::read_to_string(&meta_path)
        .await
        .map_err(|e| AppError::context("No cache metadata available", e))?;
    let meta: ConfigCacheMeta = serde_json::from_str(&meta_content)
        .map_err(|e| AppError::context("Failed to parse cache metadata", e))?;
    let current_fingerprint = config_cache_fingerprint(config)?;
    if meta.fingerprint != current_fingerprint {
        return Err(AppError::message(
            "Cached config does not match current configuration",
        ));
    }

    let cached_config = tokio::fs::read_to_string(&cache)
        .await
        .map_err(|e| AppError::context("Failed to read cached config", e))?;
    let cached_config: serde_json::Value = serde_json::from_str(&cached_config)
        .map_err(|e| AppError::context("Failed to parse cached config", e))?;
    let cached_config = normalize_cached_sing_box_config(cached_config);
    let cached_config = serde_json::to_string(&cached_config)?;

    let config_path = get_sing_box_home().join("config.json");
    write_file_atomic(&config_path, &cached_config, "sing-box config")
        .await
        .map_err(|e| AppError::context("Failed to restore config from cache", e))?;
    validate_sing_box_config()
        .await
        .map_err(|e| AppError::context("Cached config validation failed", e))?;
    write_file_atomic(&cache, &cached_config, "config cache")
        .await
        .map_err(|e| AppError::context("Failed to update normalized config cache", e))?;
    info!(cache = ?cache, "Restored config from cache");
    Ok(())
}

pub async fn regenerate_and_restart_runtime(
    config: &Config,
    state: &Arc<AppState>,
    policy: SubFetchPolicy,
) -> AppResult<GenOutcome> {
    let outcome = gen_config(config, state, policy)
        .await
        .map_err(|e| AppError::context("Failed to regenerate config", e))?;
    info!("Config regenerated successfully");

    validate_sing_box_config()
        .await
        .map_err(|e| AppError::context("Config validation failed, not restarting", e))?;

    stop_sing_internal(state).await;

    start_sing_internal(state)
        .await
        .map_err(|e| AppError::context("Failed to restart sing-box", e))?;
    info!("sing-box restarted successfully");

    Ok(outcome)
}

/// 用户显式点击"刷新订阅"。这是少数几条允许联网的路径之一。
pub async fn regenerate_and_restart(
    config: &Config,
    state: &Arc<AppState>,
) -> AppResult<GenOutcome> {
    let outcome = regenerate_and_restart_runtime(config, state, SubFetchPolicy::FetchAll).await?;

    finalize_started_config(config, state, &outcome).await;

    Ok(outcome)
}

pub async fn finalize_started_config(config: &Config, state: &Arc<AppState>, outcome: &GenOutcome) {
    update_config_warning(config, state, outcome).await;

    let state_for_proxy = state.clone();
    tokio::spawn(async move {
        restore_last_proxy(&state_for_proxy).await;
    });
}

async fn update_config_warning(config: &Config, state: &Arc<AppState>, outcome: &GenOutcome) {
    *state.config_source.lock().await = Some("generated".to_string());

    if outcome.has_sub_nodes() || config.subs.is_empty() {
        save_config_cache(config).await;
    }

    // 只有"一个节点都没有"才是需要用户处理的状态。链接失效但仍有缓存节点
    // 是常态（链接本就只有几分钟有效期），不能报成告警——前端会把 warning
    // 渲染成红色 toast。失效状态只体现在订阅行上。
    let warning = if outcome.has_sub_nodes() || config.subs.is_empty() {
        None
    } else {
        Some("订阅节点缓存为空，请点击刷新订阅".to_string())
    };
    *state.config_warning.lock().await = warning;
}

pub async fn regenerate_without_restart_runtime(
    config: &Config,
    state: &Arc<AppState>,
    policy: SubFetchPolicy,
) -> AppResult<GenOutcome> {
    let outcome = gen_config(config, state, policy)
        .await
        .map_err(|e| AppError::context("Failed to regenerate config", e))?;
    info!("Config regenerated successfully");

    validate_sing_box_config()
        .await
        .map_err(|e| AppError::context("Config validation failed", e))?;

    Ok(outcome)
}

pub(crate) async fn read_existing_sing_box_config() -> AppResult<serde_json::Value> {
    let config_path = get_sing_box_home().join("config.json");
    let source_path = if config_path.exists() {
        config_path
    } else {
        get_config_cache_path()
    };

    let content = tokio::fs::read_to_string(&source_path)
        .await
        .map_err(|e| AppError::context("Failed to read existing sing-box config", e))?;
    serde_json::from_str(&content)
        .map(normalize_cached_sing_box_config)
        .map_err(|e| AppError::context("Failed to parse existing sing-box config", e))
}

/// 从已生成的 sing-box 配置里读回 (节点 tag, 分享端口)。
///
/// 已部署的配置才是"实际在监听什么"的唯一真相；`SharePortMap` 只是分配账本。
pub(crate) fn extract_share_bindings_from_sing_box(
    sing_box_config: &serde_json::Value,
) -> Vec<(String, u16)> {
    let mut bindings = Vec::new();
    let Some(rules) = sing_box_config["route"]["rules"].as_array() else {
        return bindings;
    };

    for rule in rules {
        let Some(inbounds) = rule.get("inbound").and_then(|v| v.as_array()) else {
            continue;
        };
        if inbounds.len() != 1 {
            continue;
        }
        let Some(inbound) = inbounds[0].as_str() else {
            continue;
        };
        let Some(port_str) = inbound.strip_prefix("share-") else {
            continue;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        let Some(outbound) = rule.get("outbound").and_then(|v| v.as_str()) else {
            continue;
        };
        bindings.push((outbound.to_string(), port));
    }

    bindings
}

pub async fn apply_config_change(
    state: &Arc<AppState>,
    old_config: &Config,
    new_config: &Config,
    policy: SubFetchPolicy,
) -> AppResult<()> {
    let persisted_new_config = new_config.clone();
    let previous_sub_nodes = load_sub_nodes().await;

    if config_has_no_nodes(new_config) {
        return apply_no_node_config(
            state,
            old_config,
            persisted_new_config,
            &previous_sub_nodes,
            true,
        )
        .await;
    }

    match regenerate_and_restart_runtime(new_config, state, policy).await {
        Ok(outcome) => match save_config_to(&state.config_path, &persisted_new_config).await {
            Ok(()) => {
                *state.config.write().await = persisted_new_config;
                finalize_started_config(new_config, state, &outcome).await;
                Ok(())
            }
            Err(save_err) => {
                error!(error = %save_err, "Runtime config applied but persistent config write failed, attempting runtime rollback");
                let store_restore_error = restore_subscription_nodes(&previous_sub_nodes)
                    .await
                    .err()
                    .map(|error| error.to_string());
                match restart_with_previous_config(old_config, state).await {
                    Ok(()) if store_restore_error.is_none() => Err(AppError::context(
                        "Failed to persist config change; restored previous runtime config",
                        save_err,
                    )),
                    Ok(()) => Err(AppError::message(format!(
                        "Failed to persist config change: {}. Runtime rollback succeeded, but subscription cache rollback failed: {}",
                        save_err,
                        store_restore_error.unwrap()
                    ))),
                    Err(rollback_err) => Err(AppError::message(format!(
                        "Failed to persist config change: {}. Runtime rollback failed: {}{}",
                        save_err,
                        rollback_err,
                        store_restore_error
                            .map(|error| format!(". Subscription cache rollback failed: {error}"))
                            .unwrap_or_default()
                    ))),
                }
            }
        },
        Err(apply_err) => {
            error!(error = %apply_err, "Failed to apply runtime config change, attempting runtime rollback");
            let store_restore_error = restore_subscription_nodes(&previous_sub_nodes)
                .await
                .err()
                .map(|error| error.to_string());
            match restore_previous_running_config(old_config, state).await {
                Ok(()) if store_restore_error.is_none() => Err(AppError::context(
                    "Failed to apply config change; restored previous runtime config",
                    apply_err,
                )),
                Ok(()) => Err(AppError::message(format!(
                    "Failed to apply config change: {}. Runtime rollback succeeded, but subscription cache rollback failed: {}",
                    apply_err,
                    store_restore_error.unwrap()
                ))),
                Err(rollback_err) => Err(AppError::message(format!(
                    "Failed to apply config change: {}. Runtime rollback failed: {}{}",
                    apply_err,
                    rollback_err,
                    store_restore_error
                        .map(|error| format!(". Subscription cache rollback failed: {error}"))
                        .unwrap_or_default()
                ))),
            }
        }
    }
}

pub async fn apply_persistent_config_change(
    state: &Arc<AppState>,
    old_config: &Config,
    new_config: &Config,
    restart_if_running: bool,
    policy: SubFetchPolicy,
) -> AppResult<()> {
    if restart_if_running {
        return apply_config_change(state, old_config, new_config, policy).await;
    }

    let persisted_new_config = new_config.clone();
    let previous_sub_nodes = load_sub_nodes().await;

    if config_has_no_nodes(new_config) {
        return apply_no_node_config(
            state,
            old_config,
            persisted_new_config,
            &previous_sub_nodes,
            false,
        )
        .await;
    }

    match regenerate_without_restart_runtime(new_config, state, policy).await {
        Ok(outcome) => match save_config_to(&state.config_path, &persisted_new_config).await {
            Ok(()) => {
                *state.config.write().await = persisted_new_config;
                update_config_warning(new_config, state, &outcome).await;
                Ok(())
            }
            Err(save_err) => {
                let store_restore = restore_subscription_nodes(&previous_sub_nodes).await;
                let _ = restore_previous_stopped_config(old_config, state).await;
                match store_restore {
                    Ok(()) => Err(AppError::context(
                        "Failed to persist config change; restored previous stopped config",
                        save_err,
                    )),
                    Err(store_err) => Err(AppError::message(format!(
                        "Failed to persist config change: {}. Subscription cache rollback failed: {}",
                        save_err, store_err
                    ))),
                }
            }
        },
        Err(apply_err) => {
            let store_restore = restore_subscription_nodes(&previous_sub_nodes).await;
            let _ = restore_previous_stopped_config(old_config, state).await;
            match store_restore {
                Ok(()) => Err(AppError::context(
                    "Failed to apply config change; restored previous stopped config",
                    apply_err,
                )),
                Err(store_err) => Err(AppError::message(format!(
                    "Failed to apply config change: {}. Subscription cache rollback failed: {}",
                    apply_err, store_err
                ))),
            }
        }
    }
}

fn config_has_no_nodes(config: &Config) -> bool {
    config.subs.is_empty() && config.nodes.is_empty()
}

/// 回滚路径。**故意不接受 policy 参数**：回滚时联网抓订阅是灾难性的——
/// 一次失效期内的失败变更会因为抓不到订阅而彻底恢复不了，最终让 sing-box
/// 停在无配置状态。这三个函数一律只用本地缓存。
async fn restore_previous_running_config(
    old_config: &Config,
    state: &Arc<AppState>,
) -> AppResult<()> {
    if sing_box_is_running(state).await {
        match restore_config_from_cache(old_config).await {
            Ok(()) => {}
            Err(cache_err) => {
                warn!(error = %cache_err, "Failed to restore runtime config from cache while previous sing-box process is still running");
                let outcome = regenerate_without_restart_runtime(
                    old_config,
                    state,
                    SubFetchPolicy::CacheOnly,
                )
                .await?;
                update_config_warning(old_config, state, &outcome).await;
            }
        }
        hydrate_sub_status(state, &old_config.subs).await;
        return Ok(());
    }

    restart_with_previous_config(old_config, state).await
}

async fn restart_with_previous_config(old_config: &Config, state: &Arc<AppState>) -> AppResult<()> {
    stop_sing_internal(state).await;

    if let Err(cache_err) = restore_config_from_cache(old_config).await {
        warn!(error = %cache_err, "Failed to restore runtime config from cache for rollback; regenerating previous config");
    } else {
        match start_sing_internal(state).await {
            Ok(()) => {
                let store = load_sub_nodes().await;
                let outcome = gen_outcome_from_store(old_config, &store);
                finalize_started_config(old_config, state, &outcome).await;
                hydrate_sub_status(state, &old_config.subs).await;
                return Ok(());
            }
            Err(start_err) => {
                warn!(error = %start_err, "Failed to restart sing-box from cached config; regenerating previous config");
            }
        }
    }

    let outcome =
        regenerate_without_restart_runtime(old_config, state, SubFetchPolicy::CacheOnly).await?;
    start_sing_internal(state)
        .await
        .map_err(|e| AppError::context("Failed to restart sing-box with previous config", e))?;
    finalize_started_config(old_config, state, &outcome).await;
    Ok(())
}

async fn restore_previous_stopped_config(
    old_config: &Config,
    state: &Arc<AppState>,
) -> AppResult<()> {
    let outcome =
        regenerate_without_restart_runtime(old_config, state, SubFetchPolicy::CacheOnly).await?;
    update_config_warning(old_config, state, &outcome).await;
    Ok(())
}

/// 什么时候允许联网抓订阅。
///
/// 订阅链接常常只有几分钟有效期，所以"顺手刷新一下"不是善意而是破坏：抓取必然失败，
/// 而失败会连锁触发回滚。默认一律走本地缓存，只有用户明确要求时才联网。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubFetchPolicy {
    /// 永不联网。除下面三种情形外的所有路径都用这个。
    CacheOnly,
    /// 仅当缓存里一个节点都没有时抓一次（首装、用户删了 ~/.miao、缓存 schema 升级）。
    /// 这是唯一无需用户手势即可联网的路径。
    CacheOrBootstrap,
    /// 只抓指定的订阅，其余读缓存。用于"新增订阅"。
    FetchOnly(Vec<String>),
    /// 抓取全部。仅由用户点击"刷新订阅"触发。
    FetchAll,
}

impl SubFetchPolicy {
    fn urls_to_fetch(&self, store: &SubNodeStore, subs: &[String]) -> Vec<String> {
        match self {
            SubFetchPolicy::CacheOnly => Vec::new(),
            SubFetchPolicy::CacheOrBootstrap => {
                if store.is_empty_for(subs) {
                    subs.to_vec()
                } else {
                    Vec::new()
                }
            }
            SubFetchPolicy::FetchOnly(urls) => {
                subs.iter().filter(|u| urls.contains(u)).cloned().collect()
            }
            SubFetchPolicy::FetchAll => subs.to_vec(),
        }
    }
}

/// 一次配置生成的结果。
pub struct GenOutcome {
    /// 订阅节点总数（含缓存命中的）。
    pub sub_nodes: usize,
    /// 至少有一个订阅处于失效状态。用于展示，不作为错误。
    pub any_expired: bool,
}

impl GenOutcome {
    pub fn has_sub_nodes(&self) -> bool {
        self.sub_nodes > 0
    }
}

fn gen_outcome_from_store(config: &Config, store: &SubNodeStore) -> GenOutcome {
    GenOutcome {
        sub_nodes: config.subs.iter().map(|url| store.node_count(url)).sum(),
        any_expired: config
            .subs
            .iter()
            .any(|url| store.subs.get(url).is_some_and(|entry| entry.stale)),
    }
}

async fn fetch_subscriptions(
    urls: &[String],
    state: &Arc<AppState>,
) -> Vec<(
    String,
    Result<crate::services::subscription::FetchResult, String>,
)> {
    let sub_futures: Vec<_> = urls
        .iter()
        .map(|sub| {
            let sub = sub.clone();
            let client = state.http_client.clone();
            async move {
                info!(url = %sub, "Fetching subscription");
                let result =
                    tokio::time::timeout(Duration::from_secs(30), fetch_sub(&sub, &client)).await;

                match result {
                    Ok(Ok(fetch_result)) => {
                        let valid_count = fetch_result.node_names.len();
                        let total_count = fetch_result.total_count;
                        let error_count = fetch_result.parse_errors.len();

                        if error_count > 0 {
                            warn!(
                                url = %sub,
                                valid = valid_count,
                                total = total_count,
                                errors = error_count,
                                "Partial fetch: some nodes failed to parse"
                            );
                        } else {
                            info!(
                                url = %sub,
                                nodes = valid_count,
                                "Subscription fetched successfully"
                            );
                        }

                        (sub.clone(), Ok(fetch_result))
                    }
                    Ok(Err(e)) => {
                        warn!(url = %sub, error = %e, "Subscription fetch failed, keeping cached nodes");
                        (sub.clone(), Err(e.to_string()))
                    }
                    Err(_) => {
                        warn!(url = %sub, timeout_secs = 30, "Subscription fetch timed out, keeping cached nodes");
                        (sub.clone(), Err("Request timeout".to_string()))
                    }
                }
            }
        })
        .collect();

    // 限制并发，避免同时发起过多请求。
    stream::iter(sub_futures)
        .buffer_unordered(MAX_CONCURRENT_SUBS)
        .collect()
        .await
}

pub(crate) struct FetchedSubscriptionNodes {
    pub nodes: Vec<StoredNode>,
    pub fetched_at: String,
    pub parse_warning: Option<String>,
}

pub(crate) async fn fetch_subscription_nodes(
    url: &str,
    state: &Arc<AppState>,
) -> AppResult<FetchedSubscriptionNodes> {
    let mut results = fetch_subscriptions(&[url.to_string()], state).await;
    let (_, result) = results
        .pop()
        .ok_or_else(|| AppError::message("Subscription fetch returned no result"))?;
    let fetch_result = result.map_err(AppError::message)?;
    if fetch_result.node_names.is_empty() {
        return Err(AppError::message("Subscription returned no nodes"));
    }

    let parse_warning = if fetch_result.parse_errors.is_empty() {
        None
    } else {
        Some(format!(
            "{} nodes skipped due to parse errors",
            fetch_result.parse_errors.len()
        ))
    };
    let nodes = fetch_result
        .node_names
        .into_iter()
        .zip(fetch_result.outbounds)
        .map(|(name, outbound)| StoredNode { name, outbound })
        .collect();

    Ok(FetchedSubscriptionNodes {
        nodes,
        fetched_at: now_rfc3339(),
        parse_warning,
    })
}

fn extract_legacy_subscription_nodes(
    config: &Config,
    sing_box_config: &serde_json::Value,
) -> Vec<StoredNode> {
    let Some(outbounds) = sing_box_config.get("outbounds").and_then(|value| value.as_array()) else {
        return Vec::new();
    };
    let Some(selector) = outbounds.iter().find(|outbound| {
        outbound.get("type").and_then(|value| value.as_str()) == Some("selector")
            && outbound.get("tag").and_then(|value| value.as_str()) == Some("proxy")
    }) else {
        return Vec::new();
    };
    let Some(selector_tags) = selector.get("outbounds").and_then(|value| value.as_array()) else {
        return Vec::new();
    };

    let (manual_outbounds, manual_names) = collect_manual_outbounds(config);
    let (manual_names, _) = normalize_outbound_tags(manual_names, manual_outbounds);
    let selector_names: Vec<&str> = selector_tags.iter().filter_map(|tag| tag.as_str()).collect();
    if selector_names.len() < manual_names.len()
        || selector_names[..manual_names.len()]
            .iter()
            .copied()
            .ne(manual_names.iter().map(String::as_str))
    {
        warn!("Legacy config cache does not match current manual nodes; skipping subscription node import");
        return Vec::new();
    }

    selector_names[manual_names.len()..]
        .iter()
        .filter_map(|tag| {
            outbounds
                .iter()
                .find(|outbound| outbound.get("tag").and_then(|value| value.as_str()) == Some(*tag))
                .cloned()
                .map(|outbound| StoredNode {
                    name: (*tag).to_string(),
                    outbound,
                })
        })
        .collect()
}

pub async fn migrate_legacy_subscription_nodes(config: &Config) -> AppResult<bool> {
    if config.subs.is_empty() {
        return Ok(false);
    }

    let mut store = load_sub_nodes().await;
    if !store.is_empty_for(&config.subs) {
        return Ok(false);
    }

    let cache_path = get_config_cache_path();
    let cached = match tokio::fs::read_to_string(&cache_path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            warn!(path = ?cache_path, error = %error, "Failed to read legacy config cache for subscription node import");
            return Ok(false);
        }
    };
    let cached: serde_json::Value = match serde_json::from_str(&cached) {
        Ok(value) => value,
        Err(error) => {
            warn!(path = ?cache_path, error = %error, "Failed to parse legacy config cache for subscription node import");
            return Ok(false);
        }
    };
    let nodes = extract_legacy_subscription_nodes(config, &cached);
    if nodes.is_empty() {
        return Ok(false);
    }

    let url = &config.subs[0];
    let node_count = nodes.len();
    store.record_success(url, nodes, None);
    save_sub_nodes(&store).await?;
    info!(url = %url, nodes = node_count, "Imported subscription nodes from legacy config cache");
    Ok(true)
}

pub async fn gen_config(
    config: &Config,
    state: &Arc<AppState>,
    policy: SubFetchPolicy,
) -> AppResult<GenOutcome> {
    let (my_outbounds, my_names) = collect_manual_outbounds(config);

    migrate_legacy_subscription_nodes(config).await?;
    let mut store = load_sub_nodes().await;
    let store_before = store.clone();
    // 订阅被删掉时，它的节点也要跟着走——这一步不需要联网。
    store.retain_urls(&config.subs);

    let to_fetch = policy.urls_to_fetch(&store, &config.subs);
    if to_fetch.is_empty() {
        info!(
            subs = config.subs.len(),
            "Using cached subscription nodes, not fetching"
        );
    }

    // 本轮节点列表是否完整——决定分享端口账本能不能回收失效条目。
    //
    // 判定刻意保守：抓取失败、解析丢节点、以及"订阅返回了 0 个节点"都算不完整。
    // 最后一条是必须的：机场限额/过期时经常返回 HTTP 200 + 一个错误 JSON，
    // 解析得到零节点且零错误，看起来和"订阅确实空了"一模一样。
    // 两种误判的代价不对等——误判成不完整只会让账本多留几条废记录（真装满了
    // 会在分配时明确报错），误判成完整则会把用户已经分发出去的端口收走。
    let mut node_list_is_complete = true;
    let mut fetch_errors: std::collections::HashMap<String, Option<String>> = Default::default();

    let results = fetch_subscriptions(&to_fetch, state).await;
    for (url, result) in results {
        match result {
            Ok(fetch_result) => {
                let count = fetch_result.node_names.len();
                if count == 0 {
                    // 抓到了但一个节点都没有：多半是限额/过期返回的错误页。
                    // 当成失败处理，保留缓存里的节点。
                    node_list_is_complete = false;
                    store.record_failure(&url, "Subscription returned no nodes".to_string());
                    fetch_errors.insert(url, None);
                    continue;
                }

                if !fetch_result.parse_errors.is_empty() {
                    node_list_is_complete = false;
                    fetch_errors.insert(
                        url.clone(),
                        Some(format!(
                            "{} nodes skipped due to parse errors",
                            fetch_result.parse_errors.len()
                        )),
                    );
                } else {
                    fetch_errors.insert(url.clone(), None);
                }

                let nodes = fetch_result
                    .node_names
                    .into_iter()
                    .zip(fetch_result.outbounds)
                    .map(|(name, outbound)| StoredNode { name, outbound })
                    .collect();
                store.record_success(&url, nodes, Some(now_rfc3339()));
            }
            Err(e) => {
                // 关键：不动已有节点。链接失效不该让用户失去已经拿到的节点。
                node_list_is_complete = false;
                store.record_failure(&url, e);
                fetch_errors.insert(url, None);
            }
        }
    }

    // 任何一个订阅还没有缓存条目，也算列表不完整。
    if config
        .subs
        .iter()
        .any(|url| store.node_count(url) == 0 || store.subs.get(url).is_some_and(|e| e.stale))
    {
        node_list_is_complete = false;
    }

    {
        let mut status_map = state.sub_status.lock().await;
        status_map.retain(|url, _| config.subs.contains(url));
        for url in &config.subs {
            let mut status = store.status_for(url);
            if let Some(err) = fetch_errors.get(url) {
                // 本轮确实抓过：区分"刚抓成功"和"抓失败但有缓存"。
                if !status.state.eq(&crate::models::SubState::Expired) {
                    status.state = crate::models::SubState::Ok;
                }
                status.error = err.clone();
            }
            status_map.insert(url.clone(), status);
        }
    }

    let outcome = gen_outcome_from_store(config, &store);
    let (final_node_names, final_outbounds) = store.nodes_in_order(&config.subs);

    let mut share_map = if config.mode == ProxyMode::Pool {
        load_share_port_map().await
    } else {
        SharePortMap::default()
    };
    let share_map_before = share_map.clone();

    let sing_box_config = build_sing_box_config(
        config,
        my_names,
        my_outbounds,
        final_node_names,
        final_outbounds,
        &mut share_map,
        node_list_is_complete,
    )?;

    let sing_box_home = get_sing_box_home();
    let config_output_loc = sing_box_home.join("config.json");
    write_file_atomic(
        &config_output_loc,
        &serde_json::to_string(&sing_box_config)?,
        "sing-box config",
    )
    .await?;

    if config.mode == ProxyMode::Pool && share_map != share_map_before {
        save_share_port_map(&share_map).await?;
    }
    if store != store_before {
        save_sub_nodes(&store).await?;
    }

    Ok(outcome)
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{secs}")
}

fn collect_manual_outbounds(config: &Config) -> (Vec<serde_json::Value>, Vec<String>) {
    use crate::services::node_parser::parse_node_json;

    let mut my_outbounds = vec![];
    let mut my_names = vec![];

    for (idx, node_str) in config.nodes.iter().enumerate() {
        // 验证节点并获取解析后的 Value
        match parse_node_json(node_str) {
            Ok((info, outbound)) => {
                my_names.push(info.tag);
                my_outbounds.push(outbound);
            }
            Err(e) => {
                warn!("[collect_manual_outbounds] Skipping node #{}: {}", idx, e);
            }
        }
    }

    (my_outbounds, my_names)
}

fn make_unique_tag(tag: &str, used: &mut HashSet<String>) -> String {
    let base = if tag.trim().is_empty() { "node" } else { tag };
    if used.insert(base.to_string()) {
        return base.to_string();
    }

    for index in 2.. {
        let candidate = format!("{base} ({index})");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }

    unreachable!("unbounded duplicate tag search should always find a value")
}

fn normalize_outbound_tags(
    node_names: Vec<String>,
    outbounds: Vec<serde_json::Value>,
) -> (Vec<String>, Vec<serde_json::Value>) {
    let names_len = node_names.len();
    let mut used = HashSet::new();
    // Built-in outbounds from the template already reserve these tags.
    used.insert("proxy".to_string());
    used.insert("direct".to_string());
    let mut unique_names = Vec::with_capacity(outbounds.len());
    let mut unique_outbounds = Vec::with_capacity(outbounds.len());

    for (idx, mut outbound) in outbounds.into_iter().enumerate() {
        let original_name = node_names
            .get(idx)
            .cloned()
            .or_else(|| {
                outbound
                    .get("tag")
                    .and_then(|tag| tag.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| format!("node-{}", idx + 1));
        let unique_name = make_unique_tag(&original_name, &mut used);

        if unique_name != original_name {
            warn!(
                from = %original_name,
                to = %unique_name,
                "Renamed duplicate outbound tag to avoid sing-box conflict"
            );
        }

        if let Some(obj) = outbound.as_object_mut() {
            obj.insert(
                "tag".to_string(),
                serde_json::Value::String(unique_name.clone()),
            );
        } else {
            warn!(tag = %unique_name, "Outbound is not a JSON object; cannot set tag");
        }

        unique_names.push(unique_name);
        unique_outbounds.push(outbound);
    }

    if names_len != unique_outbounds.len() {
        warn!(
            names = names_len,
            outbounds = unique_outbounds.len(),
            "Outbound name count did not match outbound config count"
        );
    }

    (unique_names, unique_outbounds)
}

pub(crate) fn resolve_node_inventory(config: &Config, store: &SubNodeStore) -> Vec<NodeInfo> {
    let (manual_outbounds, manual_names) = collect_manual_outbounds(config);
    let (subscription_names, subscription_outbounds) = store.nodes_in_order(&config.subs);
    let (_, outbounds) = normalize_outbound_tags(
        manual_names.into_iter().chain(subscription_names).collect(),
        manual_outbounds
            .into_iter()
            .chain(subscription_outbounds)
            .collect(),
    );

    outbounds
        .iter()
        .filter_map(|outbound| {
            crate::services::node_parser::node_display_info(outbound)
                .map(|info| NodeInfo {
                    tag: info.tag,
                    server: info.server,
                    server_port: info.server_port,
                    node_type: info.node_type,
                    sni: info.sni,
                })
                .map_err(|error| {
                    warn!(error = %error, "Skipping invalid cached node in inventory");
                })
                .ok()
        })
        .collect()
}

/// 构建 sing-box 配置。纯函数：不碰磁盘。
///
/// `share_map` 是分享端口的分配账本，就地更新；落盘由调用方在构建成功之后完成，
/// 这样一次失败的构建不会留下已经改过的账本。`prune_share_ports` 表示本次传入的
/// 节点列表是否完整（所有订阅都抓取成功），只有完整时才允许回收失效 tag 的端口。
fn build_sing_box_config(
    config: &Config,
    my_names: Vec<String>,
    my_outbounds: Vec<serde_json::Value>,
    final_node_names: Vec<String>,
    final_outbounds: Vec<serde_json::Value>,
    share_map: &mut SharePortMap,
    prune_share_ports: bool,
) -> AppResult<serde_json::Value> {
    let total_nodes = my_outbounds.len() + final_outbounds.len();
    if total_nodes == 0 {
        return Err(AppError::message(
            "No nodes available: all subscriptions failed and no manual nodes configured",
        ));
    }

    let socks_port = config.socks_port.unwrap_or(DEFAULT_SOCKS_PORT);
    if socks_port == 0 {
        return Err(AppError::message(
            "Invalid socks_port: must be between 1 and 65535",
        ));
    }

    let socks_listen = config
        .socks_listen
        .as_deref()
        .unwrap_or(DEFAULT_SOCKS_LISTEN);
    if socks_listen.parse::<std::net::IpAddr>().is_err() {
        return Err(AppError::message(
            "Invalid socks_listen: must be an IP address",
        ));
    }

    let (node_names, outbounds) = normalize_outbound_tags(
        my_names.into_iter().chain(final_node_names).collect(),
        my_outbounds.into_iter().chain(final_outbounds).collect(),
    );

    let process_proxy = config
        .tun_process
        .normalized()
        .map_err(AppError::message)?;
    let pool = config.share.normalized().map_err(AppError::message)?;
    if config.mode == ProxyMode::Process {
        process_proxy.validate_active().map_err(AppError::message)?;
    }

    let share_bindings = if config.mode == ProxyMode::Pool {
        let reserved = reserved_system_ports(config.port, Some(socks_port));
        allocate_share_ports(
            share_map,
            &node_names,
            pool.base_port,
            &reserved,
            prune_share_ports,
        )?
    } else {
        Vec::new()
    };

    let mut sing_box_config = get_config_template(
        config.mode,
        &process_proxy,
        &config.custom_rules,
        &share_bindings,
    )?;
    if let Some(inbounds) = sing_box_config["inbounds"].as_array_mut() {
        inbounds.push(serde_json::json!({
            "type": "socks",
            "tag": "socks-in",
            "listen": socks_listen,
            "listen_port": socks_port
        }));
        for (_tag, port) in &share_bindings {
            let mut inbound = serde_json::json!({
                "type": "socks",
                "tag": share_inbound_tag(*port),
                "listen": pool.listen,
                "listen_port": port
            });
            if pool.has_auth() {
                inbound.as_object_mut().unwrap().insert(
                    "users".to_string(),
                    serde_json::json!([{
                        "username": pool.username,
                        "password": pool.password
                    }]),
                );
            }
            inbounds.push(inbound);
        }
    }
    if let Some(selector_outbounds) = sing_box_config["outbounds"][0].get_mut("outbounds") {
        if let Some(arr) = selector_outbounds.as_array_mut() {
            arr.extend(node_names.into_iter().map(serde_json::Value::String));
        }
    }
    if let Some(arr) = sing_box_config["outbounds"].as_array_mut() {
        arr.extend(outbounds);
    }

    Ok(sing_box_config)
}

fn parse_custom_rules(custom_rules: &[String]) -> Vec<serde_json::Value> {
    let mut parsed = Vec::new();
    for rule_str in custom_rules {
        if let Ok(rule_json) = serde_json::from_str::<serde_json::Value>(rule_str) {
            parsed.push(rule_json);
        } else {
            warn!("Failed to parse custom rule: {}", rule_str);
        }
    }
    parsed
}

fn process_match_fields(
    process_match: &ProcessMatch,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    if !process_match.names.is_empty() {
        fields.insert(
            "process_name".to_string(),
            serde_json::json!(process_match.names),
        );
    }
    if !process_match.paths.is_empty() {
        fields.insert(
            "process_path".to_string(),
            serde_json::json!(process_match.paths),
        );
    }
    if !process_match.path_regex.is_empty() {
        fields.insert(
            "process_path_regex".to_string(),
            serde_json::json!(process_match.path_regex),
        );
    }
    fields
}

fn process_rule(process_match: &ProcessMatch, extras: serde_json::Value) -> serde_json::Value {
    let mut rule = process_match_fields(process_match);
    if let Some(extras) = extras.as_object() {
        for (key, value) in extras {
            rule.insert(key.clone(), value.clone());
        }
    }
    serde_json::Value::Object(rule)
}

fn socks_in_proxy_rule() -> serde_json::Value {
    serde_json::json!({"inbound": ["socks-in"], "action": "route", "outbound": "proxy"})
}

fn share_inbound_route_rules(share_bindings: &[(String, u16)]) -> Vec<serde_json::Value> {
    share_bindings
        .iter()
        .map(|(tag, port)| {
            serde_json::json!({
                "inbound": [share_inbound_tag(*port)],
                "action": "route",
                "outbound": tag
            })
        })
        .collect()
}

fn route_prelude_rules(share_bindings: &[(String, u16)]) -> Vec<serde_json::Value> {
    let mut rules = vec![serde_json::json!({"action": "sniff"})];
    rules.extend(share_inbound_route_rules(share_bindings));
    rules.push(socks_in_proxy_rule());
    rules
}

fn bypass_or_direct_rule(
    process_match: &ProcessMatch,
    bypass_action: BypassAction,
    protocol: Option<&str>,
) -> serde_json::Value {
    let extras = match (bypass_action, protocol) {
        (BypassAction::Bypass, Some(protocol)) => {
            serde_json::json!({"protocol": protocol, "action": "bypass"})
        }
        (BypassAction::Bypass, None) => serde_json::json!({"action": "bypass"}),
        (BypassAction::Direct, Some(protocol)) => serde_json::json!({
            "protocol": protocol,
            "action": "route",
            "outbound": "direct"
        }),
        (BypassAction::Direct, None) => serde_json::json!({
            "action": "route",
            "outbound": "direct"
        }),
    };
    process_rule(process_match, extras)
}

fn merge_process_match_into_rule(
    mut rule: serde_json::Value,
    process_match: &ProcessMatch,
) -> AppResult<serde_json::Value> {
    let Some(obj) = rule.as_object_mut() else {
        return Ok(rule);
    };

    for key in ["process_name", "process_path", "process_path_regex"] {
        if obj.contains_key(key) {
            return Err(AppError::message(format!(
                "白名单模式下 custom_rules 不能包含 {key}，请使用进程代理清单统一控制"
            )));
        }
    }

    for (key, value) in process_match_fields(process_match) {
        obj.insert(key, value);
    }
    Ok(rule)
}

fn build_dns_rules() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "rule_set": ["chinasite"],
        "action": "route",
        "server": "local"
    })]
}

fn append_global_route_tail(
    route_rules: &mut Vec<serde_json::Value>,
    custom_rules: &[String],
) {
    route_rules.push(serde_json::json!({"protocol": "dns", "action": "hijack-dns"}));
    route_rules.extend(parse_custom_rules(custom_rules));
    route_rules
        .push(serde_json::json!({"ip_is_private": true, "action": "route", "outbound": "direct"}));
}

fn build_global_route_rules(custom_rules: &[String]) -> Vec<serde_json::Value> {
    let mut route_rules = route_prelude_rules(&[]);
    append_global_route_tail(&mut route_rules, custom_rules);
    route_rules
}

fn build_blacklist_route_rules(
    process_proxy: &ProcessProxyConfig,
    custom_rules: &[String],
) -> Vec<serde_json::Value> {
    let mut route_rules = route_prelude_rules(&[]);

    if process_proxy.dns_follow_process {
        route_rules.push(bypass_or_direct_rule(
            &process_proxy.r#match,
            process_proxy.bypass_action,
            Some("dns"),
        ));
    }
    route_rules.push(bypass_or_direct_rule(
        &process_proxy.r#match,
        process_proxy.bypass_action,
        None,
    ));
    append_global_route_tail(&mut route_rules, custom_rules);

    route_rules
}

fn build_whitelist_route_rules(
    process_proxy: &ProcessProxyConfig,
    custom_rules: &[String],
) -> AppResult<Vec<serde_json::Value>> {
    let mut route_rules = route_prelude_rules(&[]);

    if process_proxy.dns_follow_process {
        route_rules.push(process_rule(
            &process_proxy.r#match,
            serde_json::json!({"protocol": "dns", "action": "hijack-dns"}),
        ));
    }

    for custom_rule in parse_custom_rules(custom_rules) {
        route_rules.push(merge_process_match_into_rule(
            custom_rule,
            &process_proxy.r#match,
        )?);
    }

    route_rules.push(process_rule(
        &process_proxy.r#match,
        serde_json::json!({"ip_is_private": true, "action": "route", "outbound": "direct"}),
    ));
    route_rules.push(process_rule(
        &process_proxy.r#match,
        serde_json::json!({"action": "route", "outbound": "proxy"}),
    ));

    Ok(route_rules)
}

fn route_final(mode: ProxyMode, process_proxy: &ProcessProxyConfig) -> &'static str {
    if mode == ProxyMode::Process && process_proxy.mode == ProcessListMode::Whitelist {
        "direct"
    } else {
        "proxy"
    }
}

fn build_route_rules(
    mode: ProxyMode,
    process_proxy: &ProcessProxyConfig,
    custom_rules: &[String],
    share_bindings: &[(String, u16)],
) -> AppResult<Vec<serde_json::Value>> {
    match mode {
        ProxyMode::Global => Ok(build_global_route_rules(custom_rules)),
        ProxyMode::Process => match process_proxy.mode {
            ProcessListMode::Blacklist => {
                Ok(build_blacklist_route_rules(process_proxy, custom_rules))
            }
            ProcessListMode::Whitelist => {
                build_whitelist_route_rules(process_proxy, custom_rules)
            }
        },
        ProxyMode::Pool => Ok(route_prelude_rules(share_bindings)),
    }
}

fn get_config_template(
    mode: ProxyMode,
    process_proxy: &ProcessProxyConfig,
    custom_rules: &[String],
    share_bindings: &[(String, u16)],
) -> AppResult<serde_json::Value> {
    let route_rules = build_route_rules(mode, process_proxy, custom_rules, share_bindings)?;
    let dns_rules = build_dns_rules();
    let default_domain_resolver = "local";
    let route_final = route_final(mode, process_proxy);
    let inbounds = if mode == ProxyMode::Pool {
        Vec::new()
    } else {
        vec![serde_json::json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "sing-tun",
            "address": ["172.18.0.1/30"],
            "mtu": 9000,
            "auto_route": true,
            "strict_route": true,
            "auto_redirect": true,
            "dns_mode": "disabled"
        })]
    };

    Ok(serde_json::json!({
        "log": {"disabled": false, "timestamp": true, "level": "info"},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:6262"}},
        "dns": {
            "final": "cfdns",
            "strategy": "ipv4_only",
            "disable_cache": false,
            "servers": [
                {"type": "udp", "tag": "cfdns", "server": "1.1.1.1", "detour": "proxy"},
                {"tag": "local", "type": "udp", "server": "223.5.5.5"}
            ],
            "rules": dns_rules
        },
        "inbounds": inbounds,
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": []},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "final": route_final,
            "auto_detect_interface": true,
            "default_domain_resolver": default_domain_resolver,
            "rules": route_rules,
            "rule_set": [
                {"type": "local", "tag": "chinasite", "format": "binary", "path": "./chinasite.srs"},
                {"type": "local", "tag": "chinaip", "format": "binary", "path": "./chinaip.srs"}
            ]
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        collect_manual_outbounds, config_cache_fingerprint, normalize_cached_sing_box_config,
        extract_legacy_subscription_nodes, resolve_node_inventory, save_config_to, SubFetchPolicy,
    };
    use crate::error::AppResult;
    use crate::models::{
        Config, PoolConfig, ProcessListMode, ProcessMatch, ProcessProxyConfig, ProxyMode,
    };
    use crate::services::share_ports::SharePortMap;
    use crate::services::sub_nodes::SubNodeStore;
    use serde_json::json;

    #[test]
    fn cache_only_never_fetches() {
        let store = SubNodeStore::default();
        let subs = vec!["a".to_string(), "b".to_string()];

        // 即使缓存彻底是空的，CacheOnly 也不许联网。
        assert!(SubFetchPolicy::CacheOnly
            .urls_to_fetch(&store, &subs)
            .is_empty());
    }

    #[test]
    fn bootstrap_fetches_only_when_cache_is_empty() {
        let subs = vec!["a".to_string(), "b".to_string()];
        let empty = SubNodeStore::default();
        assert_eq!(
            SubFetchPolicy::CacheOrBootstrap.urls_to_fetch(&empty, &subs),
            subs,
            "缓存为空时做一次首装抓取"
        );

        let mut primed = SubNodeStore::default();
        primed.record_success(
            "a",
            vec![crate::services::sub_nodes::StoredNode {
                name: "n1".to_string(),
                outbound: json!({}),
            }],
            None,
        );
        assert!(
            SubFetchPolicy::CacheOrBootstrap
                .urls_to_fetch(&primed, &subs)
                .is_empty(),
            "只要有任何缓存节点就不再自动抓取"
        );
    }

    #[test]
    fn fetch_only_targets_the_named_subscription() {
        let store = SubNodeStore::default();
        let subs = vec!["a".to_string(), "b".to_string()];

        let picked = SubFetchPolicy::FetchOnly(vec!["b".to_string()]).urls_to_fetch(&store, &subs);
        assert_eq!(picked, vec!["b".to_string()], "新增订阅只抓新增的那一个");

        // 不在配置里的 URL 不会被抓。
        let bogus = SubFetchPolicy::FetchOnly(vec!["zzz".to_string()]).urls_to_fetch(&store, &subs);
        assert!(bogus.is_empty());
    }

    #[test]
    fn fetch_all_targets_every_subscription() {
        let store = SubNodeStore::default();
        let subs = vec!["a".to_string(), "b".to_string()];
        assert_eq!(SubFetchPolicy::FetchAll.urls_to_fetch(&store, &subs), subs);
    }

    #[test]
    fn legacy_config_cache_imports_nodes_after_manual_selector_entries() {
        let config = Config {
            subs: vec!["https://example.com/sub".to_string()],
            nodes: vec![
                r#"{"type":"socks","tag":"manual","server":"127.0.0.1","server_port":1081}"#
                    .to_string(),
            ],
            ..Default::default()
        };
        let cached = json!({
            "outbounds": [
                {"type":"selector","tag":"proxy","outbounds":["manual","sub-a","sub-b"]},
                {"type":"direct","tag":"direct"},
                {"type":"socks","tag":"manual","server":"127.0.0.1","server_port":1081},
                {"type":"socks","tag":"sub-a","server":"a.example.com","server_port":1080},
                {"type":"http","tag":"sub-b","server":"b.example.com","server_port":8080}
            ]
        });

        let imported = extract_legacy_subscription_nodes(&config, &cached);

        assert_eq!(
            imported.iter().map(|node| node.name.as_str()).collect::<Vec<_>>(),
            vec!["sub-a", "sub-b"]
        );
        assert_eq!(imported[0].outbound["server"], "a.example.com");
    }

    #[test]
    fn legacy_config_cache_rejects_a_different_manual_node_prefix() {
        let config = Config {
            subs: vec!["https://example.com/sub".to_string()],
            nodes: vec![
                r#"{"type":"socks","tag":"manual","server":"127.0.0.1","server_port":1081}"#
                    .to_string(),
            ],
            ..Default::default()
        };
        let cached = json!({
            "outbounds": [
                {"type":"selector","tag":"proxy","outbounds":["different-manual","sub-a"]},
                {"type":"direct","tag":"direct"},
                {"type":"socks","tag":"different-manual","server":"127.0.0.1","server_port":1081},
                {"type":"socks","tag":"sub-a","server":"a.example.com","server_port":1080}
            ]
        });

        assert!(extract_legacy_subscription_nodes(&config, &cached).is_empty());
    }

    /// 构建器现在是纯函数，账本由调用方持有。绝大多数用例不关心分享模式，
    /// 给它们一本一次性的空账本即可——不再需要环境变量注入和全局测试锁。
    fn build_sing_box_config(
        config: &Config,
        my_names: Vec<String>,
        my_outbounds: Vec<serde_json::Value>,
        final_node_names: Vec<String>,
        final_outbounds: Vec<serde_json::Value>,
    ) -> AppResult<serde_json::Value> {
        let mut share_map = SharePortMap::default();
        super::build_sing_box_config(
            config,
            my_names,
            my_outbounds,
            final_node_names,
            final_outbounds,
            &mut share_map,
            true,
        )
    }

    fn manual_outbound() -> serde_json::Value {
        json!({
            "type": "hysteria2",
            "tag": "manual-a",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "secret"
        })
    }

    fn process_proxy(mode: ProcessListMode) -> ProcessProxyConfig {
        ProcessProxyConfig {
            mode,
            r#match: ProcessMatch {
                names: vec!["curl".to_string(), "git-remote-https".to_string()],
                paths: vec![],
                path_regex: vec![],
            },
            dns_follow_process: true,
            bypass_action: Default::default(),
            legacy_enabled: false,
        }
    }

    #[test]
    fn collect_manual_outbounds_ignores_invalid_json_nodes() {
        let config = Config {
            nodes: vec![ r#"{"type":"hysteria2","tag":"manual-a","server":"a.example.com","server_port":443,"password":"p","up_mbps":40,"down_mbps":350,"tls":{"enabled":true,"insecure":true}}"#.to_string(), "{invalid-json".to_string(), ],
            ..Default::default()
        };

        let (outbounds, names) = collect_manual_outbounds(&config);

        assert_eq!(outbounds.len(), 1);
        assert_eq!(names, vec!["manual-a"]);
        assert_eq!(outbounds[0]["tag"], "manual-a");
    }

    #[test]
    fn collect_manual_outbounds_preserves_hysteria2_without_default_bandwidth() {
        // 测试：Hysteria2 节点不强制包含带宽默认值
        let config = Config {
            nodes: vec![
    // 不包含 up_mbps/down_mbps 的节点
    r#"{"type":"hysteria2","tag":"no-bandwidth","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true}}"#.to_string(),
],
            ..Default::default()
        };

        let (outbounds, names) = collect_manual_outbounds(&config);

        assert_eq!(outbounds.len(), 1);
        assert_eq!(names, vec!["no-bandwidth"]);
        // 验证不包含硬编码的带宽字段
        assert!(outbounds[0].get("up_mbps").is_none() || outbounds[0]["up_mbps"].is_null());
        assert!(outbounds[0].get("down_mbps").is_none() || outbounds[0]["down_mbps"].is_null());
    }

    #[test]
    fn collect_manual_outbounds_preserves_socks_and_http_nodes() {
        let config = Config {
            nodes: vec![ r#"{"type":"socks","tag":"socks-a","server":"socks.example.com","server_port":1080}"#.to_string(), r#"{"type":"http","tag":"http-a","server":"http.example.com","server_port":8080,"username":"user","password":"pass"}"#.to_string(), ],
            ..Default::default()
        };

        let (outbounds, names) = collect_manual_outbounds(&config);

        assert_eq!(names, vec!["socks-a", "http-a"]);
        assert_eq!(outbounds[0]["type"], "socks");
        assert_eq!(outbounds[0]["server_port"], 1080);
        assert!(outbounds[0].get("username").is_none());
        assert_eq!(outbounds[1]["type"], "http");
        assert_eq!(outbounds[1]["username"], "user");
        assert_eq!(outbounds[1]["password"], "pass");
    }

    #[test]
    fn build_sing_box_config_merges_nodes_and_valid_custom_rules() {
        let config = Config {
            socks_port: Some(1080),
            custom_rules: vec![
                r#"{"domain_suffix":["example.com"],"action":"route","outbound":"proxy"}"#
                    .to_string(),
                "not-json".to_string(),
            ],
            mode: ProxyMode::Global,
            ..Default::default()
        };

        let my_outbounds = vec![json!({
            "type": "hysteria2",
            "tag": "manual-a",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "secret"
        })];
        let final_outbounds = vec![json!({
            "type": "shadowsocks",
            "tag": "sub-a",
            "server": "sub.example.com",
            "server_port": 8388,
            "method": "2022-blake3-aes-128-gcm",
            "password": "sub-secret"
        })];

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            my_outbounds,
            vec!["sub-a".to_string()],
            final_outbounds,
        )
        .unwrap();

        let selector = built["outbounds"][0]["outbounds"].as_array().unwrap();
        assert_eq!(selector.len(), 2);
        assert_eq!(selector[0], "manual-a");
        assert_eq!(selector[1], "sub-a");

        let inbounds = built["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["type"], "tun");
        assert_eq!(inbounds[0]["dns_mode"], "disabled");
        assert_eq!(inbounds[1]["type"], "socks");
        assert_eq!(inbounds[1]["listen"], "127.0.0.1");
        assert_eq!(inbounds[1]["listen_port"], 1080);

        let all_outbounds = built["outbounds"].as_array().unwrap();
        assert_eq!(all_outbounds.len(), 4);
        assert_eq!(all_outbounds[2]["tag"], "manual-a");
        assert_eq!(all_outbounds[3]["tag"], "sub-a");

        let rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(rules[1]["outbound"], "proxy");
        assert_eq!(rules[2]["action"], "hijack-dns");
        assert_eq!(rules[3]["domain_suffix"][0], "example.com");
        assert_eq!(rules[4]["ip_is_private"], true);
    }

    #[test]
    fn build_sing_box_config_blacklist_adds_process_rules_before_dns_hijack() {
        let config = Config {
            mode: ProxyMode::Process,
            tun_process: process_proxy(ProcessListMode::Blacklist),
            ..Default::default()
        };

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![manual_outbound()],
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(rules[1]["outbound"], "proxy");
        assert_eq!(
            rules[2]["process_name"],
            json!(["curl", "git-remote-https"])
        );
        assert_eq!(rules[2]["protocol"], "dns");
        assert_eq!(rules[2]["action"], "bypass");
        assert_eq!(
            rules[3]["process_name"],
            json!(["curl", "git-remote-https"])
        );
        assert_eq!(rules[3]["action"], "bypass");
        assert_eq!(rules[4]["action"], "hijack-dns");
    }

    #[test]
    fn build_sing_box_config_whitelist_scopes_dns_and_uses_direct_final() {
        let config = Config {
            mode: ProxyMode::Process,
            tun_process: process_proxy(ProcessListMode::Whitelist),
            ..Default::default()
        };

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![manual_outbound()],
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(rules[1]["action"], "route");
        assert_eq!(rules[1]["outbound"], "proxy");
        assert_eq!(rules[2]["protocol"], "dns");
        assert_eq!(
            rules[2]["process_name"],
            json!(["curl", "git-remote-https"])
        );
        assert!(!rules.iter().any(|rule| {
            rule["protocol"] == "dns"
                && rule.get("process_name").is_none()
                && rule["action"] == "hijack-dns"
        }));
        assert_eq!(rules.last().unwrap()["action"], "route");
        assert_eq!(rules.last().unwrap()["outbound"], "proxy");
        assert_eq!(built["route"]["final"], "direct");
    }

    #[test]
    fn build_sing_box_config_whitelist_forces_socks_in_to_proxy() {
        let config = Config {
            mode: ProxyMode::Process,
            tun_process: process_proxy(ProcessListMode::Whitelist),
            ..Default::default()
        };

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![manual_outbound()],
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(
            rules[1],
            json!({"inbound": ["socks-in"], "action": "route", "outbound": "proxy"})
        );
        assert_eq!(built["route"]["final"], "direct");
    }

    #[test]
    fn build_sing_box_config_whitelist_scopes_custom_rules_to_processes() {
        let config = Config {
            custom_rules: vec![
                r#"{"domain_suffix":["example.com"],"action":"route","outbound":"direct"}"#
                    .to_string(),
            ],
            mode: ProxyMode::Process,
            tun_process: process_proxy(ProcessListMode::Whitelist),
            ..Default::default()
        };

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![manual_outbound()],
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        let custom_rule = rules
            .iter()
            .find(|rule| rule.get("domain_suffix").is_some())
            .unwrap();
        assert_eq!(
            custom_rule["process_name"],
            json!(["curl", "git-remote-https"])
        );
    }

    #[test]
    fn build_sing_box_config_errors_when_active_process_has_empty_match() {
        let config = Config {
            mode: ProxyMode::Process,
            tun_process: ProcessProxyConfig::default(),
            ..Default::default()
        };

        let err = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![manual_outbound()],
            vec![],
            vec![],
        )
        .unwrap_err();

        assert!(err.to_string().contains("至少需要填写"));
    }

    #[test]
    fn build_sing_box_config_global_mode_keeps_custom_rules_without_domestic_split() {
        let config = Config {
            custom_rules: vec![
                r#"{"domain_suffix":["example.com"],"action":"route","outbound":"direct"}"#
                    .to_string(),
            ],
            mode: ProxyMode::Global,
            ..Default::default()
        };

        let my_outbounds = vec![json!({
            "type": "hysteria2",
            "tag": "manual-a",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "secret"
        })];

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            my_outbounds,
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(rules[1]["outbound"], "proxy");
        assert_eq!(rules[2]["action"], "hijack-dns");
        assert_eq!(rules[3]["domain_suffix"][0], "example.com");
        assert_eq!(rules[4]["ip_is_private"], true);
        assert_eq!(rules[4]["outbound"], "direct");
        assert!(!rules.iter().any(|rule| rule.get("rule_set").is_some()));

        let dns_rules = built["dns"]["rules"].as_array().unwrap();
        assert_eq!(dns_rules.len(), 1);
        assert_eq!(built["route"]["final"], "proxy");
    }

    #[test]
    fn build_sing_box_config_renames_duplicate_outbound_tags() {
        let config = Config::default();

        let my_outbounds = vec![json!({
            "type": "hysteria2",
            "tag": "dup",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "manual-secret"
        })];
        let final_outbounds = vec![
            json!({
                "type": "hysteria2",
                "tag": "dup",
                "server": "sub1.example.com",
                "server_port": 443,
                "password": "sub-secret-1"
            }),
            json!({
                "type": "shadowsocks",
                "tag": "dup",
                "server": "sub2.example.com",
                "server_port": 8388,
                "method": "2022-blake3-aes-128-gcm",
                "password": "sub-secret-2"
            }),
        ];

        let built = build_sing_box_config(
            &config,
            vec!["dup".to_string()],
            my_outbounds,
            vec!["dup".to_string(), "dup".to_string()],
            final_outbounds,
        )
        .unwrap();

        let selector = built["outbounds"][0]["outbounds"].as_array().unwrap();
        let selector_tags: Vec<_> = selector
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(selector_tags, vec!["dup", "dup (2)", "dup (3)"]);

        let all_outbounds = built["outbounds"].as_array().unwrap();
        assert_eq!(all_outbounds[2]["tag"], "dup");
        assert_eq!(all_outbounds[3]["tag"], "dup (2)");
        assert_eq!(all_outbounds[4]["tag"], "dup (3)");
    }

    #[test]
    fn node_inventory_uses_the_same_normalized_tags_as_selector() {
        let config = Config {
            subs: vec!["sub".to_string()],
            nodes: vec![serde_json::to_string(&json!({
                "type": "hysteria2",
                "tag": "dup",
                "server": "manual.example.com",
                "server_port": 443,
                "password": "manual-secret"
            }))
            .unwrap()],
            ..Default::default()
        };
        let mut store = SubNodeStore::default();
        store.record_success(
            "sub",
            vec![crate::services::sub_nodes::StoredNode {
                name: "dup".to_string(),
                outbound: json!({
                    "type": "hysteria2",
                    "tag": "dup",
                    "server": "sub.example.com",
                    "server_port": 443,
                    "password": "sub-secret"
                }),
            }],
            None,
        );

        let inventory = resolve_node_inventory(&config, &store);
        let (manual_outbounds, manual_names) = collect_manual_outbounds(&config);
        let (sub_names, sub_outbounds) = store.nodes_in_order(&config.subs);
        let built = build_sing_box_config(
            &config,
            manual_names,
            manual_outbounds,
            sub_names,
            sub_outbounds,
        )
        .unwrap();
        let selector: Vec<_> = built["outbounds"][0]["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let inventory_tags: Vec<_> = inventory.iter().map(|node| node.tag.as_str()).collect();

        assert_eq!(inventory_tags, selector);
        assert_eq!(inventory_tags, vec!["dup", "dup (2)"]);
    }

    #[test]
    fn build_sing_box_config_renames_tags_reserved_by_template() {
        let config = Config::default();

        let my_outbounds = vec![
            json!({
                "type": "hysteria2",
                "tag": "proxy",
                "server": "proxy.example.com",
                "server_port": 443,
                "password": "proxy-secret"
            }),
            json!({
                "type": "hysteria2",
                "tag": "direct",
                "server": "direct.example.com",
                "server_port": 443,
                "password": "direct-secret"
            }),
        ];

        let built = build_sing_box_config(
            &config,
            vec!["proxy".to_string(), "direct".to_string()],
            my_outbounds,
            vec![],
            vec![],
        )
        .unwrap();

        let selector = built["outbounds"][0]["outbounds"].as_array().unwrap();
        let selector_tags: Vec<_> = selector
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(selector_tags, vec!["proxy (2)", "direct (2)"]);

        let all_outbounds = built["outbounds"].as_array().unwrap();
        assert_eq!(all_outbounds[0]["tag"], "proxy");
        assert_eq!(all_outbounds[1]["tag"], "direct");
        assert_eq!(all_outbounds[2]["tag"], "proxy (2)");
        assert_eq!(all_outbounds[3]["tag"], "direct (2)");
    }

    #[test]
    fn build_sing_box_config_uses_configured_socks_listen_and_port() {
        let config = Config {
            socks_listen: Some("0.0.0.0".to_string()),
            socks_port: Some(2080),
            ..Default::default()
        };
        let my_outbounds = vec![json!({
            "type": "hysteria2",
            "tag": "manual-a",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "secret"
        })];

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            my_outbounds,
            vec![],
            vec![],
        )
        .unwrap();

        let inbounds = built["inbounds"].as_array().unwrap();
        assert_eq!(inbounds[1]["type"], "socks");
        assert_eq!(inbounds[1]["listen"], "0.0.0.0");
        assert_eq!(inbounds[1]["listen_port"], 2080);
    }

    #[test]
    fn build_sing_box_config_defaults_to_global_mode_with_local_socks() {
        let config = Config::default();

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![json!({
                "type": "hysteria2",
                "tag": "manual-a",
                "server": "manual.example.com",
                "server_port": 443,
                "password": "secret"
            })],
            vec![],
            vec![],
        )
        .unwrap();

        let inbounds = built["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[1]["type"], "socks");
        assert_eq!(inbounds[1]["listen"], "127.0.0.1");
        assert_eq!(inbounds[1]["listen_port"], 1080);

        let dns_rules = built["dns"]["rules"].as_array().unwrap();
        assert_eq!(dns_rules.len(), 1);
        assert_eq!(dns_rules[0]["rule_set"][0], "chinasite");
        assert_eq!(dns_rules[0]["server"], "local");

        let route_rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(route_rules.len(), 4);
        assert_eq!(route_rules[0]["action"], "sniff");
        assert_eq!(route_rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(route_rules[1]["outbound"], "proxy");
        assert_eq!(route_rules[2]["action"], "hijack-dns");
        assert_eq!(route_rules[3]["ip_is_private"], true);
        assert_eq!(route_rules[3]["outbound"], "direct");
        assert_eq!(built["route"]["default_domain_resolver"], "local");
    }

    #[test]
    fn build_sing_box_config_supports_global_mode_private_direct() {
        let config = Config {
            mode: ProxyMode::Global,
            ..Default::default()
        };

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![json!({
                "type": "hysteria2",
                "tag": "manual-a",
                "server": "manual.example.com",
                "server_port": 443,
                "password": "secret"
            })],
            vec![],
            vec![],
        )
        .unwrap();

        let dns_rules = built["dns"]["rules"].as_array().unwrap();
        assert_eq!(dns_rules.len(), 1);
        assert_eq!(dns_rules[0]["server"], "local");

        let route_rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(route_rules.len(), 4);
        assert_eq!(route_rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(route_rules[1]["outbound"], "proxy");
        assert_eq!(route_rules[3]["ip_is_private"], true);
        assert_eq!(route_rules[3]["outbound"], "direct");
        assert_eq!(built["route"]["default_domain_resolver"], "local");
    }

    #[test]
    fn config_cache_fingerprint_ignores_web_port() {
        let mut first = Config {
            port: Some(6161),
            socks_port: Some(1080),
            mode: ProxyMode::Process,
            subs: vec!["https://example.com/sub".to_string()],
            ..Default::default()
        };
        let mut second = first.clone();
        second.port = Some(7777);

        assert_eq!(
            config_cache_fingerprint(&first).unwrap(),
            config_cache_fingerprint(&second).unwrap()
        );

        first.subs.push("https://example.com/other".to_string());
        assert_ne!(
            config_cache_fingerprint(&first).unwrap(),
            config_cache_fingerprint(&second).unwrap()
        );
    }

    #[test]
    fn normalize_cached_sing_box_config_repairs_proxy_dns_bootstrap() {
        let config = json!({
            "route": {
                "default_domain_resolver": "cfdns"
            }
        });

        let normalized = normalize_cached_sing_box_config(config);

        assert_eq!(normalized["route"]["default_domain_resolver"], "local");
    }

    #[test]
    fn build_sing_box_config_errors_when_no_nodes_available() {
        let config = Config::default();

        let err = build_sing_box_config(&config, vec![], vec![], vec![], vec![]).unwrap_err();

        assert!(err.to_string().contains(
            "No nodes available: all subscriptions failed and no manual nodes configured"
        ));
    }

    #[test]
    fn config_has_no_nodes_only_when_subs_and_manual_nodes_empty() {
        assert!(super::config_has_no_nodes(&Config::default()));

        assert!(!super::config_has_no_nodes(&Config {
            subs: vec!["https://example.com/sub".to_string()],
            ..Default::default()
        }));

        assert!(!super::config_has_no_nodes(&Config {
            nodes: vec![r#"{"tag":"manual"}"#.to_string()],
            ..Default::default()
        }));
    }

    #[test]
    fn collect_manual_outbounds_handles_empty_nodes() {
        let config = Config::default();

        let (outbounds, names) = collect_manual_outbounds(&config);

        assert!(outbounds.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn collect_manual_outbounds_handles_all_invalid_nodes() {
        let config = Config {
            nodes: vec![
                "not-json".to_string(),
                r#"{}"#.to_string(),
                // Valid JSON but no tag r#"{"type":"hysteria2"}"#.to_string(),
            ],
            ..Default::default()
        };

        let (outbounds, names) = collect_manual_outbounds(&config);

        // All nodes fail validation (missing required fields)
        assert!(outbounds.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn build_sing_box_config_preserves_node_order() {
        let config = Config::default();

        let my_outbounds = vec![
            json!({"type": "hysteria2", "tag": "node-1", "server": "s1.example.com", "server_port": 443, "password": "p1"}),
            json!({"type": "hysteria2", "tag": "node-2", "server": "s2.example.com", "server_port": 443, "password": "p2"}),
            json!({"type": "hysteria2", "tag": "node-3", "server": "s3.example.com", "server_port": 443, "password": "p3"}),
        ];

        let built = build_sing_box_config(
            &config,
            vec![
                "node-1".to_string(),
                "node-2".to_string(),
                "node-3".to_string(),
            ],
            my_outbounds,
            vec![],
            vec![],
        )
        .unwrap();

        let selector = built["outbounds"][0]["outbounds"].as_array().unwrap();
        assert_eq!(selector.len(), 3);
        assert_eq!(selector[0], "node-1");
        assert_eq!(selector[1], "node-2");
        assert_eq!(selector[2], "node-3");
    }

    #[test]
    fn build_sing_box_config_handles_no_custom_rules() {
        let config = Config::default();

        let my_outbounds = vec![json!({
            "type": "hysteria2",
            "tag": "manual-a",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "secret"
        })];

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            my_outbounds,
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        // Tunnel mode defaults to sniff + explicit SOCKS proxy + hijack-dns + private direct.
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(rules[1]["outbound"], "proxy");
    }

    #[test]
    fn build_sing_box_config_binds_clash_api_to_localhost() {
        let config = Config::default();

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            vec![json!({
                "type": "hysteria2",
                "tag": "manual-a",
                "server": "manual.example.com",
                "server_port": 443,
                "password": "secret"
            })],
            vec![],
            vec![],
        )
        .unwrap();

        assert_eq!(
            built["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:6262"
        );
    }

    #[test]
    fn build_sing_box_config_ignores_all_invalid_custom_rules() {
        let config = Config {
            custom_rules: vec![
                "not-json".to_string(),
                "{invalid".to_string(),
                "".to_string(),
            ],
            ..Default::default()
        };

        let my_outbounds = vec![json!({
            "type": "hysteria2",
            "tag": "manual-a",
            "server": "manual.example.com",
            "server_port": 443,
            "password": "secret"
        })];

        let built = build_sing_box_config(
            &config,
            vec!["manual-a".to_string()],
            my_outbounds,
            vec![],
            vec![],
        )
        .unwrap();

        let rules = built["route"]["rules"].as_array().unwrap();
        // Tunnel mode defaults to sniff + explicit SOCKS proxy + hijack-dns + private direct.
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[1]["inbound"], json!(["socks-in"]));
        assert_eq!(rules[1]["outbound"], "proxy");
    }

    #[tokio::test]
    async fn save_config_performs_atomic_write() {
        let temp_dir = std::env::temp_dir().join(format!(
            "miao-test-save-{}-{}",
            std::process::id(),
            "atomic"
        ));
        let config_path = temp_dir.join("nested").join("config.yaml");

        let config = Config {
            port: Some(8080),
            socks_port: Some(1080),
            subs: vec!["https://example.com/sub".to_string()],
            mode: ProxyMode::Process,
            tun_process: process_proxy(ProcessListMode::Whitelist),
            ..Default::default()
        };

        save_config_to(&config_path, &config).await.unwrap();

        let content = tokio::fs::read_to_string(&config_path).await.unwrap();
        let parsed: Config = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.socks_port, Some(1080));
        assert_eq!(parsed.mode, ProxyMode::Process);
        assert_eq!(parsed.subs.len(), 1);

        // 清理
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn save_config_overwrites_existing_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "miao-test-save-{}-{}",
            std::process::id(),
            "overwrite"
        ));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let config_path = temp_dir.join("config.yaml");

        // 先创建旧配置
        tokio::fs::write(
            &config_path,
            "port: 9999\nsocks_port: 1080\nmode: global\nsubs: []\nnodes: []\ncustom_rules: []",
        )
        .await
        .unwrap();

        // 使用原子写入保存新配置
        let config = Config {
            port: Some(7777),
            socks_port: Some(2080),
            mode: ProxyMode::Pool,
            ..Default::default()
        };
        save_config_to(&config_path, &config).await.unwrap();

        let content = tokio::fs::read_to_string(&config_path).await.unwrap();
        let parsed: Config = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed.port, Some(7777));
        assert_eq!(parsed.socks_port, Some(2080));

        // 清理
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn save_config_skips_identical_content() {
        let temp_dir =
            std::env::temp_dir().join(format!("miao-test-save-{}-{}", std::process::id(), "skip"));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let config_path = temp_dir.join("config.yaml");
        let config = Config {
            port: Some(6161),
            ..Default::default()
        };

        save_config_to(&config_path, &config).await.unwrap();
        let before = tokio::fs::metadata(&config_path)
            .await
            .unwrap()
            .modified()
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        save_config_to(&config_path, &config).await.unwrap();

        let after = tokio::fs::metadata(&config_path)
            .await
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(before, after);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn build_sing_box_config_pool_has_no_tun_and_adds_fixed_routes() {
        let config = Config {
            socks_port: Some(1080),
            mode: ProxyMode::Pool,
            share: PoolConfig {
                listen: "0.0.0.0".to_string(),
                base_port: 15000,
                username: "user".to_string(),
                password: "pass".to_string(),
                legacy_enabled: false,
            },
            ..Default::default()
        };

        let mut share_map = SharePortMap::default();
        let built = super::build_sing_box_config(
            &config,
            vec!["node-a".to_string(), "node-b".to_string()],
            vec![
                json!({
                    "type": "hysteria2",
                    "tag": "node-a",
                    "server": "a.example.com",
                    "server_port": 443,
                    "password": "secret"
                }),
                json!({
                    "type": "hysteria2",
                    "tag": "node-b",
                    "server": "b.example.com",
                    "server_port": 443,
                    "password": "secret"
                }),
            ],
            vec![],
            vec![],
            &mut share_map,
            true,
        )
        .unwrap();

        let inbounds = built["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        assert!(inbounds.iter().all(|inbound| inbound["type"] != "tun"));
        assert_eq!(inbounds[1]["tag"], "share-15000");
        assert_eq!(inbounds[1]["listen_port"], 15000);
        assert_eq!(inbounds[1]["users"][0]["username"], "user");
        assert_eq!(inbounds[2]["tag"], "share-15001");

        let rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["inbound"], json!(["share-15000"]));
        assert_eq!(rules[1]["outbound"], "node-a");
        assert_eq!(rules[2]["inbound"], json!(["share-15001"]));
        assert_eq!(rules[2]["outbound"], "node-b");
        assert_eq!(
            rules[3],
            json!({"inbound": ["socks-in"], "action": "route", "outbound": "proxy"})
        );

        // 账本落在调用方手里，构建本身没有碰过磁盘。
        assert_eq!(share_map.base_port, 15000);
        assert_eq!(share_map.ports.get("node-a"), Some(&15000));
        assert_eq!(share_map.ports.get("node-b"), Some(&15001));
    }

    #[test]
    fn build_sing_box_config_pool_without_auth_omits_users() {
        let config = Config {
            socks_port: Some(1080),
            mode: ProxyMode::Pool,
            share: PoolConfig {
                listen: "0.0.0.0".to_string(),
                base_port: 16000,
                username: String::new(),
                password: String::new(),
                legacy_enabled: false,
            },
            ..Default::default()
        };

        let built = build_sing_box_config(
            &config,
            vec!["solo".to_string()],
            vec![manual_outbound()],
            vec![],
            vec![],
        )
        .unwrap();

        let inbound = &built["inbounds"].as_array().unwrap()[1];
        assert_eq!(inbound["tag"], "share-16000");
        assert_eq!(inbound["listen"], "0.0.0.0");
        assert!(inbound.get("users").is_none());
    }

    #[test]
    fn config_cache_fingerprint_includes_mode_and_pool_settings() {
        let mut first = Config::default();
        let second = first.clone();
        assert_eq!(
            config_cache_fingerprint(&first).unwrap(),
            config_cache_fingerprint(&second).unwrap()
        );

        first.mode = ProxyMode::Pool;
        first.share.base_port = 13000;
        assert_ne!(
            config_cache_fingerprint(&first).unwrap(),
            config_cache_fingerprint(&second).unwrap()
        );
    }

    #[test]
    fn pool_port_allocations_survive_mode_roundtrip() {
        let mut config = Config {
            mode: ProxyMode::Pool,
            share: PoolConfig {
                base_port: 17000,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut share_map = SharePortMap::default();
        let names = vec!["node-a".to_string(), "node-b".to_string()];
        let outbounds = vec![manual_outbound(), json!({
            "type": "hysteria2",
            "tag": "node-b",
            "server": "b.example.com",
            "server_port": 443,
            "password": "secret"
        })];

        super::build_sing_box_config(
            &config,
            names.clone(),
            outbounds.clone(),
            vec![],
            vec![],
            &mut share_map,
            true,
        )
        .unwrap();
        let assigned = share_map.ports.clone();

        config.mode = ProxyMode::Global;
        super::build_sing_box_config(
            &config,
            names.clone(),
            outbounds.clone(),
            vec![],
            vec![],
            &mut share_map,
            true,
        )
        .unwrap();
        config.mode = ProxyMode::Pool;
        super::build_sing_box_config(
            &config,
            names,
            outbounds,
            vec![],
            vec![],
            &mut share_map,
            true,
        )
        .unwrap();

        assert_eq!(share_map.ports, assigned);
    }
}
