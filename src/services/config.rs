use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::error::{AppError, AppResult};
use crate::models::{Config, RouteMode, SubStatus, DEFAULT_SOCKS_LISTEN, DEFAULT_SOCKS_PORT};
use crate::services::{
    proxy::restore_last_proxy,
    singbox::{
        get_sing_box_home, start_sing_internal, stop_sing_internal, validate_sing_box_config,
    },
    subscription::fetch_sub,
};
use crate::state::AppState;

const CONFIG_CACHE_DIR: &str = "data/cache";
const CONFIG_CACHE_FILE: &str = "config.json";
const CONFIG_CACHE_META_FILE: &str = "config.meta.json";
const CONFIG_CACHE_SCHEMA_VERSION: u32 = 2;
const MAX_CONCURRENT_SUBS: usize = 5;

#[derive(Serialize, Deserialize)]
struct ConfigCacheMeta {
    fingerprint: String,
}

pub fn get_config_cache_path() -> PathBuf {
    PathBuf::from(CONFIG_CACHE_DIR).join(CONFIG_CACHE_FILE)
}

fn get_config_cache_meta_path() -> PathBuf {
    PathBuf::from(CONFIG_CACHE_DIR).join(CONFIG_CACHE_META_FILE)
}

fn config_cache_fingerprint(config: &Config) -> AppResult<String> {
    let value = serde_json::json!({
        "schema_version": CONFIG_CACHE_SCHEMA_VERSION,
        "socks_listen": &config.socks_listen,
        "socks_port": config.socks_port,
        "route_mode": &config.route_mode,
        "subs": &config.subs,
        "nodes": &config.nodes,
        "custom_rules": &config.custom_rules,
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

/// 原子写入文件：先写入临时文件，再重命名为目标文件
async fn write_file_atomic(path: &std::path::Path, content: &str) -> AppResult<()> {
    let temp_path = path.with_extension("tmp");

    // 先写入临时文件
    tokio::fs::write(&temp_path, content)
        .await
        .map_err(|e| AppError::context("Failed to write temp file", e))?;

    // 原子重命名为最终文件
    tokio::fs::rename(&temp_path, path)
        .await
        .map_err(|e| AppError::context("Failed to atomically rename file", e))?;

    Ok(())
}

pub async fn save_config(config: &Config) -> AppResult<()> {
    let yaml = serde_yaml::to_string(config)?;
    write_file_atomic(std::path::Path::new("config.yaml"), &yaml).await
}

pub async fn save_config_cache(config: &Config) {
    let config_path = get_sing_box_home().join("config.json");
    let cache_path = get_config_cache_path();
    let meta_path = get_config_cache_meta_path();

    if let Err(e) = tokio::fs::create_dir_all(CONFIG_CACHE_DIR).await {
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

    if let Err(e) = write_file_atomic(&meta_path, &meta).await {
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
    write_file_atomic(&config_path, &cached_config)
        .await
        .map_err(|e| AppError::context("Failed to restore config from cache", e))?;
    validate_sing_box_config()
        .await
        .map_err(|e| AppError::context("Cached config validation failed", e))?;
    write_file_atomic(&cache, &cached_config)
        .await
        .map_err(|e| AppError::context("Failed to update normalized config cache", e))?;
    info!(cache = ?cache, "Restored config from cache");
    Ok(())
}

pub async fn regenerate_and_restart(config: &Config, state: &Arc<AppState>) -> AppResult<()> {
    let has_sub_nodes = gen_config(config, state)
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

    *state.config_source.lock().await = Some("generated".to_string());

    if has_sub_nodes || config.subs.is_empty() {
        save_config_cache(config).await;
        *state.config_warning.lock().await = None;
    } else if !config.subs.is_empty() {
        *state.config_warning.lock().await = Some("所有订阅获取失败，请检查当前订阅".to_string());
    } else {
        *state.config_warning.lock().await = None;
    }

    let state_for_proxy = state.clone();
    tokio::spawn(async move {
        restore_last_proxy(&state_for_proxy).await;
    });

    Ok(())
}

pub async fn apply_config_change(
    state: &Arc<AppState>,
    old_config: &Config,
    new_config: &Config,
) -> AppResult<()> {
    let config_path = std::path::Path::new("config.yaml");
    let backup_path = std::path::Path::new("config.yaml.bak");

    // 修改前先备份当前配置文件，确保回滚时可从磁盘恢复
    if config_path.exists() {
        tokio::fs::copy(config_path, backup_path)
            .await
            .map_err(|e| AppError::context("Failed to backup config before applying change", e))?;
    }

    save_config(new_config).await?;

    if config_has_no_nodes(new_config) {
        stop_sing_internal(state).await;
        clear_generated_config_state().await;
        {
            let mut status_map = state.sub_status.lock().await;
            status_map.retain(|url, _| new_config.subs.contains(url));
        }
        *state.config.write().await = new_config.clone();
        *state.config_source.lock().await = None;
        *state.config_warning.lock().await = None;
        let _ = tokio::fs::remove_file(backup_path).await;
        return Ok(());
    }

    let was_running = sing_box_process_is_running(state).await;

    match regenerate_and_restart(new_config, state).await {
        Ok(()) => {
            *state.config.write().await = new_config.clone();
            let _ = tokio::fs::remove_file(backup_path).await;
            Ok(())
        }
        Err(apply_err) => {
            error!(error = %apply_err, "Failed to apply config change, attempting rollback");

            let rollback_result = async {
                // 从备份文件恢复，避免重新序列化导致格式差异或磁盘满时失败
                if backup_path.exists() {
                    tokio::fs::copy(backup_path, config_path)
                        .await
                        .map_err(|e| {
                            AppError::context("Failed to restore config from backup", e)
                        })?;
                } else {
                    save_config(old_config).await?;
                }

                // 检查 sing-box 是否仍在运行（配置校验或生成失败时进程未被停止）
                let still_running = {
                    let mut lock = state.sing_process.lock().await;
                    match &mut *lock {
                        Some(proc) => proc.child.try_wait().ok().flatten().is_none(),
                        None => false,
                    }
                };

                if still_running {
                    // sing-box 仍以旧配置运行，无需重启，config.yaml 已恢复
                    info!("sing-box still running with previous config, skipping restart");
                } else if was_running {
                    // 优先从 config.json 缓存恢复，避免重新拉取订阅
                    if get_config_cache_path().exists() {
                        info!("Restoring config.json from cache for rollback");
                        restore_config_from_cache(old_config).await?;
                        start_sing_internal(state).await.map_err(|e| {
                            AppError::context("Failed to restart sing-box with cached config", e)
                        })?;
                        *state.config_source.lock().await = Some("cache".to_string());
                        *state.config_warning.lock().await = None;
                        let state_for_proxy = state.clone();
                        tokio::spawn(async move {
                            restore_last_proxy(&state_for_proxy).await;
                        });
                    } else {
                        // 无缓存，只能重新生成（会重新拉取订阅）
                        warn!("No config cache available, falling back to full regeneration");
                        regenerate_and_restart(old_config, state).await?;
                    }
                } else {
                    info!("sing-box was stopped before config change, skipping rollback restart");
                }
                Ok::<(), AppError>(())
            }
            .await;

            let _ = tokio::fs::remove_file(backup_path).await;

            match rollback_result {
                Ok(()) => Err(AppError::context(
                    "Failed to apply config change; rolled back to previous config",
                    apply_err,
                )),
                Err(rollback_err) => Err(AppError::message(format!(
                    "Failed to apply config change: {}. Rollback failed: {}",
                    apply_err, rollback_err
                ))),
            }
        }
    }
}

fn config_has_no_nodes(config: &Config) -> bool {
    config.subs.is_empty() && config.nodes.is_empty()
}

async fn sing_box_process_is_running(state: &Arc<AppState>) -> bool {
    let mut lock = state.sing_process.lock().await;
    match &mut *lock {
        Some(proc) => proc.child.try_wait().ok().flatten().is_none(),
        None => false,
    }
}

/// Returns `true` if at least one subscription node was fetched successfully.
pub async fn gen_config(config: &Config, state: &Arc<AppState>) -> AppResult<bool> {
    let (my_outbounds, my_names) = collect_manual_outbounds(config);
    let mut final_outbounds: Vec<serde_json::Value> = vec![];
    let mut final_node_names: Vec<String> = vec![];

    {
        let mut status_map = state.sub_status.lock().await;
        status_map.retain(|url, _| config.subs.contains(url));
    }

    let sub_futures: Vec<_> = config
        .subs
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
                        error!(url = %sub, error = %e, "Failed to fetch subscription");
                        (sub.clone(), Err(e.to_string()))
                    }
                    Err(_) => {
                        error!(url = %sub, timeout_secs = 30, "Subscription fetch timed out");
                        (sub.clone(), Err("Request timeout".to_string()))
                    }
                }
            }
        })
        .collect();

    // 使用 buffer_unordered 限制并发数，避免同时发起过多请求
    let mut results: Vec<_> = stream::iter(sub_futures)
        .buffer_unordered(MAX_CONCURRENT_SUBS)
        .collect()
        .await;

    // 按原始顺序排序结果
    let subs_order: Vec<String> = config.subs.clone();
    results.sort_by_key(|(url, _)| {
        subs_order
            .iter()
            .position(|s| s == url)
            .unwrap_or(usize::MAX)
    });

    for (url, result) in results {
        let status = match result {
            Ok(fetch_result) => {
                let count = fetch_result.node_names.len();
                final_node_names.extend(fetch_result.node_names);
                final_outbounds.extend(fetch_result.outbounds);

                let error_info = if !fetch_result.parse_errors.is_empty() {
                    Some(format!(
                        "{} nodes skipped due to parse errors",
                        fetch_result.parse_errors.len()
                    ))
                } else if count == 0 && fetch_result.total_count > 0 {
                    Some("All nodes invalid (missing required fields)".into())
                } else if count == 0 {
                    Some("No nodes found".into())
                } else {
                    None
                };

                SubStatus {
                    url: url.clone(),
                    success: count > 0,
                    node_count: count,
                    error: error_info,
                }
            }
            Err(e) => SubStatus {
                url: url.clone(),
                success: false,
                node_count: 0,
                error: Some(e),
            },
        };
        state.sub_status.lock().await.insert(url, status);
    }

    let has_sub_nodes = !final_node_names.is_empty();

    let sing_box_config = build_sing_box_config(
        config,
        my_names,
        my_outbounds,
        final_node_names,
        final_outbounds,
    )?;

    let sing_box_home = get_sing_box_home();
    let config_output_loc = sing_box_home.join("config.json");
    write_file_atomic(
        &config_output_loc,
        &serde_json::to_string(&sing_box_config)?,
    )
    .await?;

    Ok(has_sub_nodes)
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

fn build_sing_box_config(
    config: &Config,
    my_names: Vec<String>,
    my_outbounds: Vec<serde_json::Value>,
    final_node_names: Vec<String>,
    final_outbounds: Vec<serde_json::Value>,
) -> AppResult<serde_json::Value> {
    let total_nodes = my_outbounds.len() + final_outbounds.len();
    if total_nodes == 0 {
        return Err(AppError::message(
            "No nodes available: all subscriptions failed and no manual nodes configured",
        ));
    }

    let route_mode = config.route_mode.clone().unwrap_or_default();
    let mut sing_box_config = get_config_template(&route_mode);
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
    if let Some(inbounds) = sing_box_config["inbounds"].as_array_mut() {
        inbounds.push(serde_json::json!({
            "type": "socks",
            "tag": "socks-in",
            "listen": socks_listen,
            "listen_port": socks_port
        }));
    }

    if let Some(outbounds) = sing_box_config["outbounds"][0].get_mut("outbounds") {
        if let Some(arr) = outbounds.as_array_mut() {
            arr.extend(
                my_names
                    .into_iter()
                    .chain(final_node_names.into_iter())
                    .map(serde_json::Value::String),
            );
        }
    }
    if let Some(arr) = sing_box_config["outbounds"].as_array_mut() {
        arr.extend(my_outbounds.into_iter().chain(final_outbounds.into_iter()));
    }

    if let Some(rules) = sing_box_config["route"]["rules"].as_array_mut() {
        for rule_str in &config.custom_rules {
            if let Ok(rule_json) = serde_json::from_str::<serde_json::Value>(rule_str) {
                rules.push(rule_json);
            } else {
                warn!("Failed to parse custom rule: {}", rule_str);
            }
        }
    }

    Ok(sing_box_config)
}

fn get_config_template(route_mode: &RouteMode) -> serde_json::Value {
    let mut route_rules = vec![
        serde_json::json!({"action": "sniff"}),
        serde_json::json!({"protocol": "dns", "action": "hijack-dns"}),
    ];

    let (dns_rules, default_domain_resolver) = match route_mode {
        RouteMode::Tunnel => {
            route_rules.push(
                serde_json::json!({"ip_is_private": true, "action": "route", "outbound": "direct"}),
            );
            (Vec::new(), "local")
        }
        RouteMode::Global => {
            route_rules.push(
                serde_json::json!({"ip_is_private": true, "action": "route", "outbound": "direct"}),
            );
            (
                vec![serde_json::json!({
                    "rule_set": ["chinasite"],
                    "action": "route",
                    "server": "local"
                })],
                "local",
            )
        }
        RouteMode::Rule => {
            route_rules.push(
                serde_json::json!({"ip_is_private": true, "action": "route", "outbound": "direct"}),
            );
            route_rules.push(serde_json::json!({
                "rule_set": ["chinaip", "chinasite"],
                "action": "route",
                "outbound": "direct"
            }));
            (
                vec![serde_json::json!({
                    "rule_set": ["chinasite"],
                    "action": "route",
                    "server": "local"
                })],
                "local",
            )
        }
    };

    serde_json::json!({
        "log": {"disabled": false, "timestamp": true, "level": "info"},
        "experimental": {"clash_api": {"external_controller": "0.0.0.0:6262", "access_control_allow_origin": ["*"]}},
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
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "sing-tun", "address": ["172.18.0.1/30"], "mtu": 9000, "auto_route": true, "strict_route": true, "auto_redirect": true, "dns_mode": "disabled"}
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": []},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "final": "proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": default_domain_resolver,
            "rules": route_rules,
            "rule_set": [
                {"type": "local", "tag": "chinasite", "format": "binary", "path": "./chinasite.srs"},
                {"type": "local", "tag": "chinaip", "format": "binary", "path": "./chinaip.srs"}
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_sing_box_config, collect_manual_outbounds, config_cache_fingerprint,
        normalize_cached_sing_box_config,
    };
    use crate::models::{Config, RouteMode};
    use serde_json::json;

    #[test]
    fn collect_manual_outbounds_ignores_invalid_json_nodes() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![
                r#"{"type":"hysteria2","tag":"manual-a","server":"a.example.com","server_port":443,"password":"p","up_mbps":40,"down_mbps":350,"tls":{"enabled":true,"insecure":true}}"#.to_string(),
                "{invalid-json".to_string(),
            ],
            custom_rules: vec![],
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
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![
                // 不包含 up_mbps/down_mbps 的节点
                r#"{"type":"hysteria2","tag":"no-bandwidth","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true}}"#.to_string(),
            ],
            custom_rules: vec![],
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
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![
                r#"{"type":"socks","tag":"socks-a","server":"socks.example.com","server_port":1080}"#.to_string(),
                r#"{"type":"http","tag":"http-a","server":"http.example.com","server_port":8080,"username":"user","password":"pass"}"#.to_string(),
            ],
            custom_rules: vec![],
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
            port: None,
            socks_listen: None,
            socks_port: Some(1080),
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![
                r#"{"domain_suffix":["example.com"],"action":"route","outbound":"proxy"}"#
                    .to_string(),
                "not-json".to_string(),
            ],
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
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[3]["domain_suffix"][0], "example.com");
    }

    #[test]
    fn build_sing_box_config_uses_configured_socks_listen_and_port() {
        let config = Config {
            port: None,
            socks_listen: Some("0.0.0.0".to_string()),
            socks_port: Some(2080),
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
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
    fn build_sing_box_config_defaults_to_tunnel_mode_with_local_socks() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
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

        let inbounds = built["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[1]["type"], "socks");
        assert_eq!(inbounds[1]["listen"], "127.0.0.1");
        assert_eq!(inbounds[1]["listen_port"], 1080);

        let dns_rules = built["dns"]["rules"].as_array().unwrap();
        assert!(dns_rules.is_empty());

        let route_rules = built["route"]["rules"].as_array().unwrap();
        assert_eq!(route_rules.len(), 3);
        assert_eq!(route_rules[0]["action"], "sniff");
        assert_eq!(route_rules[1]["action"], "hijack-dns");
        assert_eq!(route_rules[2]["ip_is_private"], true);
        assert_eq!(route_rules[2]["outbound"], "direct");
        assert_eq!(built["route"]["default_domain_resolver"], "local");
    }

    #[test]
    fn build_sing_box_config_supports_global_mode_private_direct() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: Some(RouteMode::Global),
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
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
        assert_eq!(route_rules.len(), 3);
        assert_eq!(route_rules[2]["ip_is_private"], true);
        assert_eq!(route_rules[2]["outbound"], "direct");
        assert_eq!(built["route"]["default_domain_resolver"], "local");
    }

    #[test]
    fn build_sing_box_config_supports_rule_mode_domestic_bypass() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: Some(RouteMode::Rule),
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
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
        assert_eq!(route_rules[2]["ip_is_private"], true);
        assert_eq!(route_rules[3]["outbound"], "direct");
        assert_eq!(route_rules[3]["rule_set"][0], "chinaip");
        assert_eq!(built["route"]["default_domain_resolver"], "local");
    }

    #[test]
    fn config_cache_fingerprint_ignores_web_port() {
        let mut first = Config {
            port: Some(6161),
            socks_listen: None,
            socks_port: Some(1080),
            route_mode: Some(RouteMode::Tunnel),
            subs: vec!["https://example.com/sub".to_string()],
            nodes: vec![],
            custom_rules: vec![],
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
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
        };

        let err = build_sing_box_config(&config, vec![], vec![], vec![], vec![]).unwrap_err();

        assert!(err.to_string().contains(
            "No nodes available: all subscriptions failed and no manual nodes configured"
        ));
    }

    #[test]
    fn config_has_no_nodes_only_when_subs_and_manual_nodes_empty() {
        assert!(super::config_has_no_nodes(&Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
        }));

        assert!(!super::config_has_no_nodes(&Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec!["https://example.com/sub".to_string()],
            nodes: vec![],
            custom_rules: vec![],
        }));

        assert!(!super::config_has_no_nodes(&Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![r#"{"tag":"manual"}"#.to_string()],
            custom_rules: vec![],
        }));
    }

    #[test]
    fn collect_manual_outbounds_handles_empty_nodes() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
        };

        let (outbounds, names) = collect_manual_outbounds(&config);

        assert!(outbounds.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn collect_manual_outbounds_handles_all_invalid_nodes() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![
                "not-json".to_string(),
                r#"{}"#.to_string(),                   // Valid JSON but no tag
                r#"{"type":"hysteria2"}"#.to_string(), // Valid JSON but no tag
            ],
            custom_rules: vec![],
        };

        let (outbounds, names) = collect_manual_outbounds(&config);

        // All nodes fail validation (missing required fields)
        assert!(outbounds.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn build_sing_box_config_preserves_node_order() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
        };

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
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
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
        // Tunnel mode defaults to sniff + hijack-dns + private direct
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn build_sing_box_config_ignores_all_invalid_custom_rules() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            route_mode: None,
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![
                "not-json".to_string(),
                "{invalid".to_string(),
                "".to_string(),
            ],
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
        // Tunnel mode defaults to sniff + hijack-dns + private direct
        assert_eq!(rules.len(), 3);
    }

    #[tokio::test]
    async fn save_config_performs_atomic_write() {
        let temp_dir = std::env::temp_dir().join(format!("miao-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let config = Config {
            port: Some(8080),
            socks_listen: None,
            socks_port: Some(1080),
            route_mode: Some(RouteMode::Rule),
            subs: vec!["https://example.com/sub".to_string()],
            nodes: vec![],
            custom_rules: vec![],
        };

        // 使用绝对路径保存配置
        let config_path = temp_dir.join("config.yaml");
        let temp_config_path = temp_dir.join("config.yaml.tmp");
        let yaml = serde_yaml::to_string(&config).unwrap();

        tokio::fs::write(&temp_config_path, yaml).await.unwrap();
        tokio::fs::rename(&temp_config_path, &config_path)
            .await
            .unwrap();

        // 验证文件存在且格式正确
        let content = tokio::fs::read_to_string(&config_path).await.unwrap();
        let parsed: Config = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.socks_port, Some(1080));
        assert_eq!(parsed.route_mode, Some(RouteMode::Rule));
        assert_eq!(parsed.subs.len(), 1);

        // 清理
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn save_config_overwrites_existing_file() {
        let temp_dir =
            std::env::temp_dir().join(format!("miao-test-overwrite-{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let config_path = temp_dir.join("config.yaml");

        // 先创建旧配置
        tokio::fs::write(
            &config_path,
            "port: 9999\nsocks_port: 1080\nroute_mode: tunnel\nsubs: []\nnodes: []\ncustom_rules: []",
        )
        .await
        .unwrap();

        // 使用原子写入保存新配置
        let config = Config {
            port: Some(7777),
            socks_listen: None,
            socks_port: Some(2080),
            route_mode: Some(RouteMode::Rule),
            subs: vec![],
            nodes: vec![],
            custom_rules: vec![],
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let temp_config_path = temp_dir.join("config.yaml.tmp");
        tokio::fs::write(&temp_config_path, yaml).await.unwrap();
        tokio::fs::rename(&temp_config_path, &config_path)
            .await
            .unwrap();

        // 验证被覆盖
        let content = tokio::fs::read_to_string(&config_path).await.unwrap();
        let parsed: Config = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed.port, Some(7777));
        assert_eq!(parsed.socks_port, Some(2080));
        assert_eq!(parsed.route_mode, Some(RouteMode::Rule));

        // 清理
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
