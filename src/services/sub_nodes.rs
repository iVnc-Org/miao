use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::{SubState, SubStatus};
use crate::paths::data_file;
use crate::services::write_file_atomic;
use crate::state::AppState;

const SUB_NODES_FILE: &str = "sub_nodes.json";
const SUB_NODES_SCHEMA_VERSION: u32 = 1;
pub const SUBSCRIPTION_PARSER_VERSION: u32 = 2;
pub const LOCAL_SUBSCRIPTION_PREFIX: &str = "content://";

pub fn is_local_subscription(url: &str) -> bool {
    url.starts_with(LOCAL_SUBSCRIPTION_PREFIX)
}

/// 订阅节点的本地缓存。
///
/// 订阅链接往往只有几分钟有效期，所以"节点"必须和"链接"解耦：链接失效之后，
/// 上一次成功抓到的节点仍然要能用、要能显示。这里存的是**已解析的 sing-box
/// outbound JSON**。对于用户直接粘贴的订阅，这里还会保存原文，以便刷新时
/// 在本地重新解析，不需要访问远端链接。`build_sing_box_config` 正好消费
/// `(Vec<String>, Vec<Value>)`，重新加载时零转换。
///
/// URL 订阅的已存节点等下次成功抓取才应用解析器改进；本地内容订阅在
/// 解析器升级后的启动阶段自动重新解析，也可由用户点击刷新重新解析。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubNodeStore {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub subs: BTreeMap<String, StoredSub>,
}

impl Default for SubNodeStore {
    fn default() -> Self {
        Self {
            schema_version: SUB_NODES_SCHEMA_VERSION,
            subs: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StoredSub {
    /// 用户为本地内容订阅设置的显示名称。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 粘贴的订阅原文。URL 订阅不保存该字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default)]
    pub parser_version: u32,
    #[serde(default)]
    pub parse_details: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_warning: Option<String>,
    /// 上次成功抓取的时间，仅用于展示。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    /// 最近一次抓取尝试失败。下面的 `nodes` 是上一次成功的结果，仍然有效。
    #[serde(default)]
    pub stale: bool,
    /// 失败原因，仅用于诊断日志，不作为用户可见的错误上报。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub nodes: Vec<StoredNode>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredNode {
    pub name: String,
    pub outbound: serde_json::Value,
}

impl SubNodeStore {
    /// 丢弃已经不在配置里的订阅。删除订阅因此不需要联网。
    pub fn retain_urls(&mut self, urls: &[String]) {
        self.subs.retain(|url, _| urls.contains(url));
    }

    /// 按 `urls` 给出的顺序汇总节点，保持与抓取路径一致的排列。
    pub fn nodes_in_order(&self, urls: &[String]) -> (Vec<String>, Vec<serde_json::Value>) {
        let mut names = Vec::new();
        let mut outbounds = Vec::new();
        for url in urls {
            let Some(entry) = self.subs.get(url) else {
                continue;
            };
            for node in &entry.nodes {
                names.push(node.name.clone());
                outbounds.push(node.outbound.clone());
            }
        }
        (names, outbounds)
    }

    pub fn node_count(&self, url: &str) -> usize {
        self.subs.get(url).map_or(0, |entry| entry.nodes.len())
    }

    /// 缓存里是否一个节点都没有——用于判断要不要做一次首装抓取。
    pub fn is_empty_for(&self, urls: &[String]) -> bool {
        !urls
            .iter()
            .any(|url| self.subs.get(url).is_some_and(|e| !e.nodes.is_empty()))
    }

    pub fn record_success(
        &mut self,
        url: &str,
        nodes: Vec<StoredNode>,
        fetched_at: Option<String>,
    ) {
        let (name, content) = self
            .subs
            .get(url)
            .map(|entry| (entry.name.clone(), entry.content.clone()))
            .unwrap_or_default();
        self.subs.insert(
            url.to_string(),
            StoredSub {
                name,
                content,
                parser_version: SUBSCRIPTION_PARSER_VERSION,
                parse_details: vec![],
                parse_warning: None,
                fetched_at,
                stale: false,
                last_error: None,
                nodes,
            },
        );
    }

    pub fn record_local_success(
        &mut self,
        url: &str,
        name: Option<String>,
        content: String,
        nodes: Vec<StoredNode>,
        fetched_at: Option<String>,
    ) {
        self.subs.insert(
            url.to_string(),
            StoredSub {
                name,
                content: Some(content),
                parser_version: SUBSCRIPTION_PARSER_VERSION,
                parse_details: vec![],
                parse_warning: None,
                fetched_at,
                stale: false,
                last_error: None,
                nodes,
            },
        );
    }

    /// 记录一次失败，**保留已有节点**。这是"链接失效但节点还能用"的核心。
    pub fn record_failure(&mut self, url: &str, error: String) {
        let entry = self.subs.entry(url.to_string()).or_default();
        entry.stale = true;
        entry.last_error = Some(error);
    }

    pub fn status_for(&self, url: &str) -> SubStatus {
        match self.subs.get(url) {
            Some(entry) if entry.stale => SubStatus {
                url: url.to_string(),
                name: entry.name.clone(),
                local: entry.content.is_some() || is_local_subscription(url),
                state: SubState::Expired,
                node_count: entry.nodes.len(),
                details: entry.parse_details.clone(),
                error: None,
            },
            Some(entry) => SubStatus {
                url: url.to_string(),
                name: entry.name.clone(),
                local: entry.content.is_some() || is_local_subscription(url),
                state: SubState::Cached,
                node_count: entry.nodes.len(),
                details: entry.parse_details.clone(),
                error: entry.parse_warning.clone(),
            },
            None => SubStatus {
                url: url.to_string(),
                name: None,
                local: is_local_subscription(url),
                state: SubState::Pending,
                node_count: 0,
                details: vec![],
                error: None,
            },
        }
    }
}

pub fn sub_nodes_path() -> PathBuf {
    data_file(SUB_NODES_FILE)
}

/// Reparse local originals once after a parser upgrade. Never discard a working cache on failure.
fn migrate_local_store(store: &mut SubNodeStore) -> bool {
    let mut changed = false;
    for (source, entry) in &mut store.subs {
        if !is_local_subscription(source) || entry.parser_version >= SUBSCRIPTION_PARSER_VERSION {
            continue;
        }
        let Some(content) = &entry.content else {
            continue;
        };
        let Ok(parsed) = crate::services::subscription::parse_subscription_text(source, content)
        else {
            continue;
        };
        if parsed.node_names.is_empty() || parsed.has_skipped_nodes() {
            continue;
        }
        entry.parse_warning = parsed.diagnostic_summary();
        entry.parse_details = parsed.details();
        entry.nodes = parsed
            .node_names
            .into_iter()
            .zip(parsed.outbounds)
            .map(|(name, outbound)| StoredNode { name, outbound })
            .collect();
        entry.parser_version = SUBSCRIPTION_PARSER_VERSION;
        entry.stale = false;
        entry.last_error = None;
        changed = true;
    }
    changed
}

pub async fn migrate_local_subscriptions() -> AppResult<()> {
    migrate_local_subscriptions_from(
        &sub_nodes_path(),
        &crate::services::singbox::get_sing_box_home().join("config.json"),
    )
    .await
}

async fn migrate_local_subscriptions_from(cache: &Path, runtime_config: &Path) -> AppResult<()> {
    let mut store = load_sub_nodes_from(cache).await;
    if migrate_local_store(&mut store) {
        // Invalidate before saving the migration marker: a crash must not leave migrated
        // nodes paired with an old runtime config, including when the service was stopped.
        match tokio::fs::remove_file(runtime_config).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(AppError::context(
                    "Failed to invalidate migrated runtime config",
                    e,
                ))
            }
        }
        save_sub_nodes_to(cache, &store).await?;
    }
    Ok(())
}

pub async fn load_sub_nodes() -> SubNodeStore {
    load_sub_nodes_from(&sub_nodes_path()).await
}

pub async fn load_sub_nodes_from(path: &Path) -> SubNodeStore {
    let Ok(content) = tokio::fs::read_to_string(path).await else {
        return SubNodeStore::default();
    };
    match serde_json::from_str::<SubNodeStore>(&content) {
        Ok(store) if store.schema_version == SUB_NODES_SCHEMA_VERSION => store,
        Ok(store) => {
            tracing::warn!(
                path = ?path,
                found = store.schema_version,
                expected = SUB_NODES_SCHEMA_VERSION,
                "Subscription node cache schema mismatch, discarding"
            );
            SubNodeStore::default()
        }
        Err(e) => {
            tracing::warn!(path = ?path, error = %e, "Failed to parse subscription node cache, discarding");
            SubNodeStore::default()
        }
    }
}

pub async fn save_sub_nodes(store: &SubNodeStore) -> AppResult<()> {
    save_sub_nodes_to(&sub_nodes_path(), store).await
}

pub async fn save_sub_nodes_to(path: &Path, store: &SubNodeStore) -> AppResult<()> {
    let content = serde_json::to_string_pretty(store)
        .map_err(|e| AppError::context("Failed to serialize subscription node cache", e))?;
    write_file_atomic(path, &content, "subscription node cache").await?;
    // 这个文件含订阅原文、节点密码和 UUID，和 ~/.miao/config.json 同级敏感。
    restrict_permissions(path).await;
    Ok(())
}

#[cfg(unix)]
async fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await {
        tracing::warn!(path = ?path, error = %e, "Failed to restrict subscription cache permissions");
    }
}

#[cfg(not(unix))]
async fn restrict_permissions(_path: &Path) {}

/// 启动时用缓存回填订阅状态，这样面板一打开就能显示真实节点数，
/// 而不是等到某次抓取之后才有数字。
pub async fn hydrate_sub_status(state: &Arc<AppState>, urls: &[String]) {
    let store = load_sub_nodes().await;
    let mut status_map = state.sub_status.lock().await;
    status_map.retain(|url, _| urls.contains(url));
    for url in urls {
        status_map.insert(url.clone(), store.status_for(url));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> StoredNode {
        StoredNode {
            name: name.to_string(),
            outbound: serde_json::json!({"type": "socks", "tag": name}),
        }
    }

    fn store_with(url: &str, names: &[&str]) -> SubNodeStore {
        let mut store = SubNodeStore::default();
        store.record_success(url, names.iter().map(|n| node(n)).collect(), None);
        store
    }

    #[test]
    fn retain_urls_drops_removed_subscriptions() {
        let mut store = store_with("a", &["n1"]);
        store.record_success("b", vec![node("n2")], None);

        store.retain_urls(&["a".to_string()]);

        assert!(store.subs.contains_key("a"));
        assert!(!store.subs.contains_key("b"));
    }

    #[test]
    fn nodes_in_order_follows_url_order() {
        let mut store = store_with("a", &["a1", "a2"]);
        store.record_success("b", vec![node("b1")], None);

        let (names, outbounds) = store.nodes_in_order(&["b".to_string(), "a".to_string()]);

        assert_eq!(names, vec!["b1", "a1", "a2"]);
        assert_eq!(outbounds.len(), 3);
    }

    #[test]
    fn failure_keeps_previous_nodes() {
        let mut store = store_with("a", &["n1", "n2"]);

        store.record_failure("a", "timeout".to_string());

        let entry = &store.subs["a"];
        assert!(entry.stale);
        assert_eq!(entry.nodes.len(), 2, "失效不能清掉已抓到的节点");
        assert_eq!(entry.last_error.as_deref(), Some("timeout"));
    }

    #[test]
    fn expired_status_reports_retained_nodes_without_error() {
        let mut store = store_with("a", &["n1", "n2"]);
        store.record_failure("a", "timeout".to_string());

        let status = store.status_for("a");

        assert_eq!(status.state, SubState::Expired);
        assert_eq!(status.node_count, 2);
        // error 留给真正可操作的问题；链接失效不算，否则前端会渲染成红色异常。
        assert!(status.error.is_none());
    }

    #[test]
    fn success_after_failure_clears_stale() {
        let mut store = store_with("a", &["n1"]);
        store.record_failure("a", "timeout".to_string());
        store.record_success("a", vec![node("n1"), node("n2")], None);

        let entry = &store.subs["a"];
        assert!(!entry.stale);
        assert!(entry.last_error.is_none());
        assert_eq!(entry.nodes.len(), 2);
        assert_eq!(store.status_for("a").state, SubState::Cached);
    }

    #[test]
    fn parser_migration_repairs_local_nodes_and_preserves_failed_or_remote_entries() {
        use base64::Engine as _;
        let source = "content://old-http";
        let mut store = SubNodeStore::default();
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("User:pass@proxy.example.com:443/#香港");
        store.record_local_success(
            source,
            Some("Ghelper".into()),
            format!("https://{encoded}\nhy2://secret@example.com?fastopen=1#HY"),
            vec![node("garbled")],
            None,
        );
        let entry = store.subs.get_mut(source).unwrap();
        entry.parser_version = 0;
        entry.parse_warning = Some("old warning".into());
        store.record_local_success(
            "content://invalid",
            None,
            "https://user:secret@host:0".into(),
            vec![node("working")],
            None,
        );
        store
            .subs
            .get_mut("content://invalid")
            .unwrap()
            .parser_version = 0;
        store.record_success("https://remote.example.com", vec![node("remote")], None);
        store
            .subs
            .get_mut("https://remote.example.com")
            .unwrap()
            .parser_version = 0;
        let invalid = store.subs["content://invalid"].clone();
        let remote = store.subs["https://remote.example.com"].clone();
        // Legacy import_http_proxies values deserialize harmlessly; the parser no longer consults them.
        let mut json = serde_json::to_value(&store).unwrap();
        json["subs"][source]["import_http_proxies"] = serde_json::json!(false);
        store = serde_json::from_value(json).unwrap();
        assert!(migrate_local_store(&mut store));
        let migrated = &store.subs[source];
        assert_eq!(migrated.name.as_deref(), Some("Ghelper"));
        assert_eq!(migrated.nodes.len(), 2);
        assert_eq!(migrated.nodes[0].name, "香港");
        assert_eq!(migrated.nodes[0].outbound["username"], "User");
        assert!(migrated.parse_warning.is_none());
        assert_eq!(migrated.parse_details.len(), 1);
        assert_eq!(migrated.parser_version, SUBSCRIPTION_PARSER_VERSION);
        assert_eq!(store.subs["content://invalid"], invalid);
        assert_eq!(store.subs["https://remote.example.com"], remote);
        assert!(!migrate_local_store(&mut store));
        let reloaded: SubNodeStore =
            serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
        assert_eq!(reloaded, store);
        assert!(reloaded.status_for(source).error.is_none());
        assert_eq!(reloaded.status_for(source).details.len(), 1);
    }

    #[tokio::test]
    async fn migration_persists_repaired_nodes_and_invalidates_stopped_runtime_config() {
        let state = crate::test_support::app_state(crate::models::Config::default());
        let cache = state.config_path.with_extension("sub_nodes.json");
        let runtime = state.config_path.with_extension("runtime-config.json");
        let mut store = SubNodeStore::default();
        store.record_local_success(
            "content://legacy",
            None,
            "https://user:pass@proxy.example.com:8443#HTTPS".into(),
            vec![node("wrong")],
            None,
        );
        store
            .subs
            .get_mut("content://legacy")
            .unwrap()
            .parser_version = 0;
        save_sub_nodes_to(&cache, &store).await.unwrap();
        tokio::fs::write(&runtime, "old config").await.unwrap();
        migrate_local_subscriptions_from(&cache, &runtime)
            .await
            .unwrap();
        assert!(!runtime.exists());
        let store = load_sub_nodes_from(&cache).await;
        assert_eq!(store.subs["content://legacy"].nodes[0].name, "HTTPS");
        assert_eq!(
            store.subs["content://legacy"].parser_version,
            SUBSCRIPTION_PARSER_VERSION
        );
        // Once migration has completed it must not delete a freshly generated config.
        tokio::fs::write(&runtime, "new config").await.unwrap();
        migrate_local_subscriptions_from(&cache, &runtime)
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read_to_string(&runtime).await.unwrap(),
            "new config"
        );
        tokio::fs::remove_file(cache).await.unwrap();
        tokio::fs::remove_file(runtime).await.unwrap();
    }

    #[test]
    fn local_subscription_metadata_survives_node_refresh() {
        let source = format!("{}digest", LOCAL_SUBSCRIPTION_PREFIX);
        let mut store = SubNodeStore::default();
        store.record_local_success(
            &source,
            Some("Local backup".to_string()),
            "cHJveGllczogW10=".to_string(),
            vec![node("n1")],
            None,
        );

        store.subs.get_mut(&source).unwrap().parse_warning = Some("1 invalid entry".into());
        let encoded = serde_json::to_string(&store).unwrap();
        store = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            store.status_for(&source).error.as_deref(),
            Some("1 invalid entry")
        );
        store.record_success(&source, vec![node("n2")], None);

        let entry = &store.subs[&source];
        assert_eq!(entry.name.as_deref(), Some("Local backup"));
        assert_eq!(entry.content.as_deref(), Some("cHJveGllczogW10="));
        assert_eq!(entry.nodes[0].name, "n2");
        assert_eq!(entry.parser_version, SUBSCRIPTION_PARSER_VERSION);
        let status = store.status_for(&source);
        assert!(status.local);
        assert_eq!(status.name.as_deref(), Some("Local backup"));
    }

    #[test]
    fn is_empty_for_drives_the_bootstrap_decision() {
        let urls = vec!["a".to_string(), "b".to_string()];

        // 空缓存 => 允许做一次首装抓取
        assert!(SubNodeStore::default().is_empty_for(&urls));

        // 任何一个订阅有节点 => 不再自动抓取
        let store = store_with("a", &["n1"]);
        assert!(!store.is_empty_for(&urls));
    }

    #[tokio::test]
    async fn round_trips_through_disk() {
        let path = std::env::temp_dir().join(format!(
            "miao-sub-nodes-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = store_with("https://example.com/sub", &["n1", "n2"]);
        store.record_failure("https://example.com/sub", "boom".to_string());

        save_sub_nodes_to(&path, &store).await.unwrap();
        let loaded = load_sub_nodes_from(&path).await;

        assert_eq!(loaded.subs, store.subs);
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn unreadable_or_stale_schema_yields_empty_store() {
        let missing = std::env::temp_dir().join("miao-sub-nodes-does-not-exist.json");
        assert!(load_sub_nodes_from(&missing).await.subs.is_empty());

        let path = std::env::temp_dir().join(format!(
            "miao-sub-nodes-badschema-{}.json",
            std::process::id()
        ));
        tokio::fs::write(
            &path,
            r#"{"schema_version": 999, "subs": {"a": {"nodes": []}}}"#,
        )
        .await
        .unwrap();
        assert!(load_sub_nodes_from(&path).await.subs.is_empty());
        let _ = tokio::fs::remove_file(&path).await;
    }
}
