use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::{SubState, SubStatus};
use crate::services::write_file_atomic;
use crate::state::AppState;

const SUB_NODES_DIR: &str = "data/cache";
const SUB_NODES_FILE: &str = "sub_nodes.json";
const SUB_NODES_SCHEMA_VERSION: u32 = 1;

/// 订阅节点的本地缓存。
///
/// 订阅链接往往只有几分钟有效期，所以"节点"必须和"链接"解耦：链接失效之后，
/// 上一次成功抓到的节点仍然要能用、要能显示。这里存的是**已解析的 sing-box
/// outbound JSON**，而不是订阅原文——`build_sing_box_config` 正好消费
/// `(Vec<String>, Vec<Value>)`，重新加载时零转换，也不会因为解析器回归而
/// 让已经导入过的节点失效。
///
/// 代价：解析器的改进不会追溯修复已存节点，要等用户手动刷新一次。
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
        self.subs.insert(
            url.to_string(),
            StoredSub {
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
                state: SubState::Expired,
                node_count: entry.nodes.len(),
                error: None,
            },
            Some(entry) => SubStatus {
                url: url.to_string(),
                state: SubState::Cached,
                node_count: entry.nodes.len(),
                error: None,
            },
            None => SubStatus {
                url: url.to_string(),
                state: SubState::Pending,
                node_count: 0,
                error: None,
            },
        }
    }
}

pub fn sub_nodes_path() -> PathBuf {
    PathBuf::from(SUB_NODES_DIR).join(SUB_NODES_FILE)
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
    // 这个文件含节点密码/UUID，和 data/cache/config.json 同级敏感。
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
