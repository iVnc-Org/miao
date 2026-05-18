use std::path::PathBuf;
use std::sync::Arc;

use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::error::AppResult;
use crate::models::LastProxy;
use crate::services::config::get_config_cache_path;
use crate::services::singbox::get_sing_box_home;
use crate::state::AppState;

fn get_last_proxy_path() -> PathBuf {
    get_config_cache_path()
        .parent()
        .map(|dir| dir.join("last_proxy.json"))
        .unwrap_or_else(|| PathBuf::from("data/cache/last_proxy.json"))
}

fn get_legacy_last_proxy_path() -> PathBuf {
    get_sing_box_home().join(".last_proxy")
}

pub async fn save_last_proxy(proxy: &LastProxy) -> AppResult<()> {
    let json = serde_json::to_string(proxy)?;
    let path = get_last_proxy_path();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, json).await?;
    Ok(())
}

async fn load_last_proxy() -> Option<LastProxy> {
    for path in [get_last_proxy_path(), get_legacy_last_proxy_path()] {
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            if let Ok(proxy) = serde_json::from_str(&content) {
                return Some(proxy);
            }
        }
    }
    None
}

pub async fn restore_last_proxy(state: &Arc<AppState>) {
    let proxy = match load_last_proxy().await {
        Some(p) => p,
        None => return,
    };

    info!(
        "Attempting to restore last proxy: {} -> {}",
        proxy.group, proxy.name
    );

    sleep(Duration::from_secs(1)).await;

    let url = format!(
        "http://127.0.0.1:6262/proxies/{}",
        urlencoding::encode(&proxy.group)
    );
    let group_info = match state
        .http_client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(res) => match res.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(_) => return,
        },
        Err(_) => return,
    };

    let all_nodes = group_info.get("all").and_then(|v| v.as_array());
    if let Some(nodes) = all_nodes {
        let node_exists = nodes.iter().any(|n| n.as_str() == Some(&proxy.name));
        if !node_exists {
            warn!(
                "Last proxy '{}' not found in current node list, skipping restore",
                proxy.name
            );
            return;
        }
    } else {
        return;
    }

    match state
        .http_client
        .put(&url)
        .timeout(Duration::from_secs(5))
        .json(&serde_json::json!({ "name": proxy.name }))
        .send()
        .await
    {
        Ok(res) if res.status().is_success() => {
            info!("Successfully restored last proxy: {}", proxy.name);
        }
        Ok(res) => {
            warn!("Failed to restore last proxy: status {}", res.status());
        }
        Err(e) => {
            error!("Failed to restore last proxy: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::get_last_proxy_path;

    #[test]
    fn last_proxy_path_uses_persistent_cache_dir() {
        assert_eq!(
            get_last_proxy_path(),
            std::path::PathBuf::from("data/cache/last_proxy.json")
        );
    }
}
