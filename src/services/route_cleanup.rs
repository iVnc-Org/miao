//! Remember exact rules introduced by this activation, so SIGKILL cleanup cannot
//! delete pre-existing policy rules belonging to the administrator or another app.
use super::openwrt::{command_output, command_search_dirs, find_command};
use super::routing::{EffectiveRouting, RoutingPlan};
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct Journal {
    boot: String,
    namespace: u64,
    pid: u32,
    start_ticks: u64,
    tun: String,
    rules: BTreeSet<Vec<String>>,
    #[serde(default)]
    native_rules: Option<BTreeSet<Vec<u8>>>,
    nft_handle: Option<u64>,
    first_priority: u64,
    fallback_priority: u64,
    table: String,
}

fn journal_path() -> PathBuf {
    super::singbox::get_sing_box_home().join("network-ownership.json")
}
fn context() -> AppResult<(String, u64)> {
    Ok((
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        std::fs::metadata("/proc/self/ns/net")?.ino(),
    ))
}
fn start_ticks(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = text.rsplit_once(") ")?.1.split_whitespace().collect();
    if fields.first() == Some(&"Z") {
        return None;
    }
    fields.get(19)?.parse().ok()
}

async fn nft_handle() -> AppResult<Option<u64>> {
    tokio::task::spawn_blocking(super::netfilter::table_handle)
        .await
        .map_err(|e| AppError::message(format!("NFT_OWNERSHIP_CHECK_FAILED: {e}")))?
        .map_err(|e| AppError::context("NFT_OWNERSHIP_CHECK_FAILED", e))
}

pub struct RouteOwnership {
    ip: Option<PathBuf>,
    before: BTreeSet<Vec<String>>,
    added: Mutex<Option<BTreeSet<Vec<String>>>>,
    native_before: BTreeSet<Vec<u8>>,
    native_added: Mutex<Option<BTreeSet<Vec<u8>>>>,
    first_priority: u64,
    fallback_priority: u64,
    table: String,
    tun: String,
    nft_required: bool,
    nft_handle: Mutex<Option<u64>>,
    identity: Mutex<Option<(u32, u64)>>,
}

impl RouteOwnership {
    pub async fn before(config: &Value, plan: &RoutingPlan) -> AppResult<Option<Arc<Self>>> {
        Self::recover().await?;
        let Some(tun) = config["inbounds"]
            .as_array()
            .and_then(|values| values.iter().find(|inbound| inbound["type"] == "tun"))
        else {
            return Ok(None);
        };
        let name = tun["interface_name"].as_str().unwrap_or("sing-tun");
        if std::path::Path::new("/sys/class/net").join(name).exists() {
            return Err(AppError::message(
                "TUN_IN_USE: another process already owns this TUN interface",
            ));
        }
        let ip = find_command(&command_search_dirs(), "ip");
        let mut owner = Self {
            ip,
            before: BTreeSet::new(),
            added: Mutex::new(None),
            native_before: BTreeSet::new(),
            native_added: Mutex::new(None),
            first_priority: tun["iproute2_rule_index"].as_u64().unwrap_or(9000),
            fallback_priority: tun["iproute2_auto_redirect_fallback_rule_index"]
                .as_u64()
                .unwrap_or(32768),
            table: tun["iproute2_table_index"]
                .as_u64()
                .unwrap_or(2022)
                .to_string(),
            tun: name.into(),
            nft_required: plan.effective == EffectiveRouting::Nftables,
            nft_handle: Mutex::new(None),
            identity: Mutex::new(None),
        };
        owner.before = owner.snapshot().await.ok_or_else(|| {
            AppError::message("ROUTING_INSPECTION_FAILED: a working ip -4 rule show is required to establish network ownership")
        })?;
        owner.native_before = native_rules().await?;
        if owner
            .before
            .iter()
            .any(|rule| rule.get(1).is_none_or(|priority| priority != "1"))
        {
            return Err(AppError::message("ROUTING_IN_USE: policy priorities/table already exist without Miao ownership; stop the conflicting proxy first"));
        }
        if owner.nft_required && nft_handle().await?.is_some() {
            return Err(AppError::message(
                "NFT_TABLE_IN_USE: an existing inet sing-box table is not owned by this activation",
            ));
        }
        Ok(Some(Arc::new(owner)))
    }

    fn selected_rule(&self, line: &str) -> Option<Vec<String>> {
        let (priority, fields) = line.split_once(':')?;
        let priority = priority.trim().parse::<u64>().ok()?;
        let fields: Vec<String> = fields
            .split_whitespace()
            .filter(|value| *value != "[detached]")
            .map(str::to_string)
            .collect();
        let fallback = priority == self.fallback_priority
            && fields
                .windows(2)
                .any(|pair| pair[0] == "lookup" && pair[1] == self.table);
        if !((self.nft_required && priority == 1)
            || (self.first_priority..=self.first_priority.saturating_add(10)).contains(&priority)
            || fallback)
        {
            return None;
        }
        let mut rule = vec!["priority".into(), priority.to_string()];
        rule.extend(fields);
        Some(rule)
    }

    async fn snapshot(&self) -> Option<BTreeSet<Vec<String>>> {
        let output = command_output(
            self.ip.as_ref()?,
            &["-4", "rule", "show"],
            Duration::from_secs(2),
        )
        .await
        .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| self.selected_rule(line))
                .collect(),
        )
    }

    async fn capture_memory(&self) -> AppResult<()> {
        let after = self.snapshot().await.ok_or_else(|| {
            AppError::message("ROUTING_INSPECTION_FAILED: unable to record the core's policy rules")
        })?;
        let current = native_rules().await?;
        *self.native_added.lock().unwrap_or_else(|e| e.into_inner()) = Some(
            current
                .difference(&self.native_before)
                .filter(|rule| self.selected_native(rule))
                .cloned()
                .collect(),
        );
        *self.added.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(after.difference(&self.before).cloned().collect());
        if self.nft_required {
            let handle = nft_handle().await?;
            *self.nft_handle.lock().unwrap_or_else(|e| e.into_inner()) = handle;
        }
        Ok(())
    }

    pub async fn capture(&self, pid: u32) -> AppResult<()> {
        self.capture_memory().await?;
        let ticks = start_ticks(pid).ok_or_else(|| {
            AppError::message("CORE_EXITED: process disappeared before ownership recording")
        })?;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some((pid, ticks));
        let (boot, namespace) = context()?;
        let journal = Journal {
            boot,
            namespace,
            pid,
            start_ticks: ticks,
            tun: self.tun.clone(),
            rules: self
                .added
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .unwrap_or_default(),
            nft_handle: *self.nft_handle.lock().unwrap_or_else(|e| e.into_inner()),
            native_rules: self
                .native_added
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            first_priority: self.first_priority,
            fallback_priority: self.fallback_priority,
            table: self.table.clone(),
        };
        super::write_file_atomic(
            &journal_path(),
            &serde_json::to_string(&journal)?,
            "network ownership",
        )
        .await
    }

    pub async fn cleanup(&self) -> AppResult<()> {
        if self
            .added
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
        {
            self.capture_memory().await?;
        }
        let handle = *self.nft_handle.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = handle {
            tokio::task::spawn_blocking(move || super::netfilter::delete_owned_table(handle))
                .await
                .map_err(|e| AppError::message(format!("NFT_CLEANUP_FAILED: {e}")))?
                .map_err(|e| AppError::context("NFT_CLEANUP_FAILED", e))?;
        }
        // sing-tun also installs priority-1 rules pointing to a random table with
        // local 127.0.0.1 routes. Those routes reference physical devices, so the
        // kernel does not remove them when the TUN fd closes after SIGKILL.
        let tables = self.redirect_tables()?;
        tokio::task::spawn_blocking(move || super::route_netlink::cleanup_redirect_routes(&tables))
            .await
            .map_err(|e| AppError::message(format!("ROUTE_CLEANUP_FAILED: {e}")))?
            .map_err(|e| AppError::context("ROUTE_CLEANUP_FAILED", e))?;
        let owned = self
            .added
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default();
        let present = match self.snapshot().await {
            Some(present) => present,
            None if owned.is_empty() => BTreeSet::new(),
            None => {
                return Err(AppError::message(
                    "ROUTE_CLEANUP_FAILED: unable to inspect owned policy rules",
                ))
            }
        };
        let current = native_rules().await?;
        let recorded = self
            .native_added
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let delete: BTreeSet<Vec<u8>> = if let Some(recorded) = recorded {
            current.intersection(&recorded).cloned().collect()
        } else {
            // Migrate old journals only when the exact displayed owned rule maps
            // unambiguously to a single kernel rule; never delete by priority alone.
            let mut delete = BTreeSet::new();
            for rule in owned.intersection(&present) {
                let key = legacy_rule_key(rule).ok_or_else(|| {
                    AppError::message("ROUTE_CLEANUP_FAILED: invalid legacy ownership record")
                })?;
                let candidates: Vec<_> = current
                    .iter()
                    .filter(|raw| {
                        (
                            super::route_netlink::priority(raw),
                            super::route_netlink::table(raw),
                        ) == key
                    })
                    .collect();
                if candidates.len() != 1 {
                    return Err(AppError::message(
                        "ROUTE_CLEANUP_FAILED: legacy policy rule ownership is ambiguous",
                    ));
                }
                delete.insert(candidates[0].clone());
            }
            delete
        };
        tokio::task::spawn_blocking(move || {
            for rule in delete {
                super::route_netlink::delete_rule(&rule)?;
            }
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|e| AppError::message(format!("ROUTE_CLEANUP_FAILED: {e}")))?
        .map_err(|e| AppError::context("ROUTE_CLEANUP_FAILED", e))?;
        let identity = *self.identity.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(bytes) = tokio::fs::read(journal_path()).await {
            if let Ok(journal) = serde_json::from_slice::<Journal>(&bytes) {
                if identity == Some((journal.pid, journal.start_ticks)) {
                    let _ = tokio::fs::remove_file(journal_path()).await;
                }
            }
        }
        Ok(())
    }

    fn redirect_tables(&self) -> AppResult<BTreeSet<u32>> {
        if let Some(rules) = self
            .native_added
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Ok(rules
                .iter()
                .filter(|rule| super::route_netlink::priority(rule) == 1)
                .map(|rule| super::route_netlink::table(rule))
                .collect());
        }
        self.added
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .flatten()
            .filter(|rule| rule.get(1).is_some_and(|priority| priority == "1"))
            .filter_map(|rule| {
                rule.windows(2)
                    .find(|pair| pair[0] == "lookup")
                    .map(|pair| pair[1].clone())
            })
            .map(|table| {
                table.parse::<u32>().map_err(|_| {
                    AppError::message(
                        "ROUTE_CLEANUP_FAILED: legacy ownership record has no numeric table ID",
                    )
                })
            })
            .collect()
    }

    fn selected_native(&self, rule: &[u8]) -> bool {
        let priority = super::route_netlink::priority(rule) as u64;
        (self.nft_required && priority == 1)
            || (self.first_priority..=self.first_priority.saturating_add(10)).contains(&priority)
            || (priority == self.fallback_priority
                && super::route_netlink::table(rule).to_string() == self.table)
    }

    pub async fn recover() -> AppResult<()> {
        let bytes = match tokio::fs::read(journal_path()).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        let (boot, namespace) = context()?;
        if boot != journal.boot {
            tokio::fs::remove_file(journal_path()).await?;
            return Ok(());
        }
        // The previous manager may have just died and sent PDEATHSIG to its core.
        // Give that exact process a bounded chance to finish graceful cleanup.
        if namespace == journal.namespace {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while start_ticks(journal.pid) == Some(journal.start_ticks)
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        if namespace != journal.namespace
            || start_ticks(journal.pid) == Some(journal.start_ticks)
            || std::path::Path::new("/sys/class/net")
                .join(&journal.tun)
                .exists()
        {
            return Err(AppError::message(
                "NETWORK_RESOURCES_IN_USE: the recorded core or network namespace is still active",
            ));
        }
        let owner = Self {
            ip: find_command(&command_search_dirs(), "ip"),
            before: BTreeSet::new(),
            added: Mutex::new(Some(journal.rules)),
            native_before: BTreeSet::new(),
            native_added: Mutex::new(journal.native_rules),
            first_priority: journal.first_priority,
            fallback_priority: journal.fallback_priority,
            table: journal.table,
            tun: journal.tun,
            nft_required: journal.nft_handle.is_some(),
            nft_handle: Mutex::new(journal.nft_handle),
            identity: Mutex::new(Some((journal.pid, journal.start_ticks))),
        };
        owner.cleanup().await
    }
}

async fn native_rules() -> AppResult<BTreeSet<Vec<u8>>> {
    tokio::task::spawn_blocking(super::route_netlink::rules)
        .await
        .map_err(|e| AppError::message(format!("ROUTING_INSPECTION_FAILED: {e}")))?
        .map_err(|e| AppError::context("ROUTING_INSPECTION_FAILED", e))
}

fn legacy_rule_key(rule: &[String]) -> Option<(u32, u32)> {
    let priority = rule.get(1)?.parse().ok()?;
    let table = rule
        .windows(2)
        .find(|pair| pair[0] == "lookup")
        .map(|pair| pair[1].as_str())
        .unwrap_or("unspec");
    let table = match table {
        "unspec" | "[none]" => 0,
        "default" => 253,
        "main" => 254,
        "local" => 255,
        table => table.parse().ok()?,
    };
    Some((priority, table))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> RouteOwnership {
        RouteOwnership {
            ip: Some("ip".into()),
            before: BTreeSet::new(),
            added: Mutex::new(None),
            native_before: BTreeSet::new(),
            native_added: Mutex::new(None),
            first_priority: 9000,
            fallback_priority: 32768,
            table: "2022".into(),
            tun: "sing-tun".into(),
            nft_required: false,
            nft_handle: Mutex::new(None),
            identity: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn failed_policy_inspection_does_not_record_empty_network_ownership() {
        let mut owner = owner();
        owner.ip = Some("/bin/false".into());
        let error = owner.capture_memory().await.unwrap_err();
        assert!(error.to_string().contains("ROUTING_INSPECTION_FAILED"));
        assert!(owner.added.lock().unwrap().is_none());
    }

    #[test]
    fn ownership_is_limited_to_the_configured_priority_range_and_table() {
        let owner = owner();
        assert!(owner.selected_rule("100: from all lookup 2022").is_none());
        assert!(owner.selected_rule("32768: from all lookup 1234").is_none());
        assert!(owner
            .selected_rule("9002: from all iif sing-tun [detached] goto 9010")
            .unwrap()
            .iter()
            .all(|field| field != "[detached]"));
        assert!(owner
            .selected_rule("32768: not from all fwmark 0x2024 lookup 2022")
            .is_some());
    }

    #[test]
    fn native_table_ids_do_not_depend_on_busybox_display_names() {
        let owner = owner();
        let id = 0xf1234567u32;
        let mut rule = vec![2, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        for (kind, value) in [(6u16, 1u32), (15, id)] {
            rule.extend_from_slice(&8u16.to_ne_bytes());
            rule.extend_from_slice(&kind.to_ne_bytes());
            rule.extend_from_slice(&value.to_ne_bytes());
        }
        *owner.added.lock().unwrap() = Some(BTreeSet::from([vec![
            "priority", "1", "from", "all", "lookup", "unknown",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()]));
        *owner.native_added.lock().unwrap() = Some(BTreeSet::from([rule]));
        assert_eq!(owner.redirect_tables().unwrap(), BTreeSet::from([id]));
    }
}
