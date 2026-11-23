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
        for table in self.redirect_tables() {
            let ip = self
                .ip
                .as_ref()
                .ok_or_else(|| AppError::message("ROUTE_CLEANUP_FAILED: iproute2 missing"))?;
            let output = command_output(
                ip,
                &["-4", "route", "show", "table", &table],
                Duration::from_secs(2),
            )
            .await?;
            if !output.status.success()
                && !String::from_utf8_lossy(&output.stderr).contains("does not exist")
            {
                return Err(AppError::message(
                    "ROUTE_CLEANUP_FAILED: unable to inspect owned redirect table",
                ));
            }
            let routes = String::from_utf8_lossy(&output.stdout);
            for line in routes.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.first() != Some(&"local")
                    || !matches!(fields.get(1), Some(&"127.0.0.1" | &"127.0.0.1/32"))
                    || !fields.windows(2).any(|pair| pair == ["scope", "host"])
                {
                    continue;
                }
                let mut arguments = vec!["-4", "route", "del", "table", &table];
                arguments.extend(fields);
                let deleted = command_output(ip, &arguments, Duration::from_secs(2)).await?;
                if !deleted.status.success() {
                    return Err(AppError::message(format!(
                        "ROUTE_CLEANUP_FAILED: {}",
                        String::from_utf8_lossy(&deleted.stderr)
                    )));
                }
            }
        }
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
        for rule in owned.intersection(&present) {
            let mut arguments = vec!["-4", "rule", "del"];
            arguments.extend(rule.iter().map(String::as_str));
            match command_output(
                self.ip
                    .as_ref()
                    .ok_or_else(|| AppError::message("ROUTE_CLEANUP_FAILED: iproute2 missing"))?,
                &arguments,
                Duration::from_secs(2),
            )
            .await
            {
                Ok(output) if output.status.success() => {}
                result => {
                    return Err(AppError::message(format!(
                        "ROUTE_CLEANUP_FAILED: {result:?}"
                    )))
                }
            }
        }
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

    fn redirect_tables(&self) -> BTreeSet<String> {
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
            .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> RouteOwnership {
        RouteOwnership {
            ip: Some("ip".into()),
            before: BTreeSet::new(),
            added: Mutex::new(None),
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
}
