//! Scoped, runtime-only fw3 integration. No zone, NAT policy, or persistent UCI changes.
use super::{
    openwrt::{command_output, command_search_dirs, find_command},
    routing::{EffectiveRouting, RoutingPlan},
};
use crate::{
    error::{AppError, AppResult},
    models::TunConfig,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Mutex;

/// ImmortalWrt provides `fw3 -> fw4` for command compatibility. Only the
/// distinct legacy program needs iptables rules; a compat alias uses native nftables.
fn legacy_fw3_in(dirs: &[PathBuf]) -> bool {
    let Some(fw3) = find_command(dirs, "fw3") else {
        return false;
    };
    if let Some(fw4) = find_command(dirs, "fw4") {
        if let (Ok(legacy), Ok(native)) = (std::fs::metadata(&fw3), std::fs::metadata(&fw4)) {
            if legacy.dev() == native.dev() && legacy.ino() == native.ino() {
                return false;
            }
        }
    }
    true
}

pub struct Fw3Rules {
    iptables: PathBuf,
    save: Option<PathBuf>,
    input: String,
    forward: String,
    marker: String,
    tun: String,
    lan: Vec<String>,
    stopped: AtomicBool,
    update: Mutex<()>,
    last_error: std::sync::Mutex<Option<String>>,
}

pub(crate) async fn discover_lan() -> AppResult<Vec<String>> {
    let dirs = command_search_dirs();
    let uci = find_command(&dirs, "uci")
        .ok_or_else(|| AppError::message("FW3_LAN_UNDETECTED: configure tun.lan_interfaces"))?;
    let output = command_output(&uci, &["-q", "show", "firewall"], Duration::from_secs(3)).await?;
    let mut zones: BTreeMap<&str, BTreeMap<&str, String>> = BTreeMap::new();
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some((field, value)) = line.split_once('=') {
            if let Some((section, key)) = field.rsplit_once('.') {
                zones
                    .entry(section)
                    .or_default()
                    .insert(key, value.replace('\'', ""));
            }
        }
    }
    let ubus = find_command(&dirs, "ubus").ok_or_else(|| {
        AppError::message("FW3_LAN_UNDETECTED: ubus missing; configure tun.lan_interfaces")
    })?;
    let mut devices = Vec::new();
    for zone in zones
        .values()
        .filter(|zone| zone.get("name").is_some_and(|name| name == "lan"))
    {
        for network in zone
            .get("network")
            .into_iter()
            .flat_map(|value| value.split_whitespace())
        {
            // Network names are arguments, never shell text.
            let object = format!("network.interface.{network}");
            let output = command_output(
                &ubus,
                &["-S", "call", &object, "status"],
                Duration::from_secs(3),
            )
            .await?;
            if !output.status.success() {
                continue;
            }
            let interface: Value = serde_json::from_slice(&output.stdout)?;
            if let Some(device) = interface["l3_device"]
                .as_str()
                .or_else(|| interface["device"].as_str())
            {
                devices.push(device.to_string());
            }
        }
    }
    Ok(TunConfig {
        lan_interfaces: devices,
        ..Default::default()
    }
    .normalized()
    .map_err(AppError::message)?
    .lan_interfaces)
}

impl Fw3Rules {
    fn owned(iptables: PathBuf, tun: &str, lan: Vec<String>) -> Arc<Self> {
        let token = &hex::encode(Sha256::digest(
            super::singbox::get_sing_box_home()
                .as_os_str()
                .as_encoded_bytes(),
        ))[..8];
        Arc::new(Self {
            iptables,
            save: find_command(&command_search_dirs(), "iptables-save"),
            input: format!("MIAO_I_{token}"),
            forward: format!("MIAO_F_{token}"),
            marker: format!("miao:{token}"),
            tun: tun.into(),
            lan,
            stopped: AtomicBool::new(false),
            update: Mutex::new(()),
            last_error: std::sync::Mutex::new(None),
        })
    }

    /// Recover a dead manager's chains even when the next activation uses pool mode.
    /// The caller must first confirm that its previous core no longer owns the network.
    pub async fn cleanup_stale() -> AppResult<()> {
        let dirs = command_search_dirs();
        if !legacy_fw3_in(&dirs) {
            return Ok(());
        }
        if let Some(iptables) = find_command(&dirs, "iptables") {
            Self::owned(iptables, "", Vec::new()).cleanup().await?;
        }
        Ok(())
    }

    pub async fn preflight(plan: &RoutingPlan) -> AppResult<()> {
        let dirs = command_search_dirs();
        if plan.effective != EffectiveRouting::None
            && legacy_fw3_in(&dirs)
            && find_command(&dirs, "iptables").is_none()
        {
            return Err(AppError::message(
                "FW3_IPTABLES_MISSING: legacy fw3 requires its userspace iptables tool",
            ));
        }
        Ok(())
    }

    pub async fn install(plan: &RoutingPlan, tun: &str) -> AppResult<Option<Arc<Self>>> {
        if plan.effective == EffectiveRouting::None || !legacy_fw3_in(&command_search_dirs()) {
            return Ok(None);
        }
        let lan = if plan.lan_interfaces.is_empty() {
            discover_lan().await?
        } else {
            plan.lan_interfaces.clone()
        };
        if lan.is_empty()
            || lan.iter().any(|name| {
                !Path::new("/sys/class/net").join(name).exists() || name == tun || name == "lo"
            })
        {
            return Err(AppError::message(
                "FW3_LAN_UNDETECTED: specify active trusted LAN devices in tun.lan_interfaces",
            ));
        }
        let iptables = find_command(&command_search_dirs(), "iptables")
            .ok_or_else(|| AppError::message("FW3_IPTABLES_MISSING"))?;
        let rules = Self::owned(iptables, tun, lan);
        // The runtime directory identifies ownership across restarts, including a previous crash.
        rules.cleanup_inner().await?;
        if let Err(error) = rules.ensure().await {
            let _ = rules.cleanup_inner().await;
            return Err(error);
        }
        Ok(Some(rules))
    }

    async fn run(&self, args: &[&str]) -> AppResult<bool> {
        let mut command = vec!["-w", "2", "-t", "filter"];
        command.extend_from_slice(args);
        Ok(
            command_output(&self.iptables, &command, Duration::from_secs(4))
                .await?
                .status
                .success(),
        )
    }

    async fn required(&self, args: &[&str]) -> AppResult<()> {
        let mut command = vec!["-w", "2", "-t", "filter"];
        command.extend_from_slice(args);
        let output = command_output(&self.iptables, &command, Duration::from_secs(4)).await?;
        if !output.status.success() {
            return Err(AppError::message(format!(
                "FW3_RULES_FAILED: {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(512)
                    .collect::<String>()
            )));
        }
        Ok(())
    }

    async fn ensure(&self) -> AppResult<()> {
        let _update = self.update.lock().await;
        if self.stopped.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut expected = vec![vec![
            "-A".to_string(),
            self.input.clone(),
            "-i".into(),
            self.tun.clone(),
            "-j".into(),
            "ACCEPT".into(),
        ]];
        for lan in &self.lan {
            expected.push(vec![
                "-A".into(),
                self.forward.clone(),
                "-i".into(),
                lan.clone(),
                "-o".into(),
                self.tun.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ]);
            expected.push(vec![
                "-A".into(),
                self.forward.clone(),
                "-i".into(),
                self.tun.clone(),
                "-o".into(),
                lan.clone(),
                "-m".into(),
                "conntrack".into(),
                "--ctstate".into(),
                "ESTABLISHED,RELATED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ]);
        }
        for (parent, chain) in [("INPUT", &self.input), ("FORWARD", &self.forward)] {
            expected.push(vec![
                "-A".into(),
                parent.into(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                self.marker.clone(),
                "-j".into(),
                chain.clone(),
            ]);
        }
        // One read-only snapshot per watch tick; fork rule commands only after a reload.
        if let Some(save) = &self.save {
            if let Ok(snapshot) =
                command_output(save, &["-t", "filter"], Duration::from_secs(3)).await
            {
                let present: std::collections::BTreeSet<String> =
                    String::from_utf8_lossy(&snapshot.stdout)
                        .lines()
                        .map(normalized_rule)
                        .collect();
                if snapshot.status.success()
                    && expected
                        .iter()
                        .all(|rule| present.contains(&normalized_rule(&rule.join(" "))))
                {
                    return Ok(());
                }
            }
        }
        if !self.run(&["-L", &self.input]).await? {
            self.required(&["-N", &self.input]).await?;
        }
        if !self.run(&["-L", &self.forward]).await? {
            self.required(&["-N", &self.forward]).await?;
        }
        for rule in &expected[..expected.len() - 2] {
            let arguments: Vec<&str> = rule.iter().skip(1).map(String::as_str).collect();
            let mut check = vec!["-C"];
            check.extend_from_slice(&arguments);
            if !self.run(&check).await? {
                let append: Vec<&str> = rule.iter().map(String::as_str).collect();
                self.required(&append).await?;
            }
        }
        for (parent, chain) in [
            ("INPUT", self.input.as_str()),
            ("FORWARD", self.forward.as_str()),
        ] {
            if !self
                .run(&[
                    "-C",
                    parent,
                    "-m",
                    "comment",
                    "--comment",
                    &self.marker,
                    "-j",
                    chain,
                ])
                .await?
            {
                self.required(&[
                    "-I",
                    parent,
                    "1",
                    "-m",
                    "comment",
                    "--comment",
                    &self.marker,
                    "-j",
                    chain,
                ])
                .await?;
            }
        }
        Ok(())
    }

    pub fn watch(self: &Arc<Self>) {
        let rules = self.clone();
        tokio::spawn(async move {
            while !rules.stopped.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let error = rules.ensure().await.err().map(|error| error.to_string());
                if let Some(error) = &error {
                    tracing::warn!(%error, "Failed to restore fw3 rules after reload");
                }
                *rules.last_error.lock().unwrap_or_else(|e| e.into_inner()) = error;
            }
        });
    }

    pub fn diagnostic(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn cleanup_inner(&self) -> AppResult<()> {
        for (parent, chain) in [
            ("INPUT", self.input.as_str()),
            ("FORWARD", self.forward.as_str()),
        ] {
            // Delete only the exact jump belonging to this runtime directory.
            for _ in 0..8 {
                if !self
                    .run(&[
                        "-D",
                        parent,
                        "-m",
                        "comment",
                        "--comment",
                        &self.marker,
                        "-j",
                        chain,
                    ])
                    .await?
                {
                    break;
                }
            }
            self.run(&["-F", chain]).await?;
            self.run(&["-X", chain]).await?;
            if self.run(&["-L", chain]).await? {
                return Err(AppError::message(format!(
                    "FW3_CLEANUP_FAILED: owned chain {chain} remains in use"
                )));
            }
        }
        if let Some(save) = &self.save {
            let output = command_output(save, &["-t", "filter"], Duration::from_secs(3)).await?;
            if !output.status.success() {
                return Err(AppError::message(
                    "FW3_CLEANUP_FAILED: unable to verify owned rule removal",
                ));
            }
            if String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .any(|word| {
                    word == self.input
                        || word == self.forward
                        || word == format!(":{}", self.input)
                        || word == format!(":{}", self.forward)
                })
            {
                return Err(AppError::message(
                    "FW3_CLEANUP_FAILED: owned chains or jumps remain",
                ));
            }
        }
        Ok(())
    }

    pub async fn cleanup(&self) -> AppResult<()> {
        self.stopped.store(true, Ordering::SeqCst);
        let _update = self.update.lock().await;
        self.cleanup_inner().await
    }
}

fn normalized_rule(line: &str) -> String {
    let mut words: Vec<String> = line
        .split_whitespace()
        .map(|word| word.trim_matches('"').to_string())
        .collect();
    for index in 1..words.len() {
        if words[index - 1] == "--ctstate" {
            let mut states: Vec<&str> = words[index].split(',').collect();
            states.sort_unstable();
            words[index] = states.join(",");
        }
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::symlink, sync::atomic::AtomicU64};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn fw4_compat_alias_does_not_require_missing_iptables() {
        let path = std::env::temp_dir().join(format!(
            "miao-fw4-alias-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let dirs = vec![path.clone()];
        assert!(!legacy_fw3_in(&dirs));
        std::fs::write(path.join("fw4"), b"native fw4").unwrap();
        symlink("fw4", path.join("fw3")).unwrap();
        assert!(find_command(&dirs, "iptables").is_none());
        assert!(!legacy_fw3_in(&dirs));
        std::fs::remove_file(path.join("fw3")).unwrap();
        std::fs::hard_link(path.join("fw4"), path.join("fw3")).unwrap();
        assert!(!legacy_fw3_in(&dirs));
        std::fs::remove_file(path.join("fw3")).unwrap();
        std::fs::write(path.join("fw3"), b"legacy fw3").unwrap();
        assert!(legacy_fw3_in(&dirs));
        std::fs::remove_file(path.join("fw4")).unwrap();
        assert!(legacy_fw3_in(&dirs));
        std::fs::remove_dir_all(path).unwrap();
    }
}
