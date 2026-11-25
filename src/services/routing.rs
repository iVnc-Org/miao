//! Resolve host capabilities before rendering, and bind the decision to the exact runtime bytes.
use crate::{
    error::{AppError, AppResult},
    models::{Config, ProxyMode, TunRouting},
    state::AppState,
};

use nix::libc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

static NFT_RULES_UNAVAILABLE: AtomicBool = AtomicBool::new(false);
pub fn remember_nft_rules(available: bool) {
    NFT_RULES_UNAVAILABLE.store(!available, Ordering::SeqCst);
}

/// An explicit Start re-probes capabilities after packages or kernel modules change.
pub fn retry_nft_rules() {
    NFT_RULES_UNAVAILABLE.store(false, Ordering::SeqCst);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveRouting {
    #[default]
    None,
    Nftables,
    PolicyRoute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPlan {
    pub requested: TunRouting,
    pub effective: EffectiveRouting,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub lan_interfaces: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    #[default]
    Stopped,
    Preparing,
    Starting,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeStatus {
    pub phase: RuntimePhase,
    pub routing: Option<RoutingPlan>,
    pub error: Option<String>,
    pub dns: Option<super::openwrt_dns::DnsStatus>,
}

pub fn supersede(state: &AppState) -> u64 {
    state.startup_cancelled.store(true, Ordering::SeqCst);
    state.runtime_epoch.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn is_current(state: &AppState, epoch: u64) -> bool {
    state.runtime_epoch.load(Ordering::SeqCst) == epoch
        && !state.shutting_down.load(Ordering::SeqCst)
}

pub fn check_current(state: &AppState, epoch: u64) -> AppResult<()> {
    if is_current(state, epoch) {
        Ok(())
    } else {
        Err(AppError::message(
            "START_CANCELLED: activation superseded by another request",
        ))
    }
}

pub async fn until_superseded(state: &AppState, epoch: u64) {
    while is_current(state, epoch) {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub async fn cancellable<T>(
    state: &AppState,
    epoch: u64,
    work: impl std::future::Future<Output = AppResult<T>>,
) -> AppResult<T> {
    check_current(state, epoch)?;
    tokio::select! {
        result = work => { check_current(state, epoch)?; result }
        _ = until_superseded(state, epoch) => Err(AppError::message("START_CANCELLED: operation superseded")),
    }
}

pub fn status(
    state: &AppState,
    phase: RuntimePhase,
    plan: Option<RoutingPlan>,
    error: Option<String>,
) {
    let mut status = state
        .runtime_status
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    status.phase = phase;
    if let Some(plan) = plan {
        status.routing = Some(plan);
    }
    status.error = error;
}

#[derive(Debug, PartialEq, Eq)]
pub enum NftCapability {
    Available,
    Unsupported(i32),
    PermissionDenied,
    Unknown(String),
}

/// This query is also used by sing-tun 0.9.7. It neither needs the nft CLI nor changes rules.
#[cfg(target_os = "linux")]
pub fn probe_nftables() -> NftCapability {
    for family in [libc::AF_INET as u8, 1 /* NFPROTO_INET */] {
        if let Err(error) = probe_family(family) {
            return match error.raw_os_error() {
                Some(libc::EPERM | libc::EACCES) => NftCapability::PermissionDenied,
                Some(code)
                    if matches!(
                        code,
                        libc::EINVAL
                            | libc::ENOENT
                            | libc::EAFNOSUPPORT
                            | libc::EPROTONOSUPPORT
                            | libc::ENOPROTOOPT
                            | libc::EOPNOTSUPP
                    ) =>
                {
                    NftCapability::Unsupported(code)
                }
                _ => NftCapability::Unknown(error.to_string()),
            };
        }
    }
    NftCapability::Available
}

#[cfg(not(target_os = "linux"))]
pub fn probe_nftables() -> NftCapability {
    NftCapability::Unsupported(0)
}

#[cfg(target_os = "linux")]
fn probe_family(family: u8) -> std::io::Result<()> {
    let query = super::netfilter::message((10 << 8) | 1, 0x301, 1, family, 0, &[]);
    super::netfilter::exchange(&query, 1).map(|_| ())
}

pub fn resolve_with(
    config: &Config,
    capability: NftCapability,
    disable_nftables: bool,
) -> AppResult<RoutingPlan> {
    let tun = config.tun.normalized().map_err(AppError::message)?;
    let mut plan = RoutingPlan {
        requested: tun.routing,
        effective: EffectiveRouting::None,
        reason: None,
        lan_interfaces: tun.lan_interfaces,
    };
    if config.mode == ProxyMode::Pool {
        return Ok(plan);
    }
    if disable_nftables {
        plan.effective = EffectiveRouting::PolicyRoute;
        plan.reason = Some("诊断环境变量 DISABLE_NFTABLES 已启用，使用策略路由".into());
        return Ok(plan);
    }
    match capability {
        NftCapability::Available => plan.effective = EffectiveRouting::Nftables,
        NftCapability::Unsupported(code) => {
            plan.effective = EffectiveRouting::PolicyRoute;
            plan.reason = Some(format!(
                "当前内核不支持所需 nftables 操作（errno {code}），已自动适配为策略路由"
            ));
        }
        // Editing a stopped config may be unprivileged. Active starts check CAP_NET_ADMIN first.
        NftCapability::PermissionDenied => {
            plan.effective = EffectiveRouting::PolicyRoute;
            plan.reason = Some("当前进程无法访问 nftables；启动代理仍需要 CAP_NET_ADMIN".into());
        }
        NftCapability::Unknown(error) => {
            return Err(AppError::message(format!("NFT_PROBE_FAILED: {error}")))
        }
    }
    Ok(plan)
}

pub async fn resolve(config: &Config) -> AppResult<RoutingPlan> {
    let disabled = std::env::var("DISABLE_NFTABLES")
        .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"));
    if config.mode != ProxyMode::Pool && !disabled && NFT_RULES_UNAVAILABLE.load(Ordering::SeqCst) {
        let mut plan = resolve_with(config, NftCapability::Unsupported(libc::EOPNOTSUPP), false)?;
        plan.reason = Some(
            "本次运行已确认 nftables 规则不受支持，继续使用策略路由；下次启动服务时重新检测".into(),
        );
        return Ok(plan);
    }
    let capability = if config.mode == ProxyMode::Pool || disabled {
        NftCapability::Unsupported(0)
    } else {
        tokio::task::spawn_blocking(probe_nftables)
            .await
            .map_err(|e| AppError::message(format!("nftables probe failed: {e}")))?
    };
    resolve_with(config, capability, disabled)
}

pub fn apply(config: &mut Value, plan: &RoutingPlan) -> AppResult<()> {
    let inbounds = config["inbounds"]
        .as_array_mut()
        .ok_or_else(|| AppError::message("Missing inbounds"))?;
    let mut has_tun = false;
    for inbound in inbounds {
        if inbound["type"] != "tun" {
            continue;
        }
        has_tun = true;
        inbound["auto_route"] = true.into();
        inbound["strict_route"] = true.into();
        inbound["auto_redirect"] = (plan.effective == EffectiveRouting::Nftables).into();
    }
    if has_tun != (plan.effective != EffectiveRouting::None) {
        return Err(AppError::message(
            "ROUTING_CONFIG_MISMATCH: TUN presence does not match selected mode",
        ));
    }
    // Native auto-redirect marks every core socket to bypass interception. Let
    // the kernel route those sockets: binding them to the default NIC breaks
    // endpoints reached through policy routes (e.g. Tailscale) and other NICs.
    // Without auto-redirect, retain default-interface binding to prevent loops.
    // Explicit outbound bindings and detours remain authoritative in both modes.
    config["route"]["auto_detect_interface"] =
        (plan.effective == EffectiveRouting::PolicyRoute).into();
    if let Some(servers) = config["dns"]["servers"].as_array_mut() {
        for server in servers
            .iter_mut()
            .filter(|server| server["tag"] == "local" || server["tag"] == "miao-magic")
        {
            // Native auto-redirect supplies its own mark and rejects an explicit
            // routing_mark. The fallback needs the same bypass mark explicitly.
            if plan.effective == EffectiveRouting::PolicyRoute {
                server["routing_mark"] = 0x2024.into();
            } else if let Some(fields) = server.as_object_mut() {
                fields.remove("routing_mark");
            }
        }
    }
    if let Some(rules) = config["route"]["rules"].as_array_mut() {
        for rule in rules {
            normalize_bypass(rule, plan.effective);
        }
    }
    Ok(())
}

fn normalize_bypass(rule: &mut Value, effective: EffectiveRouting) {
    if rule["action"] == "bypass" {
        if rule
            .get("outbound")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            rule["outbound"] = "direct".into();
        }
        if effective != EffectiveRouting::Nftables {
            rule["action"] = "route".into();
        }
    }
    if let Some(children) = rule.get_mut("rules").and_then(Value::as_array_mut) {
        for child in children {
            normalize_bypass(child, effective);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    config_sha256: String,
    core_revision: String,
    plan: RoutingPlan,
    epoch: u64,
}

pub async fn write_config(config: &Value, plan: &RoutingPlan, epoch: u64) -> AppResult<()> {
    let directory = super::singbox::get_sing_box_home();
    let bytes = serde_json::to_string(config)?;
    let manifest = Manifest {
        config_sha256: hex::encode(Sha256::digest(bytes.as_bytes())),
        core_revision: env!("SING_BOX_REVISION").into(),
        plan: plan.clone(),
        epoch,
    };
    super::write_file_atomic(&directory.join("config.json"), &bytes, "sing-box config").await?;
    super::write_file_atomic(
        &directory.join("routing.json"),
        &serde_json::to_string(&manifest)?,
        "routing manifest",
    )
    .await
}

pub async fn read_plan() -> AppResult<(Value, RoutingPlan, u64)> {
    let directory = super::singbox::get_sing_box_home();
    let bytes = tokio::fs::read(directory.join("config.json")).await?;
    decode_prepared(
        &bytes,
        &tokio::fs::read(directory.join("routing.json")).await?,
    )
}

fn decode_prepared(bytes: &[u8], manifest: &[u8]) -> AppResult<(Value, RoutingPlan, u64)> {
    let manifest: Manifest = serde_json::from_slice(manifest)?;
    if manifest.core_revision != env!("SING_BOX_REVISION")
        || manifest.config_sha256 != hex::encode(Sha256::digest(bytes))
    {
        return Err(AppError::message(
            "ROUTING_CONFIG_MISMATCH: runtime config changed after preparation",
        ));
    }
    Ok((
        serde_json::from_slice(bytes)?,
        manifest.plan,
        manifest.epoch,
    ))
}

pub async fn prepare_existing(config: &Config, state: &AppState) -> AppResult<()> {
    let epoch = state.runtime_epoch.load(Ordering::SeqCst);
    let path = super::singbox::get_sing_box_home().join("config.json");
    let mut value: Value = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    let plan = resolve(config).await?;
    super::config::apply_runtime_routing(config, &mut value, &plan)?;
    super::proxy::pin_saved_selection(&mut value).await;
    check_current(state, epoch)?;
    write_config(&value, &plan, epoch).await
}

/// Dependency I/O is owned by a task outside the configuration lock. Cancelling a start
/// stops awaiting it, rather than interrupting a package manager halfway through a transaction.
pub async fn prepare_host(state: &Arc<AppState>, mode: ProxyMode, epoch: u64) -> AppResult<()> {
    check_current(state, epoch)?;
    if mode == ProxyMode::Pool {
        return Ok(());
    }
    super::openwrt::check_net_admin()?;
    if !super::singbox::sing_box_is_running(state).await {
        status(state, RuntimePhase::Preparing, None, None);
    }
    let work = super::openwrt::prepare_tun();
    tokio::pin!(work);
    loop {
        tokio::select! {
            result = &mut work => return result,
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => check_current(state, epoch)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_runtime_rejects_modified_bytes_and_another_core_revision() {
        let bytes = b"{\"inbounds\":[]}";
        let plan = resolve_with(
            &Config {
                mode: ProxyMode::Pool,
                ..Default::default()
            },
            NftCapability::Available,
            false,
        )
        .unwrap();
        let mut manifest = Manifest {
            config_sha256: hex::encode(Sha256::digest(bytes)),
            core_revision: env!("SING_BOX_REVISION").into(),
            plan,
            epoch: 12,
        };
        assert_eq!(
            decode_prepared(bytes, &serde_json::to_vec(&manifest).unwrap())
                .unwrap()
                .2,
            12
        );
        assert!(decode_prepared(
            b"{\"inbounds\": []}",
            &serde_json::to_vec(&manifest).unwrap()
        )
        .is_err());
        manifest.core_revision = "other".into();
        assert!(decode_prepared(bytes, &serde_json::to_vec(&manifest).unwrap()).is_err());
    }

    #[tokio::test]
    async fn superseding_a_request_releases_pending_work_without_waiting_for_it() {
        let state = crate::test_support::app_state(Config::default());
        let epoch = state.runtime_epoch.load(Ordering::SeqCst);
        let cancel = async {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            supersede(&state);
        };
        let pending = cancellable(&state, epoch, async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            Ok(())
        });
        let (result, _) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(pending, cancel)
        })
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("START_CANCELLED"));
    }
    #[test]
    fn automatic_selection_does_not_hide_unknown_probe_failures() {
        let config = Config::default();
        assert_eq!(
            resolve_with(&config, NftCapability::Available, false)
                .unwrap()
                .effective,
            EffectiveRouting::Nftables
        );
        assert_eq!(
            resolve_with(&config, NftCapability::Unsupported(22), false)
                .unwrap()
                .effective,
            EffectiveRouting::PolicyRoute
        );
        assert!(resolve_with(&config, NftCapability::Unknown("timeout".into()), false).is_err());
        assert_eq!(
            resolve_with(&config, NftCapability::Available, true)
                .unwrap()
                .effective,
            EffectiveRouting::PolicyRoute
        );
    }
    #[test]
    fn legacy_manual_choices_cannot_disable_adaptation_and_pool_needs_no_tun() {
        let mut config = Config::default();
        for legacy in [TunRouting::Nftables, TunRouting::PolicyRoute] {
            config.tun.routing = legacy;
            let native = resolve_with(&config, NftCapability::Available, false).unwrap();
            assert_eq!(native.requested, TunRouting::Auto);
            assert_eq!(native.effective, EffectiveRouting::Nftables);
            let compatible = resolve_with(&config, NftCapability::Unsupported(22), false).unwrap();
            assert_eq!(compatible.requested, TunRouting::Auto);
            assert_eq!(compatible.effective, EffectiveRouting::PolicyRoute);
        }
        config.mode = ProxyMode::Pool;
        assert_eq!(
            resolve_with(&config, NftCapability::PermissionDenied, true)
                .unwrap()
                .effective,
            EffectiveRouting::None
        );
    }
    #[test]
    fn compatibility_preserves_bypass_destination_and_nested_rules() {
        let mut config = serde_json::json!({"inbounds":[{"type":"tun","auto_redirect":true}],"route":{"rules":[{"action":"bypass"},{"action":"bypass","outbound":"other"},{"type":"logical","rules":[{"action":"bypass"}]}]}});
        let plan = resolve_with(&Config::default(), NftCapability::Unsupported(22), false).unwrap();
        apply(&mut config, &plan).unwrap();
        assert_eq!(config["inbounds"][0]["auto_redirect"], false);
        assert_eq!(config["route"]["rules"][0]["action"], "route");
        assert_eq!(config["route"]["rules"][0]["outbound"], "direct");
        assert_eq!(config["route"]["rules"][1]["outbound"], "other");
        assert_eq!(
            config["route"]["rules"][2]["rules"][0]["outbound"],
            "direct"
        );
    }

    #[test]
    fn mark_based_routing_uses_kernel_routes_and_fallback_restores_loop_protection() {
        let outbounds = serde_json::json!([
            {"type":"socks", "tag":"overlay", "server":"100.64.0.2", "bind_interface":"vpn0"},
            {"type":"socks", "tag":"chain", "server":"example.test", "detour":"overlay"}
        ]);
        let mut value = serde_json::json!({
            "inbounds":[{"type":"tun"}],
            "outbounds":outbounds,
            "route":{"auto_detect_interface":true}
        });
        let mut plan = resolve_with(&Config::default(), NftCapability::Available, false).unwrap();
        apply(&mut value, &plan).unwrap();
        assert_eq!(value["route"]["auto_detect_interface"], false);
        assert_eq!(value["outbounds"], outbounds);
        plan.effective = EffectiveRouting::PolicyRoute;
        apply(&mut value, &plan).unwrap();
        assert_eq!(value["route"]["auto_detect_interface"], true);
        assert_eq!(value["outbounds"], outbounds);
        plan.effective = EffectiveRouting::None;
        value["inbounds"] = serde_json::json!([]);
        apply(&mut value, &plan).unwrap();
        assert_eq!(value["route"]["auto_detect_interface"], false);
    }
}
