//! Runtime-only dnsmasq integration. The independent guard restores DNS even
//! when the manager is SIGKILLed; persistent UCI and resolv.conf are never edited.
use super::{
    openwrt::{command_output, command_search_dirs, find_command},
    write_file_atomic,
};
use crate::{
    error::{AppError, AppResult},
    models::{Config, ProxyMode},
};
use nix::libc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs::{File, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DNS_PORT: u16 = 6263;
const JOURNAL: &str = "dns-ownership.json";
const GUARD_ARG: &str = "--internal-dns-guard";

pub fn validate_ports(config: &Config) -> AppResult<()> {
    if config.mode == ProxyMode::Global
        && (crate::embedding::panel_port(config.port.unwrap_or(crate::models::DEFAULT_PORT))?
            == DNS_PORT
            || config
                .socks_port
                .unwrap_or(crate::models::DEFAULT_SOCKS_PORT)
                == DNS_PORT)
    {
        return Err(error(
            "DNS_PORT_CONFLICT",
            "port 6263 is reserved for automatic DNS",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsStatus {
    pub phase: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessIdentity {
    pid: u32,
    start: u64,
}

impl ProcessIdentity {
    fn read(pid: u32) -> Option<Self> {
        let data = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields: Vec<_> = data.rsplit_once(") ")?.1.split_whitespace().collect();
        if fields.first() == Some(&"Z") {
            return None;
        }
        Some(Self {
            pid,
            start: fields.get(19)?.parse().ok()?,
        })
    }
    fn alive(&self) -> bool {
        Self::read(self.pid).is_some_and(|now| now.start == self.start)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsPlan {
    instance: String,
    config: PathBuf,
    binary: PathBuf,
    init: PathBuf,
    ubus: PathBuf,
    fragment: PathBuf,
    content: String,
    dns_port: u16,
    policy: String,
    #[serde(default)]
    files: Vec<(PathBuf, String)>,
    #[serde(default)]
    system: Option<SystemDns>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SystemDns {
    nft: PathBuf,
    table: String,
    targets: Vec<IpAddr>,
    #[serde(default)]
    reply_chains: Vec<ReplyChain>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReplyChain {
    family: String,
    table: String,
    name: String,
}

fn tailscale_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]),
        IpAddr::V6(ip) => ip.octets()[..6] == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0],
    }
}

fn reply_specs(system: &SystemDns, token: &str) -> Vec<(ReplyChain, String, String)> {
    let mut specs = Vec::new();
    for chain in &system.reply_chains {
        for target in system
            .targets
            .iter()
            .filter(|address| tailscale_address(address))
        {
            let family = if target.is_ipv4() { "ip" } else { "ip6" };
            if chain.family != "inet" && chain.family != family {
                continue;
            }
            for protocol in ["udp", "tcp"] {
                let comment = format!("miao-dns:{token}:reply:{target}:{protocol}");
                let command = format!("insert rule {} {} {} iifname lo {family} saddr {target} {protocol} sport 53 ct direction reply ct status dnat ct mark 0x2024 accept comment \"{comment}\"\n", chain.family, chain.table, chain.name);
                specs.push((chain.clone(), comment, command));
            }
        }
    }
    specs
}

#[derive(Clone, Serialize, Deserialize)]
struct Ownership {
    version: u32,
    token: String,
    boot: String,
    namespace: u64,
    manager: ProcessIdentity,
    core: ProcessIdentity,
    executable: PathBuf,
    service: String,
    plan: DnsPlan,
    may_be_loaded: bool,
    restore_pending: bool,
    #[serde(default)]
    system_may_be_loaded: bool,
    #[serde(default)]
    system_handle: Option<u64>,
}

#[derive(Clone)]
pub struct DnsLease {
    root: PathBuf,
    token: String,
}

fn error(code: &str, message: impl std::fmt::Display) -> AppError {
    AppError::message(format!("{code}: {message}"))
}

fn context() -> AppResult<(String, u64)> {
    Ok((
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned(),
        std::fs::metadata("/proc/self/ns/net")?.ino(),
    ))
}

fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_instance(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

fn domain_valid(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() < 254
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

pub(crate) fn magic_domains() -> Vec<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    text.lines()
        .filter_map(|line| line.strip_prefix("search "))
        .flat_map(str::split_whitespace)
        .filter(|name| name.ends_with(".ts.net") && domain_valid(name))
        .map(str::to_owned)
        .collect()
}

#[derive(Debug)]
struct Scan {
    dirs: Vec<PathBuf>,
    no_resolv: bool,
    domains: Vec<String>,
    files: Vec<(PathBuf, String)>,
    system_targets: Vec<IpAddr>,
}

fn scan_config(config: &Path, own: Option<(&Path, &str)>) -> AppResult<Scan> {
    fn visit(
        path: &Path,
        own: Option<(&Path, &str)>,
        seen: &mut HashSet<PathBuf>,
        scan: &mut Scan,
    ) -> AppResult<()> {
        if !seen.insert(path.to_path_buf()) {
            return Ok(());
        }
        if seen.len() > 128 {
            return Err(error("DNS_CONFIG_UNSUPPORTED", "too many included files"));
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() > 1024 * 1024 {
            return Err(error(
                "DNS_CONFIG_UNSUPPORTED",
                "configuration exceeds limit",
            ));
        }
        if own.is_some_and(|(name, content)| name == path && bytes == content.as_bytes()) {
            return Ok(());
        }
        scan.files.push((path.to_path_buf(), fingerprint(&bytes)));
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| error("DNS_CONFIG_UNSUPPORTED", "non-UTF8 configuration"))?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            if line == "no-resolv" {
                scan.no_resolv = true;
            }
            if line == "dnssec" {
                return Err(error(
                    "DNS_POLICY_CONFLICT",
                    "dnsmasq DNSSEC requires a separately validated adapter",
                ));
            }
            if let Some(value) = line
                .strip_prefix("server=")
                .or_else(|| line.strip_prefix("address="))
            {
                if !value.starts_with('/') {
                    return Err(error(
                        "DNS_POLICY_CONFLICT",
                        "existing default DNS server must not race the proxy resolver",
                    ));
                }
                let (domains, address) = value.rsplit_once('/').unwrap_or(("", ""));
                if let Ok(target) = address
                    .split(['#', '@'])
                    .next()
                    .unwrap_or("")
                    .parse::<IpAddr>()
                {
                    let port = address
                        .split_once('#')
                        .map(|(_, suffix)| suffix.split('@').next().unwrap_or(""))
                        .unwrap_or("53");
                    if port == "53" && scan.system_targets.contains(&target) {
                        return Err(error(
                            "DNS_POLICY_CONFLICT",
                            "existing private forwarder would loop through system DNS redirection",
                        ));
                    }
                }
                if !address.is_empty()
                    && !scan.domains.iter().any(|local| {
                        domains
                            .trim_matches('/')
                            .split('/')
                            .all(|d| d == local || d.ends_with(&format!(".{local}")))
                    })
                {
                    return Err(error(
                        "DNS_POLICY_CONFLICT",
                        "existing domain-specific DNS forwarding requires explicit preservation",
                    ));
                }
            }
            if let Some(value) = line
                .strip_prefix("conf-file=")
                .or_else(|| line.strip_prefix("servers-file="))
            {
                let include = Path::new(value);
                if !include.is_absolute() || value.contains(',') {
                    return Err(error(
                        "DNS_CONFIG_UNSUPPORTED",
                        "non-standard included configuration",
                    ));
                }
                visit(include, own, seen, scan)?;
            }
            if let Some(value) = line.strip_prefix("conf-dir=") {
                if value.contains(',') || !Path::new(value).is_absolute() {
                    return Err(error(
                        "DNS_CONFIG_UNSUPPORTED",
                        "filtered configuration directory",
                    ));
                }
                let directory = PathBuf::from(value);
                if !std::fs::canonicalize(&directory)?.starts_with("/tmp") {
                    return Err(error(
                        "DNS_CONFIG_UNSUPPORTED",
                        "configuration directory must reside in /tmp",
                    ));
                }
                scan.dirs.push(directory.clone());
                for entry in std::fs::read_dir(directory)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with('.') || name.ends_with('~') || name.ends_with(".bak") {
                        continue;
                    }
                    if entry.file_type()?.is_symlink() {
                        return Err(error(
                            "DNS_CONFIG_UNSUPPORTED",
                            "symlink in configuration directory",
                        ));
                    }
                    if entry.file_type()?.is_file() {
                        visit(&entry.path(), own, seen, scan)?;
                    }
                }
            }
        }
        Ok(())
    }
    let mut scan = Scan {
        dirs: Vec::new(),
        no_resolv: false,
        domains: vec!["lan".into(), "in-addr.arpa".into(), "ip6.arpa".into()],
        files: Vec::new(),
        system_targets: system_targets()?,
    };
    scan.domains.extend(magic_domains());
    // dnsmasq's configured local zone is authoritative and must remain local.
    let text = std::fs::read_to_string(config)?;
    for name in text.lines().filter_map(|line| line.strip_prefix("local=/")) {
        let name = name.trim_end_matches('/');
        if domain_valid(name) {
            scan.domains.push(name.into());
        }
    }
    visit(config, own, &mut HashSet::new(), &mut scan)?;
    if let Ok(bytes) = std::fs::read("/etc/resolv.conf") {
        scan.files
            .push(("/etc/resolv.conf".into(), fingerprint(&bytes)));
    }
    scan.files.sort();
    Ok(scan)
}

fn policy(scan: &Scan) -> String {
    fingerprint(&serde_json::to_vec(&scan.files).expect("serializable file identities"))
}

fn system_targets() -> AppResult<Vec<IpAddr>> {
    let text = std::fs::read_to_string("/etc/resolv.conf")?;
    let mut targets = BTreeSet::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let target = words
            .next()
            .ok_or_else(|| error("DNS_CONFIG_UNSUPPORTED", "missing system nameserver"))?
            .parse::<IpAddr>()
            .map_err(|_| error("DNS_CONFIG_UNSUPPORTED", "non-standard system nameserver"))?;
        if !target.is_loopback() && !target.is_unspecified() {
            targets.insert(target);
        }
    }
    Ok(targets.into_iter().collect())
}

fn system_rules(system: &SystemDns, token: &str) -> String {
    // One atomic batch. `create table { chain ... }` ignores nested rules on
    // nft 1.0.2. Mark DNS before the core's IPv6 strict-route filter; the NAT
    // framework may dispatch its callbacks after that filter's hook priority.
    // A temporary skb priority distinguishes app DNS from marked core sockets;
    // the core also uses conntrack mark 0x2024 for its own resolver traffic.
    let table = &system.table;
    let mut rules = format!("create table inet {table}\nadd chain inet {table} mark_output {{ type route hook output priority -199; policy accept; }}\nadd rule inet {table} mark_output meta mark 0x2024 return comment \"miao-dns:{token}\"\nadd rule inet {table} mark_output meta mark & 0xff0000 == 0x80000 return\nadd rule inet {table} mark_output ct mark 0x2024 meta mark set 0x2024 return\nadd chain inet {table} output {{ type nat hook output priority -151; policy accept; }}\nadd rule inet {table} output meta mark 0x2024 meta priority != 0x4d444e53 return\nadd rule inet {table} output meta mark & 0xff0000 == 0x80000 return\n");
    for target in &system.targets {
        let family = if target.is_ipv4() { "ip" } else { "ip6" };
        for protocol in ["udp", "tcp"] {
            rules.push_str(&format!("add rule inet {table} mark_output {family} daddr {target} {protocol} dport 53 ct mark set 0x2024 meta mark set 0x2024 meta priority set 0x4d444e53\nadd rule inet {table} output {family} daddr {target} {protocol} dport 53 meta priority set 0 redirect to :53\n"));
        }
    }
    // dnsmasq's local-service check excludes some point-to-point source
    // addresses. Keep redirected router queries on loopback in both directions;
    // conntrack reverses the mapping back to the caller's original resolver.
    rules.push_str(&format!("add chain inet {table} source {{ type nat hook postrouting priority 99; policy accept; }}\n"));
    for (family, address) in [("ip", "127.0.0.1"), ("ip6", "::1")] {
        for protocol in ["udp", "tcp"] {
            rules.push_str(&format!("add rule inet {table} source {family} daddr {address} {protocol} dport 53 ct mark 0x2024 ct status dnat snat {family} to {address}\n"));
        }
    }
    for (_, _, command) in reply_specs(system, token) {
        rules.push_str(&command);
    }
    rules
}

async fn nft(system: &SystemDns, args: &[&str]) -> AppResult<std::process::Output> {
    let out = command_output(&system.nft, args, Duration::from_secs(5)).await?;
    if !out.status.success() {
        return Err(error(
            "DNS_SYSTEM_RULES_FAILED",
            "unable to inspect or apply owned system DNS rules",
        ));
    }
    Ok(out)
}

async fn existing_chains(system: &SystemDns) -> AppResult<Vec<ReplyChain>> {
    let out = nft(system, &["-j", "-a", "list", "chains"]).await?;
    let value: Value = serde_json::from_slice(&out.stdout)?;
    Ok(value["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let chain = entry.get("chain")?;
            Some(ReplyChain {
                family: chain["family"].as_str()?.into(),
                table: chain["table"].as_str()?.into(),
                name: chain["name"].as_str()?.into(),
            })
        })
        .collect())
}

async fn chain_rules(system: &SystemDns, chain: &ReplyChain) -> AppResult<Vec<Value>> {
    let out = nft(
        system,
        &[
            "-j",
            "-a",
            "list",
            "chain",
            &chain.family,
            &chain.table,
            &chain.name,
        ],
    )
    .await?;
    let value: Value = serde_json::from_slice(&out.stdout)?;
    Ok(value["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("rule").cloned())
        .collect())
}

async fn discover_reply_chains(system: &SystemDns) -> AppResult<Vec<ReplyChain>> {
    let mut found = Vec::new();
    if !system.targets.iter().any(tailscale_address) {
        return Ok(found);
    }
    for chain in existing_chains(system).await? {
        if chain.name != "ts-input"
            || !["ip", "ip6", "inet"].contains(&chain.family.as_str())
            || !valid_instance(&chain.table)
        {
            continue;
        }
        let rules = chain_rules(system, &chain).await?;
        if rules.iter().any(|rule| {
            let text = rule.to_string();
            (text.contains("100.64.0.0") || text.contains("fd7a:115c:a1e0::"))
                && rule["expr"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item.get("drop").is_some()))
        }) {
            found.push(chain);
        }
    }
    Ok(found)
}

async fn remove_reply_rules(system: &SystemDns, token: &str) -> AppResult<()> {
    let present = existing_chains(system).await?;
    for chain in &system.reply_chains {
        if !present.contains(chain) {
            continue;
        }
        for rule in chain_rules(system, chain).await? {
            if !rule["comment"]
                .as_str()
                .is_some_and(|comment| comment.starts_with(&format!("miao-dns:{token}:reply:")))
            {
                continue;
            }
            let handle = rule["handle"]
                .as_u64()
                .ok_or_else(|| {
                    error(
                        "DNS_OWNERSHIP_CONFLICT",
                        "DNS reply exception has no handle",
                    )
                })?
                .to_string();
            nft(
                system,
                &[
                    "delete",
                    "rule",
                    &chain.family,
                    &chain.table,
                    &chain.name,
                    "handle",
                    &handle,
                ],
            )
            .await?;
        }
    }
    Ok(())
}

async fn repair_reply_rules(root: &Path, token: &str) -> AppResult<()> {
    let _lock = lock(root).await?;
    let Some(journal) = read_journal(root).await?.filter(|j| {
        j.token == token
            && j.system_may_be_loaded
            && !j.restore_pending
            && j.manager.alive()
            && j.core.alive()
    }) else {
        return Ok(());
    };
    let Some(system) = &journal.plan.system else {
        return Ok(());
    };
    if system.reply_chains.is_empty() {
        return Ok(());
    }
    let table = system_table(system).await?.ok_or_else(|| {
        error(
            "DNS_SYSTEM_RULES_FAILED",
            "owned system DNS table disappeared",
        )
    })?;
    check_system_owner(&table, &journal)?;
    let present = existing_chains(system).await?;
    let mut commands = String::new();
    for chain in &system.reply_chains {
        if !present.contains(chain) {
            continue;
        } // Tailscale may still be restarting.
        let rules = chain_rules(system, chain).await?;
        for (expected, comment, command) in reply_specs(system, token) {
            if expected == *chain && !rules.iter().any(|rule| rule["comment"] == comment) {
                commands.push_str(&command);
            }
        }
    }
    if !commands.is_empty() {
        let file = root.join("dns-reply-repair.nft");
        write_file_atomic(&file, &commands, "DNS reply rule repair").await?;
        let result = nft(system, &["-f", file.to_str().unwrap()]).await;
        let _ = tokio::fs::remove_file(file).await;
        result?;
    }
    Ok(())
}

async fn system_table(system: &SystemDns) -> AppResult<Option<Value>> {
    let list = nft(system, &["-j", "-a", "list", "tables"]).await?;
    let list: Value = serde_json::from_slice(&list.stdout)?;
    if !list["nftables"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["table"]["family"] == "inet" && item["table"]["name"] == system.table)
    }) {
        return Ok(None);
    }
    let detail = nft(
        system,
        &["-j", "-a", "list", "table", "inet", &system.table],
    )
    .await?;
    let detail: Value = serde_json::from_slice(&detail.stdout)?;
    let mut table = detail["nftables"]
        .as_array()
        .and_then(|items| items.iter().find_map(|item| item.get("table").cloned()))
        .ok_or_else(|| {
            error(
                "DNS_SYSTEM_RULES_FAILED",
                "missing system DNS table identity",
            )
        })?;
    // nft 1.0.2 omits table comments in JSON; rule comments are portable.
    table["owner"] = detail["nftables"]
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|item| {
                item["rule"]["comment"]
                    .as_str()
                    .filter(|comment| comment.starts_with("miao-dns:"))
                    .map(str::to_owned)
            })
        })
        .map(Value::String)
        .unwrap_or(Value::Null);
    Ok(Some(table))
}

fn check_system_owner(table: &Value, journal: &Ownership) -> AppResult<u64> {
    let handle = table["handle"]
        .as_u64()
        .ok_or_else(|| error("DNS_OWNERSHIP_CONFLICT", "system DNS table has no handle"))?;
    if table["owner"] != format!("miao-dns:{}", journal.token)
        || journal
            .system_handle
            .is_some_and(|expected| expected != handle)
    {
        return Err(error(
            "DNS_OWNERSHIP_CONFLICT",
            "system DNS table ownership changed",
        ));
    }
    Ok(handle)
}

async fn install_system(root: &Path, journal: &mut Ownership) -> AppResult<()> {
    let Some(system) = journal.plan.system.clone() else {
        return Ok(());
    };
    if system_table(&system).await?.is_some() {
        return Err(error(
            "DNS_OWNERSHIP_CONFLICT",
            "system DNS table appeared during activation",
        ));
    }
    journal.system_may_be_loaded = true;
    save_journal(root, journal).await?;
    let file = root.join("dns-system.nft");
    write_file_atomic(
        &file,
        &system_rules(&system, &journal.token),
        "system DNS rules",
    )
    .await?;
    let result = nft(&system, &["-f", file.to_str().unwrap()]).await;
    let _ = tokio::fs::remove_file(file).await;
    result?;
    let table = system_table(&system)
        .await?
        .ok_or_else(|| error("DNS_SYSTEM_RULES_FAILED", "system DNS table disappeared"))?;
    journal.system_handle = Some(check_system_owner(&table, journal)?);
    save_journal(root, journal).await
}

async fn restore_system(root: &Path, journal: &mut Ownership) -> AppResult<()> {
    if !journal.system_may_be_loaded {
        return Ok(());
    }
    if let Some(system) = journal.plan.system.as_ref() {
        if let Some(table) = system_table(system).await? {
            let handle = check_system_owner(&table, journal)?.to_string();
            // Delete by the verified kernel handle, never by a reusable table name.
            if let Err(e) = nft(system, &["delete", "table", "inet", "handle", &handle]).await {
                if system_table(system).await?.is_some() {
                    return Err(e);
                }
            }
        }
        remove_reply_rules(system, &journal.token).await?;
    }
    journal.system_may_be_loaded = false;
    journal.system_handle = None;
    save_journal(root, journal).await
}

async fn ubus(path: &Path, method: &str, body: Value) -> AppResult<Value> {
    let body = serde_json::to_string(&body)?;
    let out = command_output(
        path,
        &["call", "service", method, &body],
        Duration::from_secs(5),
    )
    .await?;
    if !out.status.success() {
        return Err(error(
            "DNS_SERVICE_FAILED",
            format!("procd {method} failed"),
        ));
    }
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&out.stdout).map_err(AppError::from)
}

pub async fn preflight(config: &Config) -> AppResult<Option<DnsPlan>> {
    validate_ports(config)?;
    if config.mode != ProxyMode::Global || !Path::new("/etc/openwrt_release").is_file() {
        return Ok(None);
    }
    let dirs = command_search_dirs();
    let bus = find_command(&dirs, "ubus")
        .ok_or_else(|| error("DNS_UNSUPPORTED", "OpenWrt ubus is required"))?;
    let init = PathBuf::from("/etc/init.d/dnsmasq");
    if !init.is_file() {
        return Err(error(
            "DNS_UNSUPPORTED",
            "a managed dnsmasq instance is required",
        ));
    }
    let service = ubus(&bus, "list", json!({"name":"dnsmasq"})).await?;
    let instances = service["dnsmasq"]["instances"]
        .as_object()
        .ok_or_else(|| error("DNS_UNSUPPORTED", "dnsmasq is not managed by procd"))?;
    let active: Vec<_> = instances
        .iter()
        .filter(|(_, value)| value["running"] == true)
        .collect();
    // Never guess which resolver to mutate when custom/multiple instances are active.
    if active.len() != 1 {
        return Err(error(
            "DNS_INSTANCE_CONFLICT",
            "exactly one active dnsmasq instance is currently supported",
        ));
    }
    let (instance, value) = active[0];
    if !valid_instance(instance) {
        return Err(error("DNS_INSTANCE_CONFLICT", "invalid instance identity"));
    }
    let command: Vec<&str> = value["command"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    // Unknown command-line policy must not bypass the configuration-file scan.
    if command.iter().skip(1).any(|arg| {
        arg.starts_with("--server")
            || arg.starts_with("--address")
            || arg.starts_with("--conf-dir")
            || arg.starts_with("--servers-file")
            || arg.starts_with("-S")
            || arg.starts_with("-A")
            || arg.starts_with("-7")
    }) {
        return Err(error(
            "DNS_CONFIG_UNSUPPORTED",
            "DNS policy supplied on the command line",
        ));
    }
    let cfg = command
        .windows(2)
        .find(|pair| pair[0] == "-C" || pair[0] == "--conf-file")
        .map(|pair| PathBuf::from(pair[1]))
        .ok_or_else(|| {
            error(
                "DNS_CONFIG_UNSUPPORTED",
                "cannot identify runtime configuration",
            )
        })?;
    let binary = PathBuf::from(
        *command
            .first()
            .ok_or_else(|| error("DNS_CONFIG_UNSUPPORTED", "missing service command"))?,
    );
    if !cfg.is_absolute() || !binary.is_absolute() {
        return Err(error(
            "DNS_CONFIG_UNSUPPORTED",
            "service paths must be absolute",
        ));
    }
    let root = super::singbox::get_sing_box_home();
    let existing = read_journal(&root).await?;
    // Bind both protocols before interrupting a working runtime. An existing
    // owned core is the sole exception when preparing its replacement.
    if !existing
        .as_ref()
        .is_some_and(|j| j.core.alive() && j.manager.pid == std::process::id())
    {
        let address = (Ipv4Addr::LOCALHOST, DNS_PORT);
        let _tcp =
            std::net::TcpListener::bind(address).map_err(|e| error("DNS_PORT_CONFLICT", e))?;
        let _udp = std::net::UdpSocket::bind(address).map_err(|e| error("DNS_PORT_CONFLICT", e))?;
    }
    let own = existing.as_ref().map(|journal| {
        (
            journal.plan.fragment.as_path(),
            journal.plan.content.as_str(),
        )
    });
    let scan = scan_config(&cfg, own)?;
    if scan.dirs.len() != 1 || !scan.dirs[0].starts_with("/tmp") {
        return Err(error(
            "DNS_CONFIG_UNSUPPORTED",
            "one runtime conf-dir is required",
        ));
    }
    let name = format!(
        "miao-{}.conf",
        &fingerprint(root.as_os_str().as_encoded_bytes())[..12]
    );
    let fragment = scan.dirs[0].join(name);
    if fragment.exists()
        && !existing.as_ref().is_some_and(|j| {
            j.plan.fragment == fragment
                && std::fs::read(&fragment).ok().as_deref() == Some(j.plan.content.as_bytes())
        })
    {
        return Err(error(
            "DNS_OWNERSHIP_CONFLICT",
            "existing DNS fragment is not owned by this runtime",
        ));
    }
    let mut content = format!("# miao:{}\n", root.display());
    if !scan.no_resolv {
        content.push_str("no-resolv\n");
    }
    content.push_str(&format!("server=127.0.0.1#{DNS_PORT}\n"));
    for domain in magic_domains() {
        // MagicDNS legitimately returns CGNAT/ULA addresses. Exempt only the
        // discovered private zone, keeping rebind protection for public names.
        content.push_str(&format!("rebind-domain-ok=/{domain}/\n"));
    }
    let targets = system_targets()?;
    let system = if targets.is_empty() {
        None
    } else {
        let mut system = SystemDns {
            nft: find_command(&dirs, "nft").ok_or_else(|| {
                error(
                    "DNS_SYSTEM_RESOLVER_UNSUPPORTED",
                    "non-local system DNS requires nftables redirection",
                )
            })?,
            table: format!(
                "miao_dns_{}",
                &fingerprint(root.as_os_str().as_encoded_bytes())[..12]
            ),
            targets,
            reply_chains: Vec::new(),
        };
        system.reply_chains = discover_reply_chains(&system).await?;
        if let Some(table) = system_table(&system).await? {
            let owner = existing
                .as_ref()
                .filter(|j| {
                    j.plan
                        .system
                        .as_ref()
                        .is_some_and(|s| s.table == system.table)
                })
                .ok_or_else(|| {
                    error(
                        "DNS_OWNERSHIP_CONFLICT",
                        "system DNS table is not owned by this runtime",
                    )
                })?;
            check_system_owner(&table, owner)?;
        }
        let mut check = system.clone();
        check.table.push_str("_check");
        if system_table(&check).await?.is_some() {
            return Err(error(
                "DNS_OWNERSHIP_CONFLICT",
                "system DNS validation table already exists",
            ));
        }
        let file = root.join("dns-system-check.nft");
        write_file_atomic(
            &file,
            &system_rules(&check, "validation"),
            "system DNS check",
        )
        .await?;
        let result = nft(&check, &["-c", "-f", file.to_str().unwrap()]).await;
        let _ = tokio::fs::remove_file(file).await;
        result?;
        Some(system)
    };
    let text = std::fs::read_to_string(&cfg)?;
    let port = text
        .lines()
        .find_map(|line| line.strip_prefix("port="))
        .unwrap_or("53")
        .parse::<u16>()
        .map_err(|_| error("DNS_CONFIG_UNSUPPORTED", "invalid dnsmasq listening port"))?;
    if port != 53 {
        return Err(error(
            "DNS_UNSUPPORTED",
            "a non-standard DNS frontend requires a separately validated adapter",
        ));
    }
    let plan = DnsPlan {
        instance: instance.clone(),
        config: cfg,
        binary,
        init,
        ubus: bus,
        fragment,
        content,
        dns_port: port,
        policy: policy(&scan),
        files: scan.files,
        system,
    };
    let candidate = root.join("dns-candidate.conf");
    write_file_atomic(&candidate, &plan.content, "DNS candidate").await?;
    let out = command_output(
        &plan.binary,
        &[
            "--test",
            "-C",
            plan.config.to_str().unwrap(),
            "-C",
            candidate.to_str().unwrap(),
        ],
        Duration::from_secs(5),
    )
    .await;
    let _ = tokio::fs::remove_file(candidate).await;
    if !out?.status.success() {
        return Err(error(
            "DNS_CONFIG_INVALID",
            "dnsmasq rejected the proposed configuration",
        ));
    }
    Ok(Some(plan))
}

struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

async fn lock(root: &Path) -> AppResult<Lock> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(root.join("dns-ownership.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Lock(file));
        }
        let last = std::io::Error::last_os_error();
        if last.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(last.into());
        }
        if Instant::now() >= deadline {
            return Err(error(
                "DNS_BUSY",
                "another DNS recovery operation is still active",
            ));
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

async fn read_journal(root: &Path) -> AppResult<Option<Ownership>> {
    match tokio::fs::read(root.join(JOURNAL)).await {
        Ok(bytes) => {
            let journal: Ownership = serde_json::from_slice(&bytes)?;
            if journal.version != 1 {
                return Err(error(
                    "DNS_OWNER_FAILED",
                    "unsupported DNS ownership version",
                ));
            }
            Ok(Some(journal))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn save_journal(root: &Path, journal: &Ownership) -> AppResult<()> {
    write_file_atomic(
        &root.join(JOURNAL),
        &serde_json::to_string(journal)?,
        "DNS ownership",
    )
    .await
}

fn install_fragment(plan: &DnsPlan) -> AppResult<()> {
    let parent = plan
        .fragment
        .parent()
        .ok_or_else(|| error("DNS_CONFIG_INVALID", "missing fragment directory"))?;
    let temporary = parent.join(format!(".miao-{}.tmp", std::process::id()));
    let result = (|| -> AppResult<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(plan.content.as_bytes())?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        std::fs::hard_link(&temporary, &plan.fragment)
            .map_err(|e| error("DNS_OWNERSHIP_CONFLICT", e))?;
        std::fs::remove_file(&temporary)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

async fn service_pid(plan: &DnsPlan) -> AppResult<u64> {
    let value = ubus(&plan.ubus, "list", json!({"name":"dnsmasq"})).await?;
    let instance = &value["dnsmasq"]["instances"][&plan.instance];
    if instance["running"] != true {
        return Err(error(
            "DNS_SERVICE_FAILED",
            "dnsmasq instance is not running",
        ));
    }
    instance["pid"]
        .as_u64()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| error("DNS_SERVICE_FAILED", "invalid procd host PID"))
}

async fn restart(plan: &DnsPlan) -> AppResult<()> {
    let previous = service_pid(plan).await.ok();
    let result = command_output(
        &plan.init,
        &["restart", &plan.instance],
        Duration::from_secs(15),
    )
    .await?;
    if !result.status.success() {
        return Err(error("DNS_SERVICE_FAILED", "dnsmasq restart failed"));
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if let Ok(pid) = service_pid(plan).await {
            if previous != Some(pid)
                && tokio::time::timeout(
                    Duration::from_millis(250),
                    tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, plan.dns_port)),
                )
                .await
                .is_ok_and(|r| r.is_ok())
            {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(error(
        "DNS_SERVICE_FAILED",
        "dnsmasq did not restart and become ready",
    ))
}

fn guard_command(root: &Path, journal: &Ownership) -> Vec<String> {
    vec![
        journal.executable.to_string_lossy().into_owned(),
        GUARD_ARG.into(),
        root.to_string_lossy().into_owned(),
        journal.token.clone(),
    ]
}

async fn remove_guard(root: &Path, journal: &Ownership) -> AppResult<()> {
    let service = ubus(&journal.plan.ubus, "list", json!({"name":journal.service})).await?;
    if service[&journal.service].is_null() {
        return Ok(());
    }
    let expected = serde_json::to_value(guard_command(root, journal))?;
    if service[&journal.service]["instances"]["guard"]["command"] != expected {
        return Err(error(
            "DNS_OWNERSHIP_CONFLICT",
            "recovery service identity changed",
        ));
    }
    if let Err(e) = ubus(
        &journal.plan.ubus,
        "delete",
        json!({"name":journal.service}),
    )
    .await
    {
        let after = ubus(&journal.plan.ubus, "list", json!({"name":journal.service})).await?;
        if !after[&journal.service].is_null() {
            return Err(e);
        }
    }
    Ok(())
}

impl DnsLease {
    pub async fn diagnostic(&self) -> DnsStatus {
        match read_journal(&self.root).await {
            Ok(Some(journal)) if journal.token == self.token => {
                if journal.restore_pending {
                    DnsStatus {
                        phase: "failed",
                        message: "系统 DNS 恢复待完成，核心继续提供解析".into(),
                    }
                } else {
                    DnsStatus {
                        phase: "active",
                        message: "dnsmasq 公网查询已自动接入代理 DNS".into(),
                    }
                }
            }
            Ok(_) => DnsStatus {
                phase: "restored",
                message: "系统 DNS 已恢复原上游".into(),
            },
            Err(e) => DnsStatus {
                phase: "failed",
                message: e.to_string(),
            },
        }
    }

    pub async fn prepare(plan: DnsPlan, core_pid: u32) -> AppResult<Self> {
        let root = super::singbox::get_sing_box_home();
        let _lock = lock(&root).await?;
        if read_journal(&root).await?.is_some() {
            return Err(error(
                "DNS_RESOURCES_IN_USE",
                "previous DNS operation has not been restored",
            ));
        }
        let (boot, namespace) = context()?;
        let token = fingerprint(
            format!(
                "{boot}:{namespace}:{}:{:?}",
                std::process::id(),
                std::time::SystemTime::now()
            )
            .as_bytes(),
        );
        let journal = Ownership {
            version: 1,
            token: token.clone(),
            boot,
            namespace,
            manager: ProcessIdentity::read(std::process::id())
                .ok_or_else(|| error("DNS_OWNER_FAILED", "manager identity unavailable"))?,
            core: ProcessIdentity::read(core_pid)
                .ok_or_else(|| error("CORE_EXITED", "core exited before DNS activation"))?,
            executable: std::env::current_exe()?,
            service: format!("miao-dns-{}", &token[..16]),
            plan,
            may_be_loaded: false,
            restore_pending: false,
            system_may_be_loaded: false,
            system_handle: None,
        };
        save_journal(&root, &journal).await?;
        let request = json!({"name":journal.service,"instances":{"guard":{
            "command":guard_command(&root, &journal),
            "env":{"MIAO_EMBEDDED":"ivnc","MIAO_RUNTIME_DIR":root},
            "respawn":["3600","1","5"],"stderr":true}}});
        let setup = async {
            ubus(&journal.plan.ubus, "set", request).await?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if tokio::fs::read_to_string(root.join(format!("dns-guard-{token}.ready")))
                    .await
                    .ok()
                    .as_deref()
                    == Some(&token)
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error(
                "DNS_GUARD_FAILED",
                "independent recovery guard did not become ready",
            ))
        }
        .await;
        if let Err(e) = setup {
            let _ = remove_guard(&root, &journal).await;
            let _ = tokio::fs::remove_file(root.join(JOURNAL)).await;
            return Err(e);
        }
        Ok(Self { root, token })
    }

    pub async fn activate(&self, state: &crate::state::AppState, epoch: u64) -> AppResult<()> {
        let _lock = lock(&self.root).await?;
        let mut journal = read_journal(&self.root)
            .await?
            .filter(|j| j.token == self.token)
            .ok_or_else(|| error("DNS_OWNER_FAILED", "activation was superseded"))?;
        if !journal.manager.alive() || !journal.core.alive() {
            return Err(error("CORE_EXITED", "DNS activation owner exited"));
        }
        let expected = super::routing::cancellable(
            state,
            epoch,
            probe_backend((Ipv4Addr::LOCALHOST, DNS_PORT).into()),
        )
        .await?;
        super::routing::cancellable(
            state,
            epoch,
            probe((Ipv4Addr::LOCALHOST, DNS_PORT).into(), false),
        )
        .await?;
        let scan = scan_config(&journal.plan.config, None)?;
        if policy(&scan) != journal.plan.policy {
            let changed: BTreeSet<_> = journal
                .plan
                .files
                .iter()
                .chain(scan.files.iter())
                .filter(|entry| !journal.plan.files.contains(entry) || !scan.files.contains(entry))
                .map(|(path, _)| path.display().to_string())
                .collect();
            let changed = changed.into_iter().collect::<Vec<_>>().join(", ");
            // OpenWrt/Tailscale may regenerate resolver files while the core
            // becomes ready. Re-run every preflight once before changing DNS;
            // never accept a stale policy or replace the selected service.
            let mut intent = state.config.read().await.clone();
            intent.mode = ProxyMode::Global;
            let refreshed = super::routing::cancellable(state, epoch, preflight(&intent))
                .await?
                .ok_or_else(|| error("DNS_POLICY_CHANGED", &changed))?;
            if refreshed.instance != journal.plan.instance
                || refreshed.config != journal.plan.config
                || refreshed.binary != journal.plan.binary
                || refreshed.init != journal.plan.init
                || refreshed.ubus != journal.plan.ubus
                || refreshed.fragment != journal.plan.fragment
                || refreshed.content != journal.plan.content
                || refreshed.dns_port != journal.plan.dns_port
                || policy(&scan_config(&refreshed.config, None)?) != refreshed.policy
            {
                return Err(error(
                    "DNS_POLICY_CHANGED",
                    format!("DNS configuration remained unstable or changed identity: {changed}"),
                ));
            }
            journal.plan = refreshed;
            save_journal(&self.root, &journal).await?;
            tracing::info!(files = %changed, "Revalidated regenerated DNS configuration");
        }
        // Write-ahead ownership makes every interruption recoverable.
        journal.may_be_loaded = true;
        save_journal(&self.root, &journal).await?;
        install_fragment(&journal.plan)?;
        restart(&journal.plan).await?;
        super::routing::check_current(state, epoch)?;
        for tcp in [false, true] {
            let actual = super::routing::cancellable(
                state,
                epoch,
                probe((Ipv4Addr::LOCALHOST, journal.plan.dns_port).into(), tcp),
            )
            .await?;
            if actual != expected {
                return Err(error(
                    "DNS_FORWARDING_FAILED",
                    "dnsmasq did not use the protected resolver",
                ));
            }
        }
        install_system(&self.root, &mut journal).await?;
        if let Some(system) = &journal.plan.system {
            for target in &system.targets {
                for tcp in [false, true] {
                    let actual = super::routing::cancellable(
                        state,
                        epoch,
                        probe(SocketAddr::new(*target, 53), tcp),
                    )
                    .await?;
                    if actual != expected {
                        return Err(error(
                            "DNS_SYSTEM_FORWARDING_FAILED",
                            "system resolver bypassed protected DNS",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn restore(&self) -> AppResult<()> {
        restore_token(&self.root, &self.token, false).await
    }
}

async fn restore_token(root: &Path, token: &str, guard: bool) -> AppResult<()> {
    let _lock = lock(root).await?;
    let Some(mut journal) = read_journal(root).await?.filter(|j| j.token == token) else {
        return Ok(());
    };
    let (boot, namespace) = context()?;
    if journal.boot != boot || journal.namespace != namespace {
        return Err(error(
            "DNS_OWNER_FAILED",
            "DNS ownership belongs to another boot or namespace",
        ));
    }
    journal.restore_pending = true;
    save_journal(root, &journal).await?;
    restore_system(root, &mut journal).await?;
    match tokio::fs::read(&journal.plan.fragment).await {
        Ok(bytes) => {
            if bytes != journal.plan.content.as_bytes() {
                return Err(error(
                    "DNS_OWNERSHIP_CONFLICT",
                    "DNS fragment was changed outside Miao",
                ));
            }
            tokio::fs::remove_file(&journal.plan.fragment).await?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if journal.may_be_loaded {
        restart(&journal.plan).await?;
        journal.may_be_loaded = false;
        save_journal(root, &journal).await?;
    }
    if guard && !journal.manager.alive() {
        // PDEATHSIG does not guarantee that the core finishes route cleanup.
        // Restore all owned resources before publishing completed recovery.
        if journal.core.alive() {
            return Err(error(
                "NETWORK_RESOURCES_IN_USE",
                "waiting for the recorded core to exit before route recovery",
            ));
        }
        super::route_cleanup::RouteOwnership::recover().await?;
        super::firewall::Fw3Rules::cleanup_stale().await?;
    }
    tokio::fs::remove_file(root.join(JOURNAL)).await?;
    let _ = tokio::fs::remove_file(root.join(format!("dns-guard-{token}.ready"))).await;
    // The guard must release the cross-process lock before procd terminates it.
    drop(_lock);
    if !guard {
        remove_guard(root, &journal).await?;
    }
    Ok(())
}

pub async fn recover_stale(root: &Path) -> AppResult<()> {
    let Some(journal) = read_journal(root).await? else {
        return Ok(());
    };
    let (boot, namespace) = context()?;
    if journal.boot != boot {
        if journal.plan.fragment.exists() {
            return Err(error(
                "DNS_OWNER_FAILED",
                "unexpected fragment survived a reboot",
            ));
        }
        tokio::fs::remove_file(root.join(JOURNAL)).await?;
        return Ok(());
    }
    if journal.namespace != namespace {
        return Err(error("DNS_OWNER_FAILED", "different DNS network namespace"));
    }
    if journal.manager.alive()
        && (journal.manager.pid != std::process::id()
            || (journal.core.alive() && !journal.restore_pending))
    {
        return Err(error(
            "DNS_RESOURCES_IN_USE",
            "a live runtime still owns the DNS adapter",
        ));
    }
    restore_token(root, &journal.token, false).await
}

pub async fn run_guard(root: PathBuf, token: String) -> AppResult<()> {
    if !root.is_absolute()
        || root.parent().is_none()
        || token.len() != 64
        || !token.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(error("DNS_GUARD_INVALID", "invalid guard identity"));
    }
    let initial = read_journal(&root)
        .await?
        .filter(|j| j.token == token)
        .ok_or_else(|| error("DNS_GUARD_INVALID", "no matching DNS operation"))?;
    let (boot, namespace) = context()?;
    if initial.boot != boot || initial.namespace != namespace {
        return Err(error("DNS_GUARD_INVALID", "incorrect boot or namespace"));
    }
    write_file_atomic(
        &root.join(format!("dns-guard-{token}.ready")),
        &token,
        "DNS guard readiness",
    )
    .await?;
    let mut next_rule_check = Instant::now() + Duration::from_secs(2);
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let current = read_journal(&root).await?;
        let Some(current) = current.filter(|j| j.token == token) else {
            break;
        };
        if current.manager.alive() && current.core.alive() && !current.restore_pending {
            if Instant::now() >= next_rule_check {
                if let Err(e) = repair_reply_rules(&root, &token).await {
                    tracing::error!(%e, "DNS reply rule verification failed");
                }
                next_rule_check = Instant::now() + Duration::from_secs(2);
            }
            continue;
        }
        match restore_token(&root, &token, true).await {
            Ok(()) => break,
            Err(e) => {
                tracing::error!(%e, "Independent DNS restoration failed; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    // Actual procd deletion may terminate this guard before the call returns.
    remove_guard(&root, &initial).await
}

fn dns_query() -> (u16, Vec<u8>) {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16)
        ^ std::process::id() as u16;
    let mut data = vec![0u8; 12];
    data[..2].copy_from_slice(&id.to_be_bytes());
    data[2] = 1;
    data[5] = 1;
    data.extend_from_slice(b"\x07example\x03com\0\0\x01\0\x01");
    (id, data)
}

fn skip_name(bytes: &[u8], mut at: usize) -> Option<usize> {
    let mut end = None;
    for _ in 0..128 {
        let n = *bytes.get(at)? as usize;
        at += 1;
        if n == 0 {
            return Some(end.unwrap_or(at));
        }
        if n & 0xc0 == 0xc0 {
            let pointer = ((n & 0x3f) << 8) | *bytes.get(at)? as usize;
            end.get_or_insert(at + 1);
            at = pointer;
            continue;
        }
        if n > 63 {
            return None;
        }
        at = at.checked_add(n)?;
    }
    None
}

fn parse_answer(bytes: &[u8], id: u16) -> Option<BTreeSet<Ipv4Addr>> {
    if bytes.len() < 12
        || bytes[..2] != id.to_be_bytes()
        || bytes[2] & 0xfa != 0x80
        || bytes[3] & 0xf != 0
    {
        return None;
    }
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
    if questions != 1 {
        return None;
    }
    let answers = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(bytes, at)?.checked_add(4)?;
        if at > bytes.len() {
            return None;
        }
    }
    let mut addresses = BTreeSet::new();
    for _ in 0..answers {
        at = skip_name(bytes, at)?;
        let head = bytes.get(at..at + 10)?;
        let count = u16::from_be_bytes([head[8], head[9]]) as usize;
        at += 10;
        let body = bytes.get(at..at + count)?;
        if head[..4] == [0, 1, 0, 1] && body.len() == 4 {
            addresses.insert(Ipv4Addr::new(body[0], body[1], body[2], body[3]));
        }
        at += count;
    }
    (!addresses.is_empty()).then_some(addresses)
}

pub async fn probe(address: SocketAddr, tcp: bool) -> AppResult<BTreeSet<Ipv4Addr>> {
    let (id, query) = dns_query();
    let work = async {
        let bytes = if tcp {
            let mut stream = tokio::net::TcpStream::connect(address).await?;
            stream.write_u16(query.len() as u16).await?;
            stream.write_all(&query).await?;
            let length = stream.read_u16().await? as usize;
            if length > 4096 {
                return Err(std::io::Error::other("DNS response exceeds limit"));
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await?;
            bytes
        } else {
            let bind = if address.is_ipv4() {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            };
            let socket = tokio::net::UdpSocket::bind(bind).await?;
            socket.connect(address).await?;
            socket.send(&query).await?;
            let mut bytes = vec![0u8; 4096];
            let count = socket.recv(&mut bytes).await?;
            bytes.truncate(count);
            bytes
        };
        parse_answer(&bytes, id)
            .ok_or_else(|| std::io::Error::other("invalid or unsuccessful DNS response"))
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .map_err(|_| {
            error(
                "DNS_PROBE_FAILED",
                format!("{address}: DNS response timed out"),
            )
        })?
        .map_err(|e| {
            error(
                "DNS_PROBE_FAILED",
                format!("{address} ({}): {e}", if tcp { "TCP" } else { "UDP" }),
            )
        })
}

async fn probe_backend(address: SocketAddr) -> AppResult<BTreeSet<Ipv4Addr>> {
    // A cold overlay connection may close or time out its first DNS exchange.
    // Retry once while still cancellable and before changing the system DNS.
    match probe(address, true).await {
        Ok(answer) => Ok(answer),
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(250)).await;
            probe(address, true).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backend_readiness_tolerates_one_cold_connection_failure() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            let length = second.read_u16().await.unwrap() as usize;
            let mut query = vec![0; length];
            second.read_exact(&mut query).await.unwrap();
            query[2] = 0x81;
            query[3] = 0x80;
            query[7] = 1;
            query.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 10]);
            second.write_u16(query.len() as u16).await.unwrap();
            second.write_all(&query).await.unwrap();
        });
        assert_eq!(
            probe_backend(address).await.unwrap(),
            BTreeSet::from([Ipv4Addr::new(203, 0, 113, 10)])
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_backend_fails_after_the_bounded_retry() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (client, _) = listener.accept().await.unwrap();
                drop(client);
            }
        });
        assert!(probe_backend(address).await.is_err());
        server.await.unwrap();
    }

    #[test]
    fn dns_probe_rejects_truncated_foreign_and_compression_loop_answers() {
        let (id, query) = dns_query();
        let mut answer = query;
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 1;
        let offset = answer.len();
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 10]);
        assert_eq!(
            parse_answer(&answer, id).unwrap(),
            BTreeSet::from([Ipv4Addr::new(203, 0, 113, 10)])
        );
        for length in 0..answer.len() {
            assert!(parse_answer(&answer[..length], id).is_none());
        }
        assert!(parse_answer(&answer, id.wrapping_add(1)).is_none());
        let mut invalid = answer.clone();
        invalid[2] |= 2; // TC: a truncated UDP answer cannot prove forwarding readiness.
        assert!(parse_answer(&invalid, id).is_none());
        let mut invalid = answer.clone();
        invalid[offset + 1] = offset as u8;
        assert!(parse_answer(&invalid, id).is_none());
        let mut invalid = answer;
        invalid[offset + 1] = 255;
        assert!(parse_answer(&invalid, id).is_none());
    }

    #[test]
    fn dns_preflight_preserves_local_zones_and_refuses_competing_public_upstreams() {
        let directory = std::env::temp_dir().join(format!("miao-dns-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(directory.join("fragments")).unwrap();
        let config = directory.join("dnsmasq.conf");
        let base = format!(
            "local=/home.arpa/\nconf-dir={}\nresolv-file=/tmp/wan-dns\n",
            directory.join("fragments").display()
        );
        for directive in [
            "",
            "server=/printer.home.arpa/192.168.1.1",
            "server=/onion/",
        ] {
            std::fs::write(&config, format!("{base}{directive}\n")).unwrap();
            assert!(scan_config(&config, None).is_ok(), "{directive}");
        }
        for directive in [
            "server=192.168.1.1",
            "server=/#/192.168.1.1",
            "server=/google.com/192.168.1.1",
            "dnssec",
        ] {
            std::fs::write(&config, format!("{base}{directive}\n")).unwrap();
            assert!(
                scan_config(&config, None)
                    .unwrap_err()
                    .to_string()
                    .contains("DNS_POLICY_CONFLICT"),
                "{directive}"
            );
        }
        std::fs::write(&config, &base).unwrap();
        let fragment = directory.join("fragments/miao.conf");
        let content = "no-resolv\nserver=127.0.0.1#6263\n";
        std::fs::write(&fragment, content).unwrap();
        assert!(scan_config(&config, Some((&fragment, content))).is_ok());
        std::fs::write(&fragment, "server=192.168.1.1\n").unwrap();
        assert!(scan_config(&config, Some((&fragment, content))).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dns_port_conflicts_are_rejected_before_runtime_replacement() {
        for config in [
            Config {
                port: Some(DNS_PORT),
                ..Default::default()
            },
            Config {
                socks_port: Some(DNS_PORT),
                ..Default::default()
            },
        ] {
            assert!(validate_ports(&config)
                .unwrap_err()
                .to_string()
                .contains("DNS_PORT_CONFLICT"));
        }
        assert!(validate_ports(&Config {
            mode: ProxyMode::Pool,
            socks_port: Some(DNS_PORT),
            ..Default::default()
        })
        .is_ok());
    }

    #[test]
    fn process_identity_checks_start_ticks_and_zombies_instead_of_pid_files() {
        let identity = ProcessIdentity::read(std::process::id()).unwrap();
        assert!(identity.alive());
        assert!(!ProcessIdentity {
            start: identity.start + 1,
            ..identity
        }
        .alive());
        assert!(ProcessIdentity::read(u32::MAX).is_none());
    }
}
