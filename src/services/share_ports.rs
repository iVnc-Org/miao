use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::{DEFAULT_PORT, DEFAULT_SOCKS_PORT};
use crate::paths::data_file;
use crate::services::write_file_atomic;

const SHARE_PORTS_FILE: &str = "share_ports.json";
const CLASH_API_PORT: u16 = 6262;
const SHARE_PORTS_SCHEMA_VERSION: u32 = 2;
const SHARE_PORT_BLOCK_SIZE: u32 = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePortGroup {
    pub source: String,
    pub tags: Vec<String>,
}

/// 节点 tag -> SOCKS 端口及订阅 -> 端口段的分配账本。
///
/// 只是一本"谁曾经拿到过哪个端口"的账，用来在节点增删/订阅重排时保持端口稳定；
/// 真正在监听什么以生成出来的 sing-box 配置为准。
///
/// `base_port` 记录这本账是按哪个起始端口算出来的：用户改了起始端口就整本重算。
/// 第 0 个 1000 端口段固定属于手动节点，订阅从第 1 段开始，并按 URL 持久绑定段号。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePortMap {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub base_port: u16,
    #[serde(default)]
    pub ports: BTreeMap<String, u16>,
    #[serde(default)]
    pub subscription_blocks: BTreeMap<String, u32>,
}

impl Default for SharePortMap {
    fn default() -> Self {
        Self {
            schema_version: SHARE_PORTS_SCHEMA_VERSION,
            base_port: 0,
            ports: BTreeMap::new(),
            subscription_blocks: BTreeMap::new(),
        }
    }
}

pub fn share_ports_path() -> PathBuf {
    data_file(SHARE_PORTS_FILE)
}

pub async fn load_share_port_map() -> SharePortMap {
    load_share_port_map_from(&share_ports_path()).await
}

pub async fn load_share_port_map_from(path: &Path) -> SharePortMap {
    let Ok(content) = tokio::fs::read_to_string(path).await else {
        return SharePortMap::default();
    };
    match serde_json::from_str(&content) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(path = ?path, error = %e, "Failed to parse share port map, reallocating from scratch");
            SharePortMap::default()
        }
    }
}

pub async fn save_share_port_map(map: &SharePortMap) -> AppResult<()> {
    save_share_port_map_to(&share_ports_path(), map).await
}

pub async fn save_share_port_map_to(path: &Path, map: &SharePortMap) -> AppResult<()> {
    let content = serde_json::to_string_pretty(map)
        .map_err(|e| AppError::context("Failed to serialize share port map", e))?;
    write_file_atomic(path, &content, "share port map").await
}

pub fn reserved_system_ports(web_port: Option<u16>, socks_port: Option<u16>) -> BTreeSet<u16> {
    let mut reserved = BTreeSet::new();
    reserved.insert(web_port.unwrap_or(DEFAULT_PORT));
    reserved.insert(socks_port.unwrap_or(DEFAULT_SOCKS_PORT));
    reserved.insert(CLASH_API_PORT);
    reserved
}

/// 为手动节点和各订阅节点分配稳定的 SOCKS 端口，纯内存操作。
///
/// 规则：
/// - 手动节点只能使用 `base_port` 开始的第 0 个 1000 端口段；
/// - 每个订阅 URL 持久绑定一个从 1 开始的独立端口段，配置重排不会换段；
/// - 已有 tag 保留原端口，除非该端口与保留端口冲突或不在所属段内；
/// - `base_port` 变化时整本账重算，让"改起始端口"真的生效；
/// - 只在 `prune` 为真（即节点列表确实完整）时删除失效 tag——订阅临时抓取失败
///   不能把别人的端口收走，否则恢复后端口会变，分发出去的地址全部作废；
/// - 每组只在自己的端口段内扫描，容量不足或段起点超过 65535 时明确报错。
///
/// 返回值先按手动节点顺序、再按传入订阅及其节点顺序给出 (tag, port)。
pub fn allocate_share_ports(
    map: &mut SharePortMap,
    manual_tags: &[String],
    subscription_groups: &[SharePortGroup],
    base_port: u16,
    reserved: &BTreeSet<u16>,
    prune: bool,
) -> AppResult<Vec<(String, u16)>> {
    if base_port == 0 {
        return Err(AppError::message(
            "Invalid share base_port: must be between 1 and 65535",
        ));
    }

    let mut updated = map.clone();
    if updated.schema_version != SHARE_PORTS_SCHEMA_VERSION || updated.base_port != base_port {
        updated = SharePortMap {
            base_port,
            ..SharePortMap::default()
        };
    }

    let mut active_sources = BTreeSet::new();
    for group in subscription_groups {
        if !active_sources.insert(group.source.as_str()) {
            return Err(AppError::message(format!(
                "Share mode: duplicate subscription source: {}",
                group.source
            )));
        }
    }
    updated
        .subscription_blocks
        .retain(|source, _| active_sources.contains(source.as_str()));

    // 先校验持久化的段号。URL 顺序只用于给新订阅挑最小空闲段，已经分配的段不动。
    let mut used_blocks = BTreeSet::new();
    let mut invalid_sources = Vec::new();
    for group in subscription_groups {
        let Some(block) = updated.subscription_blocks.get(&group.source).copied() else {
            continue;
        };
        if block == 0
            || port_block_bounds(base_port, block).is_none()
            || !used_blocks.insert(block)
        {
            invalid_sources.push(group.source.clone());
        }
    }
    for source in invalid_sources {
        updated.subscription_blocks.remove(&source);
    }

    for group in subscription_groups {
        if updated.subscription_blocks.contains_key(&group.source) {
            continue;
        }
        let mut block = 1_u32;
        while used_blocks.contains(&block) {
            block += 1;
        }
        if port_block_bounds(base_port, block).is_none() {
            return Err(AppError::message(format!(
                "Share mode: no port block available for subscription {} with base_port {}",
                group.source, base_port
            )));
        }
        used_blocks.insert(block);
        updated
            .subscription_blocks
            .insert(group.source.clone(), block);
    }

    let manual_bounds = port_block_bounds(base_port, 0).expect("validated non-zero base port");
    let mut expected_bounds = BTreeMap::new();
    let mut ordered_tags = Vec::new();
    for tag in manual_tags {
        if expected_bounds.insert(tag.clone(), manual_bounds).is_some() {
            return Err(AppError::message(format!(
                "Share mode: duplicate node tag: {tag}"
            )));
        }
        ordered_tags.push(tag.clone());
    }
    for group in subscription_groups {
        let block = updated.subscription_blocks[&group.source];
        let bounds = port_block_bounds(base_port, block).expect("validated subscription block");
        for tag in &group.tags {
            if expected_bounds.insert(tag.clone(), bounds).is_some() {
                return Err(AppError::message(format!(
                    "Share mode: duplicate node tag: {tag}"
                )));
            }
            ordered_tags.push(tag.clone());
        }
    }

    if prune {
        updated
            .ports
            .retain(|tag, _| expected_bounds.contains_key(tag));
    }

    // 已落盘的活动节点必须仍在所属端口段内；非活动节点在不完整抓取期间继续占号。
    updated.ports.retain(|tag, port| {
        if *port < base_port || reserved.contains(port) {
            return false;
        }
        match expected_bounds.get(tag) {
            Some((start, end)) => *port >= *start && *port <= *end,
            None => true,
        }
    });

    // 防御手改账本导致的一端口多 tag；当前活动节点优先保留端口。
    let mut seen_ports = BTreeSet::new();
    let mut duplicate_tags = Vec::new();
    for tag in &ordered_tags {
        if let Some(port) = updated.ports.get(tag) {
            if !seen_ports.insert(*port) {
                duplicate_tags.push(tag.clone());
            }
        }
    }
    for (tag, port) in &updated.ports {
        if expected_bounds.contains_key(tag) {
            continue;
        }
        if !seen_ports.insert(*port) {
            duplicate_tags.push(tag.clone());
        }
    }
    for tag in duplicate_tags {
        updated.ports.remove(&tag);
    }

    let mut used: BTreeSet<u16> = reserved.clone();
    used.extend(updated.ports.values().copied());

    allocate_group_ports(
        &mut updated.ports,
        manual_tags,
        manual_bounds,
        &mut used,
        "manual nodes",
    )?;
    for group in subscription_groups {
        let block = updated.subscription_blocks[&group.source];
        let bounds = port_block_bounds(base_port, block).expect("validated subscription block");
        allocate_group_ports(
            &mut updated.ports,
            &group.tags,
            bounds,
            &mut used,
            &format!("subscription {}", group.source),
        )?;
    }

    let bindings = ordered_tags
        .iter()
        .filter_map(|tag| updated.ports.get(tag).map(|port| (tag.clone(), *port)))
        .collect();
    *map = updated;
    Ok(bindings)
}

fn port_block_bounds(base_port: u16, block: u32) -> Option<(u16, u16)> {
    let start = u32::from(base_port).checked_add(block.checked_mul(SHARE_PORT_BLOCK_SIZE)?)?;
    if start > u32::from(u16::MAX) {
        return None;
    }
    let end = start
        .saturating_add(SHARE_PORT_BLOCK_SIZE - 1)
        .min(u32::from(u16::MAX));
    Some((start as u16, end as u16))
}

fn allocate_group_ports(
    ports: &mut BTreeMap<String, u16>,
    tags: &[String],
    (start, end): (u16, u16),
    used: &mut BTreeSet<u16>,
    group_label: &str,
) -> AppResult<()> {
    let mut cursor = u32::from(start);
    for tag in tags {
        if ports.contains_key(tag) {
            continue;
        }
        while cursor <= u32::from(end) && used.contains(&(cursor as u16)) {
            cursor += 1;
        }
        if cursor > u32::from(end) {
            return Err(AppError::message(format!(
                "Share mode: no free port left in {start}-{end} for {group_label}"
            )));
        }
        let port = cursor as u16;
        used.insert(port);
        ports.insert(tag.clone(), port);
    }
    Ok(())
}

pub fn share_inbound_tag(port: u16) -> String {
    format!("share-{port}")
}

/// userinfo 里的保留字符必须转义，否则密码含 `@` / `:` / `/` / `#` 时
/// 复制出来的 URL 会被客户端解析成别的 host 或别的密码——代理本身能用，
/// 但用户拿到的地址是坏的，且无从排查。
fn encode_userinfo(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

/// 拼出分享端口的 SOCKS URL。
///
/// 通配监听地址原样保留，不替换成回环：后端并不知道客户端该走哪个地址，
/// 而分享模式的主要用法就是从另一台机器连入——写成 127.0.0.1 会给出一个
/// 在目标机器上必定连不上的地址。前端拿到后会用当前访问面板的主机名替换。
pub fn build_share_socks_url(listen: &str, port: u16, username: &str, password: &str) -> String {
    let host_part = if listen.contains(':') && !listen.starts_with('[') {
        format!("[{listen}]")
    } else {
        listen.to_string()
    };

    if !username.is_empty() && !password.is_empty() {
        format!(
            "socks5://{}:{}@{host_part}:{port}",
            encode_userinfo(username),
            encode_userinfo(password)
        )
    } else {
        format!("socks5://{host_part}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn alloc(
        map: &mut SharePortMap,
        names: &[&str],
        base_port: u16,
        reserved: &BTreeSet<u16>,
    ) -> Vec<(String, u16)> {
        allocate_share_ports(map, &tags(names), &[], base_port, reserved, true).unwrap()
    }

    fn group(source: &str, names: &[&str]) -> SharePortGroup {
        SharePortGroup {
            source: source.to_string(),
            tags: tags(names),
        }
    }

    #[test]
    fn keeps_stable_mapping_for_existing_tags() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();

        let first = alloc(&mut map, &["alpha", "beta"], 12000, &reserved);
        assert_eq!(first, vec![("alpha".into(), 12000), ("beta".into(), 12001)]);

        let second = alloc(&mut map, &["beta", "alpha", "gamma"], 12000, &reserved);
        assert_eq!(
            second,
            vec![
                ("beta".into(), 12001),
                ("alpha".into(), 12000),
                ("gamma".into(), 12002)
            ]
        );
    }

    #[test]
    fn skips_reserved_ports() {
        let mut reserved = reserved_system_ports(None, Some(1080));
        reserved.insert(12000);
        let mut map = SharePortMap::default();

        assert_eq!(
            alloc(&mut map, &["alpha"], 12000, &reserved),
            vec![("alpha".into(), 12001)]
        );
    }

    #[test]
    fn evicts_persisted_port_that_became_reserved() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();
        assert_eq!(
            alloc(&mut map, &["alpha"], 12000, &reserved),
            vec![("alpha".into(), 12000)]
        );

        // 用户把 socks_port 改成了 12000，正好压在已分配的端口上。
        let moved = reserved_system_ports(None, Some(12000));
        assert_eq!(
            alloc(&mut map, &["alpha"], 12000, &moved),
            vec![("alpha".into(), 12001)]
        );
    }

    #[test]
    fn incomplete_round_still_serves_current_nodes_without_renumbering() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();
        alloc(&mut map, &["alpha", "beta", "gamma"], 12000, &reserved);

        // 抓取不完整的一轮：gamma 这次没出现，但它的端口要留着，
        // 同时新加的 delta 不能抢到 gamma 占着的 12002。
        let partial = allocate_share_ports(
            &mut map,
            &tags(&["alpha", "beta", "delta"]),
            &[],
            12000,
            &reserved,
            false,
        )
        .unwrap();
        assert_eq!(
            partial,
            vec![
                ("alpha".into(), 12000),
                ("beta".into(), 12001),
                ("delta".into(), 12003)
            ]
        );
        assert_eq!(map.ports.get("gamma"), Some(&12002));
    }

    #[test]
    fn transient_node_loss_does_not_release_ports() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();
        alloc(&mut map, &["alpha", "beta"], 12000, &reserved);

        // 订阅抓取失败，本轮只看得到 alpha —— prune=false，beta 的端口必须留着。
        let partial =
            allocate_share_ports(&mut map, &tags(&["alpha"]), &[], 12000, &reserved, false)
                .unwrap();
        assert_eq!(partial, vec![("alpha".into(), 12000)]);
        assert_eq!(map.ports.get("beta"), Some(&12001));

        // 订阅恢复后 beta 拿回原来的端口。
        let restored =
            allocate_share_ports(
                &mut map,
                &tags(&["alpha", "beta"]),
                &[],
                12000,
                &reserved,
                false,
            )
            .unwrap();
        assert_eq!(
            restored,
            vec![("alpha".into(), 12000), ("beta".into(), 12001)]
        );
    }

    #[test]
    fn prune_reclaims_removed_tags_and_reuses_freed_ports() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();
        alloc(&mut map, &["alpha", "beta"], 12000, &reserved);

        assert_eq!(
            alloc(&mut map, &["beta"], 12000, &reserved),
            vec![("beta".into(), 12001)]
        );
        assert!(!map.ports.contains_key("alpha"));

        // alpha 空出来的 12000 应该被重新利用，而不是一路往上漂。
        assert_eq!(
            alloc(&mut map, &["beta", "gamma"], 12000, &reserved),
            vec![("beta".into(), 12001), ("gamma".into(), 12000)]
        );
    }

    #[test]
    fn base_port_change_reallocates_everything() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();
        alloc(&mut map, &["alpha", "beta"], 12000, &reserved);

        // 调高。
        assert_eq!(
            alloc(&mut map, &["alpha", "beta"], 20000, &reserved),
            vec![("alpha".into(), 20000), ("beta".into(), 20001)]
        );
        assert_eq!(map.base_port, 20000);

        // 调低同样必须生效（旧实现里 next_port 只增不减，调低是彻底的空操作）。
        assert_eq!(
            alloc(&mut map, &["alpha", "beta"], 9000, &reserved),
            vec![("alpha".into(), 9000), ("beta".into(), 9001)]
        );
        assert_eq!(map.base_port, 9000);
    }

    #[test]
    fn exhausting_the_range_errors_instead_of_wrapping_to_privileged_ports() {
        let reserved = reserved_system_ports(None, Some(1080));
        let mut map = SharePortMap::default();

        // base_port=65534 只剩 65534/65535 两个口，第三个节点必须报错而不是绕回 1。
        let err = allocate_share_ports(
            &mut map,
            &tags(&["a", "b", "c"]),
            &[],
            65534,
            &reserved,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no free port left"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_zero_base_port() {
        let mut map = SharePortMap::default();
        assert!(
            allocate_share_ports(
                &mut map,
                &tags(&["a"]),
                &[],
                0,
                &BTreeSet::new(),
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn separates_manual_nodes_and_subscriptions_into_thousand_port_blocks() {
        let mut map = SharePortMap::default();
        let groups = vec![
            group("subscription-a", &["a1", "a2"]),
            group("subscription-b", &["b1"]),
        ];

        let bindings = allocate_share_ports(
            &mut map,
            &tags(&["manual-1", "manual-2"]),
            &groups,
            10000,
            &BTreeSet::new(),
            true,
        )
        .unwrap();

        assert_eq!(
            bindings,
            vec![
                ("manual-1".into(), 10000),
                ("manual-2".into(), 10001),
                ("a1".into(), 11000),
                ("a2".into(), 11001),
                ("b1".into(), 12000),
            ]
        );
        assert_eq!(map.subscription_blocks["subscription-a"], 1);
        assert_eq!(map.subscription_blocks["subscription-b"], 2);
    }

    #[test]
    fn empty_subscription_still_reserves_its_port_block() {
        let mut map = SharePortMap::default();
        let bindings = allocate_share_ports(
            &mut map,
            &[],
            &[
                group("subscription-a", &[]),
                group("subscription-b", &["b1"]),
            ],
            10000,
            &BTreeSet::new(),
            true,
        )
        .unwrap();

        assert_eq!(bindings, vec![("b1".into(), 12000)]);
        assert_eq!(map.subscription_blocks["subscription-a"], 1);
        assert_eq!(map.subscription_blocks["subscription-b"], 2);
    }

    #[test]
    fn subscription_reordering_keeps_persisted_blocks() {
        let mut map = SharePortMap::default();
        allocate_share_ports(
            &mut map,
            &[],
            &[
                group("subscription-a", &["a1"]),
                group("subscription-b", &["b1"]),
            ],
            10000,
            &BTreeSet::new(),
            true,
        )
        .unwrap();

        let reordered = allocate_share_ports(
            &mut map,
            &[],
            &[
                group("subscription-b", &["b1", "b2"]),
                group("subscription-a", &["a1", "a2"]),
            ],
            10000,
            &BTreeSet::new(),
            true,
        )
        .unwrap();

        assert_eq!(
            reordered,
            vec![
                ("b1".into(), 12000),
                ("b2".into(), 12001),
                ("a1".into(), 11000),
                ("a2".into(), 11001),
            ]
        );
    }

    #[test]
    fn group_cannot_spill_into_the_next_port_block() {
        let mut map = SharePortMap::default();
        let manual_tags: Vec<String> = (0..=SHARE_PORT_BLOCK_SIZE)
            .map(|index| format!("node-{index}"))
            .collect();

        let err = allocate_share_ports(
            &mut map,
            &manual_tags,
            &[],
            10000,
            &BTreeSet::new(),
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("10000-10999"), "unexpected error: {err}");
        assert!(map.ports.is_empty(), "failed allocation must be transactional");
    }

    #[test]
    fn subscription_block_must_start_within_the_port_range() {
        let mut map = SharePortMap::default();
        let err = allocate_share_ports(
            &mut map,
            &[],
            &[group("subscription-a", &[])],
            65000,
            &BTreeSet::new(),
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("no port block available"), "unexpected error: {err}");
    }

    #[test]
    fn old_contiguous_allocation_schema_is_rebuilt() {
        let mut map = SharePortMap {
            schema_version: 1,
            base_port: 10000,
            ports: BTreeMap::from([("subscription-node".to_string(), 10000)]),
            subscription_blocks: BTreeMap::new(),
        };

        let bindings = allocate_share_ports(
            &mut map,
            &[],
            &[group("subscription-a", &["subscription-node"])],
            10000,
            &BTreeSet::new(),
            true,
        )
        .unwrap();

        assert_eq!(bindings, vec![("subscription-node".into(), 11000)]);
        assert_eq!(map.schema_version, SHARE_PORTS_SCHEMA_VERSION);
    }

    #[test]
    fn build_share_socks_url_keeps_listen_host_and_brackets_ipv6() {
        // 通配地址原样保留，交给前端替换成实际可达的主机名。
        assert_eq!(
            build_share_socks_url("0.0.0.0", 12000, "", ""),
            "socks5://0.0.0.0:12000"
        );
        assert_eq!(
            build_share_socks_url("192.168.1.10", 12000, "u", "p"),
            "socks5://u:p@192.168.1.10:12000"
        );
        assert_eq!(
            build_share_socks_url("::1", 12000, "", ""),
            "socks5://[::1]:12000"
        );
        assert_eq!(
            build_share_socks_url("::", 12000, "", ""),
            "socks5://[::]:12000"
        );
    }

    #[test]
    fn build_share_socks_url_encodes_reserved_characters() {
        assert_eq!(
            build_share_socks_url("10.0.0.2", 12000, "us er", "p@ss:w/rd#1"),
            "socks5://us%20er:p%40ss%3Aw%2Frd%231@10.0.0.2:12000"
        );
    }
}
