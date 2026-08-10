use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::{DEFAULT_PORT, DEFAULT_SOCKS_PORT};
use crate::services::write_file_atomic;

const SHARE_PORTS_DIR: &str = "data/cache";
const SHARE_PORTS_FILE: &str = "share_ports.json";
const CLASH_API_PORT: u16 = 6262;

/// 节点 tag -> SOCKS 端口的分配账本。
///
/// 只是一本"谁曾经拿到过哪个端口"的账，用来在节点增删/订阅重排时保持端口稳定；
/// 真正在监听什么以生成出来的 sing-box 配置为准。
///
/// `base_port` 记录这本账是按哪个起始端口算出来的：用户改了起始端口就整本重算，
/// 否则改设置会变成静默空操作。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePortMap {
    #[serde(default)]
    pub base_port: u16,
    #[serde(default)]
    pub ports: BTreeMap<String, u16>,
}

pub fn share_ports_path() -> PathBuf {
    PathBuf::from(SHARE_PORTS_DIR).join(SHARE_PORTS_FILE)
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

/// 为给定节点 tag 分配稳定的 SOCKS 端口，纯内存操作。
///
/// 规则：
/// - 已有 tag 保留原端口，除非该端口现在与保留端口冲突或低于起始端口；
/// - `base_port` 变化时整本账重算，让"改起始端口"真的生效；
/// - 只在 `prune` 为真（即节点列表确实完整）时删除失效 tag——订阅临时抓取失败
///   不能把别人的端口收走，否则恢复后端口会变，分发出去的地址全部作废；
/// - 端口只在 `base_port..=65535` 内扫描，扫不到就报错，绝不回绕到低位特权端口。
///
/// 返回值按传入 `tags` 的顺序给出 (tag, port)。
pub fn allocate_share_ports(
    map: &mut SharePortMap,
    tags: &[String],
    base_port: u16,
    reserved: &BTreeSet<u16>,
    prune: bool,
) -> AppResult<Vec<(String, u16)>> {
    if base_port == 0 {
        return Err(AppError::message(
            "Invalid share base_port: must be between 1 and 65535",
        ));
    }

    if map.base_port != base_port {
        map.ports.clear();
        map.base_port = base_port;
    }

    if prune {
        let active: BTreeSet<&str> = tags.iter().map(String::as_str).collect();
        map.ports.retain(|tag, _| active.contains(tag.as_str()));
    }

    // 已落盘的分配也要重新校验：起始端口调整过、或者 web/socks 端口改到了某个
    // 已分配端口上时，旧账目必须让位，否则会生成两个监听同一端口的 inbound，
    // 而 `sing-box check` 不绑定套接字、发现不了，直到启动时整个进程挂掉。
    map.ports
        .retain(|_, port| *port >= base_port && !reserved.contains(port));

    // 防御手改账本导致的一端口多 tag。
    let mut seen_ports = BTreeSet::new();
    map.ports.retain(|_, port| seen_ports.insert(*port));

    let mut used: BTreeSet<u16> = reserved.clone();
    used.extend(map.ports.values().copied());

    // 单次调用内 `used` 只增不减，所以游标可以单调前进；跨调用则从 base_port
    // 重新开始，这样被释放的低位端口能重新用上，不会一路漂到 65535。
    let mut cursor = base_port;
    for tag in tags {
        if map.ports.contains_key(tag) {
            continue;
        }
        let port = next_free_port(&mut cursor, &used, base_port)?;
        used.insert(port);
        map.ports.insert(tag.clone(), port);
    }

    Ok(tags
        .iter()
        .filter_map(|tag| map.ports.get(tag).map(|port| (tag.clone(), *port)))
        .collect())
}

fn next_free_port(cursor: &mut u16, used: &BTreeSet<u16>, base_port: u16) -> AppResult<u16> {
    loop {
        if !used.contains(cursor) {
            return Ok(*cursor);
        }
        if *cursor == u16::MAX {
            return Err(AppError::message(format!(
                "Share mode: no free port left in {}-65535 for all nodes",
                base_port
            )));
        }
        *cursor += 1;
    }
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
        allocate_share_ports(map, &tags(names), base_port, reserved, true).unwrap()
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
            allocate_share_ports(&mut map, &tags(&["alpha"]), 12000, &reserved, false).unwrap();
        assert_eq!(partial, vec![("alpha".into(), 12000)]);
        assert_eq!(map.ports.get("beta"), Some(&12001));

        // 订阅恢复后 beta 拿回原来的端口。
        let restored =
            allocate_share_ports(&mut map, &tags(&["alpha", "beta"]), 12000, &reserved, false)
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
        let err = allocate_share_ports(&mut map, &tags(&["a", "b", "c"]), 65534, &reserved, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no free port left"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_zero_base_port() {
        let mut map = SharePortMap::default();
        assert!(allocate_share_ports(&mut map, &tags(&["a"]), 0, &BTreeSet::new(), true).is_err());
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
