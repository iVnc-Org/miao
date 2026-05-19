use base64::{engine::general_purpose, Engine as _};
use serde_yaml::Value;
use url::Url;

use crate::error::{AppError, AppResult};

/// 节点解析结果，包含有效节点和错误记录
#[derive(Debug)]
pub struct ParseResult {
    pub nodes: Vec<(String, serde_json::Value)>, // (name, outbound_json)
    pub errors: Vec<String>,                     // 记录解析失败的节点及原因
    pub total_count: usize,                      // YAML 中 proxies 列表的原始总数
}

/// 从 Clash 配置中解析节点，跳过无效节点并记录错误
pub fn parse_clash_proxies(clash_yaml: &str) -> AppResult<ParseResult> {
    let clash_obj: Value = serde_yaml::from_str(clash_yaml)
        .map_err(|e| AppError::context("Failed to parse subscription YAML", e))?;

    let proxies = clash_obj
        .get("proxies")
        .and_then(|p| p.as_sequence())
        .cloned()
        .unwrap_or_default();

    let mut result = ParseResult {
        nodes: vec![],
        errors: vec![],
        total_count: proxies.len(),
    };

    for (idx, node) in proxies.iter().enumerate() {
        let node_type = node
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown");

        // Skip unsupported node types silently
        if !is_supported_node_type(node_type) {
            continue;
        }

        match parse_single_node(node) {
            Some((name, outbound)) => result.nodes.push((name, outbound)),
            None => {
                let name = node
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("<index {}>", idx));
                result.errors.push(format!(
                    "Node '{}' (type: {}): missing required fields (type/server/port/password)",
                    name, node_type
                ));
            }
        }
    }

    Ok(result)
}

pub fn parse_uri_subscription(content: &str) -> AppResult<ParseResult> {
    let decoded = decode_subscription_body(content);
    let lines: Vec<&str> = decoded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let mut result = ParseResult {
        nodes: vec![],
        errors: vec![],
        total_count: lines.len(),
    };

    for (idx, line) in lines.iter().enumerate() {
        match parse_uri_node(line) {
            Ok(Some(node)) => result.nodes.push(node),
            Ok(None) => {}
            Err(err) => result
                .errors
                .push(format!("URI node #{}: {}", idx + 1, err)),
        }
    }

    if result.total_count == 0 {
        return Err(AppError::message("No URI nodes found"));
    }

    Ok(result)
}

fn decode_subscription_body(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.contains("://") {
        return trimmed.to_string();
    }

    decode_base64_text(trimmed).unwrap_or_else(|| trimmed.to_string())
}

fn decode_base64_text(input: &str) -> Option<String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(compact.as_bytes()) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

fn parse_uri_node(uri: &str) -> AppResult<Option<(String, serde_json::Value)>> {
    if uri.starts_with("ss://") {
        return parse_shadowsocks_uri(uri).map(Some);
    }
    Ok(None)
}

fn parse_shadowsocks_uri(uri: &str) -> AppResult<(String, serde_json::Value)> {
    let url = Url::parse(uri).map_err(|e| AppError::context("Invalid ss URI", e.to_string()))?;
    let name = url
        .fragment()
        .map(urlencoding::decode)
        .transpose()
        .map_err(|e| AppError::context("Invalid ss URI name", e.to_string()))?
        .map(|name| name.into_owned())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                url.host_str().unwrap_or("unknown"),
                url.port().unwrap_or(0)
            )
        });

    let server = url
        .host_str()
        .filter(|server| !server.trim().is_empty())
        .ok_or_else(|| AppError::message("ss URI missing server"))?;
    let port = url
        .port()
        .filter(|port| *port > 0)
        .ok_or_else(|| AppError::message("ss URI missing port"))?;

    let (method, password) = parse_ss_userinfo(&url)?;
    let mut outbound = serde_json::json!({
        "type": "shadowsocks",
        "tag": name,
        "server": server,
        "server_port": port,
        "method": method,
        "password": password
    });

    if let Some(plugin) = url
        .query_pairs()
        .find(|(key, _)| key == "plugin")
        .map(|(_, value)| value.into_owned())
    {
        if let Some((plugin_name, plugin_opts)) = convert_ss_plugin(&plugin) {
            outbound["plugin"] = serde_json::Value::String(plugin_name);
            outbound["plugin_opts"] = serde_json::Value::String(plugin_opts);
        }
    }

    Ok((
        outbound["tag"].as_str().unwrap_or_default().to_string(),
        outbound,
    ))
}

fn parse_ss_userinfo(url: &Url) -> AppResult<(String, String)> {
    let username = url.username();
    let password = url.password();

    if !username.is_empty() && password.is_some() {
        let method = urlencoding::decode(username)
            .map_err(|e| AppError::context("Invalid ss method", e.to_string()))?
            .into_owned();
        let password = urlencoding::decode(password.unwrap_or_default())
            .map_err(|e| AppError::context("Invalid ss password", e.to_string()))?
            .into_owned();
        return Ok((method, password));
    }

    let decoded = decode_base64_text(username)
        .ok_or_else(|| AppError::message("ss URI userinfo is not valid base64"))?;
    let (method, password) = decoded
        .split_once(':')
        .ok_or_else(|| AppError::message("ss URI userinfo missing method/password"))?;

    if method.is_empty() || password.is_empty() {
        return Err(AppError::message("ss URI method/password is empty"));
    }

    Ok((method.to_string(), password.to_string()))
}

fn convert_ss_plugin(plugin: &str) -> Option<(String, String)> {
    let (name, opts) = plugin.split_once(';').unwrap_or((plugin, ""));
    match name {
        "simple-obfs" => Some(("obfs-local".to_string(), opts.to_string())),
        "obfs-local" => Some(("obfs-local".to_string(), opts.to_string())),
        _ => None,
    }
}

fn is_supported_node_type(node_type: &str) -> bool {
    matches!(node_type, "hysteria2" | "anytls" | "ss")
}

fn parse_single_node(node: &Value) -> Option<(String, serde_json::Value)> {
    let typ = node.get("type")?.as_str()?;
    let name = node.get("name")?.as_str()?;

    // 验证必需字段
    let server = node.get("server")?.as_str()?;
    let port = node.get("port")?.as_u64()?;
    if port == 0 || port > 65535 {
        return None;
    }
    let password = node.get("password")?.as_str()?;

    let outbound = match typ {
        "hysteria2" => {
            let sni = node.get("sni").and_then(|s| s.as_str());
            let insecure = node
                .get("skip-cert-verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut obj = serde_json::json!({
                "type": "hysteria2",
                "tag": name,
                "server": server,
                "server_port": port,
                "password": password,
                "tls": {
                    "enabled": true,
                    "insecure": insecure
                }
            });

            if let Some(sni_val) = sni {
                obj["tls"]["server_name"] = serde_json::Value::String(sni_val.to_string());
            }

            obj
        }
        "anytls" => {
            let sni = node.get("sni").and_then(|s| s.as_str());
            let insecure = node
                .get("skip-cert-verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut obj = serde_json::json!({
                "type": "anytls",
                "tag": name,
                "server": server,
                "server_port": port,
                "password": password,
                "tls": {
                    "enabled": true,
                    "insecure": insecure
                }
            });

            if let Some(sni_val) = sni {
                obj["tls"]["server_name"] = serde_json::Value::String(sni_val.to_string());
            }

            obj
        }
        "ss" => {
            let method = node.get("cipher")?.as_str()?;
            let mut obj = serde_json::json!({
                "type": "shadowsocks",
                "tag": name,
                "server": server,
                "server_port": port,
                "method": method,
                "password": password
            });

            if let Some((plugin, plugin_opts)) = parse_clash_ss_plugin(node) {
                obj["plugin"] = serde_json::Value::String(plugin);
                obj["plugin_opts"] = serde_json::Value::String(plugin_opts);
            }

            obj
        }
        _ => return None, // 不支持的类型
    };

    Some((name.to_string(), outbound))
}

fn parse_clash_ss_plugin(node: &Value) -> Option<(String, String)> {
    let plugin = node.get("plugin")?.as_str()?;
    let opts = node.get("plugin-opts").or_else(|| node.get("plugin_opts"));

    match plugin {
        "obfs" | "simple-obfs" | "obfs-local" => {
            let mode = opts
                .and_then(|opts| opts.get("mode"))
                .and_then(|mode| mode.as_str())
                .or_else(|| {
                    opts.and_then(|opts| opts.get("obfs"))
                        .and_then(|obfs| obfs.as_str())
                })
                .unwrap_or("http");
            let host = opts
                .and_then(|opts| opts.get("host"))
                .and_then(|host| host.as_str())
                .or_else(|| {
                    opts.and_then(|opts| opts.get("obfs-host"))
                        .and_then(|host| host.as_str())
                });

            let mut plugin_opts = format!("obfs={mode}");
            if let Some(host) = host.filter(|host| !host.trim().is_empty()) {
                plugin_opts.push_str(";obfs-host=");
                plugin_opts.push_str(host);
            }

            Some(("obfs-local".to_string(), plugin_opts))
        }
        _ => None,
    }
}

/// 解析单个节点 JSON 字符串，返回验证后的 Value 和显示信息
pub fn parse_node_json(node_str: &str) -> Result<(NodeDisplayInfo, serde_json::Value), String> {
    let v: serde_json::Value =
        serde_json::from_str(node_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    let tag = v
        .get("tag")
        .and_then(|t| t.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("Missing or empty tag")?
        .to_string();

    let server = v
        .get("server")
        .and_then(|s| s.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or("Missing or empty server")?
        .to_string();

    let server_port = v
        .get("server_port")
        .and_then(|p| p.as_u64())
        .and_then(|p| {
            if p > 0 && p <= 65535 {
                Some(p as u16)
            } else {
                None
            }
        })
        .ok_or("Invalid or missing port")?;

    let node_type = v
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_string();

    let sni = v
        .get("tls")
        .and_then(|t| t.get("server_name"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let info = NodeDisplayInfo {
        tag,
        server,
        server_port,
        node_type,
        sni,
    };

    Ok((info, v))
}

/// 节点显示信息结构
#[derive(Debug, Clone)]
pub struct NodeDisplayInfo {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub node_type: String,
    pub sni: Option<String>,
}

impl std::fmt::Display for NodeDisplayInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}:{}) [{}]",
            self.tag, self.server, self.server_port, self.node_type
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clash_proxies_extracts_valid_nodes() {
        let yaml = r#"
proxies:
  - name: hy2-node
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass-hy
    sni: hy.example.com
  - name: anytls-node
    type: anytls
    server: any.example.com
    port: 8443
    password: pass-any
    sni: any.example.com
    skip-cert-verify: true
  - name: ss-node
    type: ss
    server: ss.example.com
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: pass-ss
  - name: ignored-node
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: xxx
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        // 3 valid nodes + 1 unsupported type (vmess) silently skipped
        assert_eq!(result.nodes.len(), 3);
        assert!(result.errors.is_empty()); // vmess is silently skipped, not reported as error
        assert_eq!(result.nodes[0].0, "hy2-node");
        assert_eq!(result.nodes[1].0, "anytls-node");
        assert_eq!(result.nodes[2].0, "ss-node");
    }

    #[test]
    fn parse_uri_subscription_decodes_base64_shadowsocks_links() {
        let body = general_purpose::STANDARD.encode(
            "ss://YWVzLTEyOC1nY206cGFzcw@example.com:12022/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#%E9%A6%99%E6%B8%AF%2001\n",
        );

        let result = parse_uri_subscription(&body).unwrap();

        assert_eq!(result.total_count, 1);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].0, "香港 01");
        let outbound = &result.nodes[0].1;
        assert_eq!(outbound["type"], "shadowsocks");
        assert_eq!(outbound["tag"], "香港 01");
        assert_eq!(outbound["server"], "example.com");
        assert_eq!(outbound["server_port"], 12022);
        assert_eq!(outbound["method"], "aes-128-gcm");
        assert_eq!(outbound["password"], "pass");
        assert_eq!(outbound["plugin"], "obfs-local");
        assert_eq!(
            outbound["plugin_opts"],
            "obfs=http;obfs-host=cdn.example.com"
        );
    }

    #[test]
    fn parse_uri_subscription_skips_unsupported_uri_types() {
        let result = parse_uri_subscription("vmess://ignored\nss://bad").unwrap();

        assert_eq!(result.total_count, 2);
        assert!(result.nodes.is_empty());
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn parse_clash_proxies_skips_invalid_nodes() {
        let yaml = r#"
proxies:
  - name: valid-node
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass-hy
  - name: invalid-missing-server
    type: hysteria2
    port: 443
    password: pass-hy
  - name: invalid-zero-port
    type: hysteria2
    server: hy.example.com
    port: 0
    password: pass-hy
  - name: invalid-missing-password
    type: hysteria2
    server: hy.example.com
    port: 443
  - name: unsupported-type
    type: vmess
    server: vm.example.com
    port: 443
    uuid: xxx
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].0, "valid-node");
        // 3 errors: missing-server, zero-port, missing-password
        // unsupported-type (vmess) is silently skipped, not reported as error
        assert_eq!(result.errors.len(), 3);

        // Verify error messages contain node names
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("invalid-missing-server")));
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("invalid-zero-port")));
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("invalid-missing-password")));
    }

    #[test]
    fn parse_clash_proxies_returns_empty_for_missing_proxies() {
        let yaml = "mixed-port: 7890";

        let result = parse_clash_proxies(yaml).unwrap();

        assert!(result.nodes.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn parse_clash_proxies_reports_invalid_yaml() {
        let err = parse_clash_proxies("proxies: [").unwrap_err();

        assert!(err
            .to_string()
            .contains("Failed to parse subscription YAML"));
    }

    #[test]
    fn parse_node_json_extracts_valid_node() {
        let json = r#"{"type":"hysteria2","tag":"test-node","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true,"server_name":"sni.example.com"}}"#;

        let (info, value) = parse_node_json(json).unwrap();

        assert_eq!(info.tag, "test-node");
        assert_eq!(info.server, "example.com");
        assert_eq!(info.server_port, 443);
        assert_eq!(info.node_type, "hysteria2");
        assert_eq!(info.sni, Some("sni.example.com".to_string()));
        // 验证返回的 Value 是正确的
        assert_eq!(value["tag"], "test-node");
        assert_eq!(value["server"], "example.com");
    }

    #[test]
    fn parse_node_json_rejects_empty_tag() {
        let json = r#"{"type":"hysteria2","tag":"","server":"example.com","server_port":443,"password":"secret"}"#;

        let err = parse_node_json(json).unwrap_err();
        assert!(err.contains("tag"));
    }

    #[test]
    fn parse_node_json_rejects_zero_port() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"example.com","server_port":0,"password":"secret"}"#;

        let err = parse_node_json(json).unwrap_err();
        assert!(err.contains("port"));
    }

    #[test]
    fn parse_node_json_rejects_missing_server() {
        let json = r#"{"type":"hysteria2","tag":"test","server_port":443,"password":"secret"}"#;

        let err = parse_node_json(json).unwrap_err();
        assert!(err.contains("server"));
    }

    #[test]
    fn parse_node_json_handles_optional_sni() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true}}"#;

        let (info, _) = parse_node_json(json).unwrap();
        assert_eq!(info.sni, None);
    }

    #[test]
    fn parse_node_json_handles_missing_tls() {
        let json = r#"{"type":"shadowsocks","tag":"test","server":"example.com","server_port":8388,"password":"secret","method":"aes-128-gcm"}"#;

        let (info, _) = parse_node_json(json).unwrap();
        assert_eq!(info.sni, None);
    }

    #[test]
    fn parse_node_json_rejects_port_too_large() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"example.com","server_port":65536,"password":"secret"}"#;

        let err = parse_node_json(json).unwrap_err();
        assert!(err.contains("port"));
    }

    #[test]
    fn parse_node_json_rejects_max_valid_port() {
        // 65535 should be accepted
        let json = r#"{"type":"hysteria2","tag":"test","server":"example.com","server_port":65535,"password":"secret"}"#;

        let (info, _) = parse_node_json(json).unwrap();
        assert_eq!(info.server_port, 65535);
    }

    #[test]
    fn parse_node_json_accepts_ipv4_server() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"192.168.1.1","server_port":443,"password":"secret"}"#;

        let (info, _) = parse_node_json(json).unwrap();
        assert_eq!(info.server, "192.168.1.1");
    }

    #[test]
    fn parse_node_json_accepts_ipv6_server() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"::1","server_port":443,"password":"secret"}"#;

        let (info, _) = parse_node_json(json).unwrap();
        assert_eq!(info.server, "::1");
    }

    #[test]
    fn parse_clash_proxies_handles_all_supported_types() {
        let yaml = r#"
proxies:
  - name: hy2-1
    type: hysteria2
    server: hy1.example.com
    port: 443
    password: pass1
  - name: hy2-2
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: pass2
    sni: hy2.example.com
  - name: anytls-1
    type: anytls
    server: any1.example.com
    port: 8443
    password: pass3
  - name: ss-1
    type: ss
    server: ss1.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pass4
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 4);
        assert!(result.errors.is_empty());

        let types: Vec<String> = result
            .nodes
            .iter()
            .map(|(_, o)| o.get("type").unwrap().as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            types,
            vec!["hysteria2", "hysteria2", "anytls", "shadowsocks"]
        );
    }

    #[test]
    fn parse_clash_proxies_handles_empty_proxies_list() {
        let yaml = r#"
proxies: []
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert!(result.nodes.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn parse_clash_proxies_preserves_skip_cert_verify() {
        let yaml = r#"
proxies:
  - name: test-skip-verify
    type: hysteria2
    server: test.example.com
    port: 443
    password: pass
    skip-cert-verify: true
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        let outbound = &result.nodes[0].1;
        assert_eq!(outbound["tls"]["insecure"], true);
    }

    #[test]
    fn parse_clash_proxies_defaults_skip_cert_verify_to_false() {
        let yaml = r#"
proxies:
  - name: test-default-verify
    type: hysteria2
    server: test.example.com
    port: 443
    password: pass
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        let outbound = &result.nodes[0].1;
        assert_eq!(outbound["tls"]["insecure"], false);
    }

    #[test]
    fn parse_clash_proxies_handles_mixed_valid_and_unsupported() {
        let yaml = r#"
proxies:
  - name: valid-hy2
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
  - name: unsupported-vmess
    type: vmess
    server: vm.example.com
    port: 443
    uuid: xxx
  - name: unsupported-trojan
    type: trojan
    server: tr.example.com
    port: 443
    password: pass
  - name: valid-ss
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        // Only 2 valid nodes (hysteria2 and ss), vmess and trojan silently skipped
        assert_eq!(result.nodes.len(), 2);
        assert!(result.errors.is_empty());

        let names: Vec<String> = result.nodes.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(names, vec!["valid-hy2", "valid-ss"]);
    }

    #[test]
    fn parse_clash_proxies_hysteria2_without_bandwidth_defaults() {
        // 测试：从 Clash 配置解析 Hysteria2 时不添加硬编码带宽
        let yaml = r#"
proxies:
  - name: hy2-without-bandwidth
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    sni: hy.example.com
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        let outbound = &result.nodes[0].1;
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["tag"], "hy2-without-bandwidth");
        // 关键测试：不应包含硬编码的 up_mbps/down_mbps
        assert!(outbound.get("up_mbps").is_none() || outbound["up_mbps"].is_null());
        assert!(outbound.get("down_mbps").is_none() || outbound["down_mbps"].is_null());
    }

    #[test]
    fn parse_node_json_rejects_empty_server() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"","server_port":443,"password":"secret"}"#;

        let err = parse_node_json(json).unwrap_err();
        assert!(err.contains("server"));
    }

    #[test]
    fn parse_node_json_rejects_whitespace_only_server() {
        let json = r#"{"type":"hysteria2","tag":"test","server":"   ","server_port":443,"password":"secret"}"#;

        let err = parse_node_json(json).unwrap_err();
        assert!(err.contains("server"));
    }

    #[test]
    fn parse_node_json_accepts_whitespace_in_tag() {
        let json = r#"{"type":"hysteria2","tag":"My Node 1","server":"example.com","server_port":443,"password":"secret"}"#;

        let (info, _) = parse_node_json(json).unwrap();
        assert_eq!(info.tag, "My Node 1");
    }

    #[test]
    fn parse_clash_proxies_reports_multiple_missing_fields() {
        let yaml = r#"
proxies:
  - name: missing-everything
    type: hysteria2
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert!(result.nodes.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("missing-everything"));
    }

    #[test]
    fn parse_clash_proxies_handles_ss_without_cipher() {
        let yaml = r#"
proxies:
  - name: ss-no-cipher
    type: ss
    server: ss.example.com
    port: 8388
    password: pass
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        // SS without cipher should be rejected
        assert!(result.nodes.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("ss-no-cipher"));
    }

    #[test]
    fn parse_node_json_display_format() {
        let info = NodeDisplayInfo {
            tag: "Test Node".to_string(),
            server: "192.168.1.1".to_string(),
            server_port: 8388,
            node_type: "shadowsocks".to_string(),
            sni: None,
        };

        let display = format!("{}", info);
        assert_eq!(display, "Test Node (192.168.1.1:8388) [shadowsocks]");
    }
}
