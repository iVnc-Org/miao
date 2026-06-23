use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde_json::{json, Map, Value as JsonValue};
use serde_yaml::{Mapping, Value};
use std::sync::LazyLock;
use url::Url;

use crate::error::{AppError, AppResult};

static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .unwrap()
});
static VALID_VMESS_SECURITIES: &[&str] =
    &["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"];
static VALID_PACKET_ENCODINGS: &[&str] = &["packetaddr", "xudp"];
static VALID_VLESS_FLOWS: &[&str] = &["xtls-rprx-vision"];
static VALID_CLIENT_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
];
static VALID_TUIC_CONGESTION_CONTROLS: &[&str] = &["cubic", "new_reno", "bbr"];
static VALID_TUIC_UDP_RELAY_MODES: &[&str] = &["native", "quic"];

/// 节点解析结果，包含有效节点和错误记录
#[derive(Debug)]
pub struct ParseResult {
    pub nodes: Vec<(String, JsonValue)>, // (name, outbound_json)
    pub errors: Vec<String>,             // 记录解析失败的节点及原因
    pub total_count: usize,              // YAML 中 proxies 列表的原始总数
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
        let normalized_type = node_type.to_ascii_lowercase();

        // Skip unsupported node types silently
        if !is_supported_node_type(&normalized_type) {
            continue;
        }

        match parse_single_node(node) {
            Ok((name, outbound)) => result.nodes.push((name, outbound)),
            Err(err) => {
                let name = node
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("<index {}>", idx));
                result
                    .errors
                    .push(format!("Node '{}' (type: {}): {}", name, node_type, err));
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
    if has_uri_scheme(uri, "ss://") {
        return parse_shadowsocks_uri(uri).map(Some);
    }
    if has_uri_scheme(uri, "anytls://") {
        return parse_anytls_uri(uri).map(Some);
    }
    Ok(None)
}

fn has_uri_scheme(uri: &str, scheme: &str) -> bool {
    uri.get(..scheme.len())
        .map(|prefix| prefix.eq_ignore_ascii_case(scheme))
        .unwrap_or(false)
}

fn parse_anytls_uri(uri: &str) -> AppResult<(String, serde_json::Value)> {
    let url =
        Url::parse(uri).map_err(|e| AppError::context("Invalid anytls URI", e.to_string()))?;
    let name = parse_uri_name(&url, "anytls")?;

    let server = url
        .host_str()
        .filter(|server| !server.trim().is_empty())
        .ok_or_else(|| AppError::message("anytls URI missing server"))?;
    let port = url
        .port()
        .filter(|port| *port > 0)
        .ok_or_else(|| AppError::message("anytls URI missing port"))?;
    let password = decode_uri_component(url.username(), "Invalid anytls password")?;
    if password.trim().is_empty() {
        return Err(AppError::message("anytls URI missing password"));
    }

    let sni = query_value(&url, "sni").filter(|sni| !sni.trim().is_empty());
    let insecure = query_value(&url, "insecure")
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false);
    let mut outbound = serde_json::json!({
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

    if let Some(sni) = sni {
        outbound["tls"]["server_name"] = serde_json::Value::String(sni);
    }

    Ok((
        outbound["tag"].as_str().unwrap_or_default().to_string(),
        outbound,
    ))
}

fn parse_shadowsocks_uri(uri: &str) -> AppResult<(String, serde_json::Value)> {
    let url = Url::parse(uri).map_err(|e| AppError::context("Invalid ss URI", e.to_string()))?;
    let name = parse_uri_name(&url, "ss")?;

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

fn parse_uri_name(url: &Url, uri_type: &str) -> AppResult<String> {
    Ok(url
        .fragment()
        .map(|name| decode_uri_component(name, &format!("Invalid {uri_type} URI name")))
        .transpose()?
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                url.host_str().unwrap_or("unknown"),
                url.port().unwrap_or(0)
            )
        }))
}

fn decode_uri_component(value: &str, context: &str) -> AppResult<String> {
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .map_err(|e| AppError::context(context, e.to_string()))
}

fn query_value(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(query_key, _)| query_key == key)
        .map(|(_, value)| value.into_owned())
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
    matches!(
        node_type,
        "hysteria2" | "anytls" | "ss" | "vmess" | "vless" | "trojan" | "tuic"
    )
}

fn get_str<'a>(node: &'a Value, key: &str) -> Option<&'a str> {
    node.get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn get_str_any<'a>(node: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| get_str(node, key))
}

fn get_required_str<'a>(node: &'a Value, key: &str) -> Result<&'a str, String> {
    get_str(node, key).ok_or_else(|| format!("missing required field '{}'", key))
}

fn validate_uuid(uuid: &str) -> Result<(), String> {
    if UUID_REGEX.is_match(uuid) {
        Ok(())
    } else {
        Err("invalid UUID".to_string())
    }
}

fn validate_vmess_security(security: &str) -> Result<(), String> {
    if VALID_VMESS_SECURITIES.contains(&security) {
        Ok(())
    } else {
        Err(format!("unsupported VMess security '{}'", security))
    }
}

fn validate_packet_encoding(packet_encoding: &str) -> Result<(), String> {
    if VALID_PACKET_ENCODINGS.contains(&packet_encoding) {
        Ok(())
    } else {
        Err(format!("unsupported packet encoding '{}'", packet_encoding))
    }
}

fn validate_vless_flow(flow: &str) -> Result<(), String> {
    if VALID_VLESS_FLOWS.contains(&flow) {
        Ok(())
    } else {
        Err(format!("unsupported VLESS flow '{}'", flow))
    }
}

fn validate_client_fingerprint(fingerprint: &str) -> Result<(), String> {
    if VALID_CLIENT_FINGERPRINTS.contains(&fingerprint) {
        Ok(())
    } else {
        Err(format!(
            "unsupported TLS client fingerprint '{}'",
            fingerprint
        ))
    }
}

fn validate_tuic_congestion_control(congestion_control: &str) -> Result<(), String> {
    if VALID_TUIC_CONGESTION_CONTROLS.contains(&congestion_control) {
        Ok(())
    } else {
        Err(format!(
            "unsupported TUIC congestion controller '{}'",
            congestion_control
        ))
    }
}

fn validate_tuic_udp_relay_mode(udp_relay_mode: &str) -> Result<(), String> {
    if VALID_TUIC_UDP_RELAY_MODES.contains(&udp_relay_mode) {
        Ok(())
    } else {
        Err(format!(
            "unsupported TUIC UDP relay mode '{}'",
            udp_relay_mode
        ))
    }
}

fn get_bool_opt(node: &Value, key: &str) -> Option<bool> {
    node.get(key).and_then(|value| value.as_bool())
}

fn get_bool(node: &Value, key: &str) -> bool {
    get_bool_opt(node, key).unwrap_or(false)
}

fn get_u64_any(node: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        node.get(key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
        })
    })
}

fn get_port(node: &Value) -> Result<u16, String> {
    let port = get_u64_any(node, &["port"]).ok_or("missing required field 'port'")?;
    if port == 0 || port > 65535 {
        return Err("invalid port".to_string());
    }
    Ok(port as u16)
}

fn map_get_str<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    map.get(Value::String(key.to_string()))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn map_get_bool(map: &Mapping, key: &str) -> Option<bool> {
    map.get(Value::String(key.to_string()))
        .and_then(|value| value.as_bool())
}

fn map_get_value<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn yaml_to_json(value: &Value) -> Option<JsonValue> {
    serde_json::to_value(value).ok()
}

fn string_list(value: &Value) -> Vec<String> {
    if let Some(items) = value.as_sequence() {
        return items
            .iter()
            .filter_map(|item| item.as_str())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect();
    }

    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default()
}

fn first_string(value: &Value) -> Option<String> {
    string_list(value).into_iter().next()
}

fn base_outbound(typ: &str, name: &str, server: &str, port: u16) -> Map<String, JsonValue> {
    let mut obj = Map::new();
    obj.insert("type".to_string(), json!(typ));
    obj.insert("tag".to_string(), json!(name));
    obj.insert("server".to_string(), json!(server));
    obj.insert("server_port".to_string(), json!(port));
    obj
}

fn insert_optional_string(obj: &mut Map<String, JsonValue>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        obj.insert(key.to_string(), json!(value));
    }
}

fn parse_hysteria2_obfs(node: &Value) -> Result<Option<JsonValue>, String> {
    let Some(obfs_type) = get_str(node, "obfs") else {
        return Ok(None);
    };

    if !matches!(obfs_type, "salamander" | "gecko") {
        return Err(format!("unsupported Hysteria2 obfs type '{}'", obfs_type));
    }

    let password = get_required_str(node, "obfs-password")?;

    Ok(Some(json!({
        "type": obfs_type,
        "password": password
    })))
}

fn parse_alpn(node: &Value) -> Vec<String> {
    node.get("alpn").map(string_list).unwrap_or_default()
}

fn has_reality_public_key(node: &Value) -> bool {
    node.get("reality-opts")
        .and_then(|value| value.as_mapping())
        .and_then(|opts| map_get_str(opts, "public-key"))
        .is_some()
}

fn has_tls_hints(node: &Value) -> bool {
    get_str_any(node, &["sni", "servername"]).is_some()
        || !parse_alpn(node).is_empty()
        || get_bool(node, "skip-cert-verify")
        || get_str(node, "client-fingerprint").is_some()
        || has_reality_public_key(node)
}

fn build_tls(node: &Value, default_enabled: bool) -> Result<Option<JsonValue>, String> {
    let enabled = get_bool_opt(node, "tls")
        .unwrap_or(default_enabled || has_reality_public_key(node) || has_tls_hints(node));

    if !enabled {
        return Ok(None);
    }

    let mut tls = Map::new();
    tls.insert("enabled".to_string(), json!(true));
    tls.insert(
        "insecure".to_string(),
        json!(get_bool(node, "skip-cert-verify")),
    );
    insert_optional_string(
        &mut tls,
        "server_name",
        get_str_any(node, &["sni", "servername"]),
    );

    let alpn = parse_alpn(node);
    if !alpn.is_empty() {
        tls.insert("alpn".to_string(), json!(alpn));
    }

    let fingerprint = get_str(node, "client-fingerprint").map(str::to_ascii_lowercase);
    if let Some(fingerprint) = fingerprint.as_deref() {
        if fingerprint != "none" {
            validate_client_fingerprint(fingerprint)?;
            tls.insert(
                "utls".to_string(),
                json!({
                    "enabled": true,
                    "fingerprint": fingerprint
                }),
            );
        }
    }

    if let Some(reality_opts) = node
        .get("reality-opts")
        .and_then(|value| value.as_mapping())
    {
        if !matches!(fingerprint.as_deref(), Some(value) if value != "none") {
            return Err("Reality requires client-fingerprint/uTLS".to_string());
        }
        let public_key = map_get_str(reality_opts, "public-key")
            .ok_or("missing required Reality field 'public-key'")?;
        let mut reality = Map::new();
        reality.insert("enabled".to_string(), json!(true));
        reality.insert("public_key".to_string(), json!(public_key));
        if let Some(short_id) = map_get_str(reality_opts, "short-id") {
            reality.insert("short_id".to_string(), json!(short_id));
        }
        tls.insert("reality".to_string(), JsonValue::Object(reality));
    }

    if get_bool(node, "disable-sni") {
        tls.insert("disable_sni".to_string(), json!(true));
    }

    Ok(Some(JsonValue::Object(tls)))
}

fn build_required_tls(node: &Value) -> Result<JsonValue, String> {
    if let Some(tls) = build_tls(node, true)? {
        return Ok(tls);
    }

    let mut tls = Map::new();
    tls.insert("enabled".to_string(), json!(true));
    tls.insert(
        "insecure".to_string(),
        json!(get_bool(node, "skip-cert-verify")),
    );
    insert_optional_string(
        &mut tls,
        "server_name",
        get_str_any(node, &["sni", "servername"]),
    );
    Ok(JsonValue::Object(tls))
}

fn build_v2ray_transport(node: &Value) -> Result<Option<JsonValue>, String> {
    let network = get_str(node, "network")
        .unwrap_or("tcp")
        .to_ascii_lowercase();

    match network.as_str() {
        "" | "tcp" => Ok(None),
        "ws" => {
            let opts = node.get("ws-opts").and_then(|value| value.as_mapping());
            let mut transport = Map::new();
            transport.insert("type".to_string(), json!("ws"));
            if let Some(path) = opts.and_then(|opts| map_get_str(opts, "path")) {
                transport.insert("path".to_string(), json!(path));
            }
            if let Some(headers) = opts
                .and_then(|opts| map_get_value(opts, "headers"))
                .and_then(yaml_to_json)
            {
                transport.insert("headers".to_string(), headers);
            }
            Ok(Some(JsonValue::Object(transport)))
        }
        "grpc" => {
            let opts = node.get("grpc-opts").and_then(|value| value.as_mapping());
            let mut transport = Map::new();
            transport.insert("type".to_string(), json!("grpc"));
            if let Some(service_name) = opts.and_then(|opts| map_get_str(opts, "grpc-service-name"))
            {
                transport.insert("service_name".to_string(), json!(service_name));
            }
            Ok(Some(JsonValue::Object(transport)))
        }
        "http" | "h2" => {
            let opts_key = if network == "h2" {
                "h2-opts"
            } else {
                "http-opts"
            };
            let opts = node.get(opts_key).and_then(|value| value.as_mapping());
            let mut transport = Map::new();
            transport.insert("type".to_string(), json!("http"));
            if let Some(method) = opts.and_then(|opts| map_get_str(opts, "method")) {
                transport.insert("method".to_string(), json!(method));
            }
            if let Some(path) = opts
                .and_then(|opts| map_get_value(opts, "path"))
                .and_then(first_string)
            {
                transport.insert("path".to_string(), json!(path));
            }
            if let Some(hosts) = opts
                .and_then(|opts| map_get_value(opts, "host"))
                .map(string_list)
                .filter(|hosts| !hosts.is_empty())
            {
                transport.insert("host".to_string(), json!(hosts));
            }
            if let Some(headers) = opts
                .and_then(|opts| map_get_value(opts, "headers"))
                .and_then(yaml_to_json)
            {
                transport.insert("headers".to_string(), headers);
            }
            Ok(Some(JsonValue::Object(transport)))
        }
        "xhttp" => Err("unsupported transport network 'xhttp'".to_string()),
        other => Err(format!("unsupported transport network '{}'", other)),
    }
}

fn parse_single_node(node: &Value) -> Result<(String, JsonValue), String> {
    let typ = get_required_str(node, "type")?.to_ascii_lowercase();
    let name = get_required_str(node, "name")?;

    let server = get_required_str(node, "server")?;
    let port = get_port(node)?;

    let outbound = match typ.as_str() {
        "hysteria2" => {
            let password = get_required_str(node, "password")?;
            let mut obj = base_outbound("hysteria2", name, server, port);
            obj.insert("password".to_string(), json!(password));
            obj.insert("tls".to_string(), build_required_tls(node)?);
            if let Some(obfs) = parse_hysteria2_obfs(node)? {
                obj.insert("obfs".to_string(), obfs);
            }
            JsonValue::Object(obj)
        }
        "anytls" => {
            let password = get_required_str(node, "password")?;
            let mut obj = base_outbound("anytls", name, server, port);
            obj.insert("password".to_string(), json!(password));
            obj.insert("tls".to_string(), build_required_tls(node)?);
            JsonValue::Object(obj)
        }
        "ss" => {
            let method = get_required_str(node, "cipher")?;
            let password = get_required_str(node, "password")?;
            let mut obj = base_outbound("shadowsocks", name, server, port);
            obj.insert("method".to_string(), json!(method));
            obj.insert("password".to_string(), json!(password));
            if let Some((plugin, plugin_opts)) = parse_clash_ss_plugin(node) {
                obj.insert("plugin".to_string(), json!(plugin));
                obj.insert("plugin_opts".to_string(), json!(plugin_opts));
            }
            JsonValue::Object(obj)
        }
        "vmess" => {
            let uuid = get_required_str(node, "uuid")?;
            validate_uuid(uuid)?;
            let security = get_str(node, "cipher").unwrap_or("auto");
            validate_vmess_security(security)?;
            let mut obj = base_outbound("vmess", name, server, port);
            obj.insert("uuid".to_string(), json!(uuid));
            obj.insert("security".to_string(), json!(security));
            obj.insert(
                "alter_id".to_string(),
                json!(get_u64_any(node, &["alterId", "alter-id"]).unwrap_or(0)),
            );
            if let Some(packet_encoding) = get_str(node, "packet-encoding") {
                validate_packet_encoding(packet_encoding)?;
                obj.insert("packet_encoding".to_string(), json!(packet_encoding));
            }
            if let Some(tls) = build_tls(node, false)? {
                obj.insert("tls".to_string(), tls);
            }
            if let Some(transport) = build_v2ray_transport(node)? {
                obj.insert("transport".to_string(), transport);
            }
            JsonValue::Object(obj)
        }
        "vless" => {
            if let Some(encryption) = get_str(node, "encryption") {
                if encryption != "none" {
                    return Err(format!(
                        "unsupported VLESS encryption '{}'; only 'none' is supported",
                        encryption
                    ));
                }
            }
            let uuid = get_required_str(node, "uuid")?;
            validate_uuid(uuid)?;
            let mut obj = base_outbound("vless", name, server, port);
            obj.insert("uuid".to_string(), json!(uuid));
            if let Some(flow) = get_str(node, "flow") {
                validate_vless_flow(flow)?;
                obj.insert("flow".to_string(), json!(flow));
            }
            if let Some(packet_encoding) = get_str(node, "packet-encoding") {
                validate_packet_encoding(packet_encoding)?;
                obj.insert("packet_encoding".to_string(), json!(packet_encoding));
            }
            if let Some(tls) = build_tls(node, false)? {
                obj.insert("tls".to_string(), tls);
            }
            if let Some(transport) = build_v2ray_transport(node)? {
                obj.insert("transport".to_string(), transport);
            }
            JsonValue::Object(obj)
        }
        "trojan" => {
            if node
                .get("ss-opts")
                .and_then(|value| value.as_mapping())
                .and_then(|opts| map_get_bool(opts, "enabled"))
                .unwrap_or(false)
            {
                return Err("unsupported Trojan ss-opts".to_string());
            }
            let password = get_required_str(node, "password")?;
            let mut obj = base_outbound("trojan", name, server, port);
            obj.insert("password".to_string(), json!(password));
            if let Some(tls) = build_tls(node, true)? {
                obj.insert("tls".to_string(), tls);
            }
            if let Some(transport) = build_v2ray_transport(node)? {
                obj.insert("transport".to_string(), transport);
            }
            JsonValue::Object(obj)
        }
        "tuic" => {
            if get_str(node, "token").is_some() {
                return Err(
                    "unsupported TUIC token/v4 format; only TUIC v5 uuid/password is supported"
                        .to_string(),
                );
            }
            let uuid = get_required_str(node, "uuid")?;
            validate_uuid(uuid)?;
            let password = get_required_str(node, "password")?;
            let mut obj = base_outbound("tuic", name, server, port);
            obj.insert("uuid".to_string(), json!(uuid));
            obj.insert("password".to_string(), json!(password));
            if let Some(congestion_control) = get_str(node, "congestion-controller") {
                validate_tuic_congestion_control(congestion_control)?;
                obj.insert("congestion_control".to_string(), json!(congestion_control));
            }
            if let Some(udp_relay_mode) = get_str(node, "udp-relay-mode") {
                validate_tuic_udp_relay_mode(udp_relay_mode)?;
                obj.insert("udp_relay_mode".to_string(), json!(udp_relay_mode));
            }
            if get_bool(node, "reduce-rtt") {
                obj.insert("zero_rtt_handshake".to_string(), json!(true));
            }
            obj.insert("tls".to_string(), build_required_tls(node)?);
            JsonValue::Object(obj)
        }
        _ => return Err(format!("unsupported node type '{}'", typ)),
    };

    Ok((name.to_string(), outbound))
}

fn parse_clash_ss_plugin(node: &Value) -> Option<(String, String)> {
    let plugin = node.get("plugin")?.as_str()?;
    let (plugin_name, inline_opts) = plugin.split_once(';').unwrap_or((plugin, ""));
    let opts = node.get("plugin-opts").or_else(|| node.get("plugin_opts"));

    match plugin_name {
        "obfs" | "simple-obfs" | "obfs-local" => {
            let plugin_opts = if inline_opts.is_empty() {
                parse_clash_ss_plugin_opts(opts)
            } else {
                inline_opts.to_string()
            };
            Some(("obfs-local".to_string(), plugin_opts))
        }
        _ => None,
    }
}

fn parse_clash_ss_plugin_opts(opts: Option<&Value>) -> String {
    if let Some(opts) = opts.and_then(|opts| opts.as_str()) {
        return opts.to_string();
    }

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

    plugin_opts
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
  - name: vmess-node
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    cipher: auto
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 4);
        assert!(result.errors.is_empty());
        assert_eq!(result.nodes[0].0, "hy2-node");
        assert_eq!(result.nodes[1].0, "anytls-node");
        assert_eq!(result.nodes[2].0, "ss-node");
        assert_eq!(result.nodes[3].0, "vmess-node");
        assert_eq!(result.nodes[3].1["type"], "vmess");
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
    fn parse_uri_subscription_decodes_base64_anytls_links() {
        let body = general_purpose::STANDARD.encode(
            "anytls://secret-pass@example.com:23001/?type=tcp&insecure=0&fp=chrome&sni=live.example.com#%E9%A6%99%E6%B8%AF%2001\n\
             AnyTLS://second-pass@example.com:23002/?type=tcp&insecure=1&fingerprint=firefox&sni=tw.example.com#%E5%8F%B0%E6%B9%BE%2001\n",
        );

        let result = parse_uri_subscription(&body).unwrap();

        assert_eq!(result.total_count, 2);
        assert_eq!(result.nodes.len(), 2);
        assert!(result.errors.is_empty());

        let first = &result.nodes[0].1;
        assert_eq!(result.nodes[0].0, "香港 01");
        assert_eq!(first["type"], "anytls");
        assert_eq!(first["tag"], "香港 01");
        assert_eq!(first["server"], "example.com");
        assert_eq!(first["server_port"], 23001);
        assert_eq!(first["password"], "secret-pass");
        assert_eq!(first["tls"]["server_name"], "live.example.com");
        assert_eq!(first["tls"]["insecure"], false);
        assert!(first["tls"].get("utls").is_none());

        let second = &result.nodes[1].1;
        assert_eq!(result.nodes[1].0, "台湾 01");
        assert_eq!(second["tls"]["insecure"], true);
        assert!(second["tls"].get("utls").is_none());
    }

    #[test]
    fn parse_uri_subscription_reports_invalid_anytls_links() {
        let result = parse_uri_subscription(
            "anytls://@example.com:443#missing-password\n\
             anytls://pass@example.com/#missing-port\n\
             anytls://pass@:443#missing-server\n",
        )
        .unwrap();

        assert_eq!(result.total_count, 3);
        assert!(result.nodes.is_empty());
        assert_eq!(result.errors.len(), 3);
        assert!(result.errors.iter().any(|e| e.contains("password")));
        assert!(result.errors.iter().any(|e| e.contains("port")));
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("server") || e.contains("Invalid anytls URI")));
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
    type: snell
    server: vm.example.com
    port: 443
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].0, "valid-node");
        // 3 errors: missing-server, zero-port, missing-password
        // unsupported-type (snell) is silently skipped, not reported as error
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
    fn parse_clash_proxies_maps_extended_supported_types() {
        let yaml = r#"
proxies:
  - name: vmess-ws
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    cipher: auto
    alterId: 0
    tls: true
    sni: vm.example.com
    client-fingerprint: chrome
    packet-encoding: xudp
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
  - name: vless-reality
    type: vless
    server: vl.example.com
    port: 443
    uuid: 223e4567-e89b-12d3-a456-426614174000
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    packet-encoding: xudp
    network: grpc
    grpc-opts:
      grpc-service-name: edge
    reality-opts:
      public-key: public-key
      short-id: abcd
  - name: trojan-grpc
    type: trojan
    server: tr.example.com
    port: 443
    password: trojan-pass
    sni: tr.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: trojan
  - name: tuic-v5
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 323e4567-e89b-12d3-a456-426614174000
    password: tuic-pass
    congestion-controller: bbr
    udp-relay-mode: quic
    reduce-rtt: true
    disable-sni: true
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 4);
        assert!(result.errors.is_empty());

        let vmess = &result.nodes[0].1;
        assert_eq!(vmess["type"], "vmess");
        assert_eq!(vmess["security"], "auto");
        assert_eq!(vmess["alter_id"], 0);
        assert_eq!(vmess["packet_encoding"], "xudp");
        assert_eq!(vmess["tls"]["server_name"], "vm.example.com");
        assert_eq!(vmess["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(vmess["transport"]["type"], "ws");
        assert_eq!(vmess["transport"]["path"], "/ws");
        assert_eq!(vmess["transport"]["headers"]["Host"], "cdn.example.com");

        let vless = &result.nodes[1].1;
        assert_eq!(vless["type"], "vless");
        assert_eq!(vless["flow"], "xtls-rprx-vision");
        assert_eq!(vless["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(vless["tls"]["reality"]["public_key"], "public-key");
        assert_eq!(vless["tls"]["reality"]["short_id"], "abcd");
        assert_eq!(vless["transport"]["type"], "grpc");
        assert_eq!(vless["transport"]["service_name"], "edge");

        let trojan = &result.nodes[2].1;
        assert_eq!(trojan["type"], "trojan");
        assert_eq!(trojan["tls"]["server_name"], "tr.example.com");
        assert_eq!(trojan["transport"]["service_name"], "trojan");

        let tuic = &result.nodes[3].1;
        assert_eq!(tuic["type"], "tuic");
        assert_eq!(tuic["congestion_control"], "bbr");
        assert_eq!(tuic["udp_relay_mode"], "quic");
        assert_eq!(tuic["zero_rtt_handshake"], true);
        assert_eq!(tuic["tls"]["disable_sni"], true);
    }

    #[test]
    fn parse_clash_proxies_reports_unsupported_extended_variants() {
        let yaml = r#"
proxies:
  - name: vless-encryption
    type: vless
    server: vl.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    encryption: aes-128-gcm
  - name: trojan-ss-opts
    type: trojan
    server: tr.example.com
    port: 443
    password: trojan-pass
    ss-opts:
      enabled: true
  - name: tuic-token
    type: tuic
    server: tuic.example.com
    port: 443
    token: old-token
  - name: vmess-xhttp
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 223e4567-e89b-12d3-a456-426614174000
    network: xhttp
  - name: vless-reality-no-fingerprint
    type: vless
    server: vl.example.com
    port: 443
    uuid: 323e4567-e89b-12d3-a456-426614174000
    reality-opts:
      public-key: public-key
  - name: vless-reality-none-fingerprint
    type: vless
    server: vl2.example.com
    port: 443
    uuid: 423e4567-e89b-12d3-a456-426614174000
    client-fingerprint: none
    reality-opts:
      public-key: public-key
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert!(result.nodes.is_empty());
        assert_eq!(result.errors.len(), 6);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("vless-encryption")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("trojan-ss-opts")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("tuic-token")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("vmess-xhttp")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("vless-reality-no-fingerprint")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("vless-reality-none-fingerprint")));
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
    fn parse_clash_proxies_maps_hysteria2_obfs() {
        let yaml = r#"
proxies:
  - name: hy2-obfs
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    obfs: salamander
    obfs-password: obfs-pass
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert!(result.errors.is_empty());
        let outbound = &result.nodes[0].1;
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "obfs-pass");
    }

    #[test]
    fn parse_clash_proxies_maps_hysteria2_gecko_obfs() {
        let yaml = r#"
proxies:
  - name: hy2-gecko-obfs
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    obfs: gecko
    obfs-password: gecko-pass
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert!(result.errors.is_empty());
        let outbound = &result.nodes[0].1;
        assert_eq!(outbound["obfs"]["type"], "gecko");
        assert_eq!(outbound["obfs"]["password"], "gecko-pass");
    }

    #[test]
    fn parse_clash_proxies_omits_empty_hysteria2_obfs() {
        let yaml = r#"
proxies:
  - name: hy2-no-obfs
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    obfs: ""
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert!(result.errors.is_empty());
        let outbound = &result.nodes[0].1;
        assert!(outbound.get("obfs").is_none());
    }

    #[test]
    fn parse_clash_proxies_rejects_invalid_hysteria2_obfs() {
        let yaml = r#"
proxies:
  - name: hy2-invalid-obfs
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    obfs: unsupported
    obfs-password: obfs-pass
  - name: hy2-missing-obfs-password
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: pass
    obfs: salamander
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        assert!(result.nodes.is_empty());
        assert_eq!(result.errors.len(), 2);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("hy2-invalid-obfs")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("hy2-missing-obfs-password")));
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
  - name: valid-vmess
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
  - name: valid-trojan
    type: trojan
    server: tr.example.com
    port: 443
    password: pass
  - name: unsupported-snell
    type: snell
    server: snell.example.com
    port: 443
  - name: valid-ss
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
"#;

        let result = parse_clash_proxies(yaml).unwrap();

        // Snell remains unsupported and is silently skipped.
        assert_eq!(result.nodes.len(), 4);
        assert!(result.errors.is_empty());

        let names: Vec<String> = result.nodes.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(
            names,
            vec!["valid-hy2", "valid-vmess", "valid-trojan", "valid-ss"]
        );
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
