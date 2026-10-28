//! Conversion of extended sharing URIs into sing-box outbound objects.
use super::{
    base_outbound, build_v2ray_transport, decode_uri_component, query_value,
    validate_client_fingerprint, validate_packet_encoding, validate_tuic_congestion_control,
    validate_tuic_udp_relay_mode, validate_uuid, validate_vless_flow,
};
use crate::error::{AppError, AppResult};
use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value as JsonValue};
use url::Url;

fn uri_bool(url: &Url, keys: &[&str]) -> AppResult<Option<bool>> {
    let mut result = None;
    for key in keys {
        if let Some(value) = query_value(url, key) {
            let value = match value.to_ascii_lowercase().as_str() {
                "1" | "true" => true,
                "0" | "false" => false,
                _ => return Err(AppError::message("Invalid boolean URI parameter")),
            };
            if result.is_some_and(|previous| previous != value) {
                return Err(AppError::message("Conflicting boolean URI parameters"));
            }
            result = Some(value);
        }
    }
    Ok(result)
}

fn uri_alias(url: &Url, keys: &[&str]) -> AppResult<Option<String>> {
    let mut result = None;
    for key in keys {
        if let Some(value) = query_value(url, key) {
            if result.as_ref().is_some_and(|previous| previous != &value) {
                return Err(AppError::message("Conflicting URI parameter aliases"));
            }
            result = Some(value);
        }
    }
    Ok(result)
}

fn uri_tls(url: &Url) -> AppResult<JsonValue> {
    let mut tls = json!({"enabled": true, "insecure": uri_bool(url, &["insecure", "allow_insecure", "allowInsecure"])?.unwrap_or(false)});
    if let Some(sni) = uri_alias(url, &["sni", "peer"])? {
        tls["server_name"] = json!(sni);
    }
    if let Some(alpn) = query_value(url, "alpn") {
        tls["alpn"] = json!(alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>());
    }
    Ok(tls)
}

fn has_proxy_authority(payload: &str) -> bool {
    let authority = payload.split(['/', '?', '#']).next().unwrap_or_default();
    let endpoint = authority.rsplit('@').next().unwrap_or_default();
    let explicit_port = if endpoint.starts_with('[') {
        endpoint
            .split_once(']')
            .is_some_and(|(_, tail)| tail.starts_with(':'))
    } else {
        endpoint.contains(':')
    };
    authority.contains('@') || explicit_port
}

/// Decode before URL parsing: URL hosts are case-insensitive, Base64 is not.
pub(super) fn normalize_http_uri(uri: &str) -> AppResult<Option<String>> {
    let Some((scheme, payload)) = uri.split_once("://") else {
        return Ok(None);
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return Ok(None);
    }
    let scheme = scheme.to_ascii_lowercase();
    let (encoded, outer_name) = payload
        .split_once('#')
        .map_or((payload, None), |(body, name)| (body, Some(name)));
    // Decode only structurally recognizable proxy authorities; never recursively fetch links.
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(encoded) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                if !has_proxy_authority(&decoded) {
                    continue;
                }
                if decoded.chars().any(char::is_control) {
                    return Err(AppError::message("Invalid encoded HTTP proxy text"));
                }
                let mut normalized = format!("{scheme}://{decoded}");
                if let Some(name) = outer_name {
                    if decoded.contains('#') {
                        return Err(AppError::message("Conflicting encoded HTTP proxy names"));
                    }
                    normalized.push('#');
                    normalized.push_str(name);
                }
                let url = Url::parse(&normalized)
                    .map_err(|_| AppError::message("Invalid encoded HTTP proxy URI"))?;
                if url.host_str().is_none() {
                    return Err(AppError::message("Invalid encoded HTTP proxy authority"));
                }
                return Ok(Some(normalized));
            }
        }
    }
    // Read the raw authority: Url normalizes explicit :443/:80 away.
    if has_proxy_authority(payload) {
        return Ok(Some(uri.to_string()));
    }
    // Long Base64-looking payloads are malformed encoded proxy candidates, not hostnames.
    if encoded.len() >= 64
        && encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
    {
        return Err(AppError::message("Invalid encoded HTTP proxy URI"));
    }
    Ok(None) // Ordinary or ambiguous web links are not proxy nodes.
}

pub(super) fn parse_extended_uri(uri: &str) -> AppResult<(String, JsonValue)> {
    let raw = uri.as_bytes();
    for (index, byte) in raw.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= raw.len()
                || !raw[index + 1].is_ascii_hexdigit()
                || !raw[index + 2].is_ascii_hexdigit())
        {
            return Err(AppError::message("Invalid percent encoding in URI"));
        }
    }
    decode_uri_component(uri, "Invalid URI text encoding")?;
    let url = Url::parse(uri).map_err(|_| AppError::message("Invalid proxy URI"))?;
    let scheme = url.scheme();
    let host = url
        .host_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::message("Proxy URI missing server"))?;
    // url::Url keeps brackets for IPv6; sing-box expects the bare address.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url
        .port_or_known_default()
        .or_else(|| matches!(scheme, "hy2" | "hysteria2").then_some(443))
        .filter(|p| *p > 0)
        .ok_or_else(|| AppError::message("Proxy URI missing or invalid port"))?;
    let name = url
        .fragment()
        .map(|f| decode_uri_component(f, "Invalid URI name"))
        .transpose()?
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{}:{}", url.host_str().unwrap_or_default(), port));
    let user = decode_uri_component(url.username(), "Invalid URI username")?;
    let password = url
        .password()
        .map(|p| decode_uri_component(p, "Invalid URI password"))
        .transpose()?;
    // Reject duplicate parameters rather than silently choosing a conflicting value.
    let mut seen = std::collections::HashSet::new();
    for (key, _) in url.query_pairs() {
        if !seen.insert(key.into_owned()) {
            return Err(AppError::message("Duplicate URI query parameter"));
        }
    }
    let typ = match scheme {
        "socks" | "socks5" => "socks",
        "http" | "https" => "http",
        "hy2" => "hysteria2",
        other => other,
    };
    if typ != "http" && !matches!(url.path(), "" | "/") {
        return Err(AppError::message("Unexpected path in proxy URI"));
    }
    let tls_keys = [
        "sni",
        "peer",
        "insecure",
        "allow_insecure",
        "allowInsecure",
        "alpn",
    ];
    let protocol_keys: &[&str] = match typ {
        "socks" => &[],
        "http" => &[],
        "hysteria2" => &["obfs", "obfs-password", "fastopen"],
        "tuic" => &[
            "congestion_control",
            "udp_relay_mode",
            "zero_rtt_handshake",
            "reduce_rtt",
        ],
        "vless" => &[
            "encryption",
            "flow",
            "packetEncoding",
            "packet_encoding",
            "security",
            "pbk",
            "sid",
            "fp",
            "type",
            "path",
            "host",
            "serviceName",
            "mode",
            "headerType",
        ],
        _ => unreachable!(),
    };
    for (key, _) in url.query_pairs() {
        let tls_allowed = !matches!(typ, "socks") && (typ != "http" || scheme == "https");
        if !(protocol_keys.contains(&key.as_ref())
            || tls_allowed && tls_keys.contains(&key.as_ref()))
        {
            return Err(AppError::message(
                "Unknown or unsupported URI query parameter",
            ));
        }
    }
    let mut obj = JsonValue::Object(base_outbound(typ, &name, host, port));
    match typ {
        "socks" | "http" => {
            if user.is_empty() && password.is_some() {
                return Err(AppError::message("Proxy password requires a username"));
            }
            if !user.is_empty() {
                obj["username"] = json!(user);
            }
            if let Some(password) = password {
                obj["password"] = json!(password);
            }
            if typ == "socks" {
                obj["version"] = json!("5");
            }
            if typ == "http" {
                if scheme == "https" {
                    obj["tls"] = uri_tls(&url)?;
                }
                if url.path() != "/" && !url.path().is_empty() {
                    obj["path"] = json!(url.path());
                }
            }
        }
        "hysteria2" => {
            uri_bool(&url, &["fastopen"])?;
            if query_value(&url, "obfs-password").is_some() && query_value(&url, "obfs").is_none() {
                return Err(AppError::message(
                    "Hysteria2 obfs password requires an obfs type",
                ));
            }
            if user.is_empty() {
                return Err(AppError::message("Hysteria2 URI missing password"));
            }
            obj["password"] = json!(match password {
                Some(p) => format!("{user}:{p}"),
                None => user,
            });
            obj["tls"] = uri_tls(&url)?;
            if let Some(obfs) = query_value(&url, "obfs") {
                if !matches!(obfs.as_str(), "salamander" | "gecko") {
                    return Err(AppError::message("Unsupported Hysteria2 obfs"));
                }
                let pass = query_value(&url, "obfs-password")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| AppError::message("Hysteria2 obfs missing password"))?;
                obj["obfs"] = json!({"type": obfs, "password": pass});
            }
        }
        "tuic" => {
            validate_uuid(&user)
                .map_err(|_| AppError::message("TUIC requires a v5 UUID/password URI"))?;
            let password = password
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::message("TUIC URI missing password"))?;
            obj["uuid"] = json!(user);
            obj["password"] = json!(password);
            obj["tls"] = uri_tls(&url)?;
            if let Some(cc) = query_value(&url, "congestion_control") {
                validate_tuic_congestion_control(&cc)
                    .map_err(|_| AppError::message("Invalid TUIC congestion control"))?;
                obj["congestion_control"] = json!(cc);
            }
            if let Some(mode) = query_value(&url, "udp_relay_mode") {
                validate_tuic_udp_relay_mode(&mode)
                    .map_err(|_| AppError::message("Invalid TUIC UDP relay mode"))?;
                obj["udp_relay_mode"] = json!(mode);
            }
            if let Some(value) = uri_bool(&url, &["zero_rtt_handshake", "reduce_rtt"])? {
                obj["zero_rtt_handshake"] = json!(value);
            }
        }
        "vless" => {
            validate_uuid(&user).map_err(|_| AppError::message("Invalid VLESS UUID"))?;
            if password.is_some() {
                return Err(AppError::message("VLESS URI must not contain a password"));
            }
            if query_value(&url, "encryption").is_some_and(|v| v != "none") {
                return Err(AppError::message(
                    "Unsupported VLESS encryption; only none is supported",
                ));
            }
            obj["uuid"] = json!(user);
            if let Some(flow) = query_value(&url, "flow").filter(|s| !s.is_empty()) {
                validate_vless_flow(&flow)
                    .map_err(|_| AppError::message("Unsupported VLESS flow"))?;
                obj["flow"] = json!(flow);
            }
            if let Some(encoding) = uri_alias(&url, &["packetEncoding", "packet_encoding"])? {
                validate_packet_encoding(&encoding)
                    .map_err(|_| AppError::message("Unsupported VLESS packet encoding"))?;
                obj["packet_encoding"] = json!(encoding);
            }
            match query_value(&url, "security").as_deref().unwrap_or("none") {
                "none" | "" => {
                    if ["pbk", "sid", "fp"]
                        .iter()
                        .chain(tls_keys.iter())
                        .any(|key| query_value(&url, key).is_some())
                    {
                        return Err(AppError::message(
                            "VLESS TLS parameters require security=tls or reality",
                        ));
                    }
                }
                security @ ("tls" | "reality") => {
                    let mut tls = uri_tls(&url)?;
                    let fingerprint =
                        query_value(&url, "fp").filter(|s| !s.is_empty() && s != "none");
                    if let Some(fp) = fingerprint.as_deref() {
                        validate_client_fingerprint(fp)
                            .map_err(|_| AppError::message("Unsupported VLESS TLS fingerprint"))?;
                        tls["utls"] = json!({"enabled":true,"fingerprint":fp});
                    }
                    if security == "reality" {
                        let public_key = query_value(&url, "pbk")
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| AppError::message("Reality missing public key"))?;
                        if fingerprint.is_none() {
                            return Err(AppError::message("Reality requires fp/uTLS"));
                        }
                        let short_id = query_value(&url, "sid").unwrap_or_default();
                        if short_id.len() > 16
                            || !short_id.len().is_multiple_of(2)
                            || !short_id.chars().all(|c| c.is_ascii_hexdigit())
                        {
                            return Err(AppError::message("Invalid Reality short ID"));
                        }
                        if general_purpose::URL_SAFE_NO_PAD
                            .decode(&public_key)
                            .map_or(true, |v| v.len() != 32)
                        {
                            return Err(AppError::message("Invalid Reality public key"));
                        }
                        tls["reality"] =
                            json!({"enabled":true,"public_key":public_key,"short_id":short_id});
                    } else if query_value(&url, "pbk").is_some()
                        || query_value(&url, "sid").is_some()
                    {
                        return Err(AppError::message(
                            "Reality parameters require security=reality",
                        ));
                    }
                    obj["tls"] = tls;
                }
                _ => return Err(AppError::message("Unsupported VLESS security")),
            }
            // Reuse YAML transport construction so both formats have identical support.
            let network = query_value(&url, "type").unwrap_or_else(|| "tcp".to_string());
            let valid_transport_keys: &[&str] = match network.as_str() {
                "tcp" => &["headerType"],
                "ws" | "http" | "h2" => &["path", "host"],
                "grpc" => &["serviceName", "mode"],
                _ => &[],
            };
            for key in ["headerType", "path", "host", "serviceName", "mode"] {
                if query_value(&url, key).is_some() && !valid_transport_keys.contains(&key) {
                    return Err(AppError::message(
                        "URI parameter does not apply to the selected VLESS transport",
                    ));
                }
            }
            if obj.get("flow").is_some() && (network != "tcp" || obj.get("tls").is_none()) {
                return Err(AppError::message(
                    "VLESS Vision requires TCP and TLS/Reality",
                ));
            }
            let mut transport_node = json!({"network":network});
            match network.as_str() {
                "ws" => {
                    transport_node["ws-opts"] =
                        json!({"path":query_value(&url,"path").unwrap_or_else(|| "/".into())});
                    if let Some(host) = query_value(&url, "host") {
                        transport_node["ws-opts"]["headers"] = json!({"Host":host});
                    }
                }
                "grpc" => {
                    if query_value(&url, "mode").is_some_and(|v| v != "gun") {
                        return Err(AppError::message("Unsupported gRPC mode"));
                    }
                    transport_node["grpc-opts"] = json!({"grpc-service-name":query_value(&url,"serviceName").unwrap_or_default()});
                }
                "http" | "h2" => {
                    transport_node[format!("{network}-opts")] = json!({"path":query_value(&url,"path").unwrap_or_else(|| "/".into()),"host":query_value(&url,"host").map(|s|s.split(',').map(str::to_string).collect::<Vec<_>>()).unwrap_or_default()});
                }
                "tcp" => {
                    if query_value(&url, "headerType")
                        .is_some_and(|v| !matches!(v.as_str(), "none" | ""))
                    {
                        return Err(AppError::message("Unsupported TCP header type"));
                    }
                }
                _ => return Err(AppError::message("Unsupported VLESS transport")),
            }
            let transport_node = serde_yaml::to_value(transport_node)?;
            if let Some(transport) = build_v2ray_transport(&transport_node)
                .map_err(|_| AppError::message("Invalid VLESS transport"))?
            {
                obj["transport"] = transport;
            }
        }
        _ => unreachable!(),
    }
    Ok((name, obj))
}
