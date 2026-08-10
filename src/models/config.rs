use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    #[default]
    Global,
    Process,
    Pool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessListMode {
    #[default]
    #[serde(alias = "global_bypass")]
    Blacklist,
    #[serde(alias = "process_only")]
    Whitelist,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BypassAction {
    #[default]
    Bypass,
    Direct,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_regex: Vec<String>,
}

impl ProcessMatch {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.paths.is_empty() && self.path_regex.is_empty()
    }

    pub fn normalized(&self) -> Result<Self, String> {
        Ok(Self {
            names: normalize_process_values(&self.names, ProcessMatchKind::Name)?,
            paths: normalize_process_values(&self.paths, ProcessMatchKind::Path)?,
            path_regex: normalize_process_values(&self.path_regex, ProcessMatchKind::PathRegex)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessProxyConfig {
    #[serde(default, rename = "enabled", skip_serializing)]
    pub legacy_enabled: bool,
    #[serde(default)]
    pub mode: ProcessListMode,
    #[serde(default)]
    pub r#match: ProcessMatch,
    #[serde(default = "default_dns_follow_process")]
    pub dns_follow_process: bool,
    #[serde(default)]
    pub bypass_action: BypassAction,
}

impl Default for ProcessProxyConfig {
    fn default() -> Self {
        Self {
            legacy_enabled: false,
            mode: ProcessListMode::Blacklist,
            r#match: ProcessMatch::default(),
            dns_follow_process: true,
            bypass_action: BypassAction::Bypass,
        }
    }
}

impl ProcessProxyConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn normalized(&self) -> Result<Self, String> {
        let mut normalized = self.clone();
        normalized.legacy_enabled = false;
        normalized.r#match = self.r#match.normalized()?;
        Ok(normalized)
    }

    pub fn validate_active(&self) -> Result<(), String> {
        if self.r#match.is_empty() {
            return Err("进程代理模式至少需要填写一个进程名或进程路径".to_string());
        }
        Ok(())
    }
}

fn default_dns_follow_process() -> bool {
    true
}

/// 代理池默认监听所有 IPv4 网卡，便于局域网设备直接使用各节点端口。
pub const DEFAULT_SHARE_LISTEN: &str = "0.0.0.0";
pub const DEFAULT_SHARE_BASE_PORT: u16 = 50000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolConfig {
    #[serde(default, rename = "enabled", skip_serializing)]
    pub legacy_enabled: bool,
    #[serde(default = "default_share_listen")]
    pub listen: String,
    #[serde(default = "default_share_base_port")]
    pub base_port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

fn default_share_listen() -> String {
    DEFAULT_SHARE_LISTEN.to_string()
}

fn default_share_base_port() -> u16 {
    DEFAULT_SHARE_BASE_PORT
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            legacy_enabled: false,
            listen: default_share_listen(),
            base_port: DEFAULT_SHARE_BASE_PORT,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl PoolConfig {
    /// 只有整个配置都还是默认值时才允许在序列化时省略。
    ///
    /// 退出代理池模式时不能把用户填的监听地址、起始端口和账号密码一起从
    /// config.yaml 里抹掉，否则再次进入时会静默恢复默认设置。
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn has_auth(&self) -> bool {
        !self.username.is_empty() && !self.password.is_empty()
    }

    pub fn normalized(&self) -> Result<Self, String> {
        let listen = self.listen.trim().to_string();
        if listen.is_empty() {
            return Err("代理池监听地址不能为空".to_string());
        }
        let Ok(_listen_ip) = listen.parse::<std::net::IpAddr>() else {
            return Err("代理池监听地址必须是合法 IP".to_string());
        };
        if self.base_port == 0 {
            return Err("代理池起始端口必须在 1 到 65535 之间".to_string());
        }

        let username = self.username.trim().to_string();
        let password = self.password.trim().to_string();
        if username.is_empty() != password.is_empty() {
            return Err("代理池用户名和密码需同时填写或同时留空".to_string());
        }

        Ok(Self {
            legacy_enabled: false,
            listen,
            base_port: self.base_port,
            username,
            password,
        })
    }
}

enum ProcessMatchKind {
    Name,
    Path,
    PathRegex,
}

fn normalize_process_values(
    values: &[String],
    kind: ProcessMatchKind,
) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();

    for value in values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        match kind {
            ProcessMatchKind::Name => {
                if value.chars().any(char::is_whitespace) {
                    return Err(format!(
                        "进程名不支持命令参数或空格，请填写真实可执行文件名: {value}"
                    ));
                }
                if value.contains('/') {
                    return Err(format!("进程名不能包含路径分隔符，请改填进程路径: {value}"));
                }
            }
            ProcessMatchKind::Path => {
                if !value.starts_with('/') {
                    return Err(format!("进程路径必须是绝对路径: {value}"));
                }
            }
            ProcessMatchKind::PathRegex => {
                Regex::new(value).map_err(|e| format!("进程路径正则无效: {value}: {e}"))?;
            }
        }

        if seen.insert(value.to_string()) {
            normalized.push(value.to_string());
        }
    }

    Ok(normalized)
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    // Defaults to 127.0.0.1 when absent. Use 0.0.0.0 only on trusted networks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_listen: Option<String>,
    // Defaults to 1080 when absent. Set to another value to override the local SOCKS5 port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub subs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vps_ip: Option<String>,
    #[serde(default)]
    pub nodes: Vec<String>,
    #[serde(default)]
    pub custom_rules: Vec<String>,
    #[serde(default)]
    pub mode: ProxyMode,
    #[serde(default, skip_serializing_if = "ProcessProxyConfig::is_default")]
    pub tun_process: ProcessProxyConfig,
    #[serde(default, skip_serializing_if = "PoolConfig::is_default")]
    pub share: PoolConfig,
}

pub const DEFAULT_PORT: u16 = 6161;
pub const DEFAULT_SOCKS_LISTEN: &str = "127.0.0.1";
pub const DEFAULT_SOCKS_PORT: u16 = 1080;

#[cfg(test)]
mod tests {
    use super::{Config, PoolConfig, ProcessListMode, ProcessMatch, ProcessProxyConfig, ProxyMode};

    #[test]
    fn config_persists_mode() {
        let yaml = serde_yaml::to_string(&Config::default()).unwrap();
        assert!(yaml.contains("mode: global"));
    }

    #[test]
    fn legacy_process_and_pool_flags_deserialize_without_reserializing() {
        let config: Config = serde_yaml::from_str(
            "tun_process:\n  enabled: true\n  mode: process_only\nshare:\n  enabled: true\n",
        )
        .unwrap();
        assert!(config.tun_process.legacy_enabled);
        assert!(config.share.legacy_enabled);
        assert_eq!(config.tun_process.mode, ProcessListMode::Whitelist);

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(!yaml.contains("enabled:"));
    }

    #[test]
    fn process_config_normalizes_shape_and_validates_only_when_active() {
        let config = ProcessProxyConfig {
            mode: ProcessListMode::Whitelist,
            r#match: ProcessMatch {
                names: vec![" curl ".to_string(), "curl".to_string(), "ssh".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let normalized = config.normalized().unwrap();
        assert_eq!(normalized.r#match.names, vec!["curl", "ssh"]);
        assert!(normalized.validate_active().is_ok());
        assert!(ProcessProxyConfig::default().normalized().is_ok());
        assert!(ProcessProxyConfig::default().validate_active().is_err());
    }

    #[test]
    fn pool_keeps_customized_settings_outside_pool_mode() {
        let config = Config {
            mode: ProxyMode::Global,
            share: PoolConfig {
                listen: "192.168.1.10".to_string(),
                base_port: 20000,
                username: "alice".to_string(),
                password: "secret".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("share"));
        assert!(yaml.contains("192.168.1.10"));
        assert_eq!(serde_yaml::from_str::<Config>(&yaml).unwrap().share, config.share);
    }

    #[test]
    fn pool_defaults_to_all_interfaces_and_allows_no_auth() {
        let pool = PoolConfig::default().normalized().unwrap();

        assert_eq!(pool.listen, "0.0.0.0");
        assert_eq!(pool.base_port, 50000);
        assert!(!pool.has_auth());
    }

    #[test]
    fn process_names_reject_command_lines() {
        let config = ProcessProxyConfig {
            r#match: ProcessMatch {
                names: vec!["git clone https://example.com/repo.git".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.normalized().unwrap_err().contains("不支持命令参数"));
    }
}
