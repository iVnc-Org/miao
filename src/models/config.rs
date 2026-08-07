use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    Tunnel,
    #[default]
    Global,
    Rule,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunProcessMode {
    #[default]
    GlobalBypass,
    ProcessOnly,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BypassAction {
    #[default]
    Bypass,
    Direct,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunProcessMatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_regex: Vec<String>,
}

impl TunProcessMatch {
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
pub struct TunProcessConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: TunProcessMode,
    #[serde(default)]
    pub r#match: TunProcessMatch,
    #[serde(default = "default_dns_follow_process")]
    pub dns_follow_process: bool,
    #[serde(default)]
    pub bypass_action: BypassAction,
}

impl Default for TunProcessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: TunProcessMode::GlobalBypass,
            r#match: TunProcessMatch::default(),
            dns_follow_process: true,
            bypass_action: BypassAction::Bypass,
        }
    }
}

impl TunProcessConfig {
    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }

    pub fn normalized(&self) -> Result<Self, String> {
        let mut normalized = self.clone();
        normalized.r#match = self.r#match.normalized()?;
        if normalized.enabled && normalized.r#match.is_empty() {
            return Err("启用进程代理时至少需要填写一个进程名或进程路径".to_string());
        }
        Ok(normalized)
    }
}

fn default_dns_follow_process() -> bool {
    true
}

/// 默认只监听回环。分享模式面向局域网，但"开箱即用就对全网卡开放"是不可接受的
/// 默认值——想暴露到局域网必须显式改地址，而那条路径强制要求鉴权（见 `normalized`）。
pub const DEFAULT_SHARE_LISTEN: &str = "127.0.0.1";
pub const DEFAULT_SHARE_BASE_PORT: u16 = 12000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareConfig {
    #[serde(default)]
    pub enabled: bool,
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

impl Default for ShareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_share_listen(),
            base_port: DEFAULT_SHARE_BASE_PORT,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl ShareConfig {
    /// 只有整个配置都还是默认值时才允许在序列化时省略。
    ///
    /// 不能用 `!enabled` 做判断：那样一关掉分享模式就会把用户填的监听地址、
    /// 起始端口和账号密码一起从 config.yaml 里抹掉，重启后静默变回
    /// "全默认 + 无鉴权"，再打开就是完全不同的暴露面。
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn has_auth(&self) -> bool {
        !self.username.is_empty() && !self.password.is_empty()
    }

    pub fn normalized(&self) -> Result<Self, String> {
        let listen = self.listen.trim().to_string();
        if listen.is_empty() {
            return Err("分享模式监听地址不能为空".to_string());
        }
        let Ok(listen_ip) = listen.parse::<std::net::IpAddr>() else {
            return Err("分享模式监听地址必须是合法 IP".to_string());
        };
        if self.base_port == 0 {
            return Err("分享模式起始端口必须在 1 到 65535 之间".to_string());
        }

        let username = self.username.trim().to_string();
        let password = self.password.trim().to_string();
        if username.is_empty() != password.is_empty() {
            return Err("分享模式用户名和密码需同时填写或同时留空".to_string());
        }

        // 每个节点一个 SOCKS 监听，一旦离开回环就是对外开放的中继。
        // 无鉴权 + 非回环等于开放代理，别人可以借你的节点跑任意流量。
        if self.enabled && !listen_ip.is_loopback() && username.is_empty() {
            return Err(
                "分享模式监听非回环地址时必须设置用户名和密码，否则会变成开放代理".to_string(),
            );
        }

        Ok(Self {
            enabled: self.enabled,
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
    #[serde(default, skip_serializing_if = "TunProcessConfig::is_disabled")]
    pub tun_process: TunProcessConfig,
    #[serde(default, skip_serializing_if = "ShareConfig::is_default")]
    pub share: ShareConfig,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub route_mode: RouteMode,
}

pub const DEFAULT_PORT: u16 = 6161;
pub const DEFAULT_SOCKS_LISTEN: &str = "127.0.0.1";
pub const DEFAULT_SOCKS_PORT: u16 = 1080;

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn config_serializes_vps_ip_when_present() {
        let config = Config {
            vps_ip: Some("203.0.113.10".to_string()),
            ..Default::default()
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(yaml.contains("vps_ip: 203.0.113.10"));
    }

    #[test]
    fn config_omits_empty_vps_ip() {
        let config = Config::default();

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("vps_ip"));
    }

    #[test]
    fn config_omits_global_route_mode() {
        let config = Config {
            route_mode: super::RouteMode::Global,
            ..Default::default()
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("route_mode"));
    }

    #[test]
    fn config_omits_default_route_mode() {
        let config = Config::default();

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("route_mode"));
    }

    #[test]
    fn config_ignores_route_mode_when_deserializing() {
        let yaml = r#"
port: 6161
route_mode: definitely-not-valid
subs: []
nodes: []
custom_rules: []
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.route_mode, super::RouteMode::Global);
    }

    #[test]
    fn config_omits_disabled_tun_process() {
        let config = Config::default();

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("tun_process"));
    }

    #[test]
    fn tun_process_normalizes_match_lists() {
        let config = super::TunProcessConfig {
            enabled: true,
            mode: super::TunProcessMode::ProcessOnly,
            r#match: super::TunProcessMatch {
                names: vec![" curl ".to_string(), "curl".to_string(), "ssh".to_string()],
                paths: vec![],
                path_regex: vec![],
            },
            dns_follow_process: true,
            bypass_action: Default::default(),
        };

        let normalized = config.normalized().unwrap();

        assert_eq!(normalized.r#match.names, vec!["curl", "ssh"]);
    }

    #[test]
    fn config_omits_default_share() {
        let config = Config::default();

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("share"));
    }

    #[test]
    fn config_keeps_customized_share_when_disabled() {
        let config = Config {
            share: super::ShareConfig {
                enabled: false,
                listen: "192.168.1.10".to_string(),
                base_port: 20000,
                username: "alice".to_string(),
                password: "secret".to_string(),
            },
            ..Default::default()
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        // 关掉分享模式不能顺手把用户填的监听地址和凭据一起丢掉。
        assert!(yaml.contains("share"));
        assert!(yaml.contains("192.168.1.10"));
        assert!(yaml.contains("20000"));
        assert!(yaml.contains("alice"));

        let round_tripped: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(round_tripped.share, config.share);
    }

    #[test]
    fn share_config_normalizes_and_validates_auth() {
        let ok = super::ShareConfig {
            enabled: true,
            listen: " 0.0.0.0 ".to_string(),
            base_port: 12000,
            username: " user ".to_string(),
            password: " pass ".to_string(),
        }
        .normalized()
        .unwrap();
        assert_eq!(ok.listen, "0.0.0.0");
        assert_eq!(ok.username, "user");
        assert!(ok.has_auth());

        let err = super::ShareConfig {
            enabled: true,
            listen: "0.0.0.0".to_string(),
            base_port: 12000,
            username: "user".to_string(),
            password: String::new(),
        }
        .normalized()
        .unwrap_err();
        assert!(err.contains("同时"));
    }

    #[test]
    fn share_config_requires_auth_for_non_loopback_listen() {
        let err = super::ShareConfig {
            enabled: true,
            listen: "0.0.0.0".to_string(),
            base_port: 12000,
            username: String::new(),
            password: String::new(),
        }
        .normalized()
        .unwrap_err();
        assert!(err.contains("开放代理"), "unexpected error: {err}");

        // 回环无鉴权是允许的。
        let ok = super::ShareConfig {
            enabled: true,
            listen: "127.0.0.1".to_string(),
            base_port: 12000,
            username: String::new(),
            password: String::new(),
        }
        .normalized()
        .unwrap();
        assert!(!ok.has_auth());

        // 关闭状态下不校验，用户可以先填地址再开。
        assert!(super::ShareConfig {
            enabled: false,
            listen: "0.0.0.0".to_string(),
            base_port: 12000,
            username: String::new(),
            password: String::new(),
        }
        .normalized()
        .is_ok());
    }

    #[test]
    fn tun_process_rejects_command_line_as_process_name() {
        let config = super::TunProcessConfig {
            enabled: true,
            mode: Default::default(),
            r#match: super::TunProcessMatch {
                names: vec!["git clone https://example.com/repo.git".to_string()],
                paths: vec![],
                path_regex: vec![],
            },
            dns_follow_process: true,
            bypass_action: Default::default(),
        };

        let err = config.normalized().unwrap_err();

        assert!(err.contains("不支持命令参数"));
    }
}
