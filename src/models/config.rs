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
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            vps_ip: Some("203.0.113.10".to_string()),
            nodes: vec![],
            custom_rules: vec![],
            tun_process: Default::default(),
            route_mode: Default::default(),
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(yaml.contains("vps_ip: 203.0.113.10"));
    }

    #[test]
    fn config_omits_empty_vps_ip() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            vps_ip: None,
            nodes: vec![],
            custom_rules: vec![],
            tun_process: Default::default(),
            route_mode: Default::default(),
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("vps_ip"));
    }

    #[test]
    fn config_omits_global_route_mode() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            vps_ip: None,
            nodes: vec![],
            custom_rules: vec![],
            tun_process: Default::default(),
            route_mode: super::RouteMode::Global,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();

        assert!(!yaml.contains("route_mode"));
    }

    #[test]
    fn config_omits_default_route_mode() {
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            vps_ip: None,
            nodes: vec![],
            custom_rules: vec![],
            tun_process: Default::default(),
            route_mode: Default::default(),
        };

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
        let config = Config {
            port: None,
            socks_listen: None,
            socks_port: None,
            subs: vec![],
            vps_ip: None,
            nodes: vec![],
            custom_rules: vec![],
            tun_process: Default::default(),
            route_mode: Default::default(),
        };

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
