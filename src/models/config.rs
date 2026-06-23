use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Tunnel,
    Global,
    Rule,
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

        assert_eq!(config.route_mode, super::RouteMode::Tunnel);
    }
}
