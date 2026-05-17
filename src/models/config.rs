use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    // Defaults to 1080 when absent. Set to another value to override the local SOCKS5 port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub subs: Vec<String>,
    #[serde(default)]
    pub nodes: Vec<String>,
    #[serde(default)]
    pub custom_rules: Vec<String>,
}

pub const DEFAULT_PORT: u16 = 6161;
pub const DEFAULT_SOCKS_PORT: u16 = 1080;
