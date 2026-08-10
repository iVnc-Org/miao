use serde::{Deserialize, Serialize};

use crate::models::config::ProxyMode;

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(message: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn success_no_data(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

#[derive(Serialize)]
pub struct StatusData {
    pub running: bool,
    pub initializing: bool,
    pub mode: ProxyMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ConnectivityResult {
    pub name: String,
    pub url: String,
    pub latency_ms: Option<u64>,
    pub success: bool,
}

#[derive(Deserialize)]
pub struct SubRequest {
    pub url: String,
}

#[derive(Deserialize)]
pub struct ReplaceSubRequest {
    pub old_url: String,
    pub new_url: String,
}

#[derive(Deserialize)]
pub struct ModeRequest {
    pub mode: ProxyMode,
}

/// 一个订阅当前的可用状态。
///
/// 刻意和"抓取是否成功"分开：订阅链接通常只有几分钟有效期，抓不动是常态而不是
/// 故障。`Expired` 表示链接已经拉不动了，但上次抓到的节点仍在使用中——前端要把它
/// 渲染成提示而不是错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubState {
    /// 本轮刚抓取成功。
    Ok,
    /// 未抓取，使用本地缓存的节点。
    Cached,
    /// 抓取失败，仍在使用上次成功抓到的节点。
    Expired,
    /// 尚无任何数据。
    Pending,
}

#[derive(Clone, Serialize)]
pub struct SubStatus {
    pub url: String,
    pub state: SubState,
    pub node_count: usize,
    /// 只用于真正需要用户处理的问题（例如部分节点解析失败）。
    /// 链接失效不填这里，否则前端会渲染成红色异常。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ShareEndpoint {
    pub tag: String,
    pub port: u16,
    pub listen: String,
    pub url: String,
}

#[derive(Deserialize)]
pub struct ShareTestRequest {
    pub tag: String,
    pub port: u16,
}

#[derive(Serialize, Clone)]
pub struct ShareTestResult {
    pub tag: String,
    pub status_code: u16,
    pub status_text: String,
    pub body: serde_json::Value,
}
