pub mod clash;
pub mod nodes;
pub mod proxy;
pub mod service;
pub mod share;
pub mod static_assets;
pub mod subs;
pub mod tun_process;
pub mod version;

use std::sync::Arc;

use axum::http::StatusCode;

use crate::{
    models::Config,
    responses::{status_error, success_no_data, HandlerResult},
    services::{config::apply_persistent_config_change, singbox::sing_box_is_running},
    state::AppState,
};

/// 保存 `Config` 里某个子配置，并在需要时重启 sing-box。
///
/// 顺序不是随意的：必须先拿 `config_update` 锁再采样 `was_running`，否则并发的
/// 启停会让"改完要不要重启"的判断出错。把它收在一处，免得每个子配置各抄一份，
/// 之后调整锁序时漏改其中一份。
pub(crate) async fn apply_config_section<T>(
    state: &Arc<AppState>,
    label: &str,
    section: T,
    current: impl Fn(&Config) -> &T,
    apply: impl FnOnce(&mut Config, T),
) -> HandlerResult
where
    T: PartialEq,
{
    let _config_update = state.config_update.lock().await;
    let was_running = sing_box_is_running(state).await;
    let old_config = state.config.read().await.clone();

    if current(&old_config) == &section {
        return Ok(success_no_data(format!("{label} unchanged")));
    }

    let mut new_config = old_config.clone();
    apply(&mut new_config, section);

    match apply_persistent_config_change(state, &old_config, &new_config, was_running).await {
        Ok(_) if was_running => Ok(success_no_data(format!(
            "{label} saved and sing-box restarted"
        ))),
        Ok(_) => Ok(success_no_data(format!("{label} saved"))),
        Err(e) => Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}
