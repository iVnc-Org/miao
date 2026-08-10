use axum::{extract::State, http::StatusCode, response::Json};
use std::sync::Arc;

use crate::models::{
    ApiResponse, ReplaceSubRequest, SubRequest, SubState, SubStatus,
};
use crate::responses::{status_error, success, success_no_data, HandlerResult};
use crate::services::{
    config::{
        apply_config_change, fetch_subscription_nodes, regenerate_and_restart, SubFetchPolicy,
    },
    sub_nodes::{hydrate_sub_status, load_sub_nodes, save_sub_nodes},
};
use crate::state::AppState;
use crate::validation::Validator;

pub async fn get_subs(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<SubStatus>>> {
    let config = state.config.read().await;
    let status_map = state.sub_status.lock().await;

    let subs_with_status: Vec<SubStatus> = config
        .subs
        .iter()
        .map(|url| {
            status_map.get(url).cloned().unwrap_or(SubStatus {
                url: url.clone(),
                state: SubState::Pending,
                node_count: 0,
                error: None,
            })
        })
        .collect();

    success("Subscriptions loaded", subs_with_status)
}

pub async fn add_sub(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubRequest>,
) -> HandlerResult {
    if let Err(e) = Validator::subscription_url(&req.url) {
        return Err(status_error(StatusCode::BAD_REQUEST, e));
    }

    let _config_update = state.config_update.lock().await;
    let old_config = state.config.read().await.clone();
    let mut new_config = old_config.clone();

    if new_config.subs.contains(&req.url) {
        return Err(status_error(
            StatusCode::BAD_REQUEST,
            "Subscription already exists",
        ));
    }

    let added = req.url.clone();
    new_config.subs.push(req.url);

    // 首次导入：只抓这一个新链接，别顺手把其它订阅也刷一遍——那些链接多半已经过期。
    match apply_config_change(
        &state,
        &old_config,
        &new_config,
        SubFetchPolicy::FetchOnly(vec![added]),
    )
    .await
    {
        Ok(_) => Ok(success_no_data("Subscription added and sing-box restarted")),
        Err(e) => Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn delete_sub(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubRequest>,
) -> HandlerResult {
    let _config_update = state.config_update.lock().await;
    let old_config = state.config.read().await.clone();
    let mut new_config = old_config.clone();

    let original_len = new_config.subs.len();
    new_config.subs.retain(|s| s != &req.url);

    if new_config.subs.len() == original_len {
        return Err(status_error(
            StatusCode::NOT_FOUND,
            "Subscription not found",
        ));
    }

    // 删订阅不需要联网：store.retain_urls 会顺带丢掉它的节点。
    match apply_config_change(&state, &old_config, &new_config, SubFetchPolicy::CacheOnly).await {
        Ok(_) if new_config.subs.is_empty() && new_config.nodes.is_empty() => Ok(success_no_data(
            "Subscription deleted; no nodes configured, sing-box stopped",
        )),
        Ok(_) => Ok(success_no_data(
            "Subscription deleted and sing-box restarted",
        )),
        Err(e) => Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn replace_sub(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReplaceSubRequest>,
) -> HandlerResult {
    if let Err(error) = Validator::subscription_url(&req.new_url) {
        return Err(status_error(StatusCode::BAD_REQUEST, error));
    }
    if req.old_url == req.new_url {
        return Err(status_error(
            StatusCode::BAD_REQUEST,
            "New subscription URL must be different",
        ));
    }

    let _config_update = state.config_update.lock().await;
    let old_config = state.config.read().await.clone();
    let Some(index) = old_config.subs.iter().position(|url| url == &req.old_url) else {
        return Err(status_error(
            StatusCode::NOT_FOUND,
            "Subscription not found",
        ));
    };
    if old_config.subs.iter().any(|url| url == &req.new_url) {
        return Err(status_error(
            StatusCode::BAD_REQUEST,
            "Subscription already exists",
        ));
    }

    let fetched = fetch_subscription_nodes(&req.new_url, &state)
        .await
        .map_err(|error| status_error(StatusCode::BAD_REQUEST, error))?;
    let previous_store = load_sub_nodes().await;
    let mut staged_store = previous_store.clone();
    staged_store.record_success(
        &req.new_url,
        fetched.nodes,
        Some(fetched.fetched_at),
    );
    save_sub_nodes(&staged_store)
        .await
        .map_err(|error| status_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;

    let mut new_config = old_config.clone();
    new_config.subs[index] = req.new_url.clone();
    if let Err(apply_error) = apply_config_change(
        &state,
        &old_config,
        &new_config,
        SubFetchPolicy::CacheOnly,
    )
    .await
    {
        if let Err(restore_error) = save_sub_nodes(&previous_store).await {
            return Err(status_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Subscription replacement failed: {}. Cache rollback failed: {}",
                    apply_error, restore_error
                ),
            ));
        }
        hydrate_sub_status(&state, &old_config.subs).await;
        return Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, apply_error));
    }

    state.sub_status.lock().await.insert(
        req.new_url.clone(),
        SubStatus {
            url: req.new_url,
            state: SubState::Ok,
            node_count: staged_store
                .subs
                .get(&new_config.subs[index])
                .map_or(0, |entry| entry.nodes.len()),
            error: fetched.parse_warning,
        },
    );
    Ok(success_no_data("Subscription replaced"))
}

pub async fn refresh_subs(State(state): State<Arc<AppState>>) -> HandlerResult {
    let _config_update = state.config_update.lock().await;
    let config = state.config.read().await;
    let config_clone = config.clone();
    drop(config);

    // 唯一会全量联网的路径。链接大概率已经过期，那不是错误：
    // 抓不动就继续用缓存里的节点，只是告诉用户链接失效了。
    match regenerate_and_restart(&config_clone, &state).await {
        Ok(outcome) if outcome.any_expired => {
            Ok(success_no_data("订阅链接已失效，继续使用上次获取的节点"))
        }
        Ok(_) => Ok(success_no_data("订阅已刷新")),
        Err(e) => Err(status_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

#[cfg(test)]
mod tests {
    use axum::{extract::State, response::Json};

    use super::get_subs;
    use crate::{error::AppError, models::Config, test_support::app_state};

    #[test]
    fn app_error_context_message_stays_user_visible() {
        let err = AppError::context(
            "Failed to apply config change; rolled back to previous config",
            AppError::message("new config invalid"),
        );

        assert_eq!(
            err.to_string(),
            "Failed to apply config change; rolled back to previous config: new config invalid"
        );
    }

    #[tokio::test]
    async fn get_subs_returns_default_pending_status_when_status_missing() {
        let state = app_state(Config {
            subs: vec!["https://example.com/sub".to_string()],
            ..Default::default()
        });

        let Json(response) = get_subs(State(state)).await;

        assert!(response.success);
        assert_eq!(response.message, "Subscriptions loaded");
        let subs = response.data.unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].url, "https://example.com/sub");
        // 还没有任何抓取或缓存数据时是 Pending，不是"失败"。
        assert_eq!(subs[0].state, crate::models::SubState::Pending);
        assert_eq!(subs[0].node_count, 0);
        assert!(subs[0].error.is_none());
    }
}
