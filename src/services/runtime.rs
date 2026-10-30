use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::warn;

use crate::{error::AppResult, paths::data_file, services::write_file_atomic};

const RUNTIME_STATE_FILE: &str = "runtime.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeState {
    #[serde(default)]
    pub running: bool,
}

fn runtime_state_path() -> PathBuf {
    data_file(RUNTIME_STATE_FILE)
}

pub async fn load_runtime_state() -> RuntimeState {
    load_runtime_state_report().await.0
}

pub async fn load_runtime_state_report() -> (RuntimeState, Option<String>) {
    let legacy_running =
        super::proxy::load_last_proxy().await.is_some() && data_file("config.meta.json").is_file();
    read_state(&runtime_state_path(), legacy_running).await
}

async fn read_state(
    path: &std::path::Path,
    legacy_running: bool,
) -> (RuntimeState, Option<String>) {
    let result = tokio::fs::read_to_string(path).await;
    if matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
        // Only missing files allow legacy migration; corrupt files fail stopped.
        let state = RuntimeState {
            running: legacy_running,
        };
        if let Err(error) = write_file_atomic(
            path,
            &serde_json::to_string(&state).expect("runtime state"),
            "initial runtime state",
        )
        .await
        {
            warn!(%error, "Unable to persist initial runtime state");
            return (
                RuntimeState::default(),
                Some("无法保存初始运行状态，代理保持停止".into()),
            );
        }
        return (state, None);
    }
    match result {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(state) => (state, None),
            Err(error) => {
                warn!(?path, %error, "Runtime state is invalid; proxy remains stopped");
                (
                    RuntimeState::default(),
                    Some("运行状态文件损坏，代理保持停止；可在面板手动启动".into()),
                )
            }
        },
        Err(error) => {
            warn!(?path, %error, "Unable to read runtime state; proxy remains stopped");
            (
                RuntimeState::default(),
                Some("无法读取运行状态，代理保持停止；请检查文件权限".into()),
            )
        }
    }
}

pub async fn save_runtime_state(state: RuntimeState) -> AppResult<()> {
    let content = serde_json::to_string(&state)?;
    write_file_atomic(&runtime_state_path(), &content, "runtime state").await
}

pub async fn save_running_state(running: bool) -> AppResult<()> {
    save_runtime_state(RuntimeState { running }).await
}

#[cfg(test)]
mod tests {
    use super::RuntimeState;

    #[tokio::test]
    async fn first_run_legacy_migration_and_corruption_have_distinct_behavior() {
        for legacy in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "miao-runtime-test-{}-{}",
                std::process::id(),
                legacy
            ));
            tokio::fs::create_dir_all(&dir).await.unwrap();
            let path = dir.join("runtime.json");
            let _ = tokio::fs::remove_file(&path).await;
            let (state, warning) = super::read_state(&path, legacy).await;
            assert_eq!(state.running, legacy);
            assert!(warning.is_none());
            let (state, _) = super::read_state(&path, !legacy).await;
            assert_eq!(state.running, legacy); // migrated state takes precedence
            tokio::fs::write(&path, "corrupt").await.unwrap();
            let (state, warning) = super::read_state(&path, true).await;
            assert!(!state.running);
            assert!(warning.is_some());
            assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), "corrupt");
            tokio::fs::remove_dir_all(dir).await.unwrap();
        }
    }

    #[test]
    fn runtime_state_defaults_to_stopped_without_history() {
        let state = RuntimeState::default();

        assert!(!state.running);
    }

    #[test]
    fn runtime_state_ignores_legacy_route_mode() {
        let state: RuntimeState =
            serde_json::from_str(r#"{"running":false,"route_mode":"rule"}"#).unwrap();
        assert!(!state.running);
    }
}
