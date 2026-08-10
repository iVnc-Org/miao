use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::warn;

use crate::{error::AppResult, paths::data_file, services::write_file_atomic};

const RUNTIME_STATE_FILE: &str = "runtime.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeState {
    #[serde(default = "default_running")]
    pub running: bool,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            running: true,
        }
    }
}

fn default_running() -> bool {
    true
}

fn runtime_state_path() -> PathBuf {
    data_file(RUNTIME_STATE_FILE)
}

pub async fn load_runtime_state() -> RuntimeState {
    let path = runtime_state_path();
    let Ok(content) = tokio::fs::read_to_string(&path).await else {
        return RuntimeState::default();
    };

    match serde_json::from_str(&content) {
        Ok(state) => state,
        Err(e) => {
            warn!(path = ?path, error = %e, "Failed to parse runtime state, using defaults");
            RuntimeState::default()
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

    #[test]
    fn runtime_state_defaults_to_running_for_compatibility() {
        let state = RuntimeState::default();

        assert!(state.running);
    }

    #[test]
    fn runtime_state_ignores_legacy_route_mode() {
        let state: RuntimeState =
            serde_json::from_str(r#"{"running":false,"route_mode":"rule"}"#).unwrap();
        assert!(!state.running);
    }
}
