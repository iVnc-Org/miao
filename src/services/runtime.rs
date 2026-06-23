use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::{
    error::{AppError, AppResult},
    models::RouteMode,
};

const RUNTIME_STATE_DIR: &str = "data/cache";
const RUNTIME_STATE_FILE: &str = "runtime.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeState {
    #[serde(default = "default_running")]
    pub running: bool,
    #[serde(default)]
    pub route_mode: RouteMode,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            running: true,
            route_mode: RouteMode::default(),
        }
    }
}

fn default_running() -> bool {
    true
}

fn runtime_state_path() -> PathBuf {
    PathBuf::from(RUNTIME_STATE_DIR).join(RUNTIME_STATE_FILE)
}

async fn write_file_atomic(path: &Path, content: &str) -> AppResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::context("Failed to create runtime state directory", e))?;
    }

    let temp_path = path.with_extension("tmp");
    tokio::fs::write(&temp_path, content)
        .await
        .map_err(|e| AppError::context("Failed to write runtime state temp file", e))?;
    tokio::fs::rename(&temp_path, path)
        .await
        .map_err(|e| AppError::context("Failed to atomically rename runtime state file", e))?;
    Ok(())
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
    write_file_atomic(&runtime_state_path(), &content).await
}

pub async fn save_running_state(running: bool, route_mode: RouteMode) -> AppResult<()> {
    save_runtime_state(RuntimeState {
        running,
        route_mode,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::RuntimeState;
    use crate::models::RouteMode;

    #[test]
    fn runtime_state_defaults_to_running_for_compatibility() {
        let state = RuntimeState::default();

        assert!(state.running);
        assert_eq!(state.route_mode, RouteMode::Tunnel);
    }
}
