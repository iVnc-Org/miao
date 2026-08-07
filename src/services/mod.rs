pub mod config;
pub mod node_parser;
pub mod openwrt;
pub mod proxy;
pub mod runtime;
pub mod share_ports;
pub mod singbox;
pub mod subscription;
pub mod version;
pub mod vps;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{AppError, AppResult};

static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// 原子写入文件：先写入进程内唯一的临时文件，再重命名为目标文件。
///
/// 临时文件名带 pid 与自增序号，避免同一目标文件的并发写入者互相踩踏
/// （`with_extension("tmp")` 这种固定名字会让两个写入者交错写进同一个临时文件）。
pub(crate) async fn write_file_atomic(path: &Path, content: &str, what: &str) -> AppResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::context(format!("Failed to create {} directory", what), e))?;
    }

    let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), seq));

    if let Err(e) = tokio::fs::write(&temp_path, content).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::context(
            format!("Failed to write {} temp file", what),
            e,
        ));
    }

    if let Err(e) = tokio::fs::rename(&temp_path, path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::context(
            format!("Failed to atomically rename {}", what),
            e,
        ));
    }

    Ok(())
}
