//! The host owns process startup and upgrades; proxy configuration remains in Miao.
use std::path::PathBuf;

use crate::error::{AppError, AppResult};

pub const INTEGRATION_VERSION: u32 = 1;

pub fn enabled() -> bool {
    std::env::var("MIAO_EMBEDDED").as_deref() == Ok("ivnc")
}

pub fn panel_port(configured: u16) -> AppResult<u16> {
    resolve_panel_port(
        enabled(),
        std::env::var("MIAO_PORT").ok().as_deref(),
        configured,
    )
}

fn resolve_panel_port(embedded: bool, value: Option<&str>, configured: u16) -> AppResult<u16> {
    if !embedded {
        return Ok(configured);
    }
    match value {
        None => Ok(configured),
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| AppError::message("MIAO_PORT must be between 1 and 65535")),
    }
}

pub fn validate() -> AppResult<()> {
    resolve_runtime_dir(
        enabled(),
        std::env::var_os("MIAO_RUNTIME_DIR").map(PathBuf::from),
    )?;
    Ok(())
}

pub fn runtime_dir() -> PathBuf {
    // main validates this before any files or processes are created.
    resolve_runtime_dir(
        enabled(),
        std::env::var_os("MIAO_RUNTIME_DIR").map(PathBuf::from),
    )
    .expect("validated Miao runtime directory")
}

fn resolve_runtime_dir(embedded: bool, path: Option<PathBuf>) -> AppResult<PathBuf> {
    if !embedded {
        return Ok(PathBuf::from("/tmp/miao-sing-box"));
    }
    path.filter(|path| path.is_absolute() && path.parent().is_some())
        .ok_or_else(|| {
            AppError::message("Embedded Miao requires an absolute, non-root MIAO_RUNTIME_DIR")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_port_is_runtime_only_and_standalone_ignores_host_settings() {
        assert_eq!(
            resolve_panel_port(true, Some("12345"), 6161).unwrap(),
            12345
        );
        assert_eq!(
            resolve_panel_port(false, Some("invalid"), 7000).unwrap(),
            7000
        );
        assert!(resolve_panel_port(true, Some("0"), 6161).is_err());
        assert!(resolve_panel_port(true, Some("65536"), 6161).is_err());
    }

    #[test]
    fn embedded_runtime_never_falls_back_to_shared_temporary_files() {
        assert!(resolve_runtime_dir(true, None).is_err());
        assert!(resolve_runtime_dir(true, Some("relative".into())).is_err());
        assert!(resolve_runtime_dir(true, Some("/".into())).is_err());
        assert_eq!(
            resolve_runtime_dir(true, Some("/private/miao".into())).unwrap(),
            PathBuf::from("/private/miao")
        );
        assert_eq!(
            resolve_runtime_dir(false, Some("relative".into())).unwrap(),
            PathBuf::from("/tmp/miao-sing-box")
        );
    }
}
