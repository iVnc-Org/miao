use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};

pub const CONFIG_FILENAME: &str = "config.yaml";
pub const ETC_CONFIG_PATH: &str = "/etc/miao/config.yaml";
pub const DATA_DIR_NAME: &str = ".miao";

const LEGACY_CACHE_DIR: &str = "data/cache";
const LEGACY_CACHE_FILES: [&str; 6] = [
    "config.json",
    "config.meta.json",
    "last_proxy.json",
    "runtime.json",
    "share_ports.json",
    "sub_nodes.json",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigPathSource {
    Explicit,
    ExecutableDirExisting,
    HomeDataDir,
    EtcExisting,
}

#[derive(Clone, Debug)]
pub struct ConfigPathResolution {
    pub path: PathBuf,
    pub source: ConfigPathSource,
}

fn data_dir_from_home(home: Option<PathBuf>) -> PathBuf {
    home.filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/root"))
        .join(DATA_DIR_NAME)
}

pub fn data_dir() -> PathBuf {
    data_dir_from_home(std::env::var_os("HOME").map(PathBuf::from))
}

pub fn data_file(filename: &str) -> PathBuf {
    data_dir().join(filename)
}

pub async fn prepare_data_dir() -> AppResult<()> {
    let target_dir = data_dir();
    tokio::fs::create_dir_all(&target_dir)
        .await
        .map_err(|error| AppError::context("Failed to create Miao data directory", error))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| {
                AppError::context("Failed to secure Miao data directory", error)
            })?;
    }

    let legacy_dir = Path::new(LEGACY_CACHE_DIR);
    for filename in LEGACY_CACHE_FILES {
        let source = legacy_dir.join(filename);
        let target = target_dir.join(filename);
        if target.exists() {
            continue;
        }

        match tokio::fs::copy(&source, &target).await {
            Ok(_) => tracing::info!(from = ?source, to = ?target, "Migrated legacy persistent data"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(AppError::context(
                    format!("Failed to migrate legacy data file {}", source.display()),
                    error,
                ));
            }
        }
    }

    Ok(())
}

fn absolutize(path: PathBuf) -> AppResult<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        let cwd = std::env::current_dir()
            .map_err(|e| AppError::context("Failed to resolve current directory", e))?;
        Ok(cwd.join(path))
    }
}

fn config_arg_from(args: impl IntoIterator<Item = OsString>) -> AppResult<Option<PathBuf>> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let value = args
                .next()
                .ok_or_else(|| AppError::message("--config requires a path"))?;
            return Ok(Some(PathBuf::from(value)));
        }

        if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("--config=")) {
            if value.is_empty() {
                return Err(AppError::message("--config requires a path"));
            }
            return Ok(Some(PathBuf::from(value)));
        }
    }

    Ok(None)
}

pub fn resolve_config_path() -> AppResult<ConfigPathResolution> {
    if let Some(path) = config_arg_from(std::env::args_os().skip(1))? {
        return Ok(ConfigPathResolution {
            path: absolutize(path)?,
            source: ConfigPathSource::Explicit,
        });
    }

    let exe_dir_config = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(CONFIG_FILENAME)));
    let exe_dir_config_exists = exe_dir_config.as_deref().is_some_and(|path| path.exists());
    let home_config = data_file(CONFIG_FILENAME);
    let home_config_exists = home_config.exists();
    let etc_config_exists = Path::new(ETC_CONFIG_PATH).exists();

    Ok(resolve_config_path_from_parts(
        exe_dir_config_exists,
        exe_dir_config,
        home_config_exists,
        home_config,
        etc_config_exists,
    ))
}

fn resolve_config_path_from_parts(
    exe_dir_config_exists: bool,
    exe_dir_config: Option<PathBuf>,
    home_config_exists: bool,
    home_config: PathBuf,
    etc_config_exists: bool,
) -> ConfigPathResolution {
    if exe_dir_config_exists {
        if let Some(path) = exe_dir_config {
            return ConfigPathResolution {
                path,
                source: ConfigPathSource::ExecutableDirExisting,
            };
        }
    }

    if home_config_exists {
        return ConfigPathResolution {
            path: home_config,
            source: ConfigPathSource::HomeDataDir,
        };
    }

    if etc_config_exists {
        return ConfigPathResolution {
            path: PathBuf::from(ETC_CONFIG_PATH),
            source: ConfigPathSource::EtcExisting,
        };
    }

    ConfigPathResolution {
        path: home_config,
        source: ConfigPathSource::HomeDataDir,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        config_arg_from, data_dir_from_home, resolve_config_path_from_parts, ConfigPathSource,
        ETC_CONFIG_PATH,
    };

    #[test]
    fn config_arg_parses_separate_value() {
        let args = vec![OsString::from("--config"), OsString::from("/tmp/miao.yaml")];

        let parsed = config_arg_from(args).unwrap();

        assert_eq!(parsed, Some(PathBuf::from("/tmp/miao.yaml")));
    }

    #[test]
    fn config_arg_parses_equals_value() {
        let args = vec![OsString::from("--config=/tmp/miao.yaml")];

        let parsed = config_arg_from(args).unwrap();

        assert_eq!(parsed, Some(PathBuf::from("/tmp/miao.yaml")));
    }

    #[test]
    fn config_arg_rejects_missing_value() {
        let args = vec![OsString::from("--config")];

        let err = config_arg_from(args).unwrap_err();

        assert_eq!(err.to_string(), "--config requires a path");
    }

    #[test]
    fn executable_directory_config_is_compatible() {
        let resolution = resolve_config_path_from_parts(
            true,
            Some(PathBuf::from("/opt/miao/config.yaml")),
            false,
            PathBuf::from("/home/miao/.miao/config.yaml"),
            false,
        );

        assert_eq!(resolution.path, PathBuf::from("/opt/miao/config.yaml"));
        assert_eq!(resolution.source, ConfigPathSource::ExecutableDirExisting);
    }

    #[test]
    fn existing_home_config_precedes_legacy_etc_config() {
        let home_config = PathBuf::from("/home/miao/.miao/config.yaml");
        let resolution = resolve_config_path_from_parts(
            false,
            Some(PathBuf::from("/opt/miao/config.yaml")),
            true,
            home_config.clone(),
            true,
        );

        assert_eq!(resolution.path, home_config);
        assert_eq!(resolution.source, ConfigPathSource::HomeDataDir);
    }

    #[test]
    fn existing_etc_config_remains_compatible() {
        let resolution = resolve_config_path_from_parts(
            false,
            Some(PathBuf::from("/opt/miao/config.yaml")),
            false,
            PathBuf::from("/home/miao/.miao/config.yaml"),
            true,
        );

        assert_eq!(resolution.path, PathBuf::from(ETC_CONFIG_PATH));
        assert_eq!(resolution.source, ConfigPathSource::EtcExisting);
    }

    #[test]
    fn home_data_dir_is_the_new_default() {
        let home_config = PathBuf::from("/home/miao/.miao/config.yaml");
        let resolution = resolve_config_path_from_parts(
            false,
            Some(PathBuf::from("/opt/miao/config.yaml")),
            false,
            home_config.clone(),
            false,
        );

        assert_eq!(resolution.path, home_config);
        assert_eq!(resolution.source, ConfigPathSource::HomeDataDir);
    }

    #[test]
    fn data_dir_is_relative_to_home() {
        assert_eq!(
            data_dir_from_home(Some(PathBuf::from("/home/miao"))),
            PathBuf::from("/home/miao/.miao")
        );
    }
}
