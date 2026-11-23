use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

use crate::error::{AppError, AppResult};

/// Package managers are serialized even when the start that requested them was cancelled.
static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Preparation = tokio::sync::watch::Receiver<Option<Result<(), String>>>;
static PREPARATION: std::sync::Mutex<Option<Preparation>> = std::sync::Mutex::new(None);
static PREPARATION_DRAINING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static PREPARATION_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PREPARATION_DONE: tokio::sync::Notify = tokio::sync::Notify::const_new();

pub async fn prepare_tun() -> AppResult<()> {
    if tun_available()? {
        return Ok(());
    }
    let mut receiver = {
        let mut slot = PREPARATION.lock().unwrap_or_else(|e| e.into_inner());
        if PREPARATION_DRAINING.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AppError::message(
                "START_CANCELLED: dependency preparation is shutting down",
            ));
        }
        if slot
            .as_ref()
            .is_none_or(|receiver| receiver.borrow().is_some() || receiver.has_changed().is_err())
        {
            let (sender, receiver) = tokio::sync::watch::channel(None);
            PREPARATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                struct Done;
                impl Drop for Done {
                    fn drop(&mut self) {
                        PREPARATION_COUNT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        PREPARATION_DONE.notify_waiters();
                    }
                }
                let _done = Done;
                let result = ensure_tun().await.map_err(|error| error.to_string());
                sender.send_replace(Some(result));
            });
            *slot = Some(receiver);
        }
        slot.as_ref().unwrap().clone()
    };
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result.map_err(AppError::message);
        }
        receiver
            .changed()
            .await
            .map_err(|e| AppError::message(format!("Dependency worker disappeared: {e}")))?;
    }
}

/// Graceful shutdown drains the package transaction instead of dropping its child handle.
pub async fn finish_preparation() {
    {
        let _slot = PREPARATION.lock().unwrap_or_else(|e| e.into_inner());
        PREPARATION_DRAINING.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    loop {
        let notified = PREPARATION_DONE.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if PREPARATION_COUNT.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            return;
        }
        notified.await;
    }
}

pub async fn command_output(
    path: &Path,
    args: &[&str],
    timeout: Duration,
) -> AppResult<std::process::Output> {
    let mut command = tokio::process::Command::new(path);
    command
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command.as_std_mut().process_group(0);
    let child = command
        .spawn()
        .map_err(|e| AppError::context(format!("Failed to execute {}", path.display()), e))?;
    let pid = child.id();
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(result) => result.map_err(|e| AppError::context("Failed to collect command output", e)),
        Err(_) => {
            if let Some(pid) = pid {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            Err(AppError::message(format!(
                "DEPENDENCY_TIMEOUT: {} exceeded {} seconds; inspect package state before retrying",
                path.display(),
                timeout.as_secs()
            )))
        }
    }
}

use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;

pub fn tun_available() -> AppResult<bool> {
    let metadata = match std::fs::metadata("/dev/net/tun") {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(AppError::context("TUN_DEVICE_CHECK_FAILED", error)),
    };
    if !metadata.file_type().is_char_device() {
        return Err(AppError::message(
            "TUN_INVALID_DEVICE: /dev/net/tun is not a character device",
        ));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .map_err(|e| {
            AppError::context(
                "TUN_ACCESS_DENIED: check host/container device permissions",
                e,
            )
        })?;
    Ok(true)
}

pub fn check_net_admin() -> AppResult<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or(0);
    if capabilities & (1 << 12) == 0 {
        return Err(AppError::message("NO_NET_ADMIN: TUN routing requires CAP_NET_ADMIN (root on the router, or the corresponding container capability)"));
    }
    Ok(())
}

enum PkgManager {
    Apk(PathBuf),
    Opkg(PathBuf),
}

impl PkgManager {
    fn detect() -> Option<Self> {
        Self::detect_in_dirs(command_search_dirs())
    }

    fn detect_in_dirs(dirs: impl IntoIterator<Item = PathBuf>) -> Option<Self> {
        let dirs: Vec<PathBuf> = dirs.into_iter().collect();
        find_command(&dirs, "apk")
            .map(Self::Apk)
            .or_else(|| find_command(&dirs, "opkg").map(Self::Opkg))
    }

    fn name(&self) -> &str {
        match self {
            Self::Apk(_) => "apk",
            Self::Opkg(_) => "opkg",
        }
    }

    fn command_path(&self) -> &Path {
        match self {
            Self::Apk(path) | Self::Opkg(path) => path.as_path(),
        }
    }

    async fn is_installed(&self, pkg: &str) -> AppResult<bool> {
        match self {
            Self::Apk(_) => {
                // apk info -e <pkg> 返回 0 表示已安装
                Ok(command_output(
                    self.command_path(),
                    &["info", "-e", pkg],
                    Duration::from_secs(10),
                )
                .await?
                .status
                .success())
            }
            Self::Opkg(_) => {
                let output = command_output(
                    self.command_path(),
                    &["status", pkg],
                    Duration::from_secs(10),
                )
                .await?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(output.status.success() && package_is_installed(&stdout))
            }
        }
    }

    async fn update_index(&self) -> AppResult<()> {
        info!("Running '{} update'...", self.name());
        let output =
            command_output(self.command_path(), &["update"], Duration::from_secs(30)).await?;
        if !output.status.success() {
            return Err(AppError::message(format!(
                "DEPENDENCY_INDEX_FAILED: {} update failed: {}",
                self.name(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    async fn install(&self, pkg: &str) -> AppResult<()> {
        info!("Installing {} via {}...", pkg, self.name());
        self.verify_kernel_abi(pkg).await?;
        let verb = if matches!(self, Self::Apk(_)) {
            "add"
        } else {
            "install"
        };
        let output =
            command_output(self.command_path(), &[verb, pkg], Duration::from_secs(120)).await?;
        if !output.status.success() {
            return Err(AppError::message(format!(
                "DEPENDENCY_INSTALL_FAILED: Failed to install {} via {}: {}",
                pkg,
                self.name(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    async fn verify_kernel_abi(&self, pkg: &str) -> AppResult<()> {
        if matches!(self, Self::Apk(_)) {
            let output = command_output(
                self.command_path(),
                &["add", "--simulate", pkg],
                Duration::from_secs(20),
            )
            .await?;
            if !output.status.success() {
                return Err(AppError::message(format!(
                    "KERNEL_ABI_MISMATCH: apk cannot satisfy the current kernel dependencies: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            return Ok(());
        }
        let kernel = command_output(
            self.command_path(),
            &["status", "kernel"],
            Duration::from_secs(10),
        )
        .await?;
        let package =
            command_output(self.command_path(), &["info", pkg], Duration::from_secs(10)).await?;
        verify_opkg_kernel_abi(
            &String::from_utf8_lossy(&kernel.stdout),
            &String::from_utf8_lossy(&package.stdout),
        )
    }
}

fn package_is_installed(record: &str) -> bool {
    record
        .lines()
        .filter_map(|line| line.strip_prefix("Status:"))
        .any(|status| status.split_whitespace().last() == Some("installed"))
}

fn verify_opkg_kernel_abi(kernel: &str, package: &str) -> AppResult<()> {
    let installed = kernel
        .lines()
        .find_map(|line| line.strip_prefix("Version: "))
        .ok_or_else(|| {
            AppError::message("KERNEL_ABI_UNKNOWN: installed kernel package has no version")
        })?;
    let compatible = package.split("\n\n").any(|block| {
        block
            .lines()
            .filter_map(|line| line.strip_prefix("Depends: "))
            .any(|depends| {
                depends.split(',').map(str::trim).any(|dependency| {
                    dependency
                        .strip_prefix("kernel (= ")
                        .and_then(|value| value.strip_suffix(')'))
                        == Some(installed)
                })
            })
    });
    if !compatible {
        return Err(AppError::message(format!("KERNEL_ABI_MISMATCH: no package built for kernel {installed}; use feeds matching this firmware, without force-depends")));
    }
    Ok(())
}

pub fn command_search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();

    for path in ["/sbin", "/usr/sbin", "/bin", "/usr/bin"] {
        let path = PathBuf::from(path);
        if !dirs.iter().any(|existing| existing == &path) {
            dirs.push(path);
        }
    }

    dirs
}

pub fn find_command(dirs: &[PathBuf], command: &str) -> Option<PathBuf> {
    dirs.iter()
        .map(|dir| dir.join(command))
        .find(|path| path.exists())
}

async fn ensure_tun_device_available() -> AppResult<()> {
    if tun_available()? {
        return Ok(());
    }

    let Some(modprobe) = find_command(&command_search_dirs(), "modprobe") else {
        return Err(AppError::message(
            "/dev/net/tun is missing and modprobe was not found; install/load kmod-tun manually",
        ));
    };

    info!("/dev/net/tun is missing, trying to load tun module...");
    let output = command_output(&modprobe, &["tun"], Duration::from_secs(10)).await?;
    let status = output.status;

    if !status.success() {
        return Err(AppError::message(format!(
            "modprobe tun failed with status {status}; /dev/net/tun is still unavailable"
        )));
    }

    if !tun_available()? {
        return Err(AppError::message(
            "modprobe tun succeeded but /dev/net/tun is still missing",
        ));
    }

    Ok(())
}

pub async fn ensure_tun() -> AppResult<()> {
    if tun_available()? {
        return Ok(());
    }
    let _installation = INSTALL_LOCK.lock().await;
    if ensure_tun_device_available().await.is_ok() {
        return Ok(());
    }
    if !Path::new("/etc/openwrt_release").exists() {
        return Err(AppError::message(
            "TUN_UNAVAILABLE: enable /dev/net/tun on the host/container",
        ));
    }
    let pm = PkgManager::detect().ok_or_else(|| {
        AppError::message("TUN_UNAVAILABLE: no apk/opkg found; install/load kmod-tun on the host")
    })?;
    if pm.is_installed("kmod-tun").await? {
        return Err(AppError::message("TUN_LOAD_FAILED: kmod-tun is installed but /dev/net/tun is unavailable; check kernel/module compatibility"));
    }
    pm.update_index().await?;
    if let Err(error) = pm.install("kmod-tun").await {
        // A timed out package transaction may already have installed the module.
        // Recheck once; never immediately run a second installation or delete a lock.
        if tun_available()? {
            return Ok(());
        }
        if pm.is_installed("kmod-tun").await.unwrap_or(false)
            && ensure_tun_device_available().await.is_ok()
        {
            return Ok(());
        }
        return Err(AppError::context(
            "TUN dependency state rechecked after installation failure",
            error,
        ));
    }
    ensure_tun_device_available().await
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::PkgManager;

    #[test]
    fn package_presence_is_not_confused_with_not_installed() {
        assert!(super::package_is_installed(
            "Status: install user installed\n"
        ));
        assert!(!super::package_is_installed(
            "Status: deinstall ok not-installed\n"
        ));
        assert!(!super::package_is_installed("Package: installed-helper\n"));
    }

    #[test]
    fn refuses_kernel_packages_built_for_another_firmware() {
        let installed = "Package: kernel\nVersion: 6.12.16-1-customhash\n";
        assert!(super::verify_opkg_kernel_abi(
            installed,
            "Package: kmod-tun\nDepends: kernel (= 6.6.73-1-officialhash)\n"
        )
        .is_err());
        assert!(super::verify_opkg_kernel_abi(
            installed,
            "Package: kmod-tun\nDepends: libc, kernel (= 6.12.16-1-customhash)\n"
        )
        .is_ok());
        assert!(super::verify_opkg_kernel_abi(installed, "").is_err());
    }

    #[tokio::test]
    async fn bounded_commands_capture_both_streams_and_time_out() {
        let output = super::command_output(
            Path::new("/bin/sh"),
            &["-c", "printf stdout; printf stderr >&2"],
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
        let error = super::command_output(
            Path::new("/bin/sh"),
            &["-c", "sleep 5"],
            std::time::Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("DEPENDENCY_TIMEOUT"));
    }

    fn temp_command_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("miao-openwrt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(path: &Path) {
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn detects_apk_from_bin_style_dir() {
        let dir = temp_command_dir("apk-bin");
        touch(&dir.join("apk"));

        let pm = PkgManager::detect_in_dirs([dir.clone()]).unwrap();

        assert!(matches!(pm, PkgManager::Apk(_)));
        assert_eq!(pm.command_path(), dir.join("apk").as_path());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prefers_apk_when_both_package_managers_exist() {
        let dir = temp_command_dir("apk-opkg");
        touch(&dir.join("apk"));
        touch(&dir.join("opkg"));

        let pm = PkgManager::detect_in_dirs([dir.clone()]).unwrap();

        assert!(matches!(pm, PkgManager::Apk(_)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_opkg_when_apk_is_missing() {
        let dir = temp_command_dir("opkg");
        touch(&dir.join("opkg"));

        let pm = PkgManager::detect_in_dirs([dir.clone()]).unwrap();

        assert!(matches!(pm, PkgManager::Opkg(_)));
        assert_eq!(pm.command_path(), dir.join("opkg").as_path());
        let _ = std::fs::remove_dir_all(dir);
    }
}
