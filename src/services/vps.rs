//! Persistent VPS jobs. No SSH credentials are stored in local job records.
use crate::{
    error::{AppError, AppResult},
    state::AppState,
    validation::Validator,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
mod ssh;
const WORKER: &str = include_str!("vps/worker.py");
const BOOTSTRAP: &str = include_str!("vps/bootstrap.sh");
static JOB_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Connection {
    pub host: String,
    pub ssh_port: u16,
    pub user: String,
    pub auth: String,
    pub secret: String,
    pub listen_port: u16,
    pub node_host: String,
    pub node_port: u16,
    pub name: String,
    pub download_proxy: String,
    pub id: String,
    pub idempotency_key: String,
    #[serde(skip)]
    pub start_on_commit: bool,
}
impl Connection {
    pub fn validate(&mut self) -> AppResult<()> {
        self.host = self.host.trim().into();
        self.node_host = self.node_host.trim().into();
        Validator::server_address(&self.host).map_err(AppError::message)?;
        if self.node_host.is_empty() {
            self.node_host = self.host.clone()
        }
        Validator::server_address(&self.node_host).map_err(AppError::message)?;
        if self.ssh_port == 0 {
            self.ssh_port = 22
        }
        if self.listen_port == 0 {
            self.listen_port = 543
        }
        if self.node_port == 0 {
            self.node_port = self.listen_port
        }
        if self.user.is_empty() {
            self.user = "root".into()
        }
        if self.user != "root" {
            return Err(AppError::message("Root SSH access required"));
        }
        if !["password", "private_key", "local_key"].contains(&self.auth.as_str()) {
            return Err(AppError::message("Unsupported authentication"));
        }
        if self.auth != "local_key" && self.secret.is_empty() {
            return Err(AppError::message("SSH credential required"));
        }
        if self.secret.len() > 32768
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err(AppError::message("Input too long or invalid"));
        }
        if !self.id.is_empty()
            && (self.id.len() != 48 || !self.id.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(AppError::message("Invalid task ID"));
        }
        if !self.idempotency_key.is_empty()
            && (self.idempotency_key.len() != 48
                || !self.idempotency_key.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(AppError::message("Invalid idempotency key"));
        }
        if !self.download_proxy.is_empty() {
            let url = url::Url::parse(&self.download_proxy)
                .map_err(|_| AppError::message("Invalid download proxy"))?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(AppError::message(
                    "Download proxy must be an HTTPS prefix without credentials or query",
                ));
            }
        }
        Ok(())
    }
    fn remote(&self) -> Value {
        json!({"id":self.id,"listen_port":self.listen_port,"node_host":self.node_host,"node_port":self.node_port,"name":self.name,"download_proxy":self.download_proxy})
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Job {
    pub id: String,
    pub host: String,
    pub ssh_port: u16,
    pub listen_port: u16,
    pub node_host: String,
    pub node_port: u16,
    pub active: bool,
    pub stage: String,
    pub events: Vec<String>,
    pub started: u64,
    pub tag: Option<String>,
    pub remote_id: String,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub source: String,
}
fn directory(state: &AppState) -> PathBuf {
    state.config_path.with_extension("vps")
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub(super) fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn encoded(value: &Value) -> String {
    STANDARD.encode(serde_json::to_vec(value).expect("JSON value"))
}
async fn save(state: &AppState, job: &Job) -> AppResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    let dir = directory(state);
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    let metadata = std::fs::symlink_metadata(&dir)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(AppError::message("Unsafe VPS task directory"));
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join(format!("{}.json", job.id));
    let temp = dir.join(format!("{}.{}.tmp", job.id, ssh::random_id()?));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec(job)?)?;
    file.sync_all()?;
    std::fs::rename(temp, path)?;
    Ok(())
}
pub async fn jobs(state: &AppState) -> AppResult<Vec<Job>> {
    let mut jobs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(directory(state)) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|v| v == "json") {
                jobs.push(serde_json::from_slice::<Job>(&std::fs::read(
                    entry.path(),
                )?)?);
            }
        }
    }
    jobs.sort_by(|a, b| b.started.cmp(&a.started));
    Ok(jobs)
}
pub async fn recover_jobs(state: &AppState) {
    ssh::cleanup_credentials();
    if let Ok(records) = jobs(state).await {
        for mut job in records {
            if job.active {
                job.active = false;
                job.stage = "unknown".into();
                job.events.push(
                    "Miao restarted; re-authenticate to inspect the remote transaction".into(),
                );
                let _ = save(state, &job).await;
            }
        }
    }
}
fn inspect_script(req: &Connection) -> String {
    format!("set -eu\ncommand -v python3 >/dev/null || {{ printf '%s' '{{\"action\":\"dependencies_required\"}}'; exit 0; }}\npython3 - inspect {} <<'MIAO_PYTHON'\n{}\nMIAO_PYTHON\n",quote(&encoded(&req.remote())),WORKER)
}
pub async fn preflight(mut req: Connection) -> AppResult<Value> {
    req.validate()?;
    let out = ssh::script(&req, &inspect_script(&req), 45).await?;
    serde_json::from_slice(&out)
        .map_err(|_| AppError::message("Remote inspection returned invalid data"))
}
fn launcher(req: &Connection) -> String {
    // nohup shell bootstraps Python independently of SSH. The task is visible
    // before package installation begins and can be inspected after disconnect.
    let runner = format!(
        r#"set -eu
umask 077
TASK=/var/lib/miao-vps/tasks/{}
exec >>"$TASK/worker.log" 2>&1
printf '%s' "$$" > "$TASK/bootstrap.pid"
bootstrap_failed() {{ printf '%s' '{{"stage":"error","error":"dependencies_failed"}}' > "$TASK/status.json.new"; mv "$TASK/status.json.new" "$TASK/status.json"; }}
trap bootstrap_failed 0
if command -v timeout >/dev/null; then timeout -k 30 600 sh "$TASK/bootstrap.sh"; else sh "$TASK/bootstrap.sh"; fi
trap - 0
exec python3 "$TASK/worker.py" execute {}
"#,
        req.id,
        quote(&encoded(&req.remote()))
    );

    format!("set -eu\numask 077\n[ \"$(id -u)\" -eq 0 ] && [ \"$(uname -s)\" = Linux ] || exit 1\n[ ! -L /var/lib/miao-vps ]\nmkdir -p /var/lib/miao-vps/tasks\n[ ! -L /var/lib/miao-vps/tasks ]\nfor path in /var/lib/miao-vps /var/lib/miao-vps/tasks; do\n [ \"$(stat -c %u \"$path\")\" = 0 ]\n case \"$(stat -c %a \"$path\")\" in 7[0145][0145]) ;; *) exit 1 ;; esac\ndone\nTASK=/var/lib/miao-vps/tasks/{}\nif mkdir \"$TASK\" 2>/dev/null; then\ncat > \"$TASK/worker.py\" <<'MIAO_WORKER'\n{}\nMIAO_WORKER\ncat > \"$TASK/bootstrap.sh\" <<'MIAO_BOOTSTRAP'\n{}\nMIAO_BOOTSTRAP\ncat > \"$TASK/run.sh\" <<'MIAO_RUN'\n{}\nMIAO_RUN\nprintf '%s' '{{\"stage\":\"installing_dependencies\"}}' > \"$TASK/status.json\"\nif command -v systemd-run >/dev/null && [ -d /run/systemd/system ]; then\n systemd-run --quiet --collect --unit=miao-vps-{} /bin/sh \"$TASK/run.sh\"\nelif command -v setsid >/dev/null; then\n nohup setsid sh \"$TASK/run.sh\" </dev/null >>\"$TASK/worker.log\" 2>&1 &\nelse\n nohup sh \"$TASK/run.sh\" </dev/null >>\"$TASK/worker.log\" 2>&1 &\nfi\nfi\nprintf started\n",req.id,WORKER,BOOTSTRAP,runner,req.id)
}

fn poll_script(req: &Connection, reconcile: bool) -> String {
    format!(
        r#"set -eu
[ -d /var/lib/miao-vps/tasks/{} ] || {{ printf '%s' '{{"stage":"error","error":"remote_task_missing"}}'; exit 0; }}
command -v python3 >/dev/null || {{ printf '%s' '{{"stage":"installing_dependencies"}}'; exit 0; }}
python3 - <<'MIAO_POLL'
import os, json, pathlib, subprocess
root=pathlib.Path('/var/lib/miao-vps/tasks/{}')
if not root.exists():
 print(json.dumps({{'stage':'error','error':'remote_task_missing'}})); raise SystemExit
status=root/'status.json'
value=json.loads(status.read_text()) if status.exists() else {{'stage':'starting'}}
terminal=value.get('stage') in ('remote_ready','error','rolled_back','recovery_required')
alive=False
try:
 process=json.loads((root/'process.json').read_text())
 alive=pathlib.Path('/proc/'+str(process['pid'])+'/stat').read_text().split()[21]==process['start']
except (OSError,ValueError,KeyError):
 # Bootstrap writes its PID before installing Python dependencies.
 try:
  if (root/'process.json').exists(): raise OSError()
  pid=int((root/'bootstrap.pid').read_text()); os.kill(pid,0); alive=True
 except (OSError,ValueError): pass
if not terminal and not alive:
 if {}:
  with open(root/'worker.log','ab') as log:
   subprocess.Popen(['python3',str(root/'worker.py'),'reconcile','{}'],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
  value={{'stage':'reconnecting'}}
 else: value={{'stage':'unknown'}}
print(json.dumps(value))
MIAO_POLL
"#,
        req.id,
        req.id,
        if reconcile { "True" } else { "False" },
        encoded(&req.remote())
    )
}

pub async fn start(state: Arc<AppState>, mut req: Connection) -> AppResult<Job> {
    req.validate()?;
    let _lock = JOB_LOCK.lock().await;
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err(AppError::message("Miao is shutting down"));
    }
    if state.upgrading.load(Ordering::SeqCst) {
        return Err(AppError::message("Upgrade in progress"));
    }
    let records = jobs(&state).await?;
    if req.id.is_empty() && !req.idempotency_key.is_empty() {
        if let Some(job) = records.iter().find(|job| job.id == req.idempotency_key) {
            if job.host != req.host
                || job.ssh_port != req.ssh_port
                || job.listen_port != req.listen_port
                || job.node_host != req.node_host
                || job.node_port != req.node_port
            {
                return Err(AppError::message(
                    "Idempotency key belongs to another endpoint",
                ));
            }
            return Ok(job.clone());
        }
    }
    if records.iter().any(|j| j.active) {
        return Err(AppError::message("A VPS task is already running"));
    }
    let resume = !req.id.is_empty();
    if !resume
        && records.iter().any(|job| {
            job.host == req.host && ["unknown", "recovery_required"].contains(&job.stage.as_str())
        })
    {
        return Err(AppError::message(
            "Unresolved remote task; re-authenticate and inspect it before creating another",
        ));
    }
    let mut job = if resume {
        let old = records
            .into_iter()
            .find(|j| j.id == req.id)
            .ok_or_else(|| AppError::message("Task not found"))?;
        if old.host != req.host
            || old.ssh_port != req.ssh_port
            || old.listen_port != req.listen_port
            || old.node_host != req.node_host
            || old.node_port != req.node_port
        {
            return Err(AppError::message(
                "Resume must use the original target and ports",
            ));
        }
        if old.stage == "success" {
            return Ok(old);
        }
        old
    } else {
        req.id = if req.idempotency_key.is_empty() {
            ssh::random_id()?
        } else {
            req.idempotency_key.clone()
        };
        Job {
            id: req.id.clone(),
            remote_id: req.id.clone(),
            host: req.host.clone(),
            ssh_port: req.ssh_port,
            listen_port: req.listen_port,
            node_host: req.node_host.clone(),
            node_port: req.node_port,
            started: now(),
            ..Default::default()
        }
    };
    state.vps_active.store(true, Ordering::SeqCst);
    if state.upgrading.load(Ordering::SeqCst) {
        state.vps_active.store(false, Ordering::SeqCst);
        return Err(AppError::message("Upgrade in progress"));
    }
    job.active = true;
    job.stage = if resume { "reconnecting" } else { "starting" }.into();
    job.events.push(job.stage.clone());
    if let Err(error) = save(&state, &job).await {
        state.vps_active.store(false, Ordering::SeqCst);
        return Err(error);
    }
    let initial = job.clone();
    tokio::spawn(async move {
        use futures::FutureExt;
        let result = std::panic::AssertUnwindSafe(run_job(&state, &req, &mut job, resume))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| {
                Err(AppError::message(
                    "VPS worker interrupted; remote outcome requires inspection",
                ))
            });
        if let Err(error) = result {
            job.stage = "unknown".into();
            job.events.push(error.to_string());
        }
        job.active = false;
        state.vps_active.store(false, Ordering::SeqCst);
        if let Err(error) = save(&state, &job).await {
            tracing::error!(%error,"Unable to persist VPS task result");
        }
    });
    Ok(initial)
}
async fn stage(state: &AppState, job: &mut Job, value: &str) -> AppResult<()> {
    if job.stage != value {
        job.stage = value.into();
        job.events.push(value.into());
        if job.events.len() > 100 {
            job.events.remove(0);
        }
        save(state, job).await?;
    }
    Ok(())
}
async fn run_job(
    state: &Arc<AppState>,
    req: &Connection,
    job: &mut Job,
    resume: bool,
) -> AppResult<()> {
    if !resume {
        let report = match preflight(req.clone()).await {
            Ok(report) => report,
            Err(error) => {
                job.events.push(error.to_string());
                stage(state, job, "error").await?;
                return Ok(());
            }
        };
        if report["action"] == "blocked" {
            job.events
                .push(format!("Preflight blocked: {}", report["error"]));
            stage(state, job, "error").await?;
            return Ok(());
        }
        ssh::script(req, &launcher(req), 30).await?;
    }
    for index in 0..900 {
        let data = ssh::script(req, &poll_script(req, resume && index == 0), 30).await?;
        let value: Value = serde_json::from_slice(&data)?;
        let status = value["stage"].as_str().unwrap_or("unknown");
        if status == "downloading" {
            job.downloaded = value["downloaded"].as_u64().unwrap_or(0);
            job.total = value["total"].as_u64().unwrap_or(0);
            job.source = if value["source"] == "proxy" {
                "proxy"
            } else {
                "direct"
            }
            .into();
            save(state, job).await?;
        }
        stage(state, job, status).await?;
        match status {
            "remote_ready" => {
                let node = value
                    .get("node")
                    .ok_or_else(|| AppError::message("Remote node missing"))?;
                validate_remote_node(req, node)?;
                stage(state, job, "saving_node").await?;
                let tag = commit_node(state, node).await.map_err(|_| {
                    AppError::message(
                        "Remote deployed; local save failed. Reconnect to recover the node",
                    )
                })?;
                job.tag = Some(tag);
                if req.start_on_commit {
                    let _lock = state.config_update.lock().await;
                    if !state.shutting_down.load(Ordering::SeqCst)
                        && crate::services::runtime::load_runtime_state().await.running
                        && !crate::services::singbox::sing_box_is_running(state).await
                    {
                        if let Err(error) =
                            crate::services::singbox::start_sing_internal(state).await
                        {
                            *state.config_warning.lock().await =
                                Some(format!("VPS node saved; core startup failed: {error}"));
                            job.events.push("Node saved; main core startup failed, use the service Start action".into());
                        }
                    }
                }
                stage(state, job, "verifying_connection").await?;
                match verify_node(node).await {
                    Ok(()) => stage(state, job, "success").await?,
                    Err(_) => {
                        stage(state, job, "connectivity_failed").await?;
                        job.events.push("Node saved; check UDP firewall/security group, NAT mapping and outbound access".into());
                    }
                }
                return Ok(());
            }
            "unknown" | "error" | "rolled_back" | "recovery_required" => {
                if let Some(code) = value["error"].as_str() {
                    job.events.push(format!(
                        "Remote error: {}",
                        code.chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .take(80)
                            .collect::<String>()
                    ));
                }
                if status == "recovery_required" {
                    job.events.push(format!("Backup: /var/lib/miao-vps/tasks/{}/backup; resolve remotely before retrying",req.id));
                }
                return Ok(());
            }
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err(AppError::message(
        "Remote task still pending; re-authenticate to inspect",
    ))
}
fn validate_remote_node(req: &Connection, node: &Value) -> AppResult<()> {
    let object = node
        .as_object()
        .ok_or_else(|| AppError::message("Invalid remote node"))?;
    let allowed = [
        "type",
        "tag",
        "server",
        "server_port",
        "password",
        "obfs",
        "tls",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || node["type"] != "hysteria2"
        || node["server"] != req.node_host
        || node["server_port"] != req.node_port
        || node["tls"]["enabled"] != true
        || node["tls"]["insecure"] != false
        || node["tls"]["server_name"] != "miao-hysteria"
    {
        return Err(AppError::message(
            "Remote node does not match the requested secure endpoint",
        ));
    }
    let tls = node["tls"]
        .as_object()
        .ok_or_else(|| AppError::message("Invalid remote TLS"))?;
    if tls
        .keys()
        .any(|key| !["enabled", "insecure", "server_name", "certificate"].contains(&key.as_str()))
        || node["tls"]["certificate"].as_array().is_none_or(|v| {
            v.len() != 1
                || v[0].as_str().is_none_or(|v| {
                    !v.starts_with("-----BEGIN CERTIFICATE-----") || v.len() > 65536
                })
        })
    {
        return Err(AppError::message("Invalid remote trust certificate"));
    }
    for password in [&node["password"], &node["obfs"]["password"]] {
        if password
            .as_str()
            .is_none_or(|v| v.is_empty() || v.len() > 4096)
        {
            return Err(AppError::message("Invalid remote credential"));
        }
    }
    if !["gecko", "salamander"].contains(&node["obfs"]["type"].as_str().unwrap_or_default()) {
        return Err(AppError::message("Unsupported remote obfs"));
    }
    Ok(())
}
fn recover_existing_node(nodes: &mut [String], node: &Value) -> AppResult<Option<String>> {
    for raw in nodes {
        let Ok(mut existing) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        if existing["type"] != node["type"]
            || existing["server"] != node["server"]
            || existing["server_port"] != node["server_port"]
        {
            continue;
        }
        if existing["password"] != node["password"] || existing["obfs"] != node["obfs"] {
            return Err(AppError::message(
                "Existing endpoint has different credentials; preserving existing node",
            ));
        }
        if existing["tls"] != node["tls"] {
            if existing["tls"]["insecure"] == true {
                // Upgrade legacy Miao's skipped verification without changing its
                // tag, bandwidth preferences or credentials. Strict trust changes
                // require explicit removal/import instead of silent replacement.
                existing["tls"] = node["tls"].clone();
                *raw = existing.to_string();
            } else {
                return Err(AppError::message(
                    "Existing endpoint has different TLS trust; preserving existing node",
                ));
            }
        }
        return Ok(Some(existing["tag"].as_str().unwrap_or_default().into()));
    }
    Ok(None)
}
async fn commit_node(state: &Arc<AppState>, node: &Value) -> AppResult<String> {
    use crate::services::{
        config::{apply_persistent_config_change, SubFetchPolicy},
        singbox::sing_box_is_running,
    };
    crate::services::node_parser::parse_node_json(&node.to_string())?;
    let _lock = state.config_update.lock().await;
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err(AppError::message(
            "Miao is shutting down; recover the remote node after restart",
        ));
    }
    let old = state.config.read().await.clone();
    let mut candidate = old.clone();
    if let Some(tag) = recover_existing_node(&mut candidate.nodes, node)? {
        if candidate.nodes != old.nodes {
            let running = sing_box_is_running(state).await;
            apply_persistent_config_change(
                state,
                &old,
                &candidate,
                running,
                SubFetchPolicy::CacheOnly,
            )
            .await?;
        }
        return Ok(tag);
    }
    let mut node = node.clone();
    let tag = node["tag"]
        .as_str()
        .ok_or_else(|| AppError::message("Invalid node tag"))?
        .to_owned();
    if candidate
        .nodes
        .iter()
        .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
        .any(|v| {
            v["tag"]
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case(&tag))
        })
    {
        node["tag"] = json!(format!("{}-{}", tag, &ssh::random_id()?[..8]));
    }
    let tag = node["tag"].as_str().unwrap().into();
    candidate.nodes.push(node.to_string());
    let running = sing_box_is_running(state).await;
    apply_persistent_config_change(state, &old, &candidate, running, SubFetchPolicy::CacheOnly)
        .await?;
    Ok(tag)
}
struct PrivateDirectory(PathBuf);
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
async fn verify_node(node: &Value) -> AppResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    // Isolated core never changes the user's active proxy selection.
    let dir = std::env::temp_dir().join(format!(
        "miao-vps-check-{}-{}",
        std::process::id(),
        ssh::random_id()?
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let _cleanup = PrivateDirectory(dir.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let mut outbound = node.clone();
    outbound["tag"] = json!("vps-check");
    let config = json!({
        "log": {"disabled": true},
        "inbounds": [{"type":"socks", "tag":"in", "listen":"127.0.0.1", "listen_port":port}],
        "outbounds": [outbound], "route": {"final":"vps-check"}
    });
    let path = dir.join("config.json");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(config.to_string().as_bytes())?;
    let binary = crate::services::singbox::get_sing_box_home().join("sing-box");
    let mut child = tokio::process::Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if child.try_wait()?.is_some() {
                return Err(AppError::message("Verification core exited"));
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    match ready {
        Ok(Ok(())) => {}
        _ => {
            let _ = child.kill().await;
            return Err(AppError::message("Verification core unavailable"));
        }
    }
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?)
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let response = client
        .get("https://www.gstatic.com/generate_204")
        .send()
        .await;
    let _ = child.kill().await;
    if response?.status().as_u16() != 204 {
        return Err(AppError::message("Proxy connectivity check failed"));
    }
    Ok(())
}

pub async fn initialize_legacy(state: Arc<AppState>) {
    let config = state.config.read().await.clone();
    let Some(host) = config.vps_ip.filter(|v| !v.trim().is_empty()) else {
        return;
    };
    if config
        .nodes
        .iter()
        .filter_map(|n| serde_json::from_str::<Value>(n).ok())
        .any(|n| n["type"] == "hysteria2" && n["server"] == host && n["server_port"] == 543)
    {
        return;
    }
    let req = Connection {
        host,
        auth: "local_key".into(),
        start_on_commit: true,
        ..Default::default()
    };
    if let Err(error) = start(state.clone(), req).await {
        *state.config_warning.lock().await = Some(format!("VPS initialization: {error}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn request() -> Connection {
        Connection {
            host: "203.0.113.10".into(),
            auth: "password".into(),
            secret: "private-secret".into(),
            ..Default::default()
        }
    }
    #[test]
    fn validates_targets_and_keeps_credentials_out_of_payloads() {
        let mut req = request();
        req.validate().unwrap();
        assert_eq!(req.node_host, req.host);
        assert_eq!(req.ssh_port, 22);
        assert_eq!(req.node_port, 543);
        assert!(!req.remote().to_string().contains("private-secret"));
        for host in [
            "-oProxyCommand=x",
            "root@example.com",
            "x;id",
            "example.com:22",
        ] {
            let mut invalid = request();
            invalid.host = host.into();
            assert!(invalid.validate().is_err());
        }
        let mut invalid = request();
        invalid.download_proxy = "http://example.com/".into();
        assert!(invalid.validate().is_err());
        invalid = request();
        invalid.id = "../../etc/passwd".into();
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn shell_quoting_preserves_metacharacters_without_execution() {
        let text = "a'$(id)\n# 中文";
        let output = std::process::Command::new("sh")
            .args(["-c", &format!("printf %s {}", quote(text))])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), text);
    }
    #[test]
    fn generated_remote_scripts_are_valid_posix_shell() {
        use std::io::Write;
        let mut req = request();
        req.validate().unwrap();
        req.id = "a".repeat(48);
        for script in [
            launcher(&req),
            poll_script(&req, true),
            inspect_script(&req),
        ] {
            let mut child = std::process::Command::new("sh")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            assert!(child.wait().unwrap().success());
        }
    }
    #[tokio::test]
    async fn persistent_jobs_recover_without_credentials() {
        let root =
            std::env::temp_dir().join(format!("miao-vps-job-test-{}", ssh::random_id().unwrap()));
        std::fs::create_dir_all(&root).unwrap();
        let state =
            AppState::with_config_path(Default::default(), root.join("config.yaml")).unwrap();
        let mut job = Job {
            id: "a".repeat(48),
            active: true,
            stage: "activating".into(),
            ..Default::default()
        };
        save(&state, &job).await.unwrap();
        assert_eq!(
            std::fs::metadata(directory(&state))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let record = directory(&state).join(format!("{}.json", job.id));
        assert_eq!(
            std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        recover_jobs(&state).await;
        job = jobs(&state).await.unwrap().remove(0);
        assert!(!job.active);
        assert_eq!(job.stage, "unknown");
        let text = std::fs::read_to_string(record).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("password"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn remote_node_cannot_disable_tls_or_inject_other_outbounds() {
        let mut req = request();
        req.validate().unwrap();
        let mut node = json!({"type":"hysteria2","tag":"node","server":req.node_host,"server_port":543,"password":"secret","obfs":{"type":"gecko","password":"secret"},"tls":{"enabled":true,"insecure":false,"server_name":"miao-hysteria","certificate":["-----BEGIN CERTIFICATE-----\nfixture"]}});
        validate_remote_node(&req, &node).unwrap();
        node["tls"]["insecure"] = json!(true);
        assert!(validate_remote_node(&req, &node).is_err());
        node["tls"]["insecure"] = json!(false);
        node["detour"] = json!("direct");
        assert!(validate_remote_node(&req, &node).is_err());
    }
    #[tokio::test]
    async fn duplicate_submission_returns_original_job_without_ssh() {
        let root = std::env::temp_dir().join(format!(
            "miao-vps-idempotency-{}",
            ssh::random_id().unwrap()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let state = Arc::new(
            AppState::with_config_path(Default::default(), root.join("config.yaml")).unwrap(),
        );
        let mut req = request();
        req.validate().unwrap();
        req.idempotency_key = "b".repeat(48);
        let old = Job {
            id: req.idempotency_key.clone(),
            host: req.host.clone(),
            ssh_port: req.ssh_port,
            listen_port: req.listen_port,
            node_host: req.node_host.clone(),
            node_port: req.node_port,
            stage: "activating".into(),
            active: true,
            ..Default::default()
        };
        save(&state, &old).await.unwrap();
        let accepted = start(state.clone(), req.clone()).await.unwrap();
        assert_eq!(accepted.id, old.id);
        assert_eq!(accepted.stage, "activating");
        req.node_port = 30543;
        assert!(start(state, req).await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn legacy_insecure_node_adopts_certificate_without_duplicates_or_credential_rotation() {
        let old = json!({"type":"hysteria2","tag":"original","server":"example.com","server_port":543,"password":"same","obfs":{"type":"gecko","password":"same-obfs"},"up_mbps":12,"tls":{"enabled":true,"insecure":true}});
        let mut node = old.clone();
        node["tag"] = json!("new-name");
        node["tls"] = json!({"enabled":true,"insecure":false,"certificate":["pinned"]});
        let mut nodes = vec![old.to_string()];
        assert_eq!(
            recover_existing_node(&mut nodes, &node).unwrap(),
            Some("original".into())
        );
        assert_eq!(nodes.len(), 1);
        let updated: Value = serde_json::from_str(&nodes[0]).unwrap();
        assert_eq!(updated["tls"]["certificate"], json!(["pinned"]));
        assert_eq!(updated["up_mbps"], 12);
        node["password"] = json!("different");
        assert!(recover_existing_node(&mut nodes, &node).is_err());
        assert_eq!(nodes[0], updated.to_string());
    }
}
