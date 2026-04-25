use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use recovermax_core::io::ImageReader;
use recovermax_core::scan::{ScanEvent, ScanOptions, Scanner};
use recovermax_core::session::{open_session_for_image, RecoverySession, RecoverySessionArtifact};
use serde_json::{json, Value};

const STATE_FILE: &str = "daemon.json";
const LOG_FILE: &str = "daemon.log";
const STDERR_FILE: &str = "daemon.stderr.log";
const PROTOCOL_VERSION: u32 = 1;

#[derive(Subcommand)]
pub enum DaemonCommand {
    /// Start a background daemon for a workspace
    Start {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,

        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Show daemon/workspace status
    Status {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,

        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Release daemon-held session memory for a workspace
    Release {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,

        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Stop a workspace daemon after checkpointing state
    Stop {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,

        /// Print machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Show daemon logs for a workspace
    Logs {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,

        /// Number of trailing log lines to print
        #[arg(long, default_value_t = 100)]
        tail: usize,
    },

    /// Internal daemon server entrypoint
    #[command(hide = true)]
    Run {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,
    },
}

pub fn run(command: DaemonCommand) -> Result<()> {
    match command {
        DaemonCommand::Start { workspace, json } => start_daemon(&workspace, json),
        DaemonCommand::Status { workspace, json } => print_status(&workspace, json),
        DaemonCommand::Release { workspace, json } => send_control(&workspace, "release", json),
        DaemonCommand::Stop { workspace, json } => send_control(&workspace, "stop", json),
        DaemonCommand::Logs { workspace, tail } => print_logs(&workspace, tail),
        DaemonCommand::Run { workspace } => run_daemon(&workspace),
    }
}

pub(crate) fn submit_scan(
    workspace: &Path,
    image: &Path,
    output: Option<PathBuf>,
    deep_scan: bool,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    ensure_daemon(&workspace)?;
    let image = absolute_path(image)?;
    let output = output
        .map(|path| absolute_path(&path))
        .transpose()?
        .unwrap_or_else(|| workspace.join("scan.scn"));
    let response = request_with_payload(
        &workspace,
        "scan",
        json!({
            "image": image,
            "output": output,
            "deep_scan": deep_scan,
        }),
    )?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_filesystems(workspace: &Path, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    ensure_daemon(&workspace)?;
    let response = request(&workspace, "filesystems")?;
    print_response(&response, json_output);
    Ok(())
}

fn start_daemon(workspace: &Path, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    if let Ok(response) = request(&workspace, "status") {
        print_response(&response, json_output);
        return Ok(());
    }

    ensure_daemon(&workspace)?;
    let response = request(&workspace, "status")?;
    print_response(&response, json_output);
    Ok(())
}

fn ensure_daemon(workspace: &Path) -> Result<()> {
    if request(workspace, "status").is_ok() {
        return Ok(());
    }
    let state_path = state_path(&workspace);
    if state_path.exists() {
        fs::remove_file(&state_path)
            .with_context(|| format!("failed to remove stale {}", state_path.display()))?;
    }

    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(workspace.join(STDERR_FILE))
        .with_context(|| {
            format!(
                "failed to open daemon stderr log for {}",
                workspace.display()
            )
        })?;
    let mut command = ProcessCommand::new(exe);
    command
        .args(["daemon", "run", "--workspace"])
        .arg(&workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    detach_process(&mut command);
    let child = command
        .spawn()
        .context("failed to spawn recovermax daemon")?;

    append_log(
        &workspace,
        &format!("spawned daemon process pid={}", child.id()),
    )?;

    let deadline = SystemTime::now() + Duration::from_secs(5);
    loop {
        if request(workspace, "status").is_ok() {
            return Ok(());
        }
        if SystemTime::now() >= deadline {
            bail!("daemon did not become ready for {}", workspace.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn print_status(workspace: &Path, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = match request(&workspace, "status") {
        Ok(response) => response,
        Err(error) => offline_status(&workspace, error),
    };
    print_response(&response, json_output);
    Ok(())
}

fn send_control(workspace: &Path, command: &str, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request(&workspace, command)
        .with_context(|| format!("daemon is not reachable for {}", workspace.display()))?;
    print_response(&response, json_output);
    Ok(())
}

fn print_logs(workspace: &Path, tail: usize) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let path = log_path(&workspace);
    let content = fs::read_to_string(&path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(tail);
    for line in &lines[start..] {
        println!("{}", line);
    }
    Ok(())
}

fn run_daemon(workspace: &Path) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to bind daemon control port")?;
    let address = listener
        .local_addr()
        .context("failed to read daemon control address")?;
    let state = Arc::new(Mutex::new(RuntimeState {
        pid: process::id(),
        address: address.to_string(),
        token: new_token(),
        started_unix: unix_now(),
        released: false,
        stopping: false,
        next_task_id: 1,
        tasks: Vec::new(),
        active_image: None,
        active_scan: None,
        active_session: None,
    }));

    write_state(&workspace, &state.lock().expect("daemon state poisoned"))?;
    let (pid, address) = {
        let guard = state.lock().expect("daemon state poisoned");
        (guard.pid, guard.address.clone())
    };
    append_log(
        &workspace,
        &format!("daemon listening pid={} address={}", pid, address),
    )?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(&workspace, Arc::clone(&state), stream) {
                    append_log(&workspace, &format!("client error: {error:#}"))?;
                }
                if state.lock().expect("daemon state poisoned").stopping {
                    break;
                }
            }
            Err(error) => append_log(&workspace, &format!("accept error: {error}"))?,
        }
    }

    append_log(&workspace, "daemon stopped")?;
    write_state(&workspace, &state.lock().expect("daemon state poisoned"))?;
    Ok(())
}

fn handle_client(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    stream: TcpStream,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let request: Value =
        serde_json::from_str(line.trim()).context("invalid daemon request JSON")?;
    let token = request
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing daemon token"))?;
    let expected_token = state.lock().expect("daemon state poisoned").token.clone();
    if token != expected_token {
        write_json(
            stream,
            &error_response("unauthorized", "invalid daemon token"),
        )?;
        return Ok(());
    }

    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing daemon command"))?;
    let response = match command {
        "status" => {
            let guard = state.lock().expect("daemon state poisoned");
            status_response(workspace, &guard, true)
        }
        "release" => {
            let mut guard = state.lock().expect("daemon state poisoned");
            guard.released = true;
            guard.active_session = None;
            write_state(workspace, &guard)?;
            append_log(workspace, "released daemon-held session memory")?;
            status_response(workspace, &guard, true)
        }
        "stop" => {
            let mut guard = state.lock().expect("daemon state poisoned");
            guard.stopping = true;
            write_state(workspace, &guard)?;
            append_log(workspace, "stop requested")?;
            status_response(workspace, &guard, true)
        }
        "scan" => {
            let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
            start_scan_task(workspace, Arc::clone(&state), payload)?
        }
        "filesystems" => filesystems_response(workspace, Arc::clone(&state))?,
        other => error_response(
            "unknown_command",
            &format!("unknown daemon command: {other}"),
        ),
    };
    write_json(stream, &response)?;
    Ok(())
}

fn filesystems_response(workspace: &Path, state: Arc<Mutex<RuntimeState>>) -> Result<Value> {
    {
        let mut guard = state.lock().expect("daemon state poisoned");
        if guard.active_session.is_none() {
            if let (Some(image), Some(scan)) = (guard.active_image.clone(), guard.active_scan.clone())
            {
                let session = open_session_for_image(&image, Some(&scan), None, true)?;
                guard.active_session = Some(session);
                guard.released = false;
                write_state(workspace, &guard)?;
            }
        }
    }

    let guard = state.lock().expect("daemon state poisoned");
    let Some(session) = guard.active_session.as_ref() else {
        return Ok(error_response(
            "no_active_session",
            "workspace has no active scan session; run recovermax scan <image> --workspace <workspace>",
        ));
    };

    let filesystems = session
        .filesystems()
        .iter()
        .enumerate()
        .map(|(index, filesystem)| {
            json!({
                "index": index,
                "filesystem_index": filesystem.filesystem_index,
                "type": filesystem.fs_info.fs_type,
                "label": filesystem.fs_info.label,
                "offset": filesystem.fs_info.offset,
                "size": filesystem.fs_info.total_size,
                "has_tree": filesystem.has_tree(),
                "has_partial_tree": filesystem.has_partial_tree(),
                "warnings": filesystem.warnings.len(),
            })
        })
        .collect::<Vec<_>>();
    let count = filesystems.len();

    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "active_image": guard.active_image.clone(),
        "active_scan": guard.active_scan.clone(),
        "has_active_session": true,
        "filesystems": filesystems,
        "count": count,
        "next_actions": [
            "recovermax ls / --workspace <workspace> --json",
            "recovermax search <query> --workspace <workspace> --json"
        ],
    }))
}

fn start_scan_task(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    let image = payload
        .get("image")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("scan request is missing image"))?;
    let output = payload
        .get("output")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("scan.scn"));
    let deep_scan = payload
        .get("deep_scan")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let task = {
        let mut guard = state.lock().expect("daemon state poisoned");
        let task_id = guard.next_task_id;
        guard.next_task_id += 1;
        let task = TaskState {
            id: task_id,
            kind: "scan".to_string(),
            status: "queued".to_string(),
            source: image.clone(),
            output: output.clone(),
            phase: "queued".to_string(),
            progress_bytes: 0,
            total_bytes: 0,
            filesystems_found: 0,
            started_unix: unix_now(),
            completed_unix: None,
            error: None,
        };
        guard.tasks.push(task.clone());
        write_state(workspace, &guard)?;
        task
    };

    append_log(
        workspace,
        &format!(
            "scan task {} queued image={} output={}",
            task.id,
            image.display(),
            output.display()
        ),
    )?;

    let workspace_for_thread = workspace.to_path_buf();
    let state_for_thread = Arc::clone(&state);
    let task_id = task.id;
    std::thread::spawn(move || {
        if let Err(error) = run_scan_task(
            &workspace_for_thread,
            state_for_thread,
            task_id,
            image,
            output,
            deep_scan,
        ) {
            let _ = append_log(
                &workspace_for_thread,
                &format!("scan task {task_id} failed: {error:#}"),
            );
        }
    });

    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "accepted",
        "workspace": workspace,
        "task_id": task.id,
        "task": task_to_json(&task),
        "next_actions": [
            "recovermax daemon status --workspace <workspace> --json",
            "recovermax daemon logs --workspace <workspace> --tail 50"
        ],
    }))
}

fn run_scan_task(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    task_id: u64,
    image: PathBuf,
    output: PathBuf,
    deep_scan: bool,
) -> Result<()> {
    update_task(workspace, &state, task_id, |task| {
        task.status = "running".to_string();
        task.phase = "opening".to_string();
    })?;
    append_log(workspace, &format!("scan task {task_id} started"))?;

    let result = (|| -> Result<()> {
        let reader = ImageReader::open(&image)?;
        let image_size = reader.len();
        update_task(workspace, &state, task_id, |task| {
            task.total_bytes = image_size;
            task.phase = "detecting".to_string();
        })?;

        let event_workspace = workspace.to_path_buf();
        let event_state = Arc::clone(&state);
        let scan_callback = move |event: ScanEvent| {
            let _ = update_task_for_event(&event_workspace, &event_state, task_id, &event);
        };
        let options = ScanOptions {
            deep_scan,
            on_event: Some(Box::new(scan_callback)),
            ..Default::default()
        };
        let scanner = Scanner::new(&reader);
        let report = scanner.full_scan_with_options(&options)?;
        update_task(workspace, &state, task_id, |task| {
            task.filesystems_found = report.filesystems.len();
            task.phase = "writing-scan".to_string();
        })?;

        let tree_workspace = workspace.to_path_buf();
        let tree_state = Arc::clone(&state);
        let tree_callback = move |event: ScanEvent| {
            let _ = update_task_for_event(&tree_workspace, &tree_state, task_id, &event);
        };
        RecoverySessionArtifact::build_binary_scn(
            &image,
            &reader,
            &report,
            &output,
            Some(&tree_callback),
        )?;

        let session = open_session_for_image(&image, Some(&output), None, true)?;
        {
            let mut guard = state.lock().expect("daemon state poisoned");
            guard.active_image = Some(image.clone());
            guard.active_scan = Some(output.clone());
            guard.active_session = Some(session);
            guard.released = false;
            if let Some(task) = guard.tasks.iter_mut().find(|task| task.id == task_id) {
                task.status = "completed".to_string();
                task.phase = "complete".to_string();
                task.progress_bytes = image_size;
                task.total_bytes = image_size;
                task.completed_unix = Some(unix_now());
                task.error = None;
            }
            write_state(workspace, &guard)?;
        }
        append_log(
            workspace,
            &format!("scan task {task_id} completed output={}", output.display()),
        )?;
        Ok(())
    })();

    if let Err(error) = result {
        update_task(workspace, &state, task_id, |task| {
            task.status = "failed".to_string();
            task.phase = "failed".to_string();
            task.completed_unix = Some(unix_now());
            task.error = Some(format!("{error:#}"));
        })?;
        return Err(error);
    }

    Ok(())
}

fn update_task_for_event(
    workspace: &Path,
    state: &Arc<Mutex<RuntimeState>>,
    task_id: u64,
    event: &ScanEvent,
) -> Result<()> {
    update_task(workspace, state, task_id, |task| match event {
        ScanEvent::PhaseStarted { phase, total_bytes } => {
            task.phase = format!("{phase:?}");
            task.total_bytes = *total_bytes;
        }
        ScanEvent::Progress {
            phase,
            offset,
            bytes_scanned,
        } => {
            task.phase = format!("{phase:?}");
            task.progress_bytes = offset.saturating_add(*bytes_scanned);
        }
        ScanEvent::FilesystemFound { .. } => {
            task.filesystems_found += 1;
        }
        ScanEvent::PhaseComplete {
            phase,
            filesystems_found,
        } => {
            task.phase = format!("{phase:?}-complete");
            task.filesystems_found = *filesystems_found;
        }
        ScanEvent::TreeBuildStarted { .. } => {
            task.phase = "tree-building".to_string();
        }
        ScanEvent::TreeBuildProgress { bytes_offset, .. } => {
            task.phase = "tree-building".to_string();
            task.progress_bytes = *bytes_offset;
        }
        ScanEvent::TreeBuildComplete { .. } => {
            task.phase = "tree-complete".to_string();
        }
        ScanEvent::FileTypeFound { .. } => {}
    })
}

fn update_task(
    workspace: &Path,
    state: &Arc<Mutex<RuntimeState>>,
    task_id: u64,
    update: impl FnOnce(&mut TaskState),
) -> Result<()> {
    let mut guard = state.lock().expect("daemon state poisoned");
    let Some(task) = guard.tasks.iter_mut().find(|task| task.id == task_id) else {
        bail!("task {task_id} not found");
    };
    update(task);
    write_state(workspace, &guard)
}

fn request(workspace: &Path, command: &str) -> Result<Value> {
    request_with_payload(workspace, command, Value::Null)
}

fn request_with_payload(workspace: &Path, command: &str, payload: Value) -> Result<Value> {
    let state = read_state(workspace)?;
    let address: SocketAddr = state
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("daemon state is missing address"))?
        .parse()
        .context("daemon state has invalid address")?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .context("failed to connect to daemon")?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = json!({
        "version": PROTOCOL_VERSION,
        "command": command,
        "token": state.get("token").and_then(Value::as_str).unwrap_or_default(),
        "payload": payload,
    });
    writeln!(stream, "{}", serde_json::to_string(&request)?)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("invalid daemon response JSON")
}

fn print_response(response: &Value, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(response).unwrap_or_else(|_| response.to_string())
        );
        return;
    }

    let ok = response.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !ok {
        println!(
            "Error: {}",
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown daemon error")
        );
        return;
    }

    println!(
        "Daemon: {}",
        response
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    if let Some(workspace) = response.get("workspace").and_then(Value::as_str) {
        println!("Workspace: {}", workspace);
    }
    if let Some(pid) = response.get("pid").and_then(Value::as_u64) {
        println!("PID: {}", pid);
    }
    if let Some(address) = response.get("address").and_then(Value::as_str) {
        println!("Control: {}", address);
    }
    if let Some(released) = response.get("released").and_then(Value::as_bool) {
        println!("Memory released: {}", released);
    }
    if let Some(task_id) = response.get("task_id").and_then(Value::as_u64) {
        println!("Task: {}", task_id);
    }
    if let Some(tasks) = response.get("tasks").and_then(Value::as_array) {
        if !tasks.is_empty() {
            println!("Tasks:");
            for task in tasks {
                let id = task.get("id").and_then(Value::as_u64).unwrap_or_default();
                let status = task
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let phase = task
                    .get("phase")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                println!("  #{id} {status} {phase}");
            }
        }
    }
    if let Some(filesystems) = response.get("filesystems").and_then(Value::as_array) {
        if !filesystems.is_empty() {
            println!("Filesystems:");
            for fs in filesystems {
                let index = fs.get("index").and_then(Value::as_u64).unwrap_or_default();
                let fs_type = fs.get("type").and_then(Value::as_str).unwrap_or("unknown");
                let label = fs.get("label").and_then(Value::as_str).unwrap_or("");
                let size = fs.get("size").and_then(Value::as_u64).unwrap_or_default();
                println!("  [{index}] {fs_type} \"{label}\" ({})", bytesize::ByteSize(size));
            }
        }
    }
}

fn status_response(workspace: &Path, state: &RuntimeState, online: bool) -> Value {
    let state_label = if state.stopping {
        "stopping"
    } else if online {
        "online"
    } else {
        "offline"
    };
    json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": state_label,
        "workspace": workspace,
        "pid": state.pid,
        "address": state.address,
        "started_unix": state.started_unix,
        "released": state.released,
        "active_image": state.active_image,
        "active_scan": state.active_scan,
        "has_active_session": state.active_session.is_some(),
        "tasks": state.tasks.iter().map(task_to_json).collect::<Vec<_>>(),
        "next_actions": [
            "recovermax scan <image> --workspace <workspace>",
            "recovermax daemon release --workspace <workspace>",
            "recovermax daemon stop --workspace <workspace>"
        ],
    })
}

fn offline_status(workspace: &Path, error: anyhow::Error) -> Value {
    let state = read_state(workspace).unwrap_or_else(|_| json!({}));
    json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "offline",
        "workspace": workspace,
        "pid": state.get("pid").cloned().unwrap_or(Value::Null),
        "address": state.get("address").cloned().unwrap_or(Value::Null),
        "active_image": state.get("active_image").cloned().unwrap_or(Value::Null),
        "active_scan": state.get("active_scan").cloned().unwrap_or(Value::Null),
        "released": state.get("released").cloned().unwrap_or(Value::Bool(true)),
        "has_active_session": false,
        "tasks": state.get("tasks").cloned().unwrap_or_else(|| json!([])),
        "message": format!("daemon is offline: {error:#}"),
        "next_actions": [
            "recovermax daemon start --workspace <workspace>",
            "recovermax daemon status --workspace <workspace>"
        ],
    })
}

fn error_response(code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "version": PROTOCOL_VERSION,
        "error": code,
        "message": message,
    })
}

fn write_json(mut stream: TcpStream, value: &Value) -> Result<()> {
    writeln!(stream, "{}", serde_json::to_string(value)?)?;
    stream.flush()?;
    Ok(())
}

fn prepare_workspace(path: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create workspace {}", path.display()))?;
    path.canonicalize()
        .with_context(|| format!("failed to canonicalize workspace {}", path.display()))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("failed to resolve current directory")?
        .join(path))
}

fn state_path(workspace: &Path) -> PathBuf {
    workspace.join(STATE_FILE)
}

fn log_path(workspace: &Path) -> PathBuf {
    workspace.join(LOG_FILE)
}

#[cfg(unix)]
fn detach_process(command: &mut ProcessCommand) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn detach_process(_command: &mut ProcessCommand) {}

fn read_state(workspace: &Path) -> Result<Value> {
    let path = state_path(workspace);
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_state(workspace: &Path, state: &RuntimeState) -> Result<()> {
    let path = state_path(workspace);
    let value = json!({
        "version": PROTOCOL_VERSION,
        "pid": state.pid,
        "address": state.address,
        "token": state.token,
        "started_unix": state.started_unix,
        "released": state.released,
        "active_image": state.active_image,
        "active_scan": state.active_scan,
        "has_active_session": state.active_session.is_some(),
        "next_task_id": state.next_task_id,
        "tasks": state.tasks.iter().map(task_to_json).collect::<Vec<_>>(),
    });
    fs::write(&path, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn task_to_json(task: &TaskState) -> Value {
    let percent = if task.total_bytes > 0 {
        Some((task.progress_bytes as f64 / task.total_bytes as f64 * 100.0).min(100.0))
    } else {
        None
    };
    json!({
        "id": task.id,
        "kind": task.kind,
        "status": task.status,
        "source": task.source,
        "output": task.output,
        "phase": task.phase,
        "progress_bytes": task.progress_bytes,
        "total_bytes": task.total_bytes,
        "percent": percent,
        "filesystems_found": task.filesystems_found,
        "started_unix": task.started_unix,
        "completed_unix": task.completed_unix,
        "error": task.error,
    })
}

fn append_log(workspace: &Path, message: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path(workspace))
        .with_context(|| format!("failed to open daemon log for {}", workspace.display()))?;
    writeln!(file, "{} {}", unix_now(), message)?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", process::id())
}

struct RuntimeState {
    pid: u32,
    address: String,
    token: String,
    started_unix: u64,
    released: bool,
    stopping: bool,
    next_task_id: u64,
    tasks: Vec<TaskState>,
    active_image: Option<PathBuf>,
    active_scan: Option<PathBuf>,
    active_session: Option<RecoverySession>,
}

#[derive(Clone)]
struct TaskState {
    id: u64,
    kind: String,
    status: String,
    source: PathBuf,
    output: PathBuf,
    phase: String,
    progress_bytes: u64,
    total_bytes: u64,
    filesystems_found: usize,
    started_unix: u64,
    completed_unix: Option<u64>,
    error: Option<String>,
}
