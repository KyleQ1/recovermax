use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
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

fn start_daemon(workspace: &Path, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    if let Ok(response) = request(&workspace, "status") {
        print_response(&response, json_output);
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
        if let Ok(response) = request(&workspace, "status") {
            print_response(&response, json_output);
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
    let mut state = RuntimeState {
        pid: process::id(),
        address: address.to_string(),
        token: new_token(),
        started_unix: unix_now(),
        released: false,
        stopping: false,
    };

    write_state(&workspace, &state)?;
    append_log(
        &workspace,
        &format!(
            "daemon listening pid={} address={}",
            state.pid, state.address
        ),
    )?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(&workspace, &mut state, stream) {
                    append_log(&workspace, &format!("client error: {error:#}"))?;
                }
                if state.stopping {
                    break;
                }
            }
            Err(error) => append_log(&workspace, &format!("accept error: {error}"))?,
        }
    }

    append_log(&workspace, "daemon stopped")?;
    write_state(&workspace, &state)?;
    Ok(())
}

fn handle_client(workspace: &Path, state: &mut RuntimeState, stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let request: Value =
        serde_json::from_str(line.trim()).context("invalid daemon request JSON")?;
    let token = request
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing daemon token"))?;
    if token != state.token {
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
        "status" => status_response(workspace, state, true),
        "release" => {
            state.released = true;
            write_state(workspace, state)?;
            append_log(workspace, "released daemon-held session memory")?;
            status_response(workspace, state, true)
        }
        "stop" => {
            state.stopping = true;
            write_state(workspace, state)?;
            append_log(workspace, "stop requested")?;
            status_response(workspace, state, true)
        }
        other => error_response(
            "unknown_command",
            &format!("unknown daemon command: {other}"),
        ),
    };
    write_json(stream, &response)?;
    Ok(())
}

fn request(workspace: &Path, command: &str) -> Result<Value> {
    let state = read_state(workspace)?;
    let mut stream = TcpStream::connect(
        state
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("daemon state is missing address"))?,
    )
    .context("failed to connect to daemon")?;
    let request = json!({
        "version": PROTOCOL_VERSION,
        "command": command,
        "token": state.get("token").and_then(Value::as_str).unwrap_or_default(),
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
        "has_active_session": false,
        "tasks": [],
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
        "released": state.get("released").cloned().unwrap_or(Value::Bool(true)),
        "has_active_session": false,
        "tasks": [],
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
    });
    fs::write(&path, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to write {}", path.display()))
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
}
