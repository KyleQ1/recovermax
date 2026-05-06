use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cli::{
    list_children_with_fallback, recover_with_fallback, resolve_node_with_fallback,
    resolve_recovery_target, walk_tree_with_fallback,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use recovermax_core::io::ImageReader;
use recovermax_core::scan::{ScanEvent, ScanOptions, Scanner};
use recovermax_core::search::{SearchMatch, SearchOptions};
use recovermax_core::session::{open_session_for_image, RecoverySession, RecoverySessionArtifact};
use serde_json::{json, Value};

const STATE_FILE: &str = "daemon.json";
const LOCK_FILE: &str = "daemon.lock";
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

    /// Cancel a running daemon task
    Cancel {
        /// Workspace directory for durable session state
        #[arg(long)]
        workspace: PathBuf,

        /// Task id to cancel
        #[arg(long)]
        task: u64,

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
        DaemonCommand::Cancel {
            workspace,
            task,
            json,
        } => send_control_payload(&workspace, "cancel", json!({ "task_id": task }), json),
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
    let image = absolute_path(image)?;
    let output = output
        .map(|path| absolute_path(&path))
        .transpose()?
        .unwrap_or_else(|| workspace.join("scan.scn"));
    let response = request_or_start(
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
    let response = request_or_start(&workspace, "filesystems", Value::Null)?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_ls(
    workspace: &Path,
    path: &str,
    fs: Option<usize>,
    long: bool,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(
        &workspace,
        "ls",
        json!({
            "path": path,
            "filesystem_index": fs,
            "long": long,
        }),
    )?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_tree(
    workspace: &Path,
    path: &str,
    fs: Option<usize>,
    depth: usize,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(
        &workspace,
        "tree",
        json!({
            "path": path,
            "filesystem_index": fs,
            "depth": depth,
        }),
    )?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_stat(
    workspace: &Path,
    target: &str,
    fs: Option<usize>,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(
        &workspace,
        "stat",
        json!({
            "target": target,
            "filesystem_index": fs,
        }),
    )?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_search(
    workspace: &Path,
    query: &str,
    fs: Option<usize>,
    ignore_case: bool,
    exact: bool,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(
        &workspace,
        "search",
        json!({
            "query": query,
            "filesystem_index": fs,
            "ignore_case": ignore_case,
            "exact": exact,
        }),
    )?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_select(workspace: &Path, selector: &str, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(
        &workspace,
        "select",
        json!({
            "selector": selector,
        }),
    )?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_selection(workspace: &Path, json_output: bool) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(&workspace, "selection", Value::Null)?;
    print_response(&response, json_output);
    Ok(())
}

pub(crate) fn submit_recover(
    workspace: &Path,
    target: &str,
    dest: &Path,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_or_start(
        &workspace,
        "recover",
        json!({
            "target": target,
            "dest": absolute_path(dest)?,
        }),
    )?;
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
    let lock_path = lock_path(workspace);
    if lock_path.exists() {
        bail!(
            "workspace {} is locked but the daemon did not answer; run 'recovermax daemon status --workspace {}' or stop the stale daemon before retrying",
            workspace.display(),
            workspace.display()
        );
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
    send_control_payload(workspace, command, Value::Null, json_output)
}

fn send_control_payload(
    workspace: &Path,
    command: &str,
    payload: Value,
    json_output: bool,
) -> Result<()> {
    let workspace = prepare_workspace(workspace)?;
    let response = request_with_payload(&workspace, command, payload)
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
    let _lock = create_daemon_lock(&workspace)?;
    let checkpoint = read_state(&workspace).ok();
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to bind daemon control port")?;
    let address = listener
        .local_addr()
        .context("failed to read daemon control address")?;
    let state = Arc::new(Mutex::new(RuntimeState::from_checkpoint(
        checkpoint,
        address.to_string(),
    )));

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
    let _ = fs::remove_file(lock_path(&workspace));
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
    let response = (|| -> Result<Value> {
        Ok(match command {
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
                for flag in guard.cancel_flags.values() {
                    flag.store(true, Ordering::Relaxed);
                }
                write_state(workspace, &guard)?;
                append_log(workspace, "stop requested")?;
                status_response(workspace, &guard, true)
            }
            "cancel" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                cancel_response(workspace, Arc::clone(&state), payload)?
            }
            "scan" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                start_scan_task(workspace, Arc::clone(&state), payload)?
            }
            "filesystems" => filesystems_response(workspace, Arc::clone(&state))?,
            "ls" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                ls_response(workspace, Arc::clone(&state), payload)?
            }
            "tree" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                tree_response(workspace, Arc::clone(&state), payload)?
            }
            "stat" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                stat_response(workspace, Arc::clone(&state), payload)?
            }
            "search" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                search_response(workspace, Arc::clone(&state), payload)?
            }
            "select" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                select_response(workspace, Arc::clone(&state), payload)?
            }
            "selection" => selection_response(workspace, Arc::clone(&state))?,
            "recover" => {
                let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
                recover_response(workspace, Arc::clone(&state), payload)?
            }
            other => error_response(
                "unknown_command",
                &format!("unknown daemon command: {other}"),
            ),
        })
    })()
    .unwrap_or_else(|error| error_response("daemon_error", &format!("{error:#}")));
    let mut response = response;
    if response.get("workspace").is_none() {
        if let Some(object) = response.as_object_mut() {
            object.insert("workspace".to_string(), json!(workspace));
        }
    }
    let response = attach_request_id(response, request.get("request_id"));
    write_json(stream, &response)?;
    Ok(())
}

fn filesystems_response(workspace: &Path, state: Arc<Mutex<RuntimeState>>) -> Result<Value> {
    ensure_active_session(workspace, &state)?;

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

fn ls_response(workspace: &Path, state: Arc<Mutex<RuntimeState>>, payload: Value) -> Result<Value> {
    ensure_active_session(workspace, &state)?;
    let path = payload
        .get("path")
        .and_then(Value::as_str)
        .map(normalize_daemon_path)
        .unwrap_or_else(|| "/".to_string());
    let fs = payload
        .get("filesystem_index")
        .and_then(Value::as_u64)
        .map(|value| value as usize);
    let long = payload
        .get("long")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut guard = state.lock().expect("daemon state poisoned");
    let fs_index = fs.or(guard.active_fs).unwrap_or(0);
    guard.active_fs = Some(fs_index);
    let Some(session) = guard.active_session.as_mut() else {
        return Ok(error_response(
            "no_active_session",
            "workspace has no active scan session",
        ));
    };
    let node = resolve_node_with_fallback(session, fs_index, &path)?;
    if node.file_type != recovermax_core::fs::FileType::Directory {
        return Ok(json!({
            "ok": true,
            "version": PROTOCOL_VERSION,
            "state": "online",
            "workspace": workspace,
            "filesystem_index": fs_index,
            "path": path,
            "node": node_to_json(&node, long),
            "entries": [],
            "count": 0,
        }));
    }

    let children = list_children_with_fallback(session, fs_index, &path)?;
    let entries = children
        .iter()
        .map(|node| node_to_json(node, long))
        .collect::<Vec<_>>();
    let count = entries.len();
    write_state(workspace, &guard)?;
    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "filesystem_index": fs_index,
        "path": path,
        "entries": entries,
        "count": count,
        "next_actions": [
            "recovermax ls <path> --workspace <workspace> --json",
            "recovermax search <query> --workspace <workspace> --json"
        ],
    }))
}

fn tree_response(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    ensure_active_session(workspace, &state)?;
    let path = payload
        .get("path")
        .and_then(Value::as_str)
        .map(normalize_daemon_path)
        .unwrap_or_else(|| "/".to_string());
    let fs = payload
        .get("filesystem_index")
        .and_then(Value::as_u64)
        .map(|value| value as usize);
    let depth = payload
        .get("depth")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(64);

    let mut guard = state.lock().expect("daemon state poisoned");
    let fs_index = fs.or(guard.active_fs).unwrap_or(0);
    guard.active_fs = Some(fs_index);
    let Some(session) = guard.active_session.as_mut() else {
        return Ok(error_response(
            "no_active_session",
            "workspace has no active scan session",
        ));
    };
    let entries = walk_tree_with_fallback(session, fs_index, &path, depth)?
        .into_iter()
        .map(|entry| {
            json!({
                "depth": entry.depth,
                "node": node_to_json(&entry.node, false),
            })
        })
        .collect::<Vec<_>>();
    let count = entries.len();
    write_state(workspace, &guard)?;
    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "filesystem_index": fs_index,
        "path": path,
        "depth": depth,
        "entries": entries,
        "count": count,
        "next_actions": [
            "recovermax stat <path> --workspace <workspace> --json",
            "recovermax ls <path> --workspace <workspace> --json"
        ],
    }))
}

fn stat_response(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    ensure_active_session(workspace, &state)?;
    let target = payload
        .get("target")
        .and_then(Value::as_str)
        .map(normalize_daemon_path)
        .unwrap_or_else(|| "/".to_string());
    let fs = payload
        .get("filesystem_index")
        .and_then(Value::as_u64)
        .map(|value| value as usize);

    let mut guard = state.lock().expect("daemon state poisoned");
    let fs_index = fs.or(guard.active_fs).unwrap_or(0);
    guard.active_fs = Some(fs_index);
    let Some(session) = guard.active_session.as_mut() else {
        return Ok(error_response(
            "no_active_session",
            "workspace has no active scan session",
        ));
    };
    let node = resolve_node_with_fallback(session, fs_index, &target)?;
    write_state(workspace, &guard)?;
    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "filesystem_index": fs_index,
        "target": target,
        "node": node_to_json(&node, true),
        "next_actions": [
            "recovermax recover <path> --dest <dir> --workspace <workspace> --json"
        ],
    }))
}

fn search_response(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    ensure_active_session(workspace, &state)?;
    let query = payload
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("search request is missing query"))?;
    let fs = payload
        .get("filesystem_index")
        .and_then(Value::as_u64)
        .map(|value| value as usize);
    let options = SearchOptions {
        ignore_case: payload
            .get("ignore_case")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        exact: payload
            .get("exact")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        filesystem_index: fs,
        ..Default::default()
    };

    let mut guard = state.lock().expect("daemon state poisoned");
    let Some(session) = guard.active_session.as_mut() else {
        return Ok(error_response(
            "no_active_session",
            "workspace has no active scan session",
        ));
    };
    let matches = session.search(query, &options);
    guard.last_matches = matches.clone();
    write_state(workspace, &guard)?;
    let values = matches
        .iter()
        .enumerate()
        .map(|(index, search_match)| search_match_to_json(index, search_match))
        .collect::<Vec<_>>();
    let count = values.len();
    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "query": query,
        "matches": values,
        "count": count,
        "next_actions": [
            "recovermax select '#1' --workspace <workspace> --json",
            "recovermax selection --workspace <workspace> --json"
        ],
    }))
}

fn select_response(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    let selector = payload
        .get("selector")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("select request is missing selector"))?;

    let mut guard = state.lock().expect("daemon state poisoned");
    let selected = if let Some(index) = parse_match_selector(selector) {
        let Some(search_match) = guard.last_matches.get(index) else {
            return Ok(error_response(
                "selector_out_of_range",
                &format!("search result {} is not available", selector),
            ));
        };
        SelectedTarget {
            filesystem_index: search_match.filesystem_index,
            path: search_match.path.clone(),
        }
    } else {
        SelectedTarget {
            filesystem_index: guard.active_fs.unwrap_or(0),
            path: normalize_daemon_path(selector),
        }
    };

    if !guard.selected_targets.contains(&selected) {
        guard.selected_targets.push(selected);
    }
    write_state(workspace, &guard)?;
    Ok(selection_value(workspace, &guard))
}

fn selection_response(workspace: &Path, state: Arc<Mutex<RuntimeState>>) -> Result<Value> {
    let guard = state.lock().expect("daemon state poisoned");
    Ok(selection_value(workspace, &guard))
}

fn recover_response(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    ensure_active_session(workspace, &state)?;
    let target = payload
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("selected");
    let dest = payload
        .get("dest")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("recover request is missing dest"))?;

    let target_refs = {
        let guard = state.lock().expect("daemon state poisoned");
        match target {
            "selected" => {
                if guard.selected_targets.is_empty() {
                    return Ok(error_response(
                        "empty_selection",
                        "no selected targets; run recovermax select <path|#n> --workspace <workspace>",
                    ));
                }
                guard.selected_targets.clone()
            }
            selector => {
                if let Some(index) = parse_match_selector(selector) {
                    let Some(search_match) = guard.last_matches.get(index) else {
                        return Ok(error_response(
                            "selector_out_of_range",
                            &format!("search result {selector} is not available"),
                        ));
                    };
                    vec![SelectedTarget {
                        filesystem_index: search_match.filesystem_index,
                        path: search_match.path.clone(),
                    }]
                } else {
                    vec![SelectedTarget {
                        filesystem_index: guard.active_fs.unwrap_or(0),
                        path: normalize_daemon_path(selector),
                    }]
                }
            }
        }
    };

    let mut recovered = Vec::new();
    {
        let mut guard = state.lock().expect("daemon state poisoned");
        let Some(session) = guard.active_session.as_mut() else {
            return Ok(error_response(
                "no_active_session",
                "workspace has no active scan session",
            ));
        };
        for target_ref in target_refs {
            let node = resolve_recovery_target(
                session,
                Some(target_ref.filesystem_index),
                &target_ref.path,
            )?;
            recover_with_fallback(session, &dest, Some(&node), Some(&target_ref.path))?;
            recovered.push(json!({
                "filesystem_index": target_ref.filesystem_index,
                "path": target_ref.path,
                "dest": dest,
            }));
        }
    }

    append_log(
        workspace,
        &format!(
            "recovered {} target(s) to {}",
            recovered.len(),
            dest.display()
        ),
    )?;
    let count = recovered.len();
    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "dest": dest,
        "recovered": recovered,
        "count": count,
        "next_actions": [
            "recovermax daemon status --workspace <workspace> --json",
            "recovermax daemon logs --workspace <workspace> --tail 50"
        ],
    }))
}

fn cancel_response(
    workspace: &Path,
    state: Arc<Mutex<RuntimeState>>,
    payload: Value,
) -> Result<Value> {
    let task_id = payload
        .get("task_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("cancel request is missing task_id"))?;
    let mut guard = state.lock().expect("daemon state poisoned");
    let Some(task) = guard.tasks.iter_mut().find(|task| task.id == task_id) else {
        return Ok(error_response(
            "task_not_found",
            &format!("task {task_id} not found"),
        ));
    };
    task.cancel_requested = true;
    if task.status == "queued" || task.status == "running" {
        task.status = "cancelling".to_string();
    }
    if let Some(flag) = guard.cancel_flags.get(&task_id) {
        flag.store(true, Ordering::Relaxed);
    }
    write_state(workspace, &guard)?;
    append_log(workspace, &format!("cancel requested for task {task_id}"))?;
    Ok(json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "task_id": task_id,
        "task": guard.tasks.iter().find(|task| task.id == task_id).map(task_to_json),
    }))
}

fn ensure_active_session(workspace: &Path, state: &Arc<Mutex<RuntimeState>>) -> Result<()> {
    let mut guard = state.lock().expect("daemon state poisoned");
    if guard.active_session.is_none() {
        if let (Some(image), Some(scan)) = (guard.active_image.clone(), guard.active_scan.clone()) {
            let session = open_session_for_image(&image, Some(&scan), None, true)?;
            guard.active_session = Some(session);
            guard.released = false;
            write_state(workspace, &guard)?;
        }
    }
    Ok(())
}

fn search_match_to_json(index: usize, search_match: &SearchMatch) -> Value {
    json!({
        "index": index + 1,
        "selector": format!("#{}", index + 1),
        "filesystem_index": search_match.filesystem_index,
        "filesystem_label": search_match.filesystem_label,
        "filesystem_offset": search_match.filesystem_offset,
        "inode": search_match.inode,
        "path": search_match.path,
        "file_type": format!("{:?}", search_match.file_type),
        "deleted": search_match.deleted,
        "source": format!("{:?}", search_match.source),
        "parent_inode": search_match.parent_inode,
    })
}

fn node_to_json(node: &recovermax_core::session::SessionNode, long: bool) -> Value {
    let mut value = json!({
        "filesystem_index": node.filesystem_index,
        "path": node.path,
        "basename": node.basename,
        "file_type": format!("{:?}", node.file_type),
        "size": node.size,
        "deleted": node.deleted,
        "source": format!("{:?}", node.source),
    });
    if long {
        value["id"] = json!(node.id);
        value["parent_id"] = json!(node.parent_id);
        value["inode"] = json!(node.inode);
        value["parent_inode"] = json!(node.parent_inode);
        value["timestamps"] = json!(node.timestamps);
    }
    value
}

fn selection_value(workspace: &Path, state: &RuntimeState) -> Value {
    let selection = state
        .selected_targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            json!({
                "index": index + 1,
                "filesystem_index": target.filesystem_index,
                "path": target.path,
            })
        })
        .collect::<Vec<_>>();
    let count = selection.len();
    json!({
        "ok": true,
        "version": PROTOCOL_VERSION,
        "state": "online",
        "workspace": workspace,
        "selection": selection,
        "count": count,
        "next_actions": [
            "recovermax recover selected --dest <dir> --workspace <workspace> --json"
        ],
    })
}

fn parse_match_selector(selector: &str) -> Option<usize> {
    let number = selector.trim().strip_prefix('#')?;
    let parsed: usize = number.parse().ok()?;
    parsed.checked_sub(1)
}

fn normalize_daemon_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let mut parts = Vec::new();
    for part in trimmed.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
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
            cancel_requested: false,
            error: None,
        };
        guard.tasks.push(task.clone());
        guard
            .cancel_flags
            .insert(task_id, Arc::new(AtomicBool::new(false)));
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
    let cancel_flag = {
        let guard = state.lock().expect("daemon state poisoned");
        guard
            .cancel_flags
            .get(&task_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
    };
    std::thread::spawn(move || {
        if let Err(error) = run_scan_task(
            &workspace_for_thread,
            state_for_thread,
            task_id,
            image,
            output,
            deep_scan,
            cancel_flag,
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
    cancel_flag: Arc<AtomicBool>,
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
            cancel_flag: Some(Arc::clone(&cancel_flag)),
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
        let cancelled = cancel_flag.load(Ordering::Relaxed)
            || format!("{error:#}").to_ascii_lowercase().contains("cancel");
        update_task(workspace, &state, task_id, |task| {
            task.status = if cancelled { "cancelled" } else { "failed" }.to_string();
            task.phase = if cancelled { "cancelled" } else { "failed" }.to_string();
            task.completed_unix = Some(unix_now());
            task.error = Some(format!("{error:#}"));
        })?;
        state
            .lock()
            .expect("daemon state poisoned")
            .cancel_flags
            .remove(&task_id);
        return Err(error);
    }

    state
        .lock()
        .expect("daemon state poisoned")
        .cancel_flags
        .remove(&task_id);

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

fn request_or_start(workspace: &Path, command: &str, payload: Value) -> Result<Value> {
    match request_with_payload(workspace, command, payload.clone()) {
        Ok(response) => Ok(response),
        Err(first_error) => {
            if lock_path(workspace).exists() {
                bail!(
                    "workspace {} is locked but the daemon did not answer: {first_error:#}",
                    workspace.display()
                );
            }
            ensure_daemon(workspace)?;
            request_with_payload(workspace, command, payload)
        }
    }
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
        "request_id": new_request_id(),
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
                println!(
                    "  [{index}] {fs_type} \"{label}\" ({})",
                    bytesize::ByteSize(size)
                );
            }
        }
    }
    if let Some(matches) = response.get("matches").and_then(Value::as_array) {
        if !matches.is_empty() {
            println!("Matches:");
            for item in matches {
                let selector = item.get("selector").and_then(Value::as_str).unwrap_or("-");
                let fs = item
                    .get("filesystem_index")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let path = item.get("path").and_then(Value::as_str).unwrap_or("");
                println!("  {selector} fs={fs} {path}");
            }
        }
    }
    if let Some(entries) = response.get("entries").and_then(Value::as_array) {
        if !entries.is_empty() {
            println!("Entries:");
            for entry in entries {
                let kind = entry
                    .get("file_type")
                    .and_then(Value::as_str)
                    .unwrap_or("Other");
                let size = entry
                    .get("size")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
                println!("  {kind} {} {path}", bytesize::ByteSize(size));
            }
        }
    }
    if let Some(selection) = response.get("selection").and_then(Value::as_array) {
        if !selection.is_empty() {
            println!("Selection:");
            for item in selection {
                let index = item
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let fs = item
                    .get("filesystem_index")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let path = item.get("path").and_then(Value::as_str).unwrap_or("");
                println!("  [{index}] fs={fs} {path}");
            }
        }
    }
    if let Some(recovered) = response.get("recovered").and_then(Value::as_array) {
        if !recovered.is_empty() {
            println!("Recovered:");
            for item in recovered {
                let fs = item
                    .get("filesystem_index")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let path = item.get("path").and_then(Value::as_str).unwrap_or("");
                let dest = item.get("dest").and_then(Value::as_str).unwrap_or("");
                println!("  fs={fs} {path} -> {dest}");
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
        "active_fs": state.active_fs,
        "has_active_session": state.active_session.is_some(),
        "tasks": state.tasks.iter().map(task_to_json).collect::<Vec<_>>(),
        "last_match_count": state.last_matches.len(),
        "selection": state.selected_targets.iter().enumerate().map(|(index, target)| {
            json!({
                "index": index + 1,
                "filesystem_index": target.filesystem_index,
                "path": target.path,
            })
        }).collect::<Vec<_>>(),
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
        "active_fs": state.get("active_fs").cloned().unwrap_or(Value::Null),
        "released": state.get("released").cloned().unwrap_or(Value::Bool(true)),
        "has_active_session": false,
        "tasks": state.get("tasks").cloned().unwrap_or_else(|| json!([])),
        "last_match_count": state.get("last_match_count").cloned().unwrap_or(Value::Null),
        "selection": state.get("selection").cloned().unwrap_or_else(|| json!([])),
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
        "state": "error",
        "error": code,
        "message": message,
        "next_actions": [
            "recovermax daemon status --workspace <workspace> --json",
            "recovermax daemon logs --workspace <workspace> --tail 50"
        ],
    })
}

fn attach_request_id(mut response: Value, request_id: Option<&Value>) -> Value {
    if let Some(request_id) = request_id.and_then(Value::as_str) {
        if let Some(object) = response.as_object_mut() {
            object.insert(
                "request_id".to_string(),
                Value::String(request_id.to_string()),
            );
        }
    }
    response
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

fn lock_path(workspace: &Path) -> PathBuf {
    workspace.join(LOCK_FILE)
}

fn create_daemon_lock(workspace: &Path) -> Result<File> {
    let lock_path = lock_path(workspace);
    let mut lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "workspace {} is already locked by another daemon",
                workspace.display()
            )
        })?;
    writeln!(lock, "pid={}", process::id())?;
    Ok(lock)
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
        "active_fs": state.active_fs,
        "has_active_session": state.active_session.is_some(),
        "next_task_id": state.next_task_id,
        "tasks": state.tasks.iter().map(task_to_json).collect::<Vec<_>>(),
        "last_match_count": state.last_matches.len(),
        "selection": state.selected_targets.iter().enumerate().map(|(index, target)| {
            json!({
                "index": index + 1,
                "filesystem_index": target.filesystem_index,
                "path": target.path,
            })
        }).collect::<Vec<_>>(),
    });
    fs::write(&path, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn task_to_json(task: &TaskState) -> Value {
    let now = task.completed_unix.unwrap_or_else(unix_now);
    let elapsed_seconds = now.saturating_sub(task.started_unix);
    let throughput_bytes_per_second = if elapsed_seconds > 0 {
        Some(task.progress_bytes / elapsed_seconds)
    } else {
        None
    };
    let eta_seconds = match (
        throughput_bytes_per_second,
        task.total_bytes > task.progress_bytes,
    ) {
        (Some(rate), true) if rate > 0 => Some((task.total_bytes - task.progress_bytes) / rate),
        _ => None,
    };
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
        "throughput_bytes_per_second": throughput_bytes_per_second,
        "eta_seconds": eta_seconds,
        "filesystems_found": task.filesystems_found,
        "started_unix": task.started_unix,
        "completed_unix": task.completed_unix,
        "cancel_requested": task.cancel_requested,
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

fn new_request_id() -> String {
    new_token()
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
    active_fs: Option<usize>,
    last_matches: Vec<SearchMatch>,
    selected_targets: Vec<SelectedTarget>,
    cancel_flags: HashMap<u64, Arc<AtomicBool>>,
    active_session: Option<RecoverySession>,
}

impl RuntimeState {
    fn from_checkpoint(checkpoint: Option<Value>, address: String) -> Self {
        let tasks = checkpoint
            .as_ref()
            .and_then(|value| value.get("tasks"))
            .and_then(Value::as_array)
            .map(|tasks| tasks.iter().filter_map(TaskState::from_json).collect::<Vec<_>>())
            .unwrap_or_default();
        let next_task_id = checkpoint
            .as_ref()
            .and_then(|value| value.get("next_task_id"))
            .and_then(Value::as_u64)
            .unwrap_or_else(|| tasks.iter().map(|task| task.id).max().unwrap_or(0) + 1);
        let active_image = checkpoint
            .as_ref()
            .and_then(|value| value.get("active_image"))
            .and_then(pathbuf_from_json);
        let active_scan = checkpoint
            .as_ref()
            .and_then(|value| value.get("active_scan"))
            .and_then(pathbuf_from_json);
        let active_fs = checkpoint
            .as_ref()
            .and_then(|value| value.get("active_fs"))
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .or(Some(0));
        let selected_targets = checkpoint
            .as_ref()
            .and_then(|value| value.get("selection"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(SelectedTarget::from_json)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Self {
            pid: process::id(),
            address,
            token: new_token(),
            started_unix: unix_now(),
            released: checkpoint
                .as_ref()
                .and_then(|value| value.get("released"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            stopping: false,
            next_task_id,
            tasks,
            active_image,
            active_scan,
            active_fs,
            last_matches: Vec::new(),
            selected_targets,
            cancel_flags: HashMap::new(),
            active_session: None,
        }
    }
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
    cancel_requested: bool,
    error: Option<String>,
}

impl TaskState {
    fn from_json(value: &Value) -> Option<Self> {
        let status = value.get("status")?.as_str()?.to_string();
        let phase = value
            .get("phase")
            .and_then(Value::as_str)
            .unwrap_or(status.as_str())
            .to_string();
        let resurrected_status = match status.as_str() {
            "queued" | "running" => "interrupted".to_string(),
            _ => status,
        };
        let resurrected_phase = match phase.as_str() {
            "queued" | "running" => "interrupted".to_string(),
            _ => phase,
        };
        Some(Self {
            id: value.get("id")?.as_u64()?,
            kind: value
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("task")
                .to_string(),
            status: resurrected_status,
            source: value
                .get("source")
                .and_then(pathbuf_from_json)
                .unwrap_or_default(),
            output: value
                .get("output")
                .and_then(pathbuf_from_json)
                .unwrap_or_default(),
            phase: resurrected_phase,
            progress_bytes: value
                .get("progress_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            total_bytes: value
                .get("total_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            filesystems_found: value
                .get("filesystems_found")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(0),
            started_unix: value
                .get("started_unix")
                .and_then(Value::as_u64)
                .unwrap_or_else(unix_now),
            completed_unix: value.get("completed_unix").and_then(Value::as_u64),
            cancel_requested: false,
            error: value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SelectedTarget {
    filesystem_index: usize,
    path: String,
}

impl SelectedTarget {
    fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            filesystem_index: value.get("filesystem_index")?.as_u64()? as usize,
            path: value.get("path")?.as_str()?.to_string(),
        })
    }
}

fn pathbuf_from_json(value: &Value) -> Option<PathBuf> {
    value.as_str().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_standard_contract(value: &Value) {
        assert!(value.get("ok").and_then(Value::as_bool).is_some());
        assert_eq!(value["version"], json!(PROTOCOL_VERSION));
        assert!(value.get("state").and_then(Value::as_str).is_some());
        assert!(value
            .get("next_actions")
            .and_then(Value::as_array)
            .is_some());
    }

    fn test_runtime_state() -> RuntimeState {
        RuntimeState {
            pid: 1234,
            address: "127.0.0.1:9999".to_string(),
            token: "test-token".to_string(),
            started_unix: 1_700_000_000,
            released: false,
            stopping: false,
            next_task_id: 2,
            tasks: vec![TaskState {
                id: 1,
                kind: "scan".to_string(),
                status: "completed".to_string(),
                source: PathBuf::from("image.dd"),
                output: PathBuf::from("scan.scn"),
                phase: "complete".to_string(),
                progress_bytes: 100,
                total_bytes: 100,
                filesystems_found: 1,
                started_unix: 1_700_000_001,
                completed_unix: Some(1_700_000_002),
                cancel_requested: false,
                error: None,
            }],
            active_image: Some(PathBuf::from("image.dd")),
            active_scan: Some(PathBuf::from("scan.scn")),
            active_fs: Some(0),
            last_matches: Vec::new(),
            selected_targets: vec![SelectedTarget {
                filesystem_index: 0,
                path: "/hello.txt".to_string(),
            }],
            cancel_flags: HashMap::new(),
            active_session: None,
        }
    }

    #[test]
    fn normalize_daemon_path_cleans_relative_segments() {
        assert_eq!(normalize_daemon_path(""), "/");
        assert_eq!(normalize_daemon_path("/"), "/");
        assert_eq!(normalize_daemon_path("foo/bar"), "/foo/bar");
        assert_eq!(normalize_daemon_path("/foo/../bar/./baz"), "/bar/baz");
    }

    #[test]
    fn parse_match_selector_is_one_based() {
        assert_eq!(parse_match_selector("#1"), Some(0));
        assert_eq!(parse_match_selector("#9"), Some(8));
        assert_eq!(parse_match_selector("#0"), None);
        assert_eq!(parse_match_selector("1"), None);
        assert_eq!(parse_match_selector("#bad"), None);
    }

    #[test]
    fn runtime_state_rehydrates_workspace_checkpoint() {
        let checkpoint = json!({
            "released": false,
            "next_task_id": 9,
            "active_image": "/case/image.dd",
            "active_scan": "/case/scan.scn",
            "active_fs": 2,
            "selection": [
                {
                    "index": 1,
                    "filesystem_index": 2,
                    "path": "/hello.txt"
                }
            ],
            "tasks": [
                {
                    "id": 7,
                    "kind": "scan",
                    "status": "running",
                    "source": "/case/image.dd",
                    "output": "/case/scan.scn",
                    "phase": "detecting",
                    "progress_bytes": 42,
                    "total_bytes": 100,
                    "filesystems_found": 1,
                    "started_unix": 1700000000,
                    "completed_unix": null,
                    "cancel_requested": false,
                    "error": null
                }
            ]
        });

        let state = RuntimeState::from_checkpoint(Some(checkpoint), "127.0.0.1:9999".to_string());

        assert_eq!(state.address, "127.0.0.1:9999");
        assert_eq!(state.active_image, Some(PathBuf::from("/case/image.dd")));
        assert_eq!(state.active_scan, Some(PathBuf::from("/case/scan.scn")));
        assert_eq!(state.active_fs, Some(2));
        assert_eq!(state.next_task_id, 9);
        assert_eq!(state.tasks.len(), 1);
        assert_eq!(state.tasks[0].status, "interrupted");
        assert_eq!(state.tasks[0].phase, "detecting");
        assert_eq!(state.selected_targets.len(), 1);
        assert_eq!(state.selected_targets[0].path, "/hello.txt");
        assert!(state.active_session.is_none());
    }

    #[test]
    fn attach_request_id_preserves_response_shape() {
        let response = attach_request_id(json!({ "ok": true }), Some(&json!("req-1")));
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["request_id"], json!("req-1"));
    }

    #[test]
    fn error_response_has_llm_contract() {
        let value = error_response("bad_selector", "selector is invalid");

        assert_standard_contract(&value);
        assert_eq!(value["ok"], json!(false));
        assert_eq!(value["state"], json!("error"));
        assert_eq!(value["error"], json!("bad_selector"));
        assert_eq!(value["message"], json!("selector is invalid"));
        assert!(!value["next_actions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn status_response_has_llm_contract() {
        let workspace = Path::new("/tmp/recovermax-contract");
        let state = test_runtime_state();
        let value = status_response(workspace, &state, true);

        assert_standard_contract(&value);
        assert_eq!(value["ok"], json!(true));
        assert_eq!(value["state"], json!("online"));
        assert_eq!(value["workspace"], json!(workspace));
        assert_eq!(value["pid"], json!(1234));
        assert_eq!(value["active_fs"], json!(0));
        assert_eq!(value["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(value["selection"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn offline_status_has_llm_contract_without_state_file() {
        let workspace =
            std::env::temp_dir().join(format!("recovermax-offline-contract-{}", new_token()));
        fs::create_dir_all(&workspace).unwrap();

        let value = offline_status(&workspace, anyhow!("connection refused"));

        assert_standard_contract(&value);
        assert_eq!(value["ok"], json!(true));
        assert_eq!(value["state"], json!("offline"));
        assert_eq!(value["workspace"], json!(workspace));
        assert!(value["message"]
            .as_str()
            .unwrap()
            .contains("connection refused"));

        fs::remove_dir_all(&workspace).unwrap();
    }

    #[test]
    fn selection_value_has_llm_contract_and_json_next_action() {
        let workspace = Path::new("/tmp/recovermax-contract");
        let state = test_runtime_state();
        let value = selection_value(workspace, &state);

        assert_standard_contract(&value);
        assert_eq!(value["ok"], json!(true));
        assert_eq!(value["count"], json!(1));
        assert_eq!(value["selection"][0]["path"], json!("/hello.txt"));
        assert!(value["next_actions"][0]
            .as_str()
            .unwrap()
            .contains("--json"));
    }

    #[test]
    fn task_json_includes_progress_metrics() {
        let task = TaskState {
            id: 7,
            kind: "scan".to_string(),
            status: "running".to_string(),
            source: PathBuf::from("image.dd"),
            output: PathBuf::from("scan.scn"),
            phase: "Standard".to_string(),
            progress_bytes: 50,
            total_bytes: 100,
            filesystems_found: 1,
            started_unix: unix_now().saturating_sub(10),
            completed_unix: None,
            cancel_requested: false,
            error: None,
        };
        let value = task_to_json(&task);
        assert_eq!(value["id"], json!(7));
        assert_eq!(value["percent"], json!(50.0));
        assert!(value["throughput_bytes_per_second"].as_u64().is_some());
    }

    #[test]
    fn daemon_lock_is_exclusive() {
        let workspace = std::env::temp_dir().join(format!("recovermax-lock-test-{}", new_token()));
        fs::create_dir_all(&workspace).unwrap();
        let first = create_daemon_lock(&workspace).unwrap();
        let second = create_daemon_lock(&workspace);
        assert!(second.is_err());
        drop(first);
        let _ = fs::remove_file(lock_path(&workspace));
        fs::remove_dir_all(&workspace).unwrap();
    }
}
