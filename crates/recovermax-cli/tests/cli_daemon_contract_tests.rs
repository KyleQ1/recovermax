use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

fn recovermax_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("CARGO_BIN_EXE_recovermax")
            .expect("cargo should expose CARGO_BIN_EXE_recovermax for integration tests"),
    )
}

fn unique_workspace() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "recovermax-cli-daemon-contract-{}-{nanos}",
        std::process::id()
    ))
}

fn run_recovermax(args: &[&str]) -> Output {
    Command::new(recovermax_bin())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run recovermax {args:?}: {error}"))
}

fn run_json(args: &[&str]) -> Value {
    let output = run_recovermax(args);
    assert!(
        output.status.success(),
        "recovermax {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "recovermax {args:?} did not return JSON: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn workspace_arg(workspace: &Path) -> String {
    workspace.display().to_string()
}

fn assert_contract(value: &Value, workspace: &Path) {
    assert_eq!(value["ok"], json!(true));
    assert_eq!(value["version"], json!(1));
    assert!(value.get("state").and_then(Value::as_str).is_some());
    assert_eq!(value["workspace"], json!(workspace));
    assert!(value.get("next_actions").and_then(Value::as_array).is_some());
}

#[test]
fn daemon_start_status_stop_emit_stable_json_contract() {
    let workspace = unique_workspace();
    std::fs::create_dir_all(&workspace).expect("failed to create test workspace");
    let workspace_text = workspace_arg(&workspace);
    let canonical_workspace =
        std::fs::canonicalize(&workspace).expect("failed to canonicalize test workspace");

    let start = run_json(&[
        "daemon",
        "start",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&start, &canonical_workspace);
    assert_eq!(start["state"], json!("online"));
    assert!(start["pid"].as_u64().is_some());
    assert!(start["address"].as_str().unwrap().starts_with("127.0.0.1:"));

    let status = run_json(&[
        "daemon",
        "status",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&status, &canonical_workspace);
    assert_eq!(status["state"], json!("online"));
    assert!(status["tasks"].as_array().unwrap().is_empty());
    assert!(status["selection"].as_array().unwrap().is_empty());

    let stop = run_json(&[
        "daemon",
        "stop",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&stop, &canonical_workspace);
    assert_eq!(stop["state"], json!("stopping"));

    let _ = std::fs::remove_dir_all(&workspace);
}
