use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

struct TestWorkspace {
    path: PathBuf,
}

impl TestWorkspace {
    fn new() -> Self {
        let path = unique_workspace();
        std::fs::create_dir_all(&path).expect("failed to create test workspace");
        Self { path }
    }

    fn arg(&self) -> String {
        workspace_arg(&self.path)
    }

    fn canonical(&self) -> PathBuf {
        std::fs::canonicalize(&self.path).expect("failed to canonicalize test workspace")
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let workspace_text = workspace_arg(&self.path);
        let _ = run_recovermax(&[
            "daemon",
            "stop",
            "--workspace",
            &workspace_text,
            "--json",
        ]);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

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

fn wait_for_task(workspace: &TestWorkspace, task_id: u64) -> Value {
    let workspace_text = workspace.arg();
    for _ in 0..100 {
        let status = run_json(&[
            "daemon",
            "status",
            "--workspace",
            &workspace_text,
            "--json",
        ]);
        let task = status["tasks"]
            .as_array()
            .expect("status tasks should be an array")
            .iter()
            .find(|task| task["id"] == json!(task_id))
            .cloned()
            .unwrap_or_else(|| panic!("task {task_id} was not present in daemon status"));
        match task["status"].as_str() {
            Some("completed") => return status,
            Some("failed") | Some("cancelled") => panic!("task did not complete: {task:#}"),
            _ => thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("task {task_id} did not complete before timeout");
}

#[test]
fn daemon_start_status_stop_emit_stable_json_contract() {
    let workspace = TestWorkspace::new();
    let workspace_text = workspace.arg();
    let canonical_workspace = workspace.canonical();

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
}

#[test]
fn daemon_workspace_commands_scan_browse_search_select_and_recover() {
    let workspace = TestWorkspace::new();
    let workspace_text = workspace.arg();
    let canonical_workspace = workspace.canonical();
    let image_path = workspace.path.join("synthetic-ext4.img");
    std::fs::write(&image_path, build_synthetic_ext4_image())
        .expect("failed to write synthetic ext4 image");
    let image_text = image_path.display().to_string();

    let scan = run_json(&[
        "scan",
        &image_text,
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&scan, &canonical_workspace);
    assert_eq!(scan["state"], json!("accepted"));
    let task_id = scan["task_id"].as_u64().expect("scan should return task id");

    let status = wait_for_task(&workspace, task_id);
    assert_contract(&status, &canonical_workspace);
    assert_eq!(status["has_active_session"], json!(true));
    assert_eq!(status["tasks"][0]["status"], json!("completed"));

    let filesystems = run_json(&[
        "filesystems",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&filesystems, &canonical_workspace);
    assert_eq!(filesystems["count"], json!(1));
    assert_eq!(filesystems["filesystems"][0]["type"], json!("ext4"));
    assert_eq!(filesystems["filesystems"][0]["label"], json!("cli-smoke"));

    let ls = run_json(&["ls", "/", "--workspace", &workspace_text, "--json"]);
    assert_contract(&ls, &canonical_workspace);
    assert_eq!(ls["path"], json!("/"));
    assert!(
        ls["entries"]
            .as_array()
            .expect("ls entries should be an array")
            .iter()
            .any(|entry| entry["path"] == json!("/hello.txt")),
        "root listing should include hello.txt: {ls:#}"
    );

    let tree = run_json(&["tree", "/", "--workspace", &workspace_text, "--json"]);
    assert_contract(&tree, &canonical_workspace);
    assert!(
        tree["entries"]
            .as_array()
            .expect("tree entries should be an array")
            .iter()
            .any(|entry| entry["node"]["path"] == json!("/hello.txt")),
        "tree should include hello.txt: {tree:#}"
    );

    let stat = run_json(&[
        "stat",
        "/hello.txt",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&stat, &canonical_workspace);
    assert_eq!(stat["node"]["path"], json!("/hello.txt"));
    assert_eq!(stat["node"]["size"], json!(18));

    let search = run_json(&[
        "search",
        "hello",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&search, &canonical_workspace);
    assert_eq!(search["count"], json!(1));
    assert_eq!(search["matches"][0]["path"], json!("/hello.txt"));

    let selected = run_json(&[
        "select",
        "#1",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&selected, &canonical_workspace);
    assert_eq!(selected["count"], json!(1));

    let selection = run_json(&[
        "selection",
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&selection, &canonical_workspace);
    assert_eq!(selection["count"], json!(1));
    assert_eq!(selection["selection"][0]["path"], json!("/hello.txt"));

    let dest = workspace.path.join("recovered");
    let dest_text = dest.display().to_string();
    let recovered = run_json(&[
        "recover",
        "selected",
        "--dest",
        &dest_text,
        "--workspace",
        &workspace_text,
        "--json",
    ]);
    assert_contract(&recovered, &canonical_workspace);
    assert_eq!(recovered["state"], json!("online"));
    assert_eq!(recovered["count"], json!(1));
    let recovered_file = dest.join("hello.txt");
    let content = std::fs::read_to_string(&recovered_file)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", recovered_file.display()));
    assert_eq!(content, "RecoverMax says hi");
}

fn build_synthetic_ext4_image() -> Vec<u8> {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("cli-smoke");
    builder.write_block_group_descriptor(0, 3);
    builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
    builder.write_inode_with_extent(12, 0x8000 | 0o644, 18, 11, 1);
    builder.write_dir_entries(
        10,
        &[(2, 2, "."), (2, 2, ".."), (12, 1, "hello.txt")],
    );
    builder.write_data(11, b"RecoverMax says hi");
    builder.build()
}

struct Ext4ImageBuilder {
    data: Vec<u8>,
    block_size: usize,
    inode_size: usize,
    inode_table_block: usize,
    inodes_per_group: usize,
}

impl Ext4ImageBuilder {
    fn new(size_blocks: usize) -> Self {
        Self {
            data: vec![0u8; size_blocks * 4096],
            block_size: 4096,
            inode_size: 256,
            inode_table_block: 3,
            inodes_per_group: 256,
        }
    }

    fn write_superblock(&mut self, label: &str) {
        let sb = 1024usize;
        let blocks = (self.data.len() / self.block_size) as u32;

        self.write_u32(sb, self.inodes_per_group as u32);
        self.write_u32(sb + 0x04, blocks);
        self.write_u32(sb + 0x0C, blocks / 2);
        self.write_u32(sb + 0x10, (self.inodes_per_group / 2) as u32);
        self.write_u32(sb + 0x14, 0);
        self.write_u32(sb + 0x18, 2);
        self.write_u32(sb + 0x20, 8192);
        self.write_u32(sb + 0x28, self.inodes_per_group as u32);
        self.write_u16(sb + 0x38, 0xEF53);
        self.write_u16(sb + 0x58, self.inode_size as u16);
        self.write_u32(sb + 0x60, 0xC0);

        for index in 0..16 {
            self.data[sb + 0x68 + index] = (index + 1) as u8;
        }
        let name = label.as_bytes();
        let len = name.len().min(16);
        self.data[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name[..len]);
        self.write_u32(sb + 0x150, 0);
    }

    fn write_block_group_descriptor(&mut self, group: usize, inode_table_block: u64) {
        let bgdt_off = self.block_size;
        let desc_size = 64usize;
        let off = bgdt_off + group * desc_size;
        self.write_u32(off + 8, inode_table_block as u32);
        self.write_u32(off + 40, (inode_table_block >> 32) as u32);
    }

    fn write_inode_with_extent(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        data_block: u64,
        block_count: u16,
    ) {
        let index = (inode_num - 1) % self.inodes_per_group as u64;
        let off = self.inode_table_block * self.block_size + index as usize * self.inode_size;

        self.write_u16(off, mode);
        self.write_u32(off + 4, size as u32);
        self.write_u32(off + 108, (size >> 32) as u32);
        self.write_u16(off + 26, 1);
        self.write_u32(off + 32, 0x80000);

        let ext_off = off + 40;
        self.write_u16(ext_off, 0xF30A);
        self.write_u16(ext_off + 2, 1);
        self.write_u16(ext_off + 4, 4);
        self.write_u16(ext_off + 6, 0);
        self.write_u32(ext_off + 12, 0);
        self.write_u16(ext_off + 16, block_count);
        self.write_u16(ext_off + 18, (data_block >> 32) as u16);
        self.write_u32(ext_off + 20, data_block as u32);
    }

    fn write_dir_entries(&mut self, block: u64, entries: &[(u32, u8, &str)]) {
        let block_off = block as usize * self.block_size;
        let mut pos = block_off;

        for (index, &(inode, file_type, name)) in entries.iter().enumerate() {
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len();
            let rec_len = if index == entries.len() - 1 {
                self.block_size - (pos - block_off)
            } else {
                (8 + name_len).div_ceil(4) * 4
            };

            self.write_u32(pos, inode);
            self.write_u16(pos + 4, rec_len as u16);
            self.data[pos + 6] = name_len as u8;
            self.data[pos + 7] = file_type;
            self.data[pos + 8..pos + 8 + name_len].copy_from_slice(name_bytes);
            pos += rec_len;
        }
    }

    fn write_data(&mut self, block: u64, content: &[u8]) {
        let off = block as usize * self.block_size;
        self.data[off..off + content.len()].copy_from_slice(content);
    }

    fn write_u16(&mut self, off: usize, value: u16) {
        self.data[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, off: usize, value: u32) {
        self.data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn build(self) -> Vec<u8> {
        self.data
    }
}
