#!/usr/bin/env bash
set -euo pipefail

IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="${FIXTURES_DIR:-$SCRIPT_DIR/out/fixtures}"
BENCH_DIR="${BENCH_DIR:-$SCRIPT_DIR/out/benchmarks}"
PROFILE="${PROFILE:-release}"
ITERATIONS="${ITERATIONS:-3}"
IMAGE_NAME="${IMAGE_NAME:-session-tree}"
SEARCH_QUERY="${SEARCH_QUERY:-ming}"
RECOVER_PATH="${RECOVER_PATH:-/home/alice}"
MEMORY_BUDGET="${MEMORY_BUDGET:-256MiB}"
RUST_LOG="${RUST_LOG:-error}"
REBUILD_FIXTURES="${REBUILD_FIXTURES:-0}"

usage() {
  cat <<'EOF'
Usage: benchmark-session-workflows.sh [options]

Run a recovermax session workflow benchmark against generated ext4 fixtures.

Default flow:
  1. Ensure fixtures exist (or rebuild them)
  2. Build recovermax in release mode
  3. Time scan/filesystems/ls/tree/stat/search/recover/cache/unload
  4. Write a JSON report plus per-iteration logs

Options:
  --fixtures-dir DIR    Location for generated fixture images and manifest
  --bench-dir DIR       Output directory for benchmark reports
  --iterations N        Number of benchmark iterations (default: 3)
  --image NAME          Fixture image to benchmark (default: session-tree)
  --query TEXT          Search query to benchmark (default: ming)
  --recover-path PATH   Recovery path to benchmark (default: /home/alice)
  --memory-budget BYTES RecoverMax memory budget (default: 256MiB)
  --profile NAME        Cargo profile to build (default: release)
  --rebuild-fixtures    Force regeneration of fixture images
  -h, --help            Show this help

Dependencies:
  Required: bash, cargo, python3
  Fixture generation also requires mkfs.ext4, debugfs, e2fsck, truncate, find, touch
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"
}

require_dependencies() {
  need_cmd bash
  need_cmd cargo
  need_cmd python3
}

build_fixtures_if_needed() {
  local manifest="$FIXTURES_DIR/manifest.json"
  if [[ "$REBUILD_FIXTURES" == "1" || ! -f "$manifest" ]]; then
    bash "$SCRIPT_DIR/build-ext4-fixtures.sh" --out-dir "$FIXTURES_DIR"
  fi
}

main() {
  case "${1:-}" in
    -h|--help)
      usage
      exit 0
      ;;
  esac

  require_dependencies

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fixtures-dir)
        [[ $# -ge 2 ]] || die "--fixtures-dir requires a value"
        FIXTURES_DIR="$2"
        shift 2
        ;;
      --fixtures-dir=*)
        FIXTURES_DIR="${1#*=}"
        shift
        ;;
      --bench-dir)
        [[ $# -ge 2 ]] || die "--bench-dir requires a value"
        BENCH_DIR="$2"
        shift 2
        ;;
      --bench-dir=*)
        BENCH_DIR="${1#*=}"
        shift
        ;;
      --iterations)
        [[ $# -ge 2 ]] || die "--iterations requires a value"
        ITERATIONS="$2"
        shift 2
        ;;
      --iterations=*)
        ITERATIONS="${1#*=}"
        shift
        ;;
      --image)
        [[ $# -ge 2 ]] || die "--image requires a value"
        IMAGE_NAME="$2"
        shift 2
        ;;
      --image=*)
        IMAGE_NAME="${1#*=}"
        shift
        ;;
      --query)
        [[ $# -ge 2 ]] || die "--query requires a value"
        SEARCH_QUERY="$2"
        shift 2
        ;;
      --query=*)
        SEARCH_QUERY="${1#*=}"
        shift
        ;;
      --recover-path)
        [[ $# -ge 2 ]] || die "--recover-path requires a value"
        RECOVER_PATH="$2"
        shift 2
        ;;
      --recover-path=*)
        RECOVER_PATH="${1#*=}"
        shift
        ;;
      --memory-budget)
        [[ $# -ge 2 ]] || die "--memory-budget requires a value"
        MEMORY_BUDGET="$2"
        shift 2
        ;;
      --memory-budget=*)
        MEMORY_BUDGET="${1#*=}"
        shift
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "--profile requires a value"
        PROFILE="$2"
        shift 2
        ;;
      --profile=*)
        PROFILE="${1#*=}"
        shift
        ;;
      --rebuild-fixtures)
        REBUILD_FIXTURES=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  mkdir -p "$BENCH_DIR"
  build_fixtures_if_needed

  local binary_dir="$REPO_ROOT/target"
  local binary_path
  if [[ "$PROFILE" == "release" ]]; then
    cargo build --quiet --release --manifest-path "$REPO_ROOT/Cargo.toml" -p recovermax
    binary_path="$binary_dir/release/recovermax"
  else
    case "$PROFILE" in
      dev|debug) ;;
      *)
        die "unsupported profile: $PROFILE (use release or debug)"
        ;;
    esac
    cargo build --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p recovermax
    binary_path="$binary_dir/debug/recovermax"
  fi

  [[ -x "$binary_path" ]] || die "recovermax binary not found at $binary_path"

  BENCH_DIR="$BENCH_DIR" \
  FIXTURES_DIR="$FIXTURES_DIR" \
  BINARY_PATH="$binary_path" \
  ITERATIONS="$ITERATIONS" \
  IMAGE_NAME="$IMAGE_NAME" \
  SEARCH_QUERY="$SEARCH_QUERY" \
  RECOVER_PATH="$RECOVER_PATH" \
  MEMORY_BUDGET="$MEMORY_BUDGET" \
  RUST_LOG="$RUST_LOG" \
  python3 - <<'PY'
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

bench_dir = Path(os.environ["BENCH_DIR"])
fixtures_dir = Path(os.environ["FIXTURES_DIR"])
binary = Path(os.environ["BINARY_PATH"])
iterations = int(os.environ["ITERATIONS"])
image_name = os.environ["IMAGE_NAME"]
search_query = os.environ["SEARCH_QUERY"]
recover_path = os.environ["RECOVER_PATH"]
memory_budget = os.environ["MEMORY_BUDGET"]
rust_log = os.environ["RUST_LOG"]

manifest_path = fixtures_dir / "manifest.json"
if not manifest_path.is_file():
    raise SystemExit(f"fixture manifest not found: {manifest_path}")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
images = {image["name"]: image for image in manifest["images"]}
if image_name not in images:
    raise SystemExit(f"fixture image {image_name!r} not found in {manifest_path}")

image = Path(images[image_name]["path"])
if not image.is_file():
    raise SystemExit(f"fixture image not found: {image}")

workflow_steps = [
    ("scan", [str(binary), "scan", str(image), "-o", "{session}"]),
    ("filesystems", [str(binary), "filesystems", str(image), "-s", "{session}", "--memory-budget", memory_budget]),
    ("ls", [str(binary), "ls", str(image), "/", "-s", "{session}", "--memory-budget", memory_budget]),
    ("tree", [str(binary), "tree", str(image), "/", "-s", "{session}", "--depth", "4", "--memory-budget", memory_budget]),
    ("stat", [str(binary), "stat", str(image), recover_path, "-s", "{session}", "--memory-budget", memory_budget]),
    ("search", [str(binary), "search", str(image), search_query, "-s", "{session}", "--memory-budget", memory_budget]),
    ("recover", [str(binary), "recover", str(image), "-d", "{recover_dir}", "-p", recover_path, "-s", "{session}", "--memory-budget", memory_budget]),
    ("cache", [str(binary), "cache", "--scan-file", "{session}", "--memory-budget", memory_budget]),
    ("unload", [str(binary), "unload", "--scan-file", "{session}", "--memory-budget", memory_budget]),
]

results = []
bench_dir.mkdir(parents=True, exist_ok=True)

def run_step(cmd, cwd=None):
    env = os.environ.copy()
    env["RUST_LOG"] = rust_log
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
    return proc.returncode, elapsed_ms, proc.stdout, proc.stderr

for iteration in range(1, iterations + 1):
    iter_dir = bench_dir / f"iteration-{iteration:02d}"
    iter_dir.mkdir(parents=True, exist_ok=True)
    session_path = iter_dir / "session.scn"
    recover_dir = iter_dir / "recovered"
    recover_dir.mkdir(parents=True, exist_ok=True)

    for step_name, template in workflow_steps:
        cmd = [
            part.format(session=str(session_path), recover_dir=str(recover_dir))
            for part in template
        ]
        code, elapsed_ms, stdout, stderr = run_step(cmd, cwd=Path.cwd())
        step_record = {
            "iteration": iteration,
            "step": step_name,
            "command": cmd,
            "exit_code": code,
            "wall_ms": elapsed_ms,
            "session_path": str(session_path),
        }
        if step_name == "recover":
            step_record["output_dir"] = str(recover_dir)
        if stdout.strip():
            step_record["stdout"] = stdout
            (iter_dir / f"{step_name}.stdout.txt").write_text(stdout, encoding="utf-8")
        if stderr.strip():
            step_record["stderr"] = stderr
            (iter_dir / f"{step_name}.stderr.txt").write_text(stderr, encoding="utf-8")

        results.append(step_record)

        if code != 0:
            print(f"{step_name} failed in iteration {iteration}", file=sys.stderr)
            if stdout.strip():
                print(stdout, end="" if stdout.endswith("\n") else "\n", file=sys.stderr)
            if stderr.strip():
                print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
            raise SystemExit(code)

summary = {}
for step_name in [name for name, _ in workflow_steps]:
    durations = [record["wall_ms"] for record in results if record["step"] == step_name]
    summary[step_name] = {
        "iterations": len(durations),
        "min_ms": min(durations),
        "median_ms": statistics.median(durations),
        "mean_ms": round(statistics.mean(durations), 3),
        "max_ms": max(durations),
    }

report = {
    "schema": 1,
    "binary": str(binary),
    "image": str(image),
    "image_name": image_name,
    "iterations": iterations,
    "memory_budget": memory_budget,
    "search_query": search_query,
    "recover_path": recover_path,
    "steps": results,
    "summary": summary,
}

report_path = bench_dir / "session-workflow-report.json"
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(f"Benchmark report written to {report_path}")
for step_name in [name for name, _ in workflow_steps]:
    data = summary[step_name]
    print(
        f"{step_name:12} min={data['min_ms']:>8.3f}ms "
        f"median={data['median_ms']:>8.3f}ms mean={data['mean_ms']:>8.3f}ms "
        f"max={data['max_ms']:>8.3f}ms"
    )
PY
}

main "$@"
