#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/recovermax-diff-validate.sh --image IMAGE --manifest MANIFEST [--image-name NAME] [--oracle-root DIR] [--recovermax BIN]

Required:
  --image IMAGE         Raw disk image to validate
  --manifest MANIFEST   JSON manifest describing expected outputs

Optional:
  --image-name NAME     Select an image from a catalog-style manifest
  --oracle-root DIR     Path to Sleuth Kit tools (defaults to PATH)
  --recovermax BIN      RecoverMax binary to invoke (defaults to cargo run)

The manifest is expected to contain:
  - image path and size metadata
  - a filesystems array with per-filesystem expectations
  - optional oracle expectations for tools such as fls/icat

This script compares RecoverMax session-aware CLI output to the manifest and,
when Sleuth Kit tools are available, performs a lightweight oracle comparison.
EOF
}

image=""
manifest=""
image_name=""
oracle_root=""
recovermax_bin=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      image="${2:-}"
      shift 2
      ;;
    --manifest)
      manifest="${2:-}"
      shift 2
      ;;
    --oracle-root)
      oracle_root="${2:-}"
      shift 2
      ;;
    --image-name)
      image_name="${2:-}"
      shift 2
      ;;
    --recovermax)
      recovermax_bin="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$image" || -z "$manifest" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -f "$image" ]]; then
  echo "image not found: $image" >&2
  exit 2
fi

if [[ ! -f "$manifest" ]]; then
  echo "manifest not found: $manifest" >&2
  exit 2
fi

run_recovermax() {
  if [[ -n "$recovermax_bin" ]]; then
    "$recovermax_bin" "$@"
  else
    cargo run --quiet --bin recovermax -- "$@"
  fi
}

normalized_manifest="$(mktemp "${TMPDIR:-/tmp}/recovermax-diff-manifest.XXXXXX.json")"
scan_tmp="$(mktemp "${TMPDIR:-/tmp}/recovermax-diff.XXXXXX.scn")"
recovery_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/recovermax-diff-recovery.XXXXXX")"

cleanup() {
  rm -f "$scan_tmp" "$normalized_manifest"
  rm -rf "$recovery_tmp_dir"
}
trap cleanup EXIT

python3 - "$manifest" "$image" "$image_name" "$normalized_manifest" <<'PY'
import json
import os
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
image_path = Path(sys.argv[2]).resolve()
image_name = sys.argv[3]
output_path = Path(sys.argv[4])

with manifest_path.open("r", encoding="utf-8") as fh:
    data = json.load(fh)

def looks_placeholder(value):
    if not isinstance(value, str):
        return False
    return value.startswith("REPLACE_WITH_")

normalized = {
    "image_size": None,
    "image_sha256": None,
    "filesystems": [],
    "expected_tree_contains": [],
    "expected_search_contains": [],
    "recovery": [],
    "oracle": {"fls_contains": []},
}

if "images" in data:
    images = data["images"]
    selected = None
    if image_name:
        for candidate in images:
            if candidate.get("name") == image_name:
                selected = candidate
                break
    if selected is None:
        for candidate in images:
            candidate_path = Path(candidate.get("path", "")).resolve()
            if candidate_path == image_path or candidate_path.name == image_path.name:
                selected = candidate
                break
    if selected is None:
        if len(images) == 1:
            selected = images[0]
        else:
            raise SystemExit("catalog manifest contains multiple images; use --image-name")

    normalized["image_size"] = selected.get("size_bytes")
    normalized["image_sha256"] = selected.get("sha256")
    normalized["filesystems"] = [{"label": selected.get("label", "")}]
    expected_paths = selected.get("expected_paths", [])
    normalized["expected_tree_contains"] = expected_paths
    normalized["expected_search_contains"] = expected_paths
    normalized["oracle"]["fls_contains"] = selected.get("expected_paths", [])
else:
    image_info = data.get("image", {})
    filesystem = data.get("filesystem", {})
    expected = data.get("expected", {})
    oracle = data.get("oracle", {})

    normalized["image_size"] = image_info.get("size_bytes")
    normalized["image_sha256"] = image_info.get("sha256")
    label = filesystem.get("label")
    if label:
        normalized["filesystems"] = [{"label": label}]
    elif expected.get("filesystems"):
        normalized["filesystems"] = [{} for _ in range(expected["filesystems"])]

    expected_paths = expected.get("paths", [])
    normalized["expected_tree_contains"] = expected_paths
    normalized["expected_search_contains"] = expected.get("search_contains", expected_paths)
    normalized["recovery"] = expected.get("recovery", [])
    normalized["oracle"]["fls_contains"] = oracle.get("fls_contains", expected_paths)

if looks_placeholder(normalized["image_sha256"]):
    normalized["image_sha256"] = None

normalized["recovery"] = [
    entry for entry in normalized["recovery"]
    if not looks_placeholder(entry.get("sha256"))
]

output_path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

manifest_image_size="$(python3 - "$normalized_manifest" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
print(data.get('image_size', '') or '')
PY
)"

manifest_image_sha="$(python3 - "$normalized_manifest" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
print(data.get('image_sha256', '') or '')
PY
)"

actual_image_size="$(python3 - <<'PY' "$image"
import os, sys
print(os.path.getsize(sys.argv[1]))
PY
)"
if [[ -n "$manifest_image_size" && "$manifest_image_size" != "$actual_image_size" ]]; then
  echo "image size mismatch: manifest=$manifest_image_size actual=$actual_image_size" >&2
  exit 1
fi

if [[ -n "$manifest_image_sha" ]]; then
  actual_image_sha="$(python3 - <<'PY' "$image"
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], 'rb') as fh:
    for chunk in iter(lambda: fh.read(1024 * 1024), b''):
        h.update(chunk)
print(h.hexdigest())
PY
)"
  if [[ "$manifest_image_sha" != "$actual_image_sha" ]]; then
    echo "image sha256 mismatch: manifest=$manifest_image_sha actual=$actual_image_sha" >&2
    exit 1
  fi
fi

run_recovermax scan "$image" -o "$scan_tmp" >/dev/null

filesystems_output="$(run_recovermax filesystems "$image" -s "$scan_tmp")"
tree_output="$(run_recovermax tree "$image" / -s "$scan_tmp")"
search_output="$(run_recovermax search "$image" / -s "$scan_tmp" || true)"

python3 - "$normalized_manifest" "$filesystems_output" "$tree_output" "$search_output" <<'PY'
import json, sys
manifest_path, filesystems_output, tree_output, search_output = sys.argv[1:5]
with open(manifest_path, 'r', encoding='utf-8') as fh:
    manifest = json.load(fh)

def tree_paths(output: str):
    stack = []
    paths = []
    for raw_line in output.splitlines():
        if not raw_line.strip():
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        depth = indent // 2
        entry = raw_line.strip()
        if len(entry) < 3 or entry[1] != " ":
            continue
        name = entry[2:]
        if name == "/":
            stack = ["/"]
            paths.append("/")
            continue
        while len(stack) > depth:
            stack.pop()
        parent = stack[-1] if stack else "/"
        path = f"/{name}" if parent == "/" else f"{parent}/{name}"
        paths.append(path)
        stack = stack[:depth]
        stack.append(path)
    return paths

expected_filesystems = manifest.get('filesystems', [])
if expected_filesystems:
    for fs in expected_filesystems:
        label = fs.get('label')
        if label and label not in filesystems_output:
            raise SystemExit(f"filesystem label missing from RecoverMax output: {label}")

expected_tree = manifest.get('expected_tree_contains', [])
actual_tree_paths = tree_paths(tree_output)
for item in expected_tree:
    if item not in actual_tree_paths:
        raise SystemExit(f"tree output missing expected entry: {item}")

expected_search = manifest.get('expected_search_contains', [])
for item in expected_search:
    if item not in search_output:
        raise SystemExit(f"search output missing expected entry: {item}")
PY

RECOVERMAX_VALIDATE_BIN="$recovermax_bin" \
python3 - "$normalized_manifest" "$image" "$scan_tmp" "$recovery_tmp_dir" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
image_path = sys.argv[2]
scan_path = sys.argv[3]
recovery_root = Path(sys.argv[4])

with manifest_path.open("r", encoding="utf-8") as fh:
    manifest = json.load(fh)

recovermax_bin = os.environ.get("RECOVERMAX_VALIDATE_BIN", "")

def run_recovermax(*args):
    if recovermax_bin:
        cmd = [recovermax_bin, *args]
    else:
        cmd = ["cargo", "run", "--quiet", "--bin", "recovermax", "--", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr or proc.stdout or f"recovermax command failed: {cmd}")

for index, entry in enumerate(manifest.get("recovery", []), start=1):
    target = recovery_root / f"item-{index:02d}"
    target.mkdir(parents=True, exist_ok=True)
    run_recovermax("recover", image_path, "-d", str(target), "-p", entry["path"], "-s", scan_path)
    recovered_path = target / entry["path"].lstrip("/")
    if not recovered_path.is_file():
        raise SystemExit(f"recovery output missing expected file: {recovered_path}")
    h = hashlib.sha256(recovered_path.read_bytes()).hexdigest()
    if h != entry["sha256"]:
        raise SystemExit(
            f"recovered sha256 mismatch for {entry['path']}: expected {entry['sha256']} got {h}"
        )
PY

oracle_needed=false
if [[ -n "$oracle_root" ]]; then
  if [[ -x "$oracle_root/fls" && -x "$oracle_root/icat" ]]; then
    oracle_needed=true
  fi
else
  if command -v fls >/dev/null 2>&1 && command -v icat >/dev/null 2>&1; then
    oracle_needed=true
  fi
fi

if [[ "$oracle_needed" == true ]]; then
  fls_bin="${oracle_root:+$oracle_root/fls}"
  icat_bin="${oracle_root:+$oracle_root/icat}"
  if [[ -z "$fls_bin" ]]; then
    fls_bin="$(command -v fls)"
    icat_bin="$(command -v icat)"
  fi

  oracle_tree="$("$fls_bin" -r "$image" 2>/dev/null || true)"
  python3 - "$normalized_manifest" "$oracle_tree" <<'PY'
import json, sys
manifest_path, oracle_tree = sys.argv[1:3]
with open(manifest_path, 'r', encoding='utf-8') as fh:
    manifest = json.load(fh)

def fls_paths(output: str):
    stack = []
    paths = []
    for raw_line in output.splitlines():
        if "\t" not in raw_line:
            continue
        left, name = raw_line.split("\t", 1)
        name = name.strip()
        if name.startswith("$"):
            continue
        depth = len(left) - len(left.lstrip("+"))
        while len(stack) > depth:
            stack.pop()
        parent = stack[-1] if stack else "/"
        path = f"/{name}" if parent == "/" else f"{parent}/{name}"
        paths.append(path)
        stack.append(path)
    return paths

oracle_expected = manifest.get('oracle', {}).get('fls_contains', [])
actual_paths = fls_paths(oracle_tree)
for item in oracle_expected:
    if item == "/":
        continue
    if item not in actual_paths:
        raise SystemExit(f"oracle fls output missing expected entry: {item}")
PY
fi

echo "differential validation passed"
