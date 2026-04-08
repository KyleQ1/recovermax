#!/usr/bin/env bash
set -euo pipefail

IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out/fixtures}"
IMAGE_SIZE="${IMAGE_SIZE:-128M}"
UUID_BASIC="${UUID_BASIC:-11111111-2222-3333-4444-555555555555}"
UUID_DELETED="${UUID_DELETED:-66666666-7777-8888-9999-aaaaaaaaaaaa}"
BASIC_LABEL="${BASIC_LABEL:-rmx-session}"
DELETED_LABEL="${DELETED_LABEL:-rmx-deleted}"
TMP_ROOT=""

usage() {
  cat <<'EOF'
Usage: build-ext4-fixtures.sh [--out-dir DIR]

Build deterministic ext4 fixture images for RecoverMax validation.

Outputs:
  session-tree.ext4.img   Broad browsable tree fixture
  deleted.ext4.img        Same tree plus a deleted file
  session-tree.manifest.json
  deleted.manifest.json
  manifest.json           Machine-readable inventory for benchmarks/tests

Dependencies:
  Required: bash, mkfs.ext4, debugfs, e2fsck, python3, truncate, find, touch

Environment overrides:
  OUT_DIR         Output directory
  IMAGE_SIZE      Image size for each fixture (default: 128M)
  UUID_BASIC      UUID for session-tree fixture
  UUID_DELETED    UUID for deleted-file fixture
  BASIC_LABEL     ext4 label for session-tree fixture (default: rmx-session)
  DELETED_LABEL   ext4 label for deleted fixture (default: rmx-deleted)
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
  need_cmd mkfs.ext4
  need_cmd debugfs
  need_cmd e2fsck
  need_cmd python3
  need_cmd truncate
  need_cmd find
  need_cmd touch
}

normalize_path() {
  python3 - "$1" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
}

image_size_bytes() {
  python3 - "$1" <<'PY'
import re
import sys

value = sys.argv[1]
match = re.fullmatch(r"(?i)(\d+)([kmgt]?)(i?b?)", value.strip())
if not match:
    raise SystemExit(f"invalid image size: {value}")

number = int(match.group(1))
suffix = match.group(2).lower()
multiplier = {
    "": 1,
    "k": 1024,
    "m": 1024 ** 2,
    "g": 1024 ** 3,
    "t": 1024 ** 4,
}[suffix]
print(number * multiplier)
PY
}

make_source_tree() {
  local root="$1"
  local deleted_variant="$2"

  mkdir -p \
    "$root/home/alice/Documents" \
    "$root/home/alice/.ssh" \
    "$root/home/bob" \
    "$root/data/ming" \
    "$root/var/log" \
    "$root/opt/archive"

  printf 'RecoverMax fixture: thesis notes\n' > "$root/home/alice/Documents/thesis.txt"
  printf 'RecoverMax fixture: session browsing\n' > "$root/home/alice/Documents/notes.txt"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKey\n' > "$root/home/alice/.ssh/id_rsa.pub"
  printf 'alice home marker\n' > "$root/home/alice/.profile"
  printf 'bob todo\n' > "$root/home/bob/todo.txt"
  printf 'dataset,score\nming,100\n' > "$root/data/ming/report.csv"
  printf 'RecoverMax fixture log\n' > "$root/var/log/system.log"
  : > "$root/opt/archive/empty.bin"
  truncate -s 1048576 "$root/opt/archive/sparse.bin"
  printf 'sparse-tail\n' | dd of="$root/opt/archive/sparse.bin" bs=1 seek=1048064 conv=notrunc status=none
  ln -s Documents "$root/home/alice/latest"

  if [[ "$deleted_variant" == "1" ]]; then
    printf 'delete me\n' > "$root/home/alice/delete-me.txt"
  fi

  touch -t 200101010000 "$root" "$root/home" "$root/home/alice" "$root/home/alice/Documents" \
    "$root/home/alice/.ssh" "$root/home/bob" "$root/data" "$root/data/ming" \
    "$root/var" "$root/var/log" "$root/opt" "$root/opt/archive" \
    "$root/home/alice/Documents/thesis.txt" "$root/home/alice/Documents/notes.txt" \
    "$root/home/alice/.ssh/id_rsa.pub" "$root/home/alice/.profile" \
    "$root/home/bob/todo.txt" "$root/data/ming/report.csv" "$root/var/log/system.log" \
    "$root/opt/archive/empty.bin" "$root/opt/archive/sparse.bin"

  if [[ "$deleted_variant" == "1" ]]; then
    touch -t 200101010000 "$root/home/alice/delete-me.txt"
  fi
}

build_image() {
  local image_path="$1"
  local label="$2"
  local uuid="$3"
  local source_root="$4"
  local delete_command_file="${5:-}"

  truncate -s "$IMAGE_SIZE_BYTES" "$image_path"
  mkfs.ext4 -F -q \
    -b 4096 \
    -I 256 \
    -L "$label" \
    -U "$uuid" \
    -d "$source_root" \
    -E lazy_itable_init=0,lazy_journal_init=0 \
    "$image_path"

  if [[ -n "$delete_command_file" ]]; then
    debugfs -w -f "$delete_command_file" "$image_path" >/dev/null
  fi

  e2fsck -fn "$image_path" >/dev/null
}

write_manifest() {
  local manifest_path="$1"
  local basic_image="$2"
  local deleted_image="$3"

  MANIFEST_PATH="$manifest_path" \
  BASIC_IMAGE_PATH="$basic_image" \
  DELETED_IMAGE_PATH="$deleted_image" \
  UUID_BASIC="$UUID_BASIC" \
  UUID_DELETED="$UUID_DELETED" \
  BASIC_LABEL="$BASIC_LABEL" \
  DELETED_LABEL="$DELETED_LABEL" \
  IMAGE_SIZE_BYTES="$image_size_bytes_value" \
  python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

manifest = {
    "schema": 1,
    "generated_by": "scripts/build-ext4-fixtures.sh",
    "images": [
        {
            "name": "session-tree",
            "path": os.environ["BASIC_IMAGE_PATH"],
            "label": os.environ["BASIC_LABEL"],
            "uuid": os.environ["UUID_BASIC"],
            "size_bytes": int(os.environ["IMAGE_SIZE_BYTES"]),
            "sha256": sha256(Path(os.environ["BASIC_IMAGE_PATH"])),
            "expected_paths": [
                "/home/alice",
                "/home/alice/Documents",
                "/home/alice/Documents/thesis.txt",
                "/home/alice/Documents/notes.txt",
                "/home/alice/.ssh",
                "/home/alice/.ssh/id_rsa.pub",
                "/home/alice/latest",
                "/home/bob/todo.txt",
                "/data/ming/report.csv",
                "/opt/archive/sparse.bin",
            ],
            "deleted_paths": [],
        },
        {
            "name": "deleted",
            "path": os.environ["DELETED_IMAGE_PATH"],
            "label": os.environ["DELETED_LABEL"],
            "uuid": os.environ["UUID_DELETED"],
            "size_bytes": int(os.environ["IMAGE_SIZE_BYTES"]),
            "sha256": sha256(Path(os.environ["DELETED_IMAGE_PATH"])),
            "expected_paths": [
                "/home/alice/delete-me.txt",
                "/home/alice/Documents/thesis.txt",
                "/data/ming/report.csv",
            ],
            "deleted_paths": [
                "/home/alice/delete-me.txt",
            ],
        },
    ],
}

manifest_path = Path(os.environ["MANIFEST_PATH"])
manifest_path.parent.mkdir(parents=True, exist_ok=True)
with manifest_path.open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

write_fixture_manifest() {
  local manifest_path="$1"
  local image_path="$2"
  local fixture_id="$3"
  local label="$4"
  local uuid="$5"
  local recovery_path="$6"
  local recovery_hash="$7"
  shift 7
  local expected_paths=("$@")

  FIXTURE_MANIFEST_PATH="$manifest_path" \
  FIXTURE_IMAGE_PATH="$image_path" \
  FIXTURE_ID="$fixture_id" \
  FIXTURE_LABEL="$label" \
  FIXTURE_UUID="$uuid" \
  FIXTURE_RECOVERY_PATH="$recovery_path" \
  FIXTURE_RECOVERY_HASH="$recovery_hash" \
  FIXTURE_IMAGE_SIZE_BYTES="$IMAGE_SIZE_BYTES" \
  FIXTURE_EXPECTED_PATHS="$(printf '%s\n' "${expected_paths[@]}")" \
  python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

expected_paths = [line for line in os.environ["FIXTURE_EXPECTED_PATHS"].splitlines() if line]
image_path = Path(os.environ["FIXTURE_IMAGE_PATH"])

manifest = {
    "id": os.environ["FIXTURE_ID"],
    "kind": "synthetic",
    "image": {
        "path": str(image_path),
        "size_bytes": int(os.environ["FIXTURE_IMAGE_SIZE_BYTES"]),
        "sha256": sha256(image_path),
    },
    "filesystem": {
        "type": "ext4",
        "block_size": 4096,
        "inode_size": 256,
        "layout": "single-partition-raw",
        "label": os.environ["FIXTURE_LABEL"],
        "uuid": os.environ["FIXTURE_UUID"],
        "session_artifact": str(image_path.with_suffix(".scn")),
    },
    "expected": {
        "filesystems": 1,
        "root_path": "/",
        "paths": expected_paths,
        "deleted_paths": ["/home/alice/delete-me.txt"] if os.environ["FIXTURE_ID"].endswith("deleted") else [],
        "recovery": [
            {
                "path": os.environ["FIXTURE_RECOVERY_PATH"],
                "sha256": os.environ["FIXTURE_RECOVERY_HASH"],
            }
        ],
    },
    "oracle": {
        "tools": ["fls", "icat"],
        "fls_contains": expected_paths,
    },
    "notes": [
        "Generated by scripts/build-ext4-fixtures.sh",
        "Use with scripts/recovermax-diff-validate.sh and scripts/benchmark-session-workflows.sh",
    ],
}

manifest_path = Path(os.environ["FIXTURE_MANIFEST_PATH"])
manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
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
      --out-dir)
        [[ $# -ge 2 ]] || die "--out-dir requires a value"
        OUT_DIR="$2"
        shift 2
        ;;
      --out-dir=*)
        OUT_DIR="${1#*=}"
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

  local_out_dir="$(normalize_path "$OUT_DIR")"
  local image_size_bytes_value
  image_size_bytes_value="$(image_size_bytes "$IMAGE_SIZE")"
  IMAGE_SIZE_BYTES="$image_size_bytes_value"
  local tmp_root
  TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/recovermax-fixtures.XXXXXX")"
  trap 'if [[ -n "${TMP_ROOT:-}" && -d "${TMP_ROOT:-}" ]]; then rm -rf "$TMP_ROOT"; fi' EXIT

  mkdir -p "$local_out_dir"

  local basic_source="$TMP_ROOT/basic-src"
  local deleted_source="$TMP_ROOT/deleted-src"
  local basic_image="$local_out_dir/session-tree.ext4.img"
  local deleted_image="$local_out_dir/deleted.ext4.img"
  local basic_fixture_manifest="$local_out_dir/session-tree.manifest.json"
  local deleted_fixture_manifest="$local_out_dir/deleted.manifest.json"
  local deleted_commands="$TMP_ROOT/delete.cmds"

  make_source_tree "$basic_source" 0
  make_source_tree "$deleted_source" 1

  printf 'rm /home/alice/delete-me.txt\n' > "$deleted_commands"

  printf 'Building %s\n' "$basic_image"
  build_image "$basic_image" "$BASIC_LABEL" "$UUID_BASIC" "$basic_source"

  printf 'Building %s\n' "$deleted_image"
  build_image "$deleted_image" "$DELETED_LABEL" "$UUID_DELETED" "$deleted_source" "$deleted_commands"

  write_manifest "$local_out_dir/manifest.json" "$basic_image" "$deleted_image"
  write_fixture_manifest \
    "$basic_fixture_manifest" \
    "$basic_image" \
    "ext4-synthetic-session-tree" \
    "$BASIC_LABEL" \
    "$UUID_BASIC" \
    "/data/ming/report.csv" \
    "$(python3 - "$basic_source/data/ming/report.csv" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
h.update(path.read_bytes())
print(h.hexdigest())
PY
)" \
    "/" \
    "/home" \
    "/home/alice" \
    "/home/alice/Documents" \
    "/home/alice/Documents/thesis.txt" \
    "/home/alice/Documents/notes.txt" \
    "/home/alice/.ssh" \
    "/home/alice/.ssh/id_rsa.pub" \
    "/home/alice/latest" \
    "/home/bob/todo.txt" \
    "/data" \
    "/data/ming" \
    "/data/ming/report.csv" \
    "/opt/archive" \
    "/opt/archive/sparse.bin"
  write_fixture_manifest \
    "$deleted_fixture_manifest" \
    "$deleted_image" \
    "ext4-synthetic-deleted" \
    "$DELETED_LABEL" \
    "$UUID_DELETED" \
    "/data/ming/report.csv" \
    "$(python3 - "$deleted_source/data/ming/report.csv" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
h.update(path.read_bytes())
print(h.hexdigest())
PY
)" \
    "/" \
    "/home" \
    "/home/alice" \
    "/home/alice/Documents" \
    "/home/alice/Documents/thesis.txt" \
    "/home/alice/Documents/notes.txt" \
    "/data" \
    "/data/ming" \
    "/data/ming/report.csv"

  printf 'Fixtures written to %s\n' "$local_out_dir"
  printf 'Manifest: %s\n' "$local_out_dir/manifest.json"
  printf 'Fixture manifests: %s %s\n' "$basic_fixture_manifest" "$deleted_fixture_manifest"
}

main "$@"
