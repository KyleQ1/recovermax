#!/usr/bin/env bash
set -euo pipefail

IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_FIXTURES="${RUN_FIXTURES:-0}"
FIXTURES_DIR="${FIXTURES_DIR:-$SCRIPT_DIR/out/fixtures}"
RECOVERMAX_BIN="${RECOVERMAX_BIN:-$REPO_ROOT/target/debug/recovermax}"

usage() {
  cat <<'EOF'
Usage: scripts/run-quality-suite.sh [--with-generated-fixtures]

Runs the RecoverMax local quality gate:
  1. cargo test -p recovermax-core
  2. cargo test -p recovermax
  3. fixture catalog scorecard
  4. optional generated ext4 fixture validation when mkfs.ext4/debugfs exist

Environment:
  RUN_FIXTURES=1       Same as --with-generated-fixtures
  FIXTURES_DIR=DIR     Generated fixture output directory
  RECOVERMAX_BIN=BIN   Binary used for fixture validation
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-generated-fixtures)
      RUN_FIXTURES=1
      shift
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

cd "$REPO_ROOT"

echo "== cargo test -p recovermax-core =="
cargo test -p recovermax-core

echo "== cargo test -p recovermax =="
cargo test -p recovermax

echo "== fixture scorecard =="
python3 scripts/fixture-scorecard.py --fail-missing-required

if [[ "$RUN_FIXTURES" != "1" ]]; then
  echo "== generated fixture validation skipped =="
  echo "Set RUN_FIXTURES=1 or pass --with-generated-fixtures to build and validate generated ext4 fixtures."
  exit 0
fi

for dep in mkfs.ext4 debugfs e2fsck truncate python3; do
  if ! need_cmd "$dep"; then
    echo "missing generated-fixture dependency: $dep" >&2
    exit 1
  fi
done

echo "== build recovermax binary =="
cargo build -p recovermax

echo "== build generated ext4 fixtures =="
bash scripts/build-ext4-fixtures.sh --out-dir "$FIXTURES_DIR"

echo "== validate session-tree fixture =="
bash scripts/recovermax-diff-validate.sh \
  --image "$FIXTURES_DIR/session-tree.ext4.img" \
  --manifest "$FIXTURES_DIR/session-tree.manifest.json" \
  --recovermax "$RECOVERMAX_BIN"

echo "== validate deleted fixture =="
bash scripts/recovermax-diff-validate.sh \
  --image "$FIXTURES_DIR/deleted.ext4.img" \
  --manifest "$FIXTURES_DIR/deleted.manifest.json" \
  --recovermax "$RECOVERMAX_BIN"
