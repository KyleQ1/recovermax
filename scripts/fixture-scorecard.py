#!/usr/bin/env python3
"""Report RecoverMax fixture coverage from testing/fixtures/catalog.json."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


REQUIRED_CATEGORIES = {
    "filesystem-public-corpus",
    "filesystem-generated",
    "parser-unit",
    "partition-layout",
    "recovery-safety",
    "session-format",
    "failed-media",
    "raid-virtual-source",
    "disk-manager",
    "image-format",
    "remote-source",
    "forensic-hash",
    "performance",
    "security-robustness",
    "platform-raw-device",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        default="testing/fixtures/catalog.json",
        help="Fixture catalog path",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root used to resolve relative paths",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON",
    )
    parser.add_argument(
        "--fail-missing-required",
        action="store_true",
        help="Exit non-zero if a required category has no catalog case",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def discover_manifests(repo_root: Path) -> dict[str, str]:
    manifests: dict[str, str] = {}
    patterns = [
        "testing/datasets/**/manifest.json",
        "testing/fixtures/**/manifest.json",
        "testing/fixtures/**/*.manifest.json",
        "testing/manifests/*.json",
    ]
    for pattern in patterns:
        for path in sorted(repo_root.glob(pattern)):
            if not path.is_file():
                continue
            try:
                data = load_json(path)
            except Exception:
                continue
            fixture_id = data.get("id")
            if isinstance(fixture_id, str):
                manifests[fixture_id] = str(path.relative_to(repo_root))
    return manifests


def summarize(catalog: dict, repo_root: Path) -> dict:
    cases = catalog.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit("catalog cases must be an array")

    allowed_statuses = set(catalog.get("status_values", []))
    manifests = discover_manifests(repo_root)
    by_status = Counter()
    by_category = Counter()
    by_priority = Counter()
    missing_manifest = []
    unknown_status = []
    duplicate_ids = []
    seen_ids = set()
    validations = Counter()
    filesystems = Counter()
    source_types = Counter()
    category_status = defaultdict(Counter)

    for case in cases:
        case_id = case.get("id")
        if case_id in seen_ids:
            duplicate_ids.append(case_id)
        seen_ids.add(case_id)

        status = case.get("status", "unknown")
        category = case.get("category", "unknown")
        priority = case.get("priority", "unknown")
        by_status[status] += 1
        by_category[category] += 1
        by_priority[priority] += 1
        category_status[category][status] += 1

        if allowed_statuses and status not in allowed_statuses:
            unknown_status.append({"id": case_id, "status": status})

        manifest = case.get("manifest")
        if manifest:
            manifest_path = repo_root / manifest
            if not manifest_path.is_file():
                missing_manifest.append({"id": case_id, "manifest": manifest})

        for value in case.get("validates", []):
            validations[value] += 1
        for value in case.get("filesystems", []):
            filesystems[value] += 1
        for value in case.get("source_types", []):
            source_types[value] += 1

    missing_categories = sorted(REQUIRED_CATEGORIES - set(by_category))
    implemented_statuses = {"available", "generated-script", "unit-covered", "manual-only"}
    implemented = sum(count for status, count in by_status.items() if status in implemented_statuses)

    return {
        "schema": catalog.get("schema"),
        "total_cases": len(cases),
        "implemented_or_actionable_cases": implemented,
        "planned_or_external_cases": len(cases) - implemented,
        "by_status": dict(sorted(by_status.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_priority": dict(sorted(by_priority.items())),
        "category_status": {
            category: dict(sorted(counter.items()))
            for category, counter in sorted(category_status.items())
        },
        "top_validations": dict(validations.most_common(25)),
        "filesystems": dict(sorted(filesystems.items())),
        "source_types": dict(sorted(source_types.items())),
        "discovered_manifests": manifests,
        "missing_manifest_references": missing_manifest,
        "missing_required_categories": missing_categories,
        "unknown_statuses": unknown_status,
        "duplicate_ids": duplicate_ids,
    }


def print_text(summary: dict) -> None:
    print("RecoverMax fixture scorecard")
    print(f"  total cases: {summary['total_cases']}")
    print(f"  implemented/actionable: {summary['implemented_or_actionable_cases']}")
    print(f"  planned/external: {summary['planned_or_external_cases']}")
    print()

    print("By status:")
    for status, count in summary["by_status"].items():
        print(f"  {status}: {count}")
    print()

    print("By category:")
    for category, count in summary["by_category"].items():
        statuses = summary["category_status"].get(category, {})
        status_text = ", ".join(f"{key}={value}" for key, value in statuses.items())
        print(f"  {category}: {count} ({status_text})")
    print()

    if summary["missing_manifest_references"]:
        print("Missing manifest references:")
        for item in summary["missing_manifest_references"]:
            print(f"  {item['id']}: {item['manifest']}")
        print()

    if summary["missing_required_categories"]:
        print("Missing required categories:")
        for category in summary["missing_required_categories"]:
            print(f"  {category}")
        print()

    if summary["unknown_statuses"]:
        print("Unknown statuses:")
        for item in summary["unknown_statuses"]:
            print(f"  {item['id']}: {item['status']}")
        print()

    if summary["duplicate_ids"]:
        print("Duplicate IDs:")
        for item in summary["duplicate_ids"]:
            print(f"  {item}")
        print()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    catalog_path = (repo_root / args.catalog).resolve()
    catalog = load_json(catalog_path)
    summary = summarize(catalog, repo_root)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print_text(summary)

    has_errors = bool(
        summary["unknown_statuses"]
        or summary["duplicate_ids"]
        or (args.fail_missing_required and summary["missing_required_categories"])
    )
    return 1 if has_errors else 0


if __name__ == "__main__":
    sys.exit(main())
