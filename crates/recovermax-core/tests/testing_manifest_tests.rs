use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should exist")
}

fn read_json(path: &Path) -> Value {
    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("failed to read {}: {e}", path.display());
    });
    serde_json::from_str(&data).unwrap_or_else(|e| {
        panic!("failed to parse JSON {}: {e}", path.display());
    })
}

#[test]
fn fixture_catalog_has_required_quality_categories() {
    let root = repo_root();
    let catalog_path = root.join("testing/fixtures/catalog.json");
    let catalog = read_json(&catalog_path);
    assert_eq!(catalog["schema"].as_i64(), Some(1));

    let cases = catalog["cases"]
        .as_array()
        .expect("fixture catalog cases must be an array");
    assert!(
        cases.len() >= 15,
        "fixture catalog should be broad enough to track professional recovery quality"
    );

    let allowed_statuses: HashSet<&str> = catalog["status_values"]
        .as_array()
        .expect("status_values must be an array")
        .iter()
        .map(|value| value.as_str().expect("status must be a string"))
        .collect();

    let required_categories = [
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
    ];

    let mut ids = HashSet::new();
    let mut categories = HashSet::new();
    for case in cases {
        let id = case["id"].as_str().expect("case id must be a string");
        assert!(ids.insert(id), "duplicate fixture case id: {id}");
        let category = case["category"]
            .as_str()
            .expect("case category must be a string");
        categories.insert(category);

        let status = case["status"].as_str().expect("case status must be a string");
        assert!(
            allowed_statuses.contains(status),
            "case {id} has unknown status {status}"
        );

        let priority = case["priority"]
            .as_str()
            .expect("case priority must be a string");
        assert!(
            matches!(priority, "P0" | "P1" | "P2"),
            "case {id} has unexpected priority {priority}"
        );

        assert!(
            case["validates"].as_array().is_some_and(|items| !items.is_empty()),
            "case {id} must list validation targets"
        );
        assert!(
            case["source_types"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "case {id} must list source types"
        );
    }

    for category in required_categories {
        assert!(
            categories.contains(category),
            "fixture catalog is missing required category {category}"
        );
    }
}

#[test]
fn checked_in_dataset_manifests_are_valid_and_resolvable() {
    let root = repo_root();
    let manifest_paths = [
        root.join("testing/datasets/cfreds-dfr-01-ext/manifest.json"),
        root.join("testing/manifests/ext4-synthetic-basic.json"),
    ];

    for manifest_path in manifest_paths {
        let manifest = read_json(&manifest_path);
        let id = manifest["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} must include id", manifest_path.display()));
        assert!(!id.trim().is_empty(), "manifest id must not be empty");

        let expected = manifest["expected"].as_object().unwrap_or_else(|| {
            panic!("{} must include expected object", manifest_path.display())
        });
        assert!(
            !expected.is_empty(),
            "{} expected object must not be empty",
            manifest_path.display()
        );

        if let Some(image_path) = manifest
            .get("image")
            .and_then(|image| image.get("path"))
            .and_then(Value::as_str)
        {
            assert!(
                !image_path.starts_with('/'),
                "{} image path should be repo-relative for portability",
                manifest_path.display()
            );
        }
    }
}
