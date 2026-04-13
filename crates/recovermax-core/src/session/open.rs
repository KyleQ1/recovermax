//! Session loading orchestration.
//!
//! High-level entry points for obtaining a [`RecoverySession`]:
//!
//! - [`open_session`] — open from a `.scn` file; image path is resolved
//!   from the session's recorded source. The primary Phase 2.1 API.
//! - [`browse_session_for_image`] — open a live session over an image
//!   without a prior scan. Scans the filesystem in-place to build the
//!   minimal artifact needed for browsing.
//! - [`open_session_for_image`] — the flexible form: given an image and
//!   optional scan file, pick the right backend (binary `.scn`, JSON
//!   `.scn`, or live scan) and return a ready session. `require_tree`
//!   forces a live rescan when the provided artifact has no tree.
//! - [`open_session_from_saved`] — like `open_session_for_image` but the
//!   image path is implicit from the scan file.
//!
//! All functions in this module are pure: no prints to stdout/stderr.
//! Warnings (e.g. scan-file vs image size mismatch) go through `tracing`
//! so callers can route them as they like.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::{
    binary_reader::ScnReader, FilesystemSessionArtifact, RecoverySession, RecoverySessionArtifact,
    ScanImageSource, SessionNode,
};
use crate::io::ImageReader;
use crate::scan::{ScanReport, Scanner};

/// Detect whether `path` points at a binary `.scn` file (vs. the older
/// JSON session format). Cheap magic-byte sniff.
pub fn is_binary_scn(path: &Path) -> bool {
    if let Ok(data) = std::fs::read(path) {
        data.len() >= 8 && &data[0..8] == b"RMXSCAN\0"
    } else {
        false
    }
}

/// Parse a human-readable memory budget string (e.g. "4GB", "512 MiB",
/// "1073741824") into bytes.
///
/// `None` input or empty string returns `Ok(None)` — the session layer
/// treats "unspecified" distinctly from "explicit zero" so it can fall
/// back to its default heuristic.
pub fn parse_memory_budget(memory_budget: Option<&str>) -> Result<Option<u64>> {
    match memory_budget {
        None => Ok(None),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }

            if let Ok(parsed) = trimmed.parse::<bytesize::ByteSize>() {
                return Ok(Some(parsed.as_u64()));
            }

            let bytes = trimmed
                .parse::<u64>()
                .with_context(|| format!("invalid memory budget {}", value))?;
            Ok(Some(bytes))
        }
    }
}

/// Run a full filesystem scan on `image` via `reader` and wrap the report
/// in a freshly-constructed [`RecoverySessionArtifact`]. Useful when the
/// caller has no prior `.scn` and needs a browsable session.
pub fn build_live_session_artifact(
    image: &Path,
    reader: &ImageReader,
) -> Result<RecoverySessionArtifact> {
    let scanner = Scanner::new(reader);
    let report = scanner.full_scan()?;
    RecoverySessionArtifact::from_scan(image, reader, report)
}

/// Open a session for `image`, optionally backed by a pre-existing scan
/// file. The scan file may be either the binary `.scn` or the older JSON
/// `.scn` format — this fn dispatches based on the magic bytes.
///
/// - `memory_budget`: human-readable cache limit. See
///   [`parse_memory_budget`].
/// - `require_tree`: when true, runs a live rescan if the loaded artifact
///   has no session tree. Useful for commands (recover, search) that
///   can't do anything without a tree but would otherwise silently load a
///   metadata-only session.
pub fn open_session_for_image(
    image: &Path,
    scan_file: Option<&Path>,
    memory_budget: Option<&str>,
    require_tree: bool,
) -> Result<RecoverySession> {
    let reader = ImageReader::open(image)?;

    if let Some(scan_file) = scan_file {
        if is_binary_scn(scan_file) {
            return open_binary_scn(image, &reader, scan_file, memory_budget);
        }
    }

    let mut artifact = if let Some(scan_file) = scan_file {
        let artifact = RecoverySessionArtifact::load_from_path(scan_file)?;
        artifact.validate_for_image_with_artifact_path(image, reader.len(), Some(scan_file))?;
        artifact
    } else {
        build_live_session_artifact(image, &reader)?
    };

    if require_tree && !artifact.filesystems.iter().any(|fs| fs.has_tree()) {
        artifact = build_live_session_artifact(image, &reader)?;
    }

    let explicit_budget = parse_memory_budget(memory_budget)?;
    Ok(RecoverySession::from_artifact_with_reader(
        artifact,
        reader,
        explicit_budget,
    ))
}

/// Materialise a [`RecoverySession`] from a binary `.scn` + image. Called
/// by [`open_session_for_image`] when the scan file sniffs as binary.
///
/// The binary reader is mmap-based and lazy; this function walks every
/// node once to reconstruct the `SessionNode` vectors because the legacy
/// downstream code paths (search, recover, resolve) still expect them.
/// The walk is O(n) in node count; a future optimisation could expose
/// the binary tree directly without materialisation.
fn open_binary_scn(
    image: &Path,
    reader: &ImageReader,
    scan_file: &Path,
    memory_budget: Option<&str>,
) -> Result<RecoverySession> {
    let scn_reader = ScnReader::open(scan_file)?;

    if let Some(meta_json) = scn_reader.metadata_json() {
        if let Ok(report) = serde_json::from_str::<ScanReport>(meta_json) {
            if report.image_size != reader.len() {
                tracing::warn!(
                    "session was created from a {} image but this image is {} — mismatched source",
                    bytesize::ByteSize(report.image_size),
                    bytesize::ByteSize(reader.len()),
                );
            }
        }
    }

    let node_count = scn_reader.node_count();

    let mut fs_nodes: HashMap<u16, Vec<SessionNode>> = HashMap::new();
    for i in 0..node_count as u32 {
        if let Some(node) = scn_reader.to_session_node(i) {
            let fs_index = scn_reader
                .get_compact_node(i)
                .map(|n| n.filesystem_index)
                .unwrap_or(0);
            fs_nodes.entry(fs_index).or_default().push(node);
        }
    }

    let report = scn_reader
        .metadata_json()
        .and_then(|m| serde_json::from_str(m).ok())
        .unwrap_or_else(|| ScanReport {
            image_size: reader.len(),
            partitions: Vec::new(),
            filesystems: Vec::new(),
        });

    let warnings: Vec<String> = scn_reader
        .warnings_json()
        .and_then(|w| serde_json::from_str(w).ok())
        .unwrap_or_default();

    let mut filesystems = Vec::new();
    for (i, fs_info) in report.filesystems.iter().enumerate() {
        let nodes = fs_nodes.remove(&(i as u16)).unwrap_or_default();
        let root_node_id = nodes.first().map(|n| n.id);
        filesystems.push(FilesystemSessionArtifact {
            filesystem_index: i,
            fs_info: fs_info.clone(),
            root_node_id,
            warnings: warnings.clone(),
            nodes,
        });
    }

    let artifact = RecoverySessionArtifact {
        version: RecoverySessionArtifact::VERSION,
        source: ScanImageSource {
            path: image.to_path_buf(),
            image_size: reader.len(),
        },
        report,
        filesystems,
    };

    let explicit_budget = parse_memory_budget(memory_budget)?;
    Ok(RecoverySession::from_artifact_with_reader(
        artifact,
        ImageReader::open(image)?,
        explicit_budget,
    ))
}

/// Open a session from a saved `.scn` file, deriving the image path from
/// the session's recorded source.
pub fn open_session_from_saved(
    scan_file: &Path,
    memory_budget: Option<&str>,
    require_tree: bool,
) -> Result<RecoverySession> {
    let artifact = RecoverySessionArtifact::load_from_path(scan_file)?;
    let image_path = artifact
        .resolved_source_path(Some(scan_file))
        .as_deref()
        .context("saved session does not record a source image path")?
        .to_path_buf();

    let reader = ImageReader::open(&image_path)?;
    artifact.validate_for_image_with_artifact_path(&image_path, reader.len(), Some(scan_file))?;

    let mut artifact = artifact;
    if require_tree && !artifact.filesystems.iter().any(|fs| fs.has_tree()) {
        artifact = build_live_session_artifact(&image_path, &reader)?;
    }

    let explicit_budget = parse_memory_budget(memory_budget)?;
    Ok(RecoverySession::from_artifact_with_reader(
        artifact,
        reader,
        explicit_budget,
    ))
}

/// Plan 2.1 convenience entry: open a session from a `.scn` file with
/// default options. Thin wrapper over [`open_session_from_saved`].
///
/// The primary API the GUI is expected to call — give it a scan file,
/// get back a browsable session.
pub fn open_session(scn_path: &Path) -> Result<RecoverySession> {
    open_session_from_saved(scn_path, None, false)
}

/// Plan 2.1 convenience entry: browse `image_path` live with no prior
/// scan. Thin wrapper over [`open_session_for_image`] that triggers a
/// live scan to build the minimal artifact.
///
/// Suitable for "just show me what's on this disk" flows. Slower than
/// [`open_session`] because it has to rescan each time.
pub fn browse_session_for_image(image_path: &Path) -> Result<RecoverySession> {
    open_session_for_image(image_path, None, None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_budget_none_stays_none() {
        assert!(parse_memory_budget(None).unwrap().is_none());
    }

    #[test]
    fn parse_memory_budget_empty_string_is_none() {
        assert!(parse_memory_budget(Some("")).unwrap().is_none());
        assert!(parse_memory_budget(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn parse_memory_budget_accepts_human_readable() {
        assert_eq!(
            parse_memory_budget(Some("1 GiB")).unwrap(),
            Some(1024 * 1024 * 1024)
        );
        assert_eq!(
            parse_memory_budget(Some("500MB")).unwrap(),
            Some(500 * 1_000_000)
        );
    }

    #[test]
    fn parse_memory_budget_accepts_raw_bytes() {
        assert_eq!(parse_memory_budget(Some("4096")).unwrap(), Some(4096));
    }

    #[test]
    fn parse_memory_budget_rejects_nonsense() {
        assert!(parse_memory_budget(Some("abc")).is_err());
    }

    #[test]
    fn is_binary_scn_false_for_missing_file() {
        assert!(!is_binary_scn(Path::new("/nonexistent/path/nope.scn")));
    }
}
