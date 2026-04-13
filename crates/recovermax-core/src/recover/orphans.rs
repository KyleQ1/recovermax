//! Orphan inode resolution: picking which recoverable inode best matches a
//! residual deleted filename when multiple candidates remain.
//!
//! The problem: when ext4 metadata is partially damaged, a directory entry
//! like `/home/user/report.pdf` may point at an inode that's been reused
//! or zeroed. Scanning turns up multiple `$OrphanFiles/OrphanFile-N`
//! entries that *could* be the original `report.pdf`. This module picks
//! among them using three strategies, in decreasing confidence:
//!
//! 1. **Content-type match** (`strongly_matched_candidate`) — read the
//!    first bytes of each candidate, compare to the filename extension's
//!    expected magic (PDF header, PNG signature, etc.). If exactly one
//!    candidate matches and nothing has unknown content, that's the
//!    answer. Cheap and unambiguous when it works.
//!
//! 2. **Content-type narrowing + scored tiebreak**
//!    (`content_type_narrowed_candidates` + `best_orphan_candidate`) —
//!    when strong matching doesn't uniquely identify one, shrink the
//!    candidate pool to only those matching the expected content kind,
//!    then run the composite scorer (see `recover::scoring`) using
//!    sibling dtimes, inode locality, inode range, and size.
//!
//! 3. **Honest ambiguity** — if the best-scoring candidate doesn't beat
//!    the runner-up by at least `MIN_SCORE_GAP`, return None. We'd rather
//!    surface the ambiguity than silently recover the wrong file.
//!
//! The orchestration that *assembles* the candidate list (from session
//! tree or live ext4 scan) lives in the CLI / eventual session layer —
//! the candidate list construction depends on CLI-private synthetic id
//! schemes and isn't worth generalizing yet.

use crate::fs::ext4::Ext4Fs;
use crate::recover::scoring;
use crate::session::{RecoverySession, SessionNode};

// --- content kind sniffing -------------------------------------------------

/// Coarse content classification for orphan candidate matching. Granular
/// enough to disambiguate extensions likely to appear in a given
/// directory; not a general MIME detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateContentKind {
    Text,
    Pdf,
    Png,
    Jpeg,
    Gif,
    Zip,
    /// Couldn't confidently classify — probably binary with no known
    /// signature or empty data. Treated as "doesn't rule in, doesn't rule
    /// out" by `content_type_narrowed_candidates`.
    Unknown,
}

/// Map a session path's extension to the content kind its content bytes
/// *should* start with. Returns None for extensions we don't sniff for —
/// archives like tar/gz aren't in the table because their signatures
/// aren't a strong unique signal worth adding scoring weight to.
pub fn expected_content_kind_for_path(path: &str) -> Option<CandidateContentKind> {
    let extension = std::path::Path::new(path)
        .extension()?
        .to_str()?
        .to_ascii_lowercase();
    match extension.as_str() {
        "txt" | "md" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "rs" | "c" | "cpp"
        | "h" | "toml" | "yaml" | "yml" => Some(CandidateContentKind::Text),
        "pdf" => Some(CandidateContentKind::Pdf),
        "png" => Some(CandidateContentKind::Png),
        "jpg" | "jpeg" => Some(CandidateContentKind::Jpeg),
        "gif" => Some(CandidateContentKind::Gif),
        "zip" => Some(CandidateContentKind::Zip),
        _ => None,
    }
}

/// Read the first 512 bytes of `candidate`'s inode and sniff its content
/// kind. Returns None when the inode can't be read at all — that's a hard
/// failure, distinguishable from CandidateContentKind::Unknown.
pub fn sniff_candidate_content_kind(
    ext4: &Ext4Fs<'_>,
    candidate: &SessionNode,
) -> Option<CandidateContentKind> {
    let inode_num = candidate.inode?;
    let inode = ext4.read_inode(inode_num).ok()?;
    let data = ext4.read_inode_data_bounded(&inode, 512).ok()?;
    Some(sniff_content_kind(&data))
}

/// Pure byte-level magic sniff. Exposed separately so carving and other
/// callers can reuse the same classification on arbitrary byte slices.
pub fn sniff_content_kind(data: &[u8]) -> CandidateContentKind {
    if data.starts_with(b"%PDF-") {
        return CandidateContentKind::Pdf;
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return CandidateContentKind::Png;
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return CandidateContentKind::Jpeg;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return CandidateContentKind::Gif;
    }
    if data.starts_with(b"PK\x03\x04") {
        return CandidateContentKind::Zip;
    }
    if data.is_empty() {
        return CandidateContentKind::Unknown;
    }

    // Heuristic text detection: 90%+ printable ASCII and no NUL bytes in
    // the sample. Catches source code, logs, config files that don't have
    // a magic signature.
    let sample = &data[..data.len().min(512)];
    let printable = sample
        .iter()
        .filter(|byte| matches!(**byte, b'\n' | b'\r' | b'\t') || !byte.is_ascii_control())
        .count();
    let nul_bytes = sample.iter().filter(|byte| **byte == 0).count();
    if nul_bytes == 0 && printable * 10 >= sample.len() * 9 {
        CandidateContentKind::Text
    } else {
        CandidateContentKind::Unknown
    }
}

/// Of the supplied candidates, return only those whose actual content
/// matches the expected kind for `node`'s path extension. Returns an
/// empty Vec in several "can't narrow safely" cases:
///
/// - Path has no extension in our table → can't tell what to expect.
/// - No attached reader (can't sniff live content).
/// - Filesystem isn't ext4.
/// - Any candidate sniffs as Unknown → can't rule it in or out, so don't
///   implicitly exclude it.
///
/// Empty-return semantics: caller should fall back to the unnarrowed
/// pool rather than interpret "empty" as "no matches."
pub fn content_type_narrowed_candidates(
    session: &RecoverySession,
    node: &SessionNode,
    candidates: &[SessionNode],
) -> Vec<SessionNode> {
    let expected_kind = match expected_content_kind_for_path(&node.path) {
        Some(kind) => kind,
        None => return Vec::new(),
    };
    let reader = match session.attached_reader() {
        Some(r) => r,
        None => return Vec::new(),
    };
    let filesystem = match session.artifact().filesystem_session(node.filesystem_index) {
        Some(fs) => fs,
        None => return Vec::new(),
    };
    if filesystem.fs_info.fs_type != "ext4" {
        return Vec::new();
    }
    let ext4 = match Ext4Fs::new(reader, filesystem.fs_info.offset) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut matching = Vec::new();
    for candidate in candidates {
        let actual_kind = match sniff_candidate_content_kind(&ext4, candidate) {
            Some(kind) => kind,
            None => return Vec::new(),
        };
        if actual_kind == CandidateContentKind::Unknown {
            return Vec::new();
        }
        if actual_kind == expected_kind {
            matching.push(candidate.clone());
        }
    }
    matching
}

/// Strong match: if exactly one candidate matches the expected content
/// kind and no candidate is Unknown, return it. Otherwise None so the
/// caller falls through to the scored tiebreaker.
pub fn strongly_matched_candidate(
    session: &RecoverySession,
    node: &SessionNode,
    candidates: &[SessionNode],
) -> Option<SessionNode> {
    let expected_kind = expected_content_kind_for_path(&node.path)?;
    let reader = session.attached_reader()?;
    let filesystem = session.artifact().filesystem_session(node.filesystem_index)?;
    if filesystem.fs_info.fs_type != "ext4" {
        return None;
    }

    let ext4 = Ext4Fs::new(reader, filesystem.fs_info.offset).ok()?;
    let mut matching = Vec::new();

    for candidate in candidates {
        let actual_kind = sniff_candidate_content_kind(&ext4, candidate)?;
        if actual_kind == expected_kind {
            matching.push(candidate.clone());
        } else if actual_kind == CandidateContentKind::Unknown {
            return None;
        }
    }

    if matching.len() == 1 {
        matching.pop()
    } else {
        None
    }
}

// --- sibling context -------------------------------------------------------

/// Aggregated signals from resolved siblings of a residual deleted entry.
/// Both fields are Options because a directory with no resolved siblings
/// (e.g. the deleted entry is the only thing we have for its parent)
/// gives no usable signal.
#[derive(Debug, Clone)]
pub struct SiblingContext {
    /// Median deleted_unix timestamp across siblings that have one.
    pub median_dtime: Option<i64>,
    /// (min, max) inode range across siblings. Used to score whether a
    /// candidate inode falls inside the sibling cluster.
    pub inode_range: Option<(u64, u64)>,
}

impl SiblingContext {
    fn empty() -> Self {
        SiblingContext {
            median_dtime: None,
            inode_range: None,
        }
    }
}

/// Gather sibling context for `node`, preferring the session's persisted
/// tree (cheap in-memory walk) and falling back to a live ext4 directory
/// read when no tree exists.
pub fn gather_sibling_context(session: &RecoverySession, node: &SessionNode) -> SiblingContext {
    if session.has_tree(node.filesystem_index) {
        return gather_sibling_context_from_session(session, node);
    }
    if let Ok(ext4) = session.live_ext4(node.filesystem_index) {
        return gather_sibling_context_live(&ext4, node.parent_inode);
    }
    SiblingContext::empty()
}

fn gather_sibling_context_from_session(
    session: &RecoverySession,
    node: &SessionNode,
) -> SiblingContext {
    let parent_id = match node.parent_id {
        Some(pid) => pid,
        None => return SiblingContext::empty(),
    };

    let filesystem = match session.artifact().filesystem_session(node.filesystem_index) {
        Some(fs) => fs,
        None => return SiblingContext::empty(),
    };

    let mut dtimes = Vec::new();
    let mut inodes = Vec::new();

    for sibling in &filesystem.nodes {
        if sibling.id == node.id || sibling.parent_id != Some(parent_id) {
            continue;
        }
        if let Some(inode) = sibling.inode {
            inodes.push(inode);
        }
        if let Some(dtime) = sibling
            .timestamps
            .as_ref()
            .and_then(|ts| ts.deleted_unix)
        {
            dtimes.push(dtime);
        }
    }

    dtimes.sort_unstable();
    inodes.sort_unstable();

    SiblingContext {
        median_dtime: if dtimes.is_empty() {
            None
        } else {
            Some(scoring::median_sorted_i64(&dtimes))
        },
        inode_range: if inodes.is_empty() {
            None
        } else {
            Some((*inodes.first().unwrap(), *inodes.last().unwrap()))
        },
    }
}

fn gather_sibling_context_live(
    ext4: &Ext4Fs<'_>,
    parent_inode: Option<u64>,
) -> SiblingContext {
    let parent_ino = match parent_inode {
        Some(ino) => ino,
        None => return SiblingContext::empty(),
    };

    let entries = match ext4.list_directory(parent_ino) {
        Ok(entries) => entries,
        Err(_) => return SiblingContext::empty(),
    };

    let mut dtimes = Vec::new();
    let mut inodes = Vec::new();
    let mut count = 0usize;
    // Cap the sample so pathological giant directories (think 100k
    // entries in /tmp) don't turn a tiebreak into a linear scan. 100 is
    // plenty for statistical signal from the surrounding file cluster.
    const MAX_SIBLINGS: usize = 100;

    for entry in &entries {
        if entry.name == "." || entry.name == ".." || entry.inode == 0 {
            continue;
        }
        count += 1;
        if count > MAX_SIBLINGS {
            break;
        }
        inodes.push(entry.inode);
        if let Ok(inode) = ext4.read_inode(entry.inode) {
            if inode.dtime != 0 {
                dtimes.push(inode.dtime as i64);
            }
        }
    }

    dtimes.sort_unstable();
    inodes.sort_unstable();

    SiblingContext {
        median_dtime: if dtimes.is_empty() {
            None
        } else {
            Some(scoring::median_sorted_i64(&dtimes))
        },
        inode_range: if inodes.is_empty() {
            None
        } else {
            Some((*inodes.first().unwrap(), *inodes.last().unwrap()))
        },
    }
}

// --- composite scoring / tiebreak ------------------------------------------

/// Pick the best orphan inode candidate for `node` among `candidates`,
/// using the weighted composite scorer from `recover::scoring`.
///
/// Returns None when:
/// - `candidates` is empty (and also Some(single) when it has exactly one).
/// - The top score doesn't beat the runner-up by `MIN_SCORE_GAP`, meaning
///   we'd be guessing.
///
/// Callers should have already used `strongly_matched_candidate` (exact
/// content match) and optionally narrowed via
/// `content_type_narrowed_candidates` before calling this — those are
/// stronger signals than the composite score.
pub fn best_orphan_candidate(
    session: &RecoverySession,
    node: &SessionNode,
    candidates: &[SessionNode],
) -> Option<SessionNode> {
    use scoring::{
        score_block_group_locality, score_dtime_proximity, score_inode_range_proximity,
        score_size_reasonableness, MIN_SCORE_GAP, WEIGHT_BLOCK_GROUP, WEIGHT_DTIME,
        WEIGHT_INODE_RANGE, WEIGHT_SIZE,
    };

    if candidates.len() < 2 {
        return candidates.first().cloned();
    }

    let siblings = gather_sibling_context(session, node);

    let inodes_per_group = session
        .live_ext4(node.filesystem_index)
        .ok()
        .map(|ext4| ext4.superblock.inodes_per_group);

    let extension = std::path::Path::new(&node.path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    let mut scores: Vec<(f64, usize)> = candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let mut total = 0.0;

            if let Some(median_dt) = siblings.median_dtime {
                total += WEIGHT_DTIME * score_dtime_proximity(candidate, median_dt);
            }

            if let (Some(parent_ino), Some(ipg)) = (node.parent_inode, inodes_per_group) {
                if let Some(candidate_ino) = candidate.inode {
                    total += WEIGHT_BLOCK_GROUP
                        * score_block_group_locality(candidate_ino, parent_ino, ipg);
                }
            }

            if let Some(range) = siblings.inode_range {
                if let Some(candidate_ino) = candidate.inode {
                    total +=
                        WEIGHT_INODE_RANGE * score_inode_range_proximity(candidate_ino, range);
                }
            }

            total += WEIGHT_SIZE * score_size_reasonableness(candidate, extension.as_deref());

            (total, idx)
        })
        .collect();

    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let best = scores[0].0;
    let runner_up = scores[1].0;

    if best - runner_up >= MIN_SCORE_GAP {
        Some(candidates[scores[0].1].clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- pure sniffers ------------------------------------------------------

    #[test]
    fn sniff_recognizes_pdf_magic() {
        assert_eq!(
            sniff_content_kind(b"%PDF-1.4\n..."),
            CandidateContentKind::Pdf
        );
    }

    #[test]
    fn sniff_recognizes_png_magic() {
        assert_eq!(
            sniff_content_kind(b"\x89PNG\r\n\x1a\n..."),
            CandidateContentKind::Png
        );
    }

    #[test]
    fn sniff_recognizes_jpeg_magic() {
        assert_eq!(
            sniff_content_kind(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]),
            CandidateContentKind::Jpeg
        );
    }

    #[test]
    fn sniff_recognizes_gif_magic() {
        assert_eq!(sniff_content_kind(b"GIF89a..."), CandidateContentKind::Gif);
        assert_eq!(sniff_content_kind(b"GIF87a..."), CandidateContentKind::Gif);
    }

    #[test]
    fn sniff_recognizes_zip_magic() {
        assert_eq!(
            sniff_content_kind(b"PK\x03\x04..."),
            CandidateContentKind::Zip
        );
    }

    #[test]
    fn sniff_classifies_text_as_text() {
        let src = b"fn main() {\n    println!(\"hi\");\n}\n";
        assert_eq!(sniff_content_kind(src), CandidateContentKind::Text);
    }

    #[test]
    fn sniff_classifies_binary_noise_as_unknown() {
        let mut binary = vec![0u8; 512];
        for (i, b) in binary.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        assert_eq!(sniff_content_kind(&binary), CandidateContentKind::Unknown);
    }

    #[test]
    fn sniff_empty_is_unknown() {
        assert_eq!(sniff_content_kind(&[]), CandidateContentKind::Unknown);
    }

    // --- extension mapping --------------------------------------------------

    #[test]
    fn extension_maps_to_expected_kinds() {
        assert_eq!(
            expected_content_kind_for_path("/x/foo.pdf"),
            Some(CandidateContentKind::Pdf)
        );
        assert_eq!(
            expected_content_kind_for_path("/x/foo.RS"),
            Some(CandidateContentKind::Text)
        );
        assert_eq!(
            expected_content_kind_for_path("/x/photo.JPEG"),
            Some(CandidateContentKind::Jpeg)
        );
        assert_eq!(expected_content_kind_for_path("/x/foo.tar"), None);
        assert_eq!(expected_content_kind_for_path("/x/noext"), None);
    }
}
