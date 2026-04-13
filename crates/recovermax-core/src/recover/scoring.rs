//! Composite scoring for orphan recovery candidates.
//!
//! When a deleted filename resolves to multiple possible orphan inodes, we
//! need a principled way to pick the most likely match. This module
//! implements pure scoring primitives (each returns 0.0–1.0) plus the
//! weighted composite used by the orphan tiebreaker.
//!
//! These functions are intentionally leaf-level: they have no session or
//! filesystem handles, take only the data they need, and are easy to unit
//! test. The orchestration that *feeds* them (sibling context gathering,
//! content-type narrowing, final candidate pick) lives in the orphan
//! resolution layer.
//!
//! ## Weighting
//!
//! - `WEIGHT_DTIME = 3.0` — deletion time proximity to sibling median.
//!   Highest weight because dtime is the strongest real-world signal:
//!   batches of related files usually get deleted together.
//! - `WEIGHT_BLOCK_GROUP = 2.0` — candidate inode in the same ext4 block
//!   group as the parent directory. Moderate weight because ext4
//!   allocation prefers locality but isn't absolute.
//! - `WEIGHT_INODE_RANGE = 2.0` — candidate inode falls inside the
//!   (min, max) range of its resolved siblings. Same rationale as block
//!   group but works across ext4 versions.
//! - `WEIGHT_SIZE = 1.0` — candidate's file size is reasonable for the
//!   filename's extension. Weakest signal, used only as a tiebreaker when
//!   the higher-weight signals don't separate two candidates.
//! - `MIN_SCORE_GAP = 2.0` — the winner must beat the runner-up by at
//!   least this absolute score. Otherwise the resolution is ambiguous
//!   (caller gets None and can surface that honestly instead of guessing).

use crate::session::SessionNode;

// --- Composite tiebreaker weights ---

pub const WEIGHT_DTIME: f64 = 3.0;
pub const WEIGHT_BLOCK_GROUP: f64 = 2.0;
pub const WEIGHT_INODE_RANGE: f64 = 2.0;
pub const WEIGHT_SIZE: f64 = 1.0;
pub const MIN_SCORE_GAP: f64 = 2.0;

// --- dtime scoring ---

/// Candidates whose deletion time is within this many seconds of the
/// sibling median score a perfect 1.0. Two seconds covers the usual burst
/// of correlated `unlink()` calls in a single rm / batch operation.
pub const DTIME_EXACT_THRESHOLD_SECS: f64 = 2.0;

/// Beyond this distance, candidates score 0.0 — an hour gap is strong
/// evidence the file was deleted in an unrelated event.
pub const DTIME_MAX_DISTANCE_SECS: f64 = 3600.0;

/// Score `candidate`'s deletion time against a sibling-median dtime.
///
/// Returns 1.0 for a near-exact match, 0.0 past the hour threshold, and a
/// linearly interpolated value in between. Returns 0.0 when the candidate
/// has no recorded dtime — a missing signal can't contribute.
pub fn score_dtime_proximity(candidate: &SessionNode, sibling_median_dtime: i64) -> f64 {
    let candidate_dtime = match candidate
        .timestamps
        .as_ref()
        .and_then(|ts| ts.deleted_unix)
    {
        Some(dt) => dt,
        None => return 0.0,
    };
    let distance = (candidate_dtime - sibling_median_dtime).unsigned_abs() as f64;
    if distance <= DTIME_EXACT_THRESHOLD_SECS {
        return 1.0;
    }
    if distance >= DTIME_MAX_DISTANCE_SECS {
        return 0.0;
    }
    1.0 - (distance - DTIME_EXACT_THRESHOLD_SECS)
        / (DTIME_MAX_DISTANCE_SECS - DTIME_EXACT_THRESHOLD_SECS)
}

// --- block-group locality ---

/// Score 1.0 if `candidate_inode` falls in the same ext4 block group as
/// `parent_inode`, else 0.0. ext4 allocates directory entries' inodes with
/// a bias toward their parent's block group, so same-group is a strong
/// positive signal.
pub fn score_block_group_locality(
    candidate_inode: u64,
    parent_inode: u64,
    inodes_per_group: u32,
) -> f64 {
    let ipg = inodes_per_group as u64;
    if ipg == 0 {
        return 0.0;
    }
    let candidate_group = candidate_inode.saturating_sub(1) / ipg;
    let parent_group = parent_inode.saturating_sub(1) / ipg;
    if candidate_group == parent_group {
        1.0
    } else {
        0.0
    }
}

// --- inode range proximity ---

/// Score 1.0 if `candidate_inode` falls inside `inode_range`, else a
/// linear falloff based on distance normalized to the sibling span.
///
/// Rationale: resolved siblings from the same directory tend to cluster
/// in a tight inode range (contemporaneous allocation). A candidate inode
/// inside that range is a plausible member of the same cluster.
pub fn score_inode_range_proximity(candidate_inode: u64, inode_range: (u64, u64)) -> f64 {
    let (min_ino, max_ino) = inode_range;
    if candidate_inode >= min_ino && candidate_inode <= max_ino {
        return 1.0;
    }
    let distance = if candidate_inode < min_ino {
        min_ino - candidate_inode
    } else {
        candidate_inode - max_ino
    };
    let span = max_ino.saturating_sub(min_ino).max(1) as f64;
    let normalized = distance as f64 / span;
    (1.0 - normalized).max(0.0)
}

// --- size reasonableness by file extension ---

/// Score how reasonable `candidate`'s size is for a file with the given
/// extension. Returns 0.5 (neutral) when we have no size or extension to
/// work with — a missing signal shouldn't penalize a candidate.
///
/// The size brackets are heuristic. They're tuned to flag egregiously
/// wrong candidates (e.g. a multi-GB "foo.txt") without being so strict
/// that they wrongly reject unusual-but-legitimate files.
pub fn score_size_reasonableness(candidate: &SessionNode, extension: Option<&str>) -> f64 {
    let size = match candidate.size {
        Some(s) => s,
        None => return 0.5,
    };
    let ext = match extension {
        Some(e) => e,
        None => return 0.5,
    };
    match ext {
        "txt" | "md" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "rs" | "c" | "cpp"
        | "h" | "toml" | "yaml" | "yml" | "py" | "js" | "ts" | "sh" | "conf" | "cfg" => {
            if size <= 10_000_000 {
                1.0
            } else if size <= 100_000_000 {
                0.7
            } else if size <= 1_000_000_000 {
                0.3
            } else {
                0.0
            }
        }
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" => {
            if size <= 50_000_000 {
                1.0
            } else if size <= 500_000_000 {
                0.5
            } else {
                0.0
            }
        }
        "pdf" => {
            if size <= 100_000_000 {
                1.0
            } else if size <= 1_000_000_000 {
                0.5
            } else {
                0.0
            }
        }
        "zip" | "tar" | "gz" | "xz" | "bz2" | "7z" | "rar" => 0.5,
        _ => 0.5,
    }
}

/// Median of a sorted slice of i64 values. The caller must pre-sort;
/// taking a sorted slice makes the function pure and cheap.
pub fn median_sorted_i64(sorted: &[i64]) -> i64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{EntrySource, FileType};
    use crate::session::{SessionNode, SessionNodeTimestamps};

    fn make_node(inode: u64, size: u64, dtime: Option<i64>) -> SessionNode {
        SessionNode {
            id: inode,
            parent_id: None,
            filesystem_index: 0,
            path: String::new(),
            basename: String::new(),
            inode: Some(inode),
            parent_inode: None,
            file_type: FileType::RegularFile,
            size: Some(size),
            source: EntrySource::SyntheticOrphan,
            deleted: true,
            timestamps: Some(SessionNodeTimestamps {
                created_unix: None,
                modified_unix: None,
                accessed_unix: None,
                deleted_unix: dtime,
            }),
        }
    }

    #[test]
    fn dtime_exact_match_scores_one() {
        let node = make_node(100, 1024, Some(1_700_000_000));
        assert_eq!(score_dtime_proximity(&node, 1_700_000_001), 1.0);
    }

    #[test]
    fn dtime_far_match_scores_zero() {
        let node = make_node(100, 1024, Some(1_700_000_000));
        assert_eq!(score_dtime_proximity(&node, 1_700_000_000 + 3600), 0.0);
    }

    #[test]
    fn dtime_missing_scores_zero() {
        let node = make_node(100, 1024, None);
        assert_eq!(score_dtime_proximity(&node, 1_700_000_000), 0.0);
    }

    #[test]
    fn block_group_locality_same_group() {
        // inodes_per_group = 1000 → inodes 1..=1000 in group 0, 1001..=2000 in group 1
        assert_eq!(score_block_group_locality(50, 500, 1000), 1.0);
        assert_eq!(score_block_group_locality(1500, 500, 1000), 0.0);
    }

    #[test]
    fn block_group_locality_zero_ipg_bails() {
        assert_eq!(score_block_group_locality(50, 500, 0), 0.0);
    }

    #[test]
    fn inode_range_inside_scores_one() {
        assert_eq!(score_inode_range_proximity(55, (50, 60)), 1.0);
    }

    #[test]
    fn inode_range_outside_falls_off_linearly() {
        // span = 10, distance = 10 → normalized = 1.0 → score = 0.0
        assert_eq!(score_inode_range_proximity(70, (50, 60)), 0.0);
        // span = 10, distance = 5 → normalized = 0.5 → score = 0.5
        assert_eq!(score_inode_range_proximity(65, (50, 60)), 0.5);
    }

    #[test]
    fn size_reasonableness_missing_inputs_neutral() {
        let no_size = SessionNode {
            size: None,
            ..make_node(1, 0, None)
        };
        assert_eq!(score_size_reasonableness(&no_size, Some("txt")), 0.5);
        let has_size = make_node(1, 1024, None);
        assert_eq!(score_size_reasonableness(&has_size, None), 0.5);
    }

    #[test]
    fn size_reasonableness_text_brackets() {
        let small = make_node(1, 1_000_000, None);
        let medium = make_node(1, 50_000_000, None);
        let huge = make_node(1, 2_000_000_000, None);
        assert_eq!(score_size_reasonableness(&small, Some("rs")), 1.0);
        assert_eq!(score_size_reasonableness(&medium, Some("rs")), 0.7);
        assert_eq!(score_size_reasonableness(&huge, Some("rs")), 0.0);
    }

    #[test]
    fn median_odd_and_even() {
        assert_eq!(median_sorted_i64(&[1, 2, 3]), 2);
        assert_eq!(median_sorted_i64(&[1, 2, 3, 4]), 2); // (2+3)/2 rounds toward 0
    }
}
