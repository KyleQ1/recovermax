use std::collections::HashSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::fs::ext4::Ext4Fs;
use crate::fs::{DirEntry, EntrySource, FileType, FsInfo};
use crate::io::ImageReader;
use crate::scan::ScanReport;
use crate::session::{RecoverySession, RecoverySessionArtifact};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOptions {
    pub ignore_case: bool,
    pub exact: bool,
    pub filesystem_index: Option<usize>,
    pub max_depth: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            ignore_case: false,
            exact: false,
            filesystem_index: None,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatch {
    pub filesystem_index: usize,
    pub filesystem_label: String,
    pub filesystem_offset: u64,
    pub inode: u64,
    pub path: String,
    pub file_type: FileType,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub source: EntrySource,
    #[serde(default)]
    pub parent_inode: Option<u64>,
}

pub struct Searcher<'a> {
    reader: &'a ImageReader,
}

impl<'a> Searcher<'a> {
    pub fn new(reader: &'a ImageReader) -> Self {
        Self { reader }
    }

    pub fn search(
        &self,
        report: &ScanReport,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<SearchMatch>> {
        let filesystem_indexes: Vec<usize> = report
            .filesystems
            .iter()
            .enumerate()
            .map(|(index, _)| index)
            .collect();
        self.search_selected(report, query, options, &filesystem_indexes)
    }

    pub fn search_selected(
        &self,
        report: &ScanReport,
        query: &str,
        options: &SearchOptions,
        filesystem_indexes: &[usize],
    ) -> Result<Vec<SearchMatch>> {
        let mut matches = Vec::new();

        for &fs_index in filesystem_indexes {
            let Some(fs_info) = report.filesystems.get(fs_index) else {
                continue;
            };
            if options.filesystem_index.is_some() && options.filesystem_index != Some(fs_index) {
                continue;
            }

            if fs_info.fs_type != "ext4" {
                continue;
            }

            let ext4 = Ext4Fs::new(self.reader, fs_info.offset)?;
            let root_entries = ext4.list_directory(2)?;
            let mut visited_dirs = HashSet::from([2u64]);
            self.search_recursive(
                &ext4,
                fs_index,
                fs_info,
                &root_entries,
                "",
                query,
                options,
                &mut matches,
                &mut visited_dirs,
                0,
            )?;
            let mut orphan_dirs_visited = HashSet::new();
            let mut deleted_inodes = ext4.scan_deleted_inodes()?;
            deleted_inodes
                .sort_by_key(|inode| (inode.file_type != FileType::Directory, inode.inode_num));
            for deleted_inode in deleted_inodes {
                let orphan_basename = format!("OrphanFile-{}", deleted_inode.inode_num);
                let orphan_path = format!("/$OrphanFiles/{}", orphan_basename);
                if path_matches(query, &orphan_basename, &orphan_path, options) {
                    matches.push(SearchMatch {
                        filesystem_index: fs_index,
                        filesystem_label: fs_info.label.clone(),
                        filesystem_offset: fs_info.offset,
                        inode: deleted_inode.inode_num,
                        path: orphan_path,
                        file_type: deleted_inode.file_type,
                        deleted: true,
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                    });
                }

                if deleted_inode.file_type == FileType::Directory
                    && orphan_dirs_visited.insert(deleted_inode.inode_num)
                {
                    match ext4.list_directory(deleted_inode.inode_num) {
                        Ok(entries) => {
                            let orphan_subpath = format!("$OrphanFiles/{}", orphan_basename);
                            self.search_recursive(
                                &ext4,
                                fs_index,
                                fs_info,
                                &entries,
                                &orphan_subpath,
                                query,
                                options,
                                &mut matches,
                                &mut orphan_dirs_visited,
                                1,
                            )?;
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Failed to read deleted orphan directory inode {} while searching filesystem {}: {}",
                                deleted_inode.inode_num,
                                fs_index,
                                err
                            );
                        }
                    }
                }
            }
        }

        Ok(matches)
    }

    pub fn search_artifact(
        &self,
        artifact: &RecoverySessionArtifact,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<SearchMatch>> {
        if artifact
            .filesystems
            .iter()
            .any(|filesystem| filesystem.has_tree())
        {
            let mut session = RecoverySession::from_artifact(artifact.clone(), None);
            return Ok(session.search(query, options));
        }

        self.search(artifact.report(), query, options)
    }

    pub fn search_session(
        &self,
        session: &mut RecoverySession,
        query: &str,
        options: &SearchOptions,
    ) -> Vec<SearchMatch> {
        session.search(query, options)
    }

    /// `current_path` is the /-separated session-path fragment relative to
    /// the filesystem root ("" for root, "$OrphanFiles/OrphanFile-13" when
    /// descending into an orphan directory). Kept as a string — not a
    /// PathBuf — so separators are platform-independent. PathBuf::join
    /// produced `\` segments on Windows which broke downstream path
    /// comparisons.
    #[allow(clippy::too_many_arguments)]
    fn search_recursive(
        &self,
        ext4: &Ext4Fs,
        filesystem_index: usize,
        fs_info: &FsInfo,
        entries: &[DirEntry],
        current_path: &str,
        query: &str,
        options: &SearchOptions,
        matches: &mut Vec<SearchMatch>,
        visited_dirs: &mut HashSet<u64>,
        depth: usize,
    ) -> Result<()> {
        if depth > options.max_depth {
            return Ok(());
        }

        for entry in entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }

            let entry_path = if current_path.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", current_path, entry.name)
            };
            let absolute_path = format!("/{}", entry_path);

            if path_matches(query, &entry.name, &absolute_path, options) {
                matches.push(SearchMatch {
                    filesystem_index,
                    filesystem_label: fs_info.label.clone(),
                    filesystem_offset: fs_info.offset,
                    inode: entry.inode,
                    path: absolute_path.clone(),
                    file_type: entry.file_type,
                    deleted: entry.deleted,
                    source: entry.source,
                    parent_inode: entry.parent_inode,
                });
            }

            if entry.file_type == FileType::Directory
                && entry.inode > 0
                && visited_dirs.insert(entry.inode)
            {
                match ext4.list_directory(entry.inode) {
                    Ok(sub_entries) => {
                        self.search_recursive(
                            ext4,
                            filesystem_index,
                            fs_info,
                            &sub_entries,
                            &entry_path,
                            query,
                            options,
                            matches,
                            visited_dirs,
                            depth + 1,
                        )?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to read dir inode {} while searching {}: {}",
                            entry.inode,
                            absolute_path,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

pub fn path_matches(
    query: &str,
    basename: &str,
    absolute_path: &str,
    options: &SearchOptions,
) -> bool {
    if query.is_empty() {
        return false;
    }

    let query_is_path = query.starts_with('/');

    if options.ignore_case {
        let query = query.to_lowercase();
        let basename = basename.to_lowercase();
        let absolute_path = absolute_path.to_lowercase();
        return path_matches_inner(
            &query,
            &basename,
            &absolute_path,
            query_is_path,
            options.exact,
        );
    }

    path_matches_inner(query, basename, absolute_path, query_is_path, options.exact)
}

fn path_matches_inner(
    query: &str,
    basename: &str,
    absolute_path: &str,
    query_is_path: bool,
    exact: bool,
) -> bool {
    if is_glob_query(query) {
        if query_is_path {
            return glob_matches(query, absolute_path);
        }
        return glob_matches(query, basename) || glob_matches(query, absolute_path);
    }

    if exact {
        if query_is_path {
            return absolute_path == query;
        }

        return basename == query || absolute_path == query;
    }

    if query_is_path {
        return absolute_path.contains(query);
    }

    basename.contains(query) || absolute_path.contains(query)
}

pub fn is_glob_query(query: &str) -> bool {
    query.contains('*') || query.contains('?')
}

/// Simple glob matching with `*` (any sequence) and `?` (any single char).
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (pn, tn) = (p.len(), t.len());
    let (mut pi, mut ti) = (0, 0);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0);

    while ti < tn {
        if pi < pn && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pn && p[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pn && p[pi] == '*' {
        pi += 1;
    }

    pi == pn
}

#[cfg(test)]
mod tests {
    use super::{path_matches, SearchOptions};

    #[test]
    fn matches_basename_substring() {
        let opts = SearchOptions::default();
        assert!(path_matches(
            "ming",
            "ming-notes.txt",
            "/data/ming-notes.txt",
            &opts
        ));
    }

    #[test]
    fn matches_full_path_substring() {
        let opts = SearchOptions::default();
        assert!(path_matches("/data/ming", "ming", "/data/ming", &opts));
    }

    #[test]
    fn exact_path_match() {
        let opts = SearchOptions {
            exact: true,
            ..Default::default()
        };
        assert!(path_matches("/data/ming", "ming", "/data/ming", &opts));
        assert!(!path_matches(
            "/data/ming",
            "ming-backup",
            "/data/ming-backup",
            &opts
        ));
    }

    #[test]
    fn exact_basename_match() {
        let opts = SearchOptions {
            exact: true,
            ..Default::default()
        };
        assert!(path_matches("ming", "ming", "/home/ming", &opts));
        assert!(!path_matches("ming", "ming-old", "/home/ming-old", &opts));
    }

    #[test]
    fn matches_ignore_case() {
        let opts = SearchOptions {
            ignore_case: true,
            ..Default::default()
        };
        assert!(path_matches("MING", "ming", "/data/ming", &opts));
    }

    #[test]
    fn glob_star_extension() {
        let opts = SearchOptions::default();
        assert!(path_matches("*.txt", "notes.txt", "/home/notes.txt", &opts));
        assert!(!path_matches("*.pdf", "notes.txt", "/home/notes.txt", &opts));
    }

    #[test]
    fn glob_question_mark() {
        let opts = SearchOptions::default();
        assert!(path_matches("file?.txt", "file1.txt", "/data/file1.txt", &opts));
        assert!(!path_matches("file?.txt", "file12.txt", "/data/file12.txt", &opts));
    }

    #[test]
    fn glob_complex_pattern() {
        let opts = SearchOptions::default();
        assert!(path_matches(
            "IMG_*.jpg",
            "IMG_2024.jpg",
            "/photos/IMG_2024.jpg",
            &opts
        ));
        assert!(!path_matches(
            "IMG_*.jpg",
            "screenshot.jpg",
            "/photos/screenshot.jpg",
            &opts
        ));
    }

    #[test]
    fn glob_path_pattern() {
        let opts = SearchOptions::default();
        assert!(path_matches(
            "/home/*/docs/*.pdf",
            "report.pdf",
            "/home/kyle/docs/report.pdf",
            &opts
        ));
        assert!(!path_matches(
            "/home/*/docs/*.pdf",
            "report.pdf",
            "/home/kyle/photos/report.pdf",
            &opts
        ));
    }

    #[test]
    fn glob_case_insensitive() {
        let opts = SearchOptions {
            ignore_case: true,
            ..Default::default()
        };
        assert!(path_matches("*.TXT", "notes.txt", "/data/notes.txt", &opts));
    }

    #[test]
    fn glob_star_only_matches_everything() {
        let opts = SearchOptions::default();
        assert!(path_matches("*", "anything.txt", "/any/path/anything.txt", &opts));
    }

    #[test]
    fn non_glob_query_still_works_as_substring() {
        let opts = SearchOptions::default();
        assert!(path_matches("notes", "my-notes.txt", "/home/my-notes.txt", &opts));
        assert!(!path_matches("missing", "my-notes.txt", "/home/my-notes.txt", &opts));
    }
}
