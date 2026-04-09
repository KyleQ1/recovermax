use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::fs::{self, FsInfo, LvmMap, LvmSegment};
use crate::io::ImageReader;
pub use crate::session::ScanImageSource;
pub type ScanArtifact = crate::session::RecoverySessionArtifact;

/// Partition table entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Partition {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub fs_type: String,
}

/// Full scan report — serializable to JSON for resuming later
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    pub image_size: u64,
    pub partitions: Vec<Partition>,
    pub filesystems: Vec<FsInfo>,
}

impl ScanReport {
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Image size: {}\n",
            bytesize::ByteSize(self.image_size)
        ));
        out.push_str(&format!("Partitions found: {}\n", self.partitions.len()));
        out.push_str(&format!("Filesystems found: {}\n", self.filesystems.len()));

        for (i, fs) in self.filesystems.iter().enumerate() {
            let status = if fs.root_readable {
                "browsable"
            } else {
                "root damaged — needs --deep scan"
            };
            out.push_str(&format!(
                "  [{}] {} at offset {} — {} ({}) [{}]\n",
                i,
                fs.fs_type,
                bytesize::ByteSize(fs.offset),
                fs.label,
                bytesize::ByteSize(fs.total_size),
                status,
            ));
        }

        out
    }
}

/// Phases of the scan pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Standard,
    PeBoundary,
    DeepScan,
    TreeBuilding,
}

/// Events emitted during scanning for progress visualization.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    PhaseStarted { phase: ScanPhase, total_bytes: u64 },
    Progress { phase: ScanPhase, offset: u64, bytes_scanned: u64 },
    FilesystemFound { fs_type: String, label: String, offset: u64, size: u64 },
    FileTypeFound { file_type: String, offset: u64 },
    PhaseComplete { phase: ScanPhase, filesystems_found: usize },
    TreeBuildStarted { filesystem_index: usize, label: String, total_inodes: u64 },
    TreeBuildProgress { filesystem_index: usize, files_found: usize, dirs_found: usize, bytes_offset: u64 },
    TreeBuildComplete { filesystem_index: usize, total_nodes: usize },
}

/// Options to control scan behavior.
pub struct ScanOptions {
    /// Run deep scan within partitions (walks every 1 MiB offset).
    pub deep_scan: bool,
    /// Auto-escalate when nothing found (PE-boundary scan, then deep scan).
    pub auto_escalate: bool,
    /// Scan only this byte range (None = full partition).
    pub start_offset: Option<u64>,
    pub end_offset: Option<u64>,
    /// Only detect these filesystem types (empty = all).
    pub fs_type_filter: Vec<String>,
    /// Probe for file carving signatures during scan.
    pub file_type_filter: Vec<String>,
    /// Progress callback — called from scan loops.
    pub on_event: Option<Box<dyn Fn(ScanEvent) + Send>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            deep_scan: false,
            auto_escalate: true,
            start_offset: None,
            end_offset: None,
            fs_type_filter: Vec::new(),
            file_type_filter: Vec::new(),
            on_event: None,
        }
    }
}

impl std::fmt::Debug for ScanOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanOptions")
            .field("deep_scan", &self.deep_scan)
            .field("auto_escalate", &self.auto_escalate)
            .field("start_offset", &self.start_offset)
            .field("end_offset", &self.end_offset)
            .field("fs_type_filter", &self.fs_type_filter)
            .field("file_type_filter", &self.file_type_filter)
            .field("on_event", &self.on_event.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

pub struct Scanner<'a> {
    reader: &'a ImageReader,
}

impl<'a> Scanner<'a> {
    pub fn new(reader: &'a ImageReader) -> Self {
        Self { reader }
    }

    fn emit(options: &ScanOptions, event: ScanEvent) {
        if let Some(ref cb) = options.on_event {
            cb(event);
        }
    }

    /// Detect partition table (MBR or GPT)
    pub fn detect_partitions(&self) -> Result<Vec<Partition>> {
        // Check for GPT first (takes priority over MBR protective)
        if let Some(gpt_parts) = self.try_gpt()? {
            return Ok(gpt_parts);
        }

        // Fall back to MBR
        if let Some(mbr_parts) = self.try_mbr()? {
            return Ok(mbr_parts);
        }

        Ok(Vec::new())
    }

    fn try_mbr(&self) -> Result<Option<Vec<Partition>>> {
        let data = self.reader.read_at(0, 512)?;

        // Check MBR signature
        if data[510] != 0x55 || data[511] != 0xAA {
            return Ok(None);
        }

        let mut partitions = Vec::new();

        for i in 0..4 {
            let offset = 446 + i * 16;
            let part_type = data[offset + 4];
            let lba_start = u32::from_le_bytes(data[offset + 8..offset + 12].try_into()?);
            let lba_count = u32::from_le_bytes(data[offset + 12..offset + 16].try_into()?);

            if part_type != 0 && lba_count > 0 {
                let byte_offset = lba_start as u64 * 512;
                let byte_size = lba_count as u64 * 512;

                let type_name = mbr_type_name(part_type);

                partitions.push(Partition {
                    name: format!("p{}", i + 1),
                    offset: byte_offset,
                    size: byte_size,
                    fs_type: type_name,
                });
            }
        }

        if partitions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(partitions))
        }
    }

    fn try_gpt(&self) -> Result<Option<Vec<Partition>>> {
        // GPT header is at LBA 1 (byte offset 512)
        let header = self.reader.read_at(512, 92)?;

        // Check "EFI PART" signature
        if &header[0..8] != b"EFI PART" {
            return Ok(None);
        }

        let entry_lba = u64::from_le_bytes(header[72..80].try_into()?);
        let entry_count = u32::from_le_bytes(header[80..84].try_into()?);
        let entry_size = u32::from_le_bytes(header[84..88].try_into()?);

        let mut partitions = Vec::new();

        for i in 0..entry_count {
            let offset = entry_lba * 512 + i as u64 * entry_size as u64;
            let entry = self.reader.read_at(offset, entry_size as usize)?;

            // Parse partition type GUID (mixed-endian)
            let type_guid_bytes: [u8; 16] = entry[0..16].try_into()?;
            if type_guid_bytes == [0u8; 16] {
                continue; // empty entry
            }

            let first_lba = u64::from_le_bytes(entry[32..40].try_into()?);
            let last_lba = u64::from_le_bytes(entry[40..48].try_into()?);

            if first_lba == 0 && last_lba == 0 {
                continue;
            }

            // Read partition name (UTF-16LE, 36 chars starting at offset 56)
            let name_bytes = &entry[56..128.min(entry.len())];
            let name: String = name_bytes
                .chunks(2)
                .filter_map(|c| {
                    if c.len() == 2 {
                        let ch = u16::from_le_bytes([c[0], c[1]]);
                        if ch == 0 {
                            None
                        } else {
                            char::from_u32(ch as u32)
                        }
                    } else {
                        None
                    }
                })
                .collect();

            let byte_offset = first_lba * 512;
            let byte_size = (last_lba - first_lba + 1) * 512;

            // Try to detect filesystem type, fall back to GPT type GUID name
            let type_guid = gpt_type_guid_to_string(&type_guid_bytes);
            let fs_type = if let Some(info) = self.detect_filesystem(byte_offset)? {
                info.fs_type
            } else if let Some(name) = gpt_type_name(&type_guid) {
                name.to_string()
            } else {
                format!("unknown ({})", type_guid)
            };

            partitions.push(Partition {
                name: if name.is_empty() {
                    format!("p{}", i + 1)
                } else {
                    name
                },
                offset: byte_offset,
                size: byte_size,
                fs_type,
            });
        }

        if partitions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(partitions))
        }
    }

    /// Try to detect filesystem at a given offset
    pub fn detect_filesystem(&self, offset: u64) -> Result<Option<FsInfo>> {
        // Try ext4
        if let Some(info) = fs::ext4::detect(self.reader, offset) {
            return Ok(Some(info));
        }

        // Try NTFS
        if let Some(info) = fs::ntfs::detect(self.reader, offset) {
            return Ok(Some(info));
        }

        // Try LVM — if found, probe each LV for a filesystem
        if let Some(lvs) = fs::lvm::detect(self.reader, offset) {
            for lv in &lvs {
                if lv.is_thin {
                    tracing::info!(
                        "Skipping thin pool/volume {}/{} — thin provisioning not yet supported. \
                         PE-boundary scan or raw carving may still recover data within the thin pool.",
                        lv.vg_name, lv.name
                    );
                    continue;
                }
                let lvm_map = LvmMap {
                    pe_start_bytes: lv.pe_start_bytes,
                    extent_size_bytes: lv.extent_size_bytes,
                    segments: lv
                        .segments
                        .iter()
                        .map(|s| LvmSegment {
                            start_le: s.start_le,
                            extent_count: s.extent_count,
                            pv_start_pe: s.pv_start_pe,
                        })
                        .collect(),
                };

                if lv.segments.len() == 1 {
                    // Fast path: single segment, compute offset directly
                    let lv_offset = lv.disk_offset().unwrap();
                    if let Some(mut info) = fs::ext4::detect(self.reader, lv_offset) {
                        info.label = format!("{}/{}", lv.vg_name, lv.name);
                        info.total_size = lv.total_size;
                        info.lvm_map = Some(lvm_map);
                        return Ok(Some(info));
                    }
                    if let Some(mut info) = fs::ntfs::detect(self.reader, lv_offset) {
                        info.label = format!("{}/{}", lv.vg_name, lv.name);
                        info.total_size = lv.total_size;
                        info.lvm_map = Some(lvm_map);
                        return Ok(Some(info));
                    }
                } else {
                    // Multi-segment: use LvReader for virtual access
                    let lv_reader = fs::lvm::LvReader::new(self.reader, lv);
                    if let Some(mut info) = fs::ext4::detect(&lv_reader, 0) {
                        info.label = format!("{}/{}", lv.vg_name, lv.name);
                        info.total_size = lv.total_size;
                        info.lvm_map = Some(lvm_map);
                        return Ok(Some(info));
                    }
                }
            }
        }

        // TODO: try xfs, btrfs, etc.

        Ok(None)
    }

    /// Full scan with default options (no deep scan)
    pub fn full_scan(&self) -> Result<ScanReport> {
        self.full_scan_with_options(&ScanOptions::default())
    }

    /// Full scan: detect partitions, then filesystems on each
    pub fn full_scan_with_options(&self, options: &ScanOptions) -> Result<ScanReport> {
        let partitions = self.detect_partitions()?;
        let mut filesystems = Vec::new();

        Self::emit(options, ScanEvent::PhaseStarted {
            phase: ScanPhase::Standard,
            total_bytes: self.reader.len(),
        });

        // Check each partition for a known filesystem at its start
        for part in &partitions {
            tracing::info!(
                "Checking partition {} at offset {}...",
                part.name,
                bytesize::ByteSize(part.offset)
            );
            if let Some(info) = self.detect_filesystem(part.offset)? {
                tracing::info!(
                    "Found {} \"{}\" ({}) on {}",
                    info.fs_type,
                    info.label,
                    bytesize::ByteSize(info.total_size),
                    part.name
                );
                Self::emit(options, ScanEvent::FilesystemFound {
                    fs_type: info.fs_type.clone(),
                    label: info.label.clone(),
                    offset: info.offset,
                    size: info.total_size,
                });
                filesystems.push(info);
            }
        }

        // Also check offset 0 in case it's a raw partition image
        if let Some(info) = self.detect_filesystem(0)? {
            if !filesystems.iter().any(|f| f.offset == 0) {
                filesystems.push(info);
            }
        }

        Self::emit(options, ScanEvent::PhaseComplete {
            phase: ScanPhase::Standard,
            filesystems_found: filesystems.len(),
        });

        // Collect which partitions already have a filesystem detected
        let covered_offsets: Vec<u64> = filesystems.iter().map(|f| f.offset).collect();

        // Escalation: for each partition that DIDN'T have a filesystem at its start,
        // try PE-boundary scan (LVM) then deep scan (1 MiB steps).
        if options.auto_escalate || options.deep_scan {
            for part in &partitions {
                // Skip partitions that already have a detected filesystem
                let has_fs = covered_offsets.iter().any(|&off| {
                    off >= part.offset && off < part.offset + part.size
                });
                if has_fs {
                    continue;
                }

                // PE-boundary scan for LVM partitions
                if options.auto_escalate
                    && (part.fs_type.contains("LVM") || part.fs_type.contains("lvm"))
                {
                    Self::emit(options, ScanEvent::PhaseStarted {
                        phase: ScanPhase::PeBoundary,
                        total_bytes: part.size,
                    });
                    let found = self.pe_boundary_scan(part.offset, part.size, options)?;
                    for info in found {
                        if !filesystems.iter().any(|f| f.offset == info.offset) {
                            Self::emit(options, ScanEvent::FilesystemFound {
                                fs_type: info.fs_type.clone(),
                                label: info.label.clone(),
                                offset: info.offset,
                                size: info.total_size,
                            });
                            filesystems.push(info);
                        }
                    }
                    Self::emit(options, ScanEvent::PhaseComplete {
                        phase: ScanPhase::PeBoundary,
                        filesystems_found: filesystems.len(),
                    });
                }

                // Deep scan if PE-boundary didn't find anything on this partition
                let now_has_fs = filesystems.iter().any(|f| {
                    f.offset >= part.offset && f.offset < part.offset + part.size
                });
                if !now_has_fs {
                    Self::emit(options, ScanEvent::PhaseStarted {
                        phase: ScanPhase::DeepScan,
                        total_bytes: part.size,
                    });
                    let found = self.deep_scan_partition(part.offset, part.size, options)?;
                    for info in found {
                        if !filesystems.iter().any(|f| f.offset == info.offset) {
                            Self::emit(options, ScanEvent::FilesystemFound {
                                fs_type: info.fs_type.clone(),
                                label: info.label.clone(),
                                offset: info.offset,
                                size: info.total_size,
                            });
                            filesystems.push(info);
                        }
                    }
                    Self::emit(options, ScanEvent::PhaseComplete {
                        phase: ScanPhase::DeepScan,
                        filesystems_found: filesystems.len(),
                    });
                }
            }
        }

        if filesystems.is_empty() {
            tracing::info!(
                "No filesystems found after all scan phases. \
                 Raw file carving (recovermax carve) may still recover individual files."
            );
        }

        Ok(ScanReport {
            image_size: self.reader.len(),
            partitions,
            filesystems,
        })
    }

    /// Scan within a partition for filesystems at MB-aligned offsets.
    /// This finds filesystems inside LVM, ZFS, LUKS, etc.
    fn deep_scan_partition(
        &self,
        part_offset: u64,
        part_size: u64,
        options: &ScanOptions,
    ) -> Result<Vec<FsInfo>> {
        let mut found = Vec::new();
        let step: u64 = 1024 * 1024;
        let start = options.start_offset.unwrap_or(part_offset).max(part_offset);
        let end = options.end_offset.unwrap_or(part_offset + part_size).min(part_offset + part_size);

        let mut offset = start;
        let mut bytes_scanned: u64 = 0;

        while offset < end {
            if offset != part_offset {
                if let Some(info) = self.detect_filesystem(offset)? {
                    found.push(info);
                    // Found a filesystem — return immediately rather than
                    // scanning the entire multi-TB partition
                    return Ok(found);
                }
            }

            offset += step;
            bytes_scanned += step;

            if bytes_scanned % (256 * 1024 * 1024) == 0 {
                Self::emit(options, ScanEvent::Progress {
                    phase: ScanPhase::DeepScan,
                    offset,
                    bytes_scanned,
                });
            }
        }

        Ok(found)
    }

    fn pe_boundary_scan(
        &self,
        part_offset: u64,
        part_size: u64,
        options: &ScanOptions,
    ) -> Result<Vec<FsInfo>> {
        let mut found = Vec::new();
        let pe_size: u64 = 4 * 1024 * 1024;
        let pe_start: u64 = 1024 * 1024;
        let end = part_offset + part_size;

        let mut offset = part_offset + pe_start;
        let mut bytes_scanned: u64 = 0;

        while offset < end {
            if let Some(info) = self.detect_filesystem(offset)? {
                found.push(info);
                return Ok(found);
            }
            offset += pe_size;
            bytes_scanned += pe_size;

            if bytes_scanned % (256 * 1024 * 1024) == 0 {
                Self::emit(options, ScanEvent::Progress {
                    phase: ScanPhase::PeBoundary,
                    offset,
                    bytes_scanned,
                });
            }
        }

        Ok(found)
    }
}

fn mbr_type_name(t: u8) -> String {
    match t {
        0x83 => "Linux".into(),
        0x82 => "Linux swap".into(),
        0x07 => "NTFS/HPFS".into(),
        0x0B | 0x0C => "FAT32".into(),
        0x05 | 0x0F => "Extended".into(),
        0xEE => "GPT protective".into(),
        0xFD => "Linux RAID".into(),
        0x8E => "Linux LVM".into(),
        _ => format!("0x{:02x}", t),
    }
}

fn gpt_type_guid_to_string(raw: &[u8; 16]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        u16::from_le_bytes([raw[4], raw[5]]),
        u16::from_le_bytes([raw[6], raw[7]]),
        raw[8], raw[9],
        raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    )
}

fn gpt_type_name(guid: &str) -> Option<&'static str> {
    match guid {
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => Some("Linux LVM"),
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => Some("Linux filesystem"),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => Some("EFI System Partition"),
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => Some("Microsoft basic data"),
        "024DEE41-33E7-11D3-9D69-0008C781F39F" => Some("MBR partition scheme"),
        "21686148-6449-6E6F-744E-656564454649" => Some("BIOS boot"),
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => Some("Linux swap"),
        _ => None,
    }
}
