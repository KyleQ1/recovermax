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
            out.push_str(&format!(
                "  [{}] {} at offset {} — {} ({})\n",
                i,
                fs.fs_type,
                bytesize::ByteSize(fs.offset),
                fs.label,
                bytesize::ByteSize(fs.total_size),
            ));
        }

        out
    }
}

/// Options to control scan behavior
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Run deep scan within partitions (walks every 1 MiB offset).
    /// Off by default — for multi-TB images this can take a very long time.
    pub deep_scan: bool,
    /// Auto-escalate: when standard detection finds nothing, try PE-boundary
    /// scanning (4 MiB steps for LVM partitions) then deep scan (1 MiB steps).
    /// Default: true.
    pub auto_escalate: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            deep_scan: false,
            auto_escalate: true,
        }
    }
}

pub struct Scanner<'a> {
    reader: &'a ImageReader,
}

impl<'a> Scanner<'a> {
    pub fn new(reader: &'a ImageReader) -> Self {
        Self { reader }
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

            // Try to detect filesystem type on this partition
            let fs_type = if let Some(info) = self.detect_filesystem(byte_offset)? {
                info.fs_type
            } else {
                "unknown".to_string()
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
                filesystems.push(info);
            }
        }

        // Also check offset 0 in case it's a raw partition image
        if let Some(info) = self.detect_filesystem(0)? {
            if !filesystems.iter().any(|f| f.offset == 0) {
                filesystems.push(info);
            }
        }

        // Escalation pipeline when nothing found at partition starts
        if filesystems.is_empty() && options.auto_escalate {
            // Phase 2: PE-boundary scan for LVM partitions (4 MiB steps — fast)
            for part in &partitions {
                if part.fs_type.contains("LVM") || part.fs_type.contains("lvm") {
                    tracing::info!(
                        "No filesystems found via LVM metadata on {}, trying PE-boundary scan...",
                        part.name
                    );
                    let found = self.pe_boundary_scan(part.offset, part.size)?;
                    for info in found {
                        if !filesystems.iter().any(|f| f.offset == info.offset) {
                            filesystems.push(info);
                        }
                    }
                }
            }
        }

        if filesystems.is_empty() && (options.deep_scan || options.auto_escalate) {
            // Phase 3: Deep scan at 1 MiB steps (slow but thorough)
            tracing::info!("No filesystems found, running deep scan...");
            for part in &partitions {
                let found = self.deep_scan_partition(part.offset, part.size)?;
                for info in found {
                    if !filesystems.iter().any(|f| f.offset == info.offset) {
                        filesystems.push(info);
                    }
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
    fn deep_scan_partition(&self, part_offset: u64, part_size: u64) -> Result<Vec<FsInfo>> {
        let mut found = Vec::new();
        let step: u64 = 1024 * 1024; // 1 MiB steps
        let end = part_offset + part_size;
        let total_steps = part_size / step;
        let log_interval = 10 * 1024; // Log every ~10 GiB (10240 MB steps)

        tracing::info!(
            "Deep scanning partition at offset {} ({}) for embedded filesystems...",
            part_offset,
            bytesize::ByteSize(part_size)
        );

        let mut offset = part_offset;
        let mut steps_done: u64 = 0;
        while offset < end {
            // Don't re-check the partition start (already done above)
            if offset != part_offset {
                if let Some(info) = self.detect_filesystem(offset)? {
                    tracing::info!(
                        "Found {} filesystem \"{}\" at offset {} ({})",
                        info.fs_type,
                        info.label,
                        offset,
                        bytesize::ByteSize(offset)
                    );
                    found.push(info);
                }
            }

            offset += step;
            steps_done += 1;

            if steps_done.is_multiple_of(log_interval) {
                tracing::info!(
                    "Deep scan progress: {} / {} ({:.1}%)",
                    bytesize::ByteSize(offset - part_offset),
                    bytesize::ByteSize(part_size),
                    (steps_done as f64 / total_steps as f64) * 100.0
                );
            }
        }

        tracing::info!("Deep scan complete: found {} filesystem(s)", found.len());

        Ok(found)
    }

    /// Scan at PE-boundary offsets (every 4 MiB from pe_start) for ext4 superblocks.
    /// Faster than deep scan for LVM partitions where metadata is destroyed.
    fn pe_boundary_scan(&self, part_offset: u64, part_size: u64) -> Result<Vec<FsInfo>> {
        let mut found = Vec::new();
        let pe_size: u64 = 4 * 1024 * 1024; // default 4 MiB PE
        let pe_start: u64 = 1024 * 1024; // default 1 MiB into partition
        let end = part_offset + part_size;

        let mut offset = part_offset + pe_start;
        let mut pe_index = 0u64;

        tracing::info!(
            "PE-boundary scan: partition at {}, pe_start={}, pe_size={}, scanning up to {}...",
            bytesize::ByteSize(part_offset),
            bytesize::ByteSize(pe_start),
            bytesize::ByteSize(pe_size),
            bytesize::ByteSize(part_size)
        );

        while offset < end {
            if let Some(info) = self.detect_filesystem(offset)? {
                tracing::info!(
                    "Found {} filesystem \"{}\" at PE boundary {} (offset {})",
                    info.fs_type,
                    info.label,
                    pe_index,
                    bytesize::ByteSize(offset)
                );
                found.push(info);
                return Ok(found);
            }
            offset += pe_size;
            pe_index += 1;

            if pe_index.is_multiple_of(1000) {
                tracing::info!("PE scan: checked {} extents...", pe_index);
            }
        }

        tracing::info!("PE-boundary scan complete: found {} filesystem(s)", found.len());
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
