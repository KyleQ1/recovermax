use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::fs::{self, FsInfo};
use crate::io::ImageReader;

/// Partition table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub fs_type: String,
}

/// Full scan report — serializable to JSON for resuming later
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub image_size: u64,
    pub partitions: Vec<Partition>,
    pub filesystems: Vec<FsInfo>,
}

impl ScanReport {
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Image size: {}\n", bytesize::ByteSize(self.image_size)));
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
                        if ch == 0 { None } else { char::from_u32(ch as u32) }
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
                name: if name.is_empty() { format!("p{}", i + 1) } else { name },
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

        // TODO: try xfs, btrfs, etc.

        Ok(None)
    }

    /// Full scan: detect partitions, then filesystems on each
    pub fn full_scan(&self) -> Result<ScanReport> {
        let partitions = self.detect_partitions()?;
        let mut filesystems = Vec::new();

        // Check each partition for a known filesystem at its start
        for part in &partitions {
            if let Some(info) = self.detect_filesystem(part.offset)? {
                filesystems.push(info);
            }
        }

        // Also check offset 0 in case it's a raw partition image
        if let Some(info) = self.detect_filesystem(0)? {
            if !filesystems.iter().any(|f| f.offset == 0) {
                filesystems.push(info);
            }
        }

        // If we haven't found any filesystems yet, do a deep scan within
        // each partition. This handles LVM/ZFS/LUKS where the filesystem
        // sits at an offset inside the partition, not at its start.
        if filesystems.is_empty() {
            for part in &partitions {
                let found = self.deep_scan_partition(part.offset, part.size)?;
                for info in found {
                    if !filesystems.iter().any(|f| f.offset == info.offset) {
                        filesystems.push(info);
                    }
                }
            }
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

            if steps_done % log_interval == 0 {
                tracing::info!(
                    "Deep scan progress: {} / {} ({:.1}%)",
                    bytesize::ByteSize(offset - part_offset),
                    bytesize::ByteSize(part_size),
                    (steps_done as f64 / total_steps as f64) * 100.0
                );
            }
        }

        tracing::info!(
            "Deep scan complete: found {} filesystem(s)",
            found.len()
        );

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
