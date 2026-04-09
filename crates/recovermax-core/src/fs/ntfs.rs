use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{DirEntry, EntrySource, FileType, FsInfo};
use crate::io::ImageReader;

/// NTFS OEM ID at offset 3 in the boot sector
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

/// MFT entry magic number
const MFT_ENTRY_MAGIC: &[u8; 4] = b"FILE";

/// MFT entry size (standard)
const MFT_ENTRY_SIZE: usize = 1024;

/// Filename attribute type
const ATTR_TYPE_FILENAME: u32 = 0x30;

/// Data attribute type
const ATTR_TYPE_DATA: u32 = 0x80;

/// End-of-attributes marker
const ATTR_TYPE_END: u32 = 0xFFFF_FFFF;

/// Parsed NTFS boot sector (subset of fields we care about)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_cluster: u64,
    pub mft_mirror_cluster: u64,
    pub clusters_per_mft_record: i8,
}

impl NtfsBootSector {
    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    pub fn mft_entry_size(&self) -> u32 {
        if self.clusters_per_mft_record > 0 {
            self.clusters_per_mft_record as u32 * self.cluster_size()
        } else {
            // Negative value means 2^|value| bytes
            1u32 << (-self.clusters_per_mft_record as u32)
        }
    }

    pub fn total_size(&self) -> u64 {
        self.total_sectors * self.bytes_per_sector as u64
    }

    pub fn mft_byte_offset(&self) -> u64 {
        self.mft_cluster * self.cluster_size() as u64
    }
}

/// Parse an NTFS boot sector from a reader at a given partition offset
pub fn parse_boot_sector(reader: &ImageReader, partition_offset: u64) -> Result<NtfsBootSector> {
    let data = reader
        .read_at(partition_offset, 512)
        .context("Failed to read NTFS boot sector")?;

    if data.len() < 512 {
        anyhow::bail!("Boot sector too small: {} bytes", data.len());
    }

    // Check OEM ID at offset 3
    if &data[3..11] != NTFS_OEM_ID {
        anyhow::bail!(
            "Not an NTFS filesystem (OEM ID: {:?}, expected {:?})",
            &data[3..11],
            NTFS_OEM_ID
        );
    }

    let bytes_per_sector = u16::from_le_bytes([data[0x0B], data[0x0C]]);
    let sectors_per_cluster = data[0x0D];
    let total_sectors = u64::from_le_bytes(data[0x28..0x30].try_into()?);
    let mft_cluster = u64::from_le_bytes(data[0x30..0x38].try_into()?);
    let mft_mirror_cluster = u64::from_le_bytes(data[0x38..0x40].try_into()?);
    let clusters_per_mft_record = data[0x40] as i8;

    // Sanity checks
    if bytes_per_sector == 0 || !bytes_per_sector.is_power_of_two() {
        anyhow::bail!("Invalid bytes per sector: {}", bytes_per_sector);
    }
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
        anyhow::bail!("Invalid sectors per cluster: {}", sectors_per_cluster);
    }

    Ok(NtfsBootSector {
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors,
        mft_cluster,
        mft_mirror_cluster,
        clusters_per_mft_record,
    })
}

/// Detect if data at offset is an NTFS filesystem
pub fn detect(reader: &ImageReader, offset: u64) -> Option<FsInfo> {
    let bs = parse_boot_sector(reader, offset).ok()?;

    Some(FsInfo {
        fs_type: "ntfs".to_string(),
        label: String::new(), // NTFS volume label is in the MFT, not the boot sector
        uuid: String::new(),
        block_size: bs.cluster_size(),
        total_size: bs.total_size(),
        offset,
        lvm_map: None,
        root_readable: true,
    })
}

/// A parsed MFT file entry
#[derive(Debug, Clone)]
pub struct MftEntry {
    /// MFT entry number
    pub entry_number: u64,
    /// Entry flags (0x01 = in use, 0x02 = directory)
    pub flags: u16,
    /// Filename from the $FILE_NAME attribute (if found)
    pub filename: Option<String>,
    /// Filename namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS)
    pub filename_namespace: u8,
    /// Parent directory MFT entry number (from $FILE_NAME)
    pub parent_entry: u64,
    /// File size from $DATA attribute (logical size)
    pub file_size: u64,
    /// Data runs from $DATA attribute (for non-resident data)
    pub data_runs: Vec<DataRun>,
    /// Resident data from $DATA (for small files stored inline)
    pub resident_data: Option<Vec<u8>>,
}

impl MftEntry {
    pub fn is_in_use(&self) -> bool {
        self.flags & 0x01 != 0
    }

    pub fn is_directory(&self) -> bool {
        self.flags & 0x02 != 0
    }

    pub fn file_type(&self) -> FileType {
        if self.is_directory() {
            FileType::Directory
        } else {
            FileType::RegularFile
        }
    }
}

/// A single data run (extent) decoded from NTFS non-resident attribute
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    /// Starting cluster (absolute, after delta accumulation)
    pub cluster_offset: u64,
    /// Number of clusters in this run
    pub cluster_count: u64,
}

/// Decode NTFS data runs from raw bytes.
///
/// Data runs are variable-length encoded pairs: each starts with a header byte
/// where the low nibble is the byte count for the length field and the high
/// nibble is the byte count for the offset field. The offset is a signed delta
/// from the previous run's start.
pub fn decode_data_runs(data: &[u8]) -> Result<Vec<DataRun>> {
    let mut runs = Vec::new();
    let mut pos = 0;
    let mut prev_offset: i64 = 0;

    while pos < data.len() {
        let header = data[pos];
        if header == 0 {
            break; // end of data runs
        }

        let length_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4) & 0x0F) as usize;

        if length_size == 0 || pos + 1 + length_size + offset_size > data.len() {
            break;
        }

        pos += 1;

        // Read cluster count (unsigned)
        let mut cluster_count: u64 = 0;
        for i in 0..length_size {
            cluster_count |= (data[pos + i] as u64) << (i * 8);
        }
        pos += length_size;

        if offset_size == 0 {
            // Sparse run — no physical clusters allocated
            // Skip it (we don't produce a DataRun for sparse extents)
            continue;
        }

        // Read cluster offset delta (signed)
        let mut offset_delta: i64 = 0;
        for i in 0..offset_size {
            offset_delta |= (data[pos + i] as i64) << (i * 8);
        }
        // Sign-extend if the high bit of the last byte is set
        if data[pos + offset_size - 1] & 0x80 != 0 {
            for i in offset_size..8 {
                offset_delta |= 0xFFi64 << (i * 8);
            }
        }
        pos += offset_size;

        prev_offset += offset_delta;
        if prev_offset < 0 {
            anyhow::bail!("Data run offset went negative: {}", prev_offset);
        }

        runs.push(DataRun {
            cluster_offset: prev_offset as u64,
            cluster_count,
        });
    }

    Ok(runs)
}

/// Parse an MFT entry from raw bytes
pub fn parse_mft_entry(data: &[u8], entry_number: u64) -> Result<MftEntry> {
    if data.len() < 42 {
        anyhow::bail!("MFT entry too small: {} bytes", data.len());
    }

    // Check magic
    if &data[0..4] != MFT_ENTRY_MAGIC {
        anyhow::bail!(
            "Not an MFT entry (magic: {:02x}{:02x}{:02x}{:02x}, expected FILE)",
            data[0],
            data[1],
            data[2],
            data[3]
        );
    }

    // Apply fixup array to get correct data
    let fixup_offset = u16::from_le_bytes([data[0x04], data[0x05]]) as usize;
    let fixup_count = u16::from_le_bytes([data[0x06], data[0x07]]) as usize;
    let mut fixed = data.to_vec();

    if fixup_count > 1 && fixup_offset + fixup_count * 2 <= data.len() {
        let signature = u16::from_le_bytes([data[fixup_offset], data[fixup_offset + 1]]);
        for i in 1..fixup_count {
            let target = i * 512 - 2;
            if target + 1 < fixed.len() {
                // Verify the signature matches what's at the end of each sector
                let found = u16::from_le_bytes([fixed[target], fixed[target + 1]]);
                if found == signature {
                    let replacement_offset = fixup_offset + i * 2;
                    if replacement_offset + 1 < data.len() {
                        fixed[target] = data[replacement_offset];
                        fixed[target + 1] = data[replacement_offset + 1];
                    }
                }
            }
        }
    }

    let flags = u16::from_le_bytes([fixed[0x16], fixed[0x17]]);
    let first_attr_offset = u16::from_le_bytes([fixed[0x14], fixed[0x15]]) as usize;

    let mut filename = None;
    let mut filename_namespace: u8 = 0;
    let mut parent_entry: u64 = 0;
    let mut file_size: u64 = 0;
    let mut data_runs = Vec::new();
    let mut resident_data = None;

    // Walk attributes
    let mut attr_pos = first_attr_offset;
    while attr_pos + 16 <= fixed.len() {
        let attr_type = u32::from_le_bytes(fixed[attr_pos..attr_pos + 4].try_into()?);
        if attr_type == ATTR_TYPE_END {
            break;
        }

        let attr_len = u32::from_le_bytes(fixed[attr_pos + 4..attr_pos + 8].try_into()?) as usize;
        if attr_len == 0 || attr_pos + attr_len > fixed.len() {
            break;
        }

        let non_resident = fixed[attr_pos + 8];

        match attr_type {
            ATTR_TYPE_FILENAME => {
                if non_resident == 0 {
                    // Resident filename attribute
                    let content_offset =
                        u16::from_le_bytes([fixed[attr_pos + 0x14], fixed[attr_pos + 0x15]])
                            as usize;
                    let content_start = attr_pos + content_offset;

                    if content_start + 66 <= fixed.len() {
                        // Parent directory reference (first 6 bytes of 8-byte ref)
                        let parent_ref_bytes = &fixed[content_start..content_start + 6];
                        let mut parent_ref = [0u8; 8];
                        parent_ref[..6].copy_from_slice(parent_ref_bytes);
                        parent_entry = u64::from_le_bytes(parent_ref) & 0x0000_FFFF_FFFF_FFFF;

                        let ns = fixed[content_start + 0x41];
                        let name_length = fixed[content_start + 0x40] as usize;
                        let name_start = content_start + 0x42;

                        if name_start + name_length * 2 <= fixed.len() {
                            // Decode UTF-16LE filename
                            let name: String = fixed[name_start..name_start + name_length * 2]
                                .chunks(2)
                                .filter_map(|c| {
                                    if c.len() == 2 {
                                        let ch = u16::from_le_bytes([c[0], c[1]]);
                                        char::from_u32(ch as u32)
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            // Prefer Win32 or Win32+DOS names over DOS-only names
                            if filename.is_none() || ns != 2 {
                                filename = Some(name);
                                filename_namespace = ns;
                            }
                        }
                    }
                }
            }
            ATTR_TYPE_DATA => {
                if non_resident == 0 {
                    // Resident data — small file stored inline
                    let content_len =
                        u32::from_le_bytes(fixed[attr_pos + 0x10..attr_pos + 0x14].try_into()?)
                            as usize;
                    let content_offset =
                        u16::from_le_bytes([fixed[attr_pos + 0x14], fixed[attr_pos + 0x15]])
                            as usize;
                    let content_start = attr_pos + content_offset;
                    let content_end = content_start + content_len;

                    if content_end <= fixed.len() {
                        resident_data = Some(fixed[content_start..content_end].to_vec());
                        file_size = content_len as u64;
                    }
                } else {
                    // Non-resident data — read size and data runs
                    if attr_pos + 0x38 <= fixed.len() {
                        file_size =
                            u64::from_le_bytes(fixed[attr_pos + 0x30..attr_pos + 0x38].try_into()?);
                    }

                    let run_offset =
                        u16::from_le_bytes([fixed[attr_pos + 0x20], fixed[attr_pos + 0x21]])
                            as usize;
                    let run_start = attr_pos + run_offset;
                    let run_end = attr_pos + attr_len;

                    if run_start < run_end && run_end <= fixed.len() {
                        data_runs = decode_data_runs(&fixed[run_start..run_end])?;
                    }
                }
            }
            _ => {}
        }

        attr_pos += attr_len;
    }

    Ok(MftEntry {
        entry_number,
        flags,
        filename,
        filename_namespace,
        parent_entry,
        file_size,
        data_runs,
        resident_data,
    })
}

/// NTFS filesystem handle for reading MFT entries and file data
pub struct NtfsFs<'a> {
    reader: &'a ImageReader,
    pub boot_sector: NtfsBootSector,
    partition_offset: u64,
}

impl<'a> NtfsFs<'a> {
    pub fn new(reader: &'a ImageReader, partition_offset: u64) -> Result<Self> {
        let boot_sector = parse_boot_sector(reader, partition_offset)?;
        Ok(Self {
            reader,
            boot_sector,
            partition_offset,
        })
    }

    /// Get the byte offset of a cluster number within this partition
    fn cluster_offset(&self, cluster: u64) -> u64 {
        self.partition_offset + cluster * self.boot_sector.cluster_size() as u64
    }

    /// Read a single MFT entry by entry number
    pub fn read_mft_entry(&self, entry_number: u64) -> Result<MftEntry> {
        let entry_size = self.boot_sector.mft_entry_size() as u64;
        let mft_offset = self.cluster_offset(self.boot_sector.mft_cluster);
        let entry_offset = mft_offset + entry_number * entry_size;

        let data = self
            .reader
            .read_at(entry_offset, entry_size as usize)
            .with_context(|| format!("Failed to read MFT entry {}", entry_number))?;

        parse_mft_entry(data, entry_number)
    }

    /// NTFS root directory is always MFT entry 5
    pub const ROOT_ENTRY: u64 = 5;

    /// List files in a directory by scanning MFT entries whose parent matches dir_entry
    pub fn list_directory(&self, dir_entry: u64) -> Result<Vec<DirEntry>> {
        let entry_size = self.boot_sector.mft_entry_size() as u64;
        let mft_offset = self.cluster_offset(self.boot_sector.mft_cluster);
        let mut entries = Vec::new();

        // Add . and .. entries
        entries.push(DirEntry {
            inode: dir_entry,
            name: ".".to_string(),
            file_type: FileType::Directory,
            size: 0,
            deleted: false,
            source: EntrySource::Filesystem,
            parent_inode: Some(dir_entry),
        });

        // For root, parent is self
        let parent = if dir_entry == Self::ROOT_ENTRY {
            Self::ROOT_ENTRY
        } else {
            match self.read_mft_entry(dir_entry) {
                Ok(e) => e.parent_entry,
                Err(_) => Self::ROOT_ENTRY,
            }
        };
        entries.push(DirEntry {
            inode: parent,
            name: "..".to_string(),
            file_type: FileType::Directory,
            size: 0,
            deleted: false,
            source: EntrySource::Filesystem,
            parent_inode: Some(dir_entry),
        });

        // Scan MFT entries whose parent_entry matches dir_entry
        let max_entries = 4096;
        for i in 0..max_entries {
            let offset = mft_offset + i * entry_size;
            let data = match self.reader.read_at(offset, entry_size as usize) {
                Ok(d) => d,
                Err(_) => break,
            };

            if data.len() < MFT_ENTRY_SIZE || &data[0..4] != MFT_ENTRY_MAGIC {
                continue;
            }

            let entry = match parse_mft_entry(data, i) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.is_in_use() || entry.parent_entry != dir_entry {
                continue;
            }

            let name = match &entry.filename {
                Some(n) => n.clone(),
                None => continue,
            };

            // Skip NTFS metafiles and DOS-only names
            if name.starts_with('$') || entry.filename_namespace == 2 {
                continue;
            }

            entries.push(DirEntry {
                inode: entry.entry_number,
                name,
                file_type: entry.file_type(),
                size: entry.file_size,
                deleted: false,
                source: EntrySource::Filesystem,
                parent_inode: Some(dir_entry),
            });
        }

        Ok(entries)
    }

    /// List files in root directory
    pub fn list_root(&self) -> Result<Vec<DirEntry>> {
        self.list_directory(Self::ROOT_ENTRY)
    }

    /// Read file data for a given MFT entry number
    pub fn read_file(&self, entry_number: u64) -> Result<Vec<u8>> {
        let entry = self.read_mft_entry(entry_number)?;

        // Resident data — small files stored inline in the MFT entry
        if let Some(data) = entry.resident_data {
            return Ok(data);
        }

        // Non-resident data — follow data runs
        if entry.data_runs.is_empty() {
            return Ok(Vec::new());
        }

        let cluster_size = self.boot_sector.cluster_size() as u64;
        let mut result = Vec::with_capacity(entry.file_size as usize);

        for run in &entry.data_runs {
            let offset = self.cluster_offset(run.cluster_offset);
            let len = run.cluster_count * cluster_size;
            let data = self.reader.read_at(offset, len as usize).with_context(|| {
                format!(
                    "Failed to read data run at cluster {} ({} clusters)",
                    run.cluster_offset, run.cluster_count
                )
            })?;
            result.extend_from_slice(data);
        }

        result.truncate(entry.file_size as usize);
        Ok(result)
    }
}
