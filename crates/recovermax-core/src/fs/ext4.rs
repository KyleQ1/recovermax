use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::io::ImageReader;
use super::{DirEntry, FileType, FsInfo};

// ext4 magic number at offset 0x38 in the superblock
const EXT4_MAGIC: u16 = 0xEF53;
// Superblock is always at byte offset 1024
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Parsed ext4 superblock (subset of fields we care about)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    pub inode_size: u16,
    pub volume_name: String,
    pub uuid: [u8; 16],
    pub feature_incompat: u32,
}

impl Ext4Superblock {
    pub fn block_size(&self) -> u32 {
        1024 << self.log_block_size
    }

    pub fn total_size(&self) -> u64 {
        self.blocks_count * self.block_size() as u64
    }

    pub fn uuid_string(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3],
            self.uuid[4], self.uuid[5],
            self.uuid[6], self.uuid[7],
            self.uuid[8], self.uuid[9],
            self.uuid[10], self.uuid[11], self.uuid[12], self.uuid[13], self.uuid[14], self.uuid[15],
        )
    }

    pub fn has_extents(&self) -> bool {
        self.feature_incompat & 0x40 != 0
    }

    pub fn has_64bit(&self) -> bool {
        self.feature_incompat & 0x02 != 0
    }
}

/// Parse an ext4 superblock from a reader at a given partition offset
pub fn parse_superblock(reader: &ImageReader, partition_offset: u64) -> Result<Ext4Superblock> {
    let sb_offset = partition_offset + SUPERBLOCK_OFFSET;
    let data = reader.read_at(sb_offset, 1024)
        .context("Failed to read superblock")?;

    let magic = u16::from_le_bytes([data[0x38], data[0x39]]);
    if magic != EXT4_MAGIC {
        anyhow::bail!("Not an ext4 filesystem (magic: 0x{:04x}, expected 0x{:04x})", magic, EXT4_MAGIC);
    }

    let inodes_count = u32::from_le_bytes(data[0x00..0x04].try_into()?);
    let blocks_count_lo = u32::from_le_bytes(data[0x04..0x08].try_into()?);
    let free_blocks_lo = u32::from_le_bytes(data[0x0C..0x10].try_into()?);
    let free_inodes_count = u32::from_le_bytes(data[0x10..0x14].try_into()?);
    let first_data_block = u32::from_le_bytes(data[0x14..0x18].try_into()?);
    let log_block_size = u32::from_le_bytes(data[0x18..0x1C].try_into()?);
    let blocks_per_group = u32::from_le_bytes(data[0x20..0x24].try_into()?);
    let inodes_per_group = u32::from_le_bytes(data[0x28..0x2C].try_into()?);
    let inode_size = u16::from_le_bytes([data[0x58], data[0x59]]);
    let feature_incompat = u32::from_le_bytes(data[0x60..0x64].try_into()?);

    // 64-bit block counts
    let blocks_count_hi = u32::from_le_bytes(data[0x150..0x154].try_into()?);
    let free_blocks_hi = u32::from_le_bytes(data[0x158..0x15C].try_into()?);

    let blocks_count = (blocks_count_hi as u64) << 32 | blocks_count_lo as u64;
    let free_blocks_count = (free_blocks_hi as u64) << 32 | free_blocks_lo as u64;

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[0x68..0x78]);

    // Volume name is at offset 0x78, 16 bytes, null-terminated
    let name_bytes = &data[0x78..0x88];
    let volume_name = String::from_utf8_lossy(
        &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(16)]
    ).to_string();

    Ok(Ext4Superblock {
        inodes_count,
        blocks_count,
        free_blocks_count,
        free_inodes_count,
        first_data_block,
        log_block_size,
        blocks_per_group,
        inodes_per_group,
        magic,
        inode_size,
        volume_name,
        uuid,
        feature_incompat,
    })
}

/// Detect if data at offset is an ext4 filesystem
pub fn detect(reader: &ImageReader, offset: u64) -> Option<FsInfo> {
    let sb = parse_superblock(reader, offset).ok()?;

    Some(FsInfo {
        fs_type: "ext4".to_string(),
        label: sb.volume_name.clone(),
        uuid: sb.uuid_string(),
        block_size: sb.block_size(),
        total_size: sb.total_size(),
        offset,
    })
}

/// ext4 filesystem handle for reading inodes, directories, files
pub struct Ext4Fs<'a> {
    reader: &'a ImageReader,
    pub superblock: Ext4Superblock,
    partition_offset: u64,
}

impl<'a> Ext4Fs<'a> {
    pub fn new(reader: &'a ImageReader, partition_offset: u64) -> Result<Self> {
        let superblock = parse_superblock(reader, partition_offset)?;
        Ok(Self {
            reader,
            superblock,
            partition_offset,
        })
    }

    /// Get the byte offset of a block number
    fn block_offset(&self, block: u64) -> u64 {
        self.partition_offset + block * self.superblock.block_size() as u64
    }

    /// Read a full block
    pub fn read_block(&self, block: u64) -> Result<&[u8]> {
        let offset = self.block_offset(block);
        let size = self.superblock.block_size() as usize;
        self.reader.read_at(offset, size)
    }

    /// Get the block group descriptor table offset
    fn bgdt_offset(&self) -> u64 {
        let bs = self.superblock.block_size();
        if bs == 1024 {
            self.partition_offset + 2048 // block 2
        } else {
            self.partition_offset + bs as u64 // block 1
        }
    }

    /// Read block group descriptor for a given group
    pub fn read_group_descriptor(&self, group: u32) -> Result<BlockGroupDescriptor> {
        let desc_size = if self.superblock.has_64bit() { 64 } else { 32 };
        let offset = self.bgdt_offset() + group as u64 * desc_size as u64;
        let data = self.reader.read_at(offset, desc_size)?;

        let inode_table_lo = u32::from_le_bytes(data[8..12].try_into()?);
        let inode_table_hi = if desc_size == 64 {
            u32::from_le_bytes(data[40..44].try_into()?)
        } else {
            0
        };

        Ok(BlockGroupDescriptor {
            inode_table: (inode_table_hi as u64) << 32 | inode_table_lo as u64,
        })
    }

    /// Read an inode by number
    pub fn read_inode(&self, inode_num: u64) -> Result<Inode> {
        if inode_num == 0 {
            anyhow::bail!("Invalid inode 0");
        }

        let inodes_per_group = self.superblock.inodes_per_group as u64;
        let group = ((inode_num - 1) / inodes_per_group) as u32;
        let index = (inode_num - 1) % inodes_per_group;

        let bg = self.read_group_descriptor(group)?;
        let inode_offset = self.block_offset(bg.inode_table)
            + index * self.superblock.inode_size as u64;

        let data = self.reader.read_at(inode_offset, self.superblock.inode_size as usize)?;

        let mode = u16::from_le_bytes(data[0..2].try_into()?);
        let size_lo = u32::from_le_bytes(data[4..8].try_into()?);
        let size_hi = u32::from_le_bytes(data[108..112].try_into()?);
        let size = (size_hi as u64) << 32 | size_lo as u64;
        let links_count = u16::from_le_bytes(data[26..28].try_into()?);
        let flags = u32::from_le_bytes(data[32..36].try_into()?);
        let dtime = u32::from_le_bytes(data[20..24].try_into()?);

        let mut block_data = [0u8; 60];
        block_data.copy_from_slice(&data[40..100]);

        Ok(Inode {
            number: inode_num,
            mode,
            size,
            links_count,
            flags,
            dtime,
            block_data,
        })
    }

    /// List directory entries from an inode
    pub fn list_directory(&self, inode_num: u64) -> Result<Vec<DirEntry>> {
        let inode = self.read_inode(inode_num)?;
        let data = self.read_inode_data(&inode)?;
        parse_directory_entries(&data, &inode)
    }

    /// Read all data blocks for an inode (handles extents and block maps)
    pub fn read_inode_data(&self, inode: &Inode) -> Result<Vec<u8>> {
        if inode.uses_extents() {
            self.read_extent_data(inode)
        } else {
            self.read_block_map_data(inode)
        }
    }

    fn read_extent_data(&self, inode: &Inode) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(inode.size as usize);
        let extents = self.parse_extent_tree(&inode.block_data)?;

        for extent in &extents {
            let offset = self.block_offset(extent.start_block);
            let len = extent.block_count as u64 * self.superblock.block_size() as u64;
            let data = self.reader.read_at(offset, len as usize)?;
            result.extend_from_slice(data);
        }

        result.truncate(inode.size as usize);
        Ok(result)
    }

    fn parse_extent_tree(&self, data: &[u8]) -> Result<Vec<Extent>> {
        // Extent header
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0xF30A {
            anyhow::bail!("Invalid extent tree magic: 0x{:04x}", magic);
        }

        let entries = u16::from_le_bytes([data[2], data[3]]);
        let depth = u16::from_le_bytes([data[6], data[7]]);

        let mut extents = Vec::new();

        if depth == 0 {
            // Leaf node - actual extents
            for i in 0..entries as usize {
                let off = 12 + i * 12;
                if off + 12 > data.len() {
                    break;
                }
                let block_count = u16::from_le_bytes([data[off + 4], data[off + 5]]);
                let start_hi = u16::from_le_bytes([data[off + 6], data[off + 7]]);
                let start_lo = u32::from_le_bytes(data[off + 8..off + 12].try_into()?);
                let start_block = (start_hi as u64) << 32 | start_lo as u64;

                extents.push(Extent {
                    start_block,
                    block_count,
                });
            }
        } else {
            // Index node - recurse
            for i in 0..entries as usize {
                let off = 12 + i * 12;
                if off + 12 > data.len() {
                    break;
                }
                let leaf_hi = u16::from_le_bytes([data[off + 6], data[off + 7]]);
                let leaf_lo = u32::from_le_bytes(data[off + 4..off + 8].try_into()?);
                let leaf_block = (leaf_hi as u64) << 32 | leaf_lo as u64;

                let block_data = self.read_block(leaf_block)?;
                let sub_extents = self.parse_extent_tree(block_data)?;
                extents.extend(sub_extents);
            }
        }

        Ok(extents)
    }

    fn read_block_map_data(&self, inode: &Inode) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(inode.size as usize);
        // Direct blocks (0-11)
        for i in 0..12 {
            let block = u32::from_le_bytes(
                inode.block_data[i * 4..(i + 1) * 4].try_into()?
            ) as u64;

            if block == 0 {
                break;
            }

            let data = self.read_block(block)?;
            result.extend_from_slice(data);

            if result.len() >= inode.size as usize {
                break;
            }
        }

        // TODO: indirect, double-indirect, triple-indirect blocks

        result.truncate(inode.size as usize);
        Ok(result)
    }
}

#[derive(Debug)]
pub struct BlockGroupDescriptor {
    pub inode_table: u64,
}

#[derive(Debug)]
pub struct Inode {
    pub number: u64,
    pub mode: u16,
    pub size: u64,
    pub links_count: u16,
    pub flags: u32,
    pub dtime: u32,
    pub block_data: [u8; 60],
}

impl Inode {
    pub fn is_directory(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }

    pub fn is_regular_file(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }

    pub fn is_deleted(&self) -> bool {
        self.dtime != 0 || self.links_count == 0
    }

    pub fn uses_extents(&self) -> bool {
        self.flags & 0x80000 != 0
    }

    pub fn file_type(&self) -> FileType {
        match self.mode & 0xF000 {
            0x4000 => FileType::Directory,
            0x8000 => FileType::RegularFile,
            0xA000 => FileType::Symlink,
            _ => FileType::Other,
        }
    }
}

#[derive(Debug)]
pub struct Extent {
    pub start_block: u64,
    pub block_count: u16,
}

fn parse_directory_entries(data: &[u8], _parent_inode: &Inode) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos + 8 <= data.len() {
        let inode = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as u64;
        let rec_len = u16::from_le_bytes(data[pos + 4..pos + 6].try_into()?) as usize;
        let name_len = data[pos + 6] as usize;
        let file_type_byte = data[pos + 7];

        if rec_len == 0 || pos + rec_len > data.len() {
            break;
        }

        if inode != 0 && name_len > 0 && pos + 8 + name_len <= data.len() {
            let name = String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();

            let file_type = match file_type_byte {
                1 => FileType::RegularFile,
                2 => FileType::Directory,
                7 => FileType::Symlink,
                _ => FileType::Other,
            };

            entries.push(DirEntry {
                inode,
                name,
                file_type,
                size: 0, // filled in later by reading the inode
                deleted: false,
            });
        } else if inode == 0 && name_len > 0 && pos + 8 + name_len <= data.len() {
            // Deleted entry - inode zeroed out but name may remain
            let name = String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();
            entries.push(DirEntry {
                inode: 0,
                name,
                file_type: FileType::Other,
                size: 0,
                deleted: true,
            });
        }

        pos += rec_len;
    }

    Ok(entries)
}
