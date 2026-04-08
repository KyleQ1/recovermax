use std::io::Write;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{DirEntry, EntrySource, FileType, FsInfo};
use crate::io::ImageReader;

/// A deleted inode found by scanning inode tables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedInode {
    pub inode_num: u64,
    pub size: u64,
    pub file_type: FileType,
    pub dtime: u32,
    pub mode: u16,
    pub ctime: u32,
    pub mtime: u32,
    pub atime: u32,
}

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
        self.feature_incompat & 0x80 != 0
    }
}

/// Parse an ext4 superblock from a reader at a given partition offset
pub fn parse_superblock(reader: &ImageReader, partition_offset: u64) -> Result<Ext4Superblock> {
    let sb_offset = partition_offset + SUPERBLOCK_OFFSET;
    let data = reader
        .read_at(sb_offset, 1024)
        .context("Failed to read superblock")?;

    let magic = u16::from_le_bytes([data[0x38], data[0x39]]);
    if magic != EXT4_MAGIC {
        anyhow::bail!(
            "Not an ext4 filesystem (magic: 0x{:04x}, expected 0x{:04x})",
            magic,
            EXT4_MAGIC
        );
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
        &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(16)],
    )
    .to_string();

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
        let inode_offset =
            self.block_offset(bg.inode_table) + index * self.superblock.inode_size as u64;

        let data = self
            .reader
            .read_at(inode_offset, self.superblock.inode_size as usize)?;

        let mode = u16::from_le_bytes(data[0..2].try_into()?);
        let atime = u32::from_le_bytes(data[8..12].try_into()?);
        let ctime = u32::from_le_bytes(data[12..16].try_into()?);
        let mtime = u32::from_le_bytes(data[16..20].try_into()?);
        let size_lo = u32::from_le_bytes(data[4..8].try_into()?);
        let size_hi = u32::from_le_bytes(data[108..112].try_into()?);
        let file_type = match mode & 0xF000 {
            0x8000 => FileType::RegularFile,
            0x4000 => FileType::Directory,
            0xA000 => FileType::Symlink,
            _ => FileType::Other,
        };
        // On ext2/ext3, i_dir_acl overlaps the high 32 bits of i_size for non-regular files.
        let size = if file_type == FileType::RegularFile {
            (size_hi as u64) << 32 | size_lo as u64
        } else {
            size_lo as u64
        };
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
            ctime,
            mtime,
            atime,
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
        let target_size = inode.size as usize;
        let bs = self.superblock.block_size() as usize;
        let mut result = Vec::with_capacity(target_size.min(bs * 12));

        // Direct blocks (entries 0-11)
        for i in 0..12 {
            if result.len() >= target_size {
                break;
            }
            let block = u32::from_le_bytes(inode.block_data[i * 4..(i + 1) * 4].try_into()?) as u64;
            self.append_block_or_hole(&mut result, block)?;
        }

        // Indirect block (entry 12)
        if result.len() < target_size {
            let indirect_block = u32::from_le_bytes(inode.block_data[48..52].try_into()?) as u64;
            if indirect_block != 0 {
                self.read_indirect(&mut result, indirect_block, target_size)?;
            }
        }

        // Double-indirect block (entry 13)
        if result.len() < target_size {
            let dind_block = u32::from_le_bytes(inode.block_data[52..56].try_into()?) as u64;
            if dind_block != 0 {
                self.read_double_indirect(&mut result, dind_block, target_size)?;
            }
        }

        // Triple-indirect block (entry 14)
        if result.len() < target_size {
            let tind_block = u32::from_le_bytes(inode.block_data[56..60].try_into()?) as u64;
            if tind_block != 0 {
                self.read_triple_indirect(&mut result, tind_block, target_size)?;
            }
        }

        result.truncate(target_size);
        Ok(result)
    }

    /// Append one block of data, or a block-sized hole if block == 0 (sparse file).
    fn append_block_or_hole(&self, result: &mut Vec<u8>, block: u64) -> Result<()> {
        if block == 0 {
            result.extend(std::iter::repeat(0u8).take(self.superblock.block_size() as usize));
        } else {
            let data = self.read_block(block)?;
            result.extend_from_slice(data);
        }
        Ok(())
    }

    /// Read block pointers from an indirect block and append data.
    fn read_indirect(
        &self,
        result: &mut Vec<u8>,
        indirect_block: u64,
        target_size: usize,
    ) -> Result<()> {
        let ptrs = self.read_block(indirect_block)?;
        let ptrs_per_block = self.superblock.block_size() as usize / 4;

        for i in 0..ptrs_per_block {
            if result.len() >= target_size {
                break;
            }
            let block = u32::from_le_bytes(ptrs[i * 4..(i + 1) * 4].try_into()?) as u64;
            self.append_block_or_hole(result, block)?;
        }
        Ok(())
    }

    /// Read from a double-indirect block.
    fn read_double_indirect(
        &self,
        result: &mut Vec<u8>,
        dind_block: u64,
        target_size: usize,
    ) -> Result<()> {
        let ptrs = self.read_block(dind_block)?;
        let ptrs_per_block = self.superblock.block_size() as usize / 4;

        for i in 0..ptrs_per_block {
            if result.len() >= target_size {
                break;
            }
            let ind_block = u32::from_le_bytes(ptrs[i * 4..(i + 1) * 4].try_into()?) as u64;
            if ind_block != 0 {
                self.read_indirect(result, ind_block, target_size)?;
            }
        }
        Ok(())
    }

    /// Read from a triple-indirect block.
    fn read_triple_indirect(
        &self,
        result: &mut Vec<u8>,
        tind_block: u64,
        target_size: usize,
    ) -> Result<()> {
        let ptrs = self.read_block(tind_block)?;
        let ptrs_per_block = self.superblock.block_size() as usize / 4;

        for i in 0..ptrs_per_block {
            if result.len() >= target_size {
                break;
            }
            let dind_block = u32::from_le_bytes(ptrs[i * 4..(i + 1) * 4].try_into()?) as u64;
            if dind_block != 0 {
                self.read_double_indirect(result, dind_block, target_size)?;
            }
        }
        Ok(())
    }

    /// Stream inode data to a writer incrementally, avoiding buffering the entire file.
    /// Handles both extents and block maps (including indirect blocks).
    pub fn stream_inode_data(&self, inode: &Inode, writer: &mut impl Write) -> Result<u64> {
        if inode.uses_extents() {
            self.stream_extent_data(inode, writer)
        } else {
            self.stream_block_map_data(inode, writer)
        }
    }

    fn stream_extent_data(&self, inode: &Inode, writer: &mut impl Write) -> Result<u64> {
        let target_size = inode.size;
        let mut written: u64 = 0;
        let extents = self.parse_extent_tree(&inode.block_data)?;

        for extent in &extents {
            if written >= target_size {
                break;
            }
            let offset = self.block_offset(extent.start_block);
            let len = extent.block_count as u64 * self.superblock.block_size() as u64;
            let data = self.reader.read_at(offset, len as usize)?;

            let to_write = (target_size - written).min(data.len() as u64) as usize;
            writer.write_all(&data[..to_write])?;
            written += to_write as u64;
        }

        Ok(written)
    }

    fn stream_block_map_data(&self, inode: &Inode, writer: &mut impl Write) -> Result<u64> {
        let target_size = inode.size;
        let mut written: u64 = 0;

        // Direct blocks (entries 0-11)
        for i in 0..12 {
            if written >= target_size {
                return Ok(written);
            }
            let block = u32::from_le_bytes(inode.block_data[i * 4..(i + 1) * 4].try_into()?) as u64;
            written = self.stream_block_or_hole(writer, block, written, target_size)?;
        }

        // Indirect block (entry 12)
        if written < target_size {
            let indirect_block = u32::from_le_bytes(inode.block_data[48..52].try_into()?) as u64;
            if indirect_block != 0 {
                written = self.stream_indirect(writer, indirect_block, written, target_size)?;
            }
        }

        // Double-indirect block (entry 13)
        if written < target_size {
            let dind_block = u32::from_le_bytes(inode.block_data[52..56].try_into()?) as u64;
            if dind_block != 0 {
                written = self.stream_double_indirect(writer, dind_block, written, target_size)?;
            }
        }

        // Triple-indirect block (entry 14)
        if written < target_size {
            let tind_block = u32::from_le_bytes(inode.block_data[56..60].try_into()?) as u64;
            if tind_block != 0 {
                written = self.stream_triple_indirect(writer, tind_block, written, target_size)?;
            }
        }

        Ok(written)
    }

    /// Write one block to the writer, or a block-sized hole (zeros) if block == 0.
    /// Returns the new total bytes written, capped at target_size.
    fn stream_block_or_hole(
        &self,
        writer: &mut impl Write,
        block: u64,
        written: u64,
        target_size: u64,
    ) -> Result<u64> {
        let bs = self.superblock.block_size() as u64;
        let remaining = target_size - written;
        let to_write = bs.min(remaining) as usize;

        if block == 0 {
            // Sparse hole — write zeros. Use a stack buffer to avoid allocation.
            let zeros = [0u8; 4096];
            let mut left = to_write;
            while left > 0 {
                let chunk = left.min(zeros.len());
                writer.write_all(&zeros[..chunk])?;
                left -= chunk;
            }
        } else {
            let data = self.read_block(block)?;
            writer.write_all(&data[..to_write])?;
        }

        Ok(written + to_write as u64)
    }

    fn stream_indirect(
        &self,
        writer: &mut impl Write,
        indirect_block: u64,
        mut written: u64,
        target_size: u64,
    ) -> Result<u64> {
        let ptrs = self.read_block(indirect_block)?;
        let ptrs_per_block = self.superblock.block_size() as usize / 4;

        for i in 0..ptrs_per_block {
            if written >= target_size {
                break;
            }
            let block = u32::from_le_bytes(ptrs[i * 4..(i + 1) * 4].try_into()?) as u64;
            written = self.stream_block_or_hole(writer, block, written, target_size)?;
        }
        Ok(written)
    }

    fn stream_double_indirect(
        &self,
        writer: &mut impl Write,
        dind_block: u64,
        mut written: u64,
        target_size: u64,
    ) -> Result<u64> {
        let ptrs = self.read_block(dind_block)?;
        let ptrs_per_block = self.superblock.block_size() as usize / 4;

        for i in 0..ptrs_per_block {
            if written >= target_size {
                break;
            }
            let ind_block = u32::from_le_bytes(ptrs[i * 4..(i + 1) * 4].try_into()?) as u64;
            if ind_block != 0 {
                written = self.stream_indirect(writer, ind_block, written, target_size)?;
            }
        }
        Ok(written)
    }

    fn stream_triple_indirect(
        &self,
        writer: &mut impl Write,
        tind_block: u64,
        mut written: u64,
        target_size: u64,
    ) -> Result<u64> {
        let ptrs = self.read_block(tind_block)?;
        let ptrs_per_block = self.superblock.block_size() as usize / 4;

        for i in 0..ptrs_per_block {
            if written >= target_size {
                break;
            }
            let dind_block = u32::from_le_bytes(ptrs[i * 4..(i + 1) * 4].try_into()?) as u64;
            if dind_block != 0 {
                written = self.stream_double_indirect(writer, dind_block, written, target_size)?;
            }
        }
        Ok(written)
    }

    /// Scan all block groups for deleted inodes.
    /// A deleted inode has `dtime != 0` or `links_count == 0`, but still has
    /// `size > 0` — meaning its data blocks may still be intact on disk.
    pub fn scan_deleted_inodes(&self) -> Result<Vec<DeletedInode>> {
        let mut deleted = Vec::new();
        let inode_size = self.superblock.inode_size as usize;
        let inodes_per_group = self.superblock.inodes_per_group;
        let block_size = self.superblock.block_size() as usize;
        let num_groups = (self.superblock.inodes_count + inodes_per_group - 1) / inodes_per_group;
        let inodes_per_block = block_size / inode_size;

        for group in 0..num_groups {
            let bg = match self.read_group_descriptor(group) {
                Ok(bg) => bg,
                Err(_) => continue,
            };
            if bg.inode_table == 0 {
                continue;
            }

            let inode_table_blocks =
                (inodes_per_group as usize * inode_size + block_size - 1) / block_size;

            for tbl_block in 0..inode_table_blocks {
                let abs_block = bg.inode_table + tbl_block as u64;
                let block_data = match self.read_block(abs_block) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                for slot in 0..inodes_per_block {
                    let local_index = tbl_block * inodes_per_block + slot;
                    if local_index >= inodes_per_group as usize {
                        break;
                    }

                    let inode_num = group as u64 * inodes_per_group as u64 + local_index as u64 + 1;
                    if inode_num <= 10 {
                        continue;
                    }

                    let off = slot * inode_size;
                    if off + inode_size > block_data.len() {
                        break;
                    }

                    let data = &block_data[off..off + inode_size];
                    let mode = u16::from_le_bytes([data[0], data[1]]);
                    let size_lo = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
                    let atime = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
                    let ctime = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));
                    let mtime = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4]));
                    let links_count = u16::from_le_bytes([data[26], data[27]]);
                    let dtime = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
                    let size_hi = if data.len() >= 112 {
                        u32::from_le_bytes(data[108..112].try_into().unwrap_or([0; 4]))
                    } else {
                        0
                    };
                    let size = (size_hi as u64) << 32 | size_lo as u64;

                    let is_deleted = dtime != 0 || links_count == 0;
                    if !is_deleted || size == 0 || mode == 0 {
                        continue;
                    }

                    let file_type = match mode & 0xF000 {
                        0x4000 => FileType::Directory,
                        0x8000 => FileType::RegularFile,
                        0xA000 => FileType::Symlink,
                        _ => FileType::Other,
                    };

                    deleted.push(DeletedInode {
                        inode_num,
                        size,
                        file_type,
                        dtime,
                        mode,
                        ctime,
                        mtime,
                        atime,
                    });
                }
            }
        }

        Ok(deleted)
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
    pub ctime: u32,
    pub mtime: u32,
    pub atime: u32,
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

fn parse_directory_entries(data: &[u8], parent_inode: &Inode) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos + 8 <= data.len() {
        let inode = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as u64;
        let rec_len = u16::from_le_bytes(data[pos + 4..pos + 6].try_into()?) as usize;
        let name_len = data[pos + 6] as usize;
        let file_type_byte = data[pos + 7];

        let Some(record_end) = pos.checked_add(rec_len) else {
            pos += 4;
            continue;
        };

        let min_record_len = directory_entry_record_len(name_len);
        let file_type = directory_entry_file_type(file_type_byte);
        let is_plausible = rec_len >= 8
            && rec_len % 4 == 0
            && record_end <= data.len()
            && name_len > 0
            && pos + 8 + name_len <= record_end
            && file_type != FileType::Other
            && directory_name_looks_plausible_live(&data[pos + 8..pos + 8 + name_len]);

        if is_plausible {
            let name = String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();
            entries.push(DirEntry {
                inode,
                name,
                file_type,
                size: 0, // filled in later by reading the inode
                deleted: inode == 0,
                source: if inode == 0 {
                    EntrySource::DeletedSlack
                } else {
                    EntrySource::Filesystem
                },
                parent_inode: Some(parent_inode.number),
            });

            if min_record_len < rec_len {
                scan_deleted_directory_slack(
                    &data[pos + min_record_len..record_end],
                    parent_inode.number,
                    &mut entries,
                )?;
            }

            pos += rec_len;
            continue;
        }

        pos += 4;
    }

    Ok(entries)
}

fn scan_deleted_directory_slack(
    data: &[u8],
    parent_inode: u64,
    entries: &mut Vec<DirEntry>,
) -> Result<()> {
    let mut pos = 0;

    while pos + 8 <= data.len() {
        let inode = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as u64;
        let rec_len = u16::from_le_bytes(data[pos + 4..pos + 6].try_into()?) as usize;
        let name_len = data[pos + 6] as usize;
        let file_type_byte = data[pos + 7];

        let Some(record_end) = pos.checked_add(rec_len) else {
            pos += 4;
            continue;
        };

        let min_record_len = directory_entry_record_len(name_len);
        let file_type = directory_entry_file_type(file_type_byte);
        let looks_valid = rec_len >= 8
            && rec_len % 4 == 0
            && name_len > 0
            && rec_len >= min_record_len
            && record_end <= data.len()
            && pos + 8 + name_len <= record_end
            && file_type != FileType::Other
            && directory_name_looks_plausible_deleted(&data[pos + 8..pos + 8 + name_len]);

        if looks_valid {
            let name = String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();
            entries.push(DirEntry {
                inode,
                name,
                file_type,
                size: 0,
                deleted: true,
                source: EntrySource::DeletedSlack,
                parent_inode: Some(parent_inode),
            });

            if min_record_len < rec_len {
                scan_deleted_directory_slack(
                    &data[pos + min_record_len..pos + rec_len],
                    parent_inode,
                    entries,
                )?;
            }

            pos += rec_len;
            continue;
        }

        pos += 4;
    }

    Ok(())
}

fn directory_entry_record_len(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

fn directory_entry_file_type(file_type_byte: u8) -> FileType {
    match file_type_byte {
        1 => FileType::RegularFile,
        2 => FileType::Directory,
        7 => FileType::Symlink,
        _ => FileType::Other,
    }
}

fn directory_name_looks_plausible_live(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|byte| {
            !byte.is_ascii_control() && *byte != 0 && *byte != b'/' && *byte != b'\\'
        })
}

fn directory_name_looks_plausible_deleted(name: &[u8]) -> bool {
    directory_name_looks_plausible_live(name) && name != b"." && name != b".."
}
