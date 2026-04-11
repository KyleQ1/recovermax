use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use memmap2::Mmap;

/// Trait for reading data from a disk image or virtual device.
/// All read methods return slices borrowing from the underlying storage.
pub trait DiskRead {
    fn read_at(&self, offset: u64, len: usize) -> Result<&[u8]>;
    fn read_at_exact(&self, offset: u64, len: usize) -> Result<&[u8]>;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Drop cached pages from RSS. No-op on non-mmap readers.
    fn drop_cache(&self) {}
}

/// Memory-mapped reader for disk images and block devices.
/// Provides zero-copy access to arbitrarily large images.
pub struct ImageReader {
    mmap: Mmap,
    size: u64,
}

impl ImageReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;

        let metadata = file.metadata()?;
        let size = metadata.len();

        // Safety: we open read-only and don't modify the file
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap {}", path.display()))?;

        // Normal advice — Sequential causes aggressive readahead across all
        // cores which is wrong for random inode reads during tree walking.
        #[cfg(unix)]
        mmap.advise(memmap2::Advice::Normal).ok();

        tracing::info!("Opened image: {} ({} bytes)", path.display(), size);

        Ok(Self { mmap, size })
    }

    /// Drop all cached pages from resident memory.
    /// Call periodically during long scans to bound RSS.
    /// Uses MADV_DONTNEED which is safe for read-only mmaps — pages get
    /// re-faulted from disk on next access.
    pub fn drop_cache(&self) {
        #[cfg(unix)]
        unsafe {
            self.mmap
                .unchecked_advise(memmap2::UncheckedAdvice::DontNeed)
                .ok();
        }
    }

    /// Hint sequential access pattern. Enables aggressive kernel readahead
    /// for linear scans. Call before sequential scan operations.
    pub fn advise_sequential(&self) {
        #[cfg(unix)]
        self.mmap.advise(memmap2::Advice::Sequential).ok();
    }

    /// Reset to normal access pattern (default random-friendly behavior).
    pub fn advise_normal(&self) {
        #[cfg(unix)]
        self.mmap.advise(memmap2::Advice::Normal).ok();
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Read bytes at a given offset. Returns up to `len` bytes.
    pub fn read_at(&self, offset: u64, len: usize) -> Result<&[u8]> {
        let start = offset as usize;
        let end = (start + len).min(self.mmap.len());

        if start >= self.mmap.len() {
            anyhow::bail!("Offset {} is beyond image size {}", offset, self.size);
        }

        Ok(&self.mmap[start..end])
    }

    /// Read exactly `len` bytes at offset. Returns an error if fewer bytes are available.
    pub fn read_at_exact(&self, offset: u64, len: usize) -> Result<&[u8]> {
        let data = self.read_at(offset, len)?;
        if data.len() < len {
            anyhow::bail!(
                "Short read at offset {}: wanted {} bytes, got {}",
                offset,
                len,
                data.len()
            );
        }
        Ok(data)
    }

    /// Get a slice of the entire image
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap
    }

    /// Read a fixed-size array at offset
    pub fn read_array<const N: usize>(&self, offset: u64) -> Result<[u8; N]> {
        let data = self.read_at(offset, N)?;
        if data.len() < N {
            anyhow::bail!(
                "Short read at offset {}: wanted {} bytes, got {}",
                offset,
                N,
                data.len()
            );
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(data);
        Ok(arr)
    }

    /// Read a little-endian u16
    pub fn read_u16_le(&self, offset: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>(offset)?))
    }

    /// Read a little-endian u32
    pub fn read_u32_le(&self, offset: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>(offset)?))
    }

    /// Read a little-endian u64
    pub fn read_u64_le(&self, offset: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>(offset)?))
    }
}

impl DiskRead for ImageReader {
    fn read_at(&self, offset: u64, len: usize) -> Result<&[u8]> {
        self.read_at(offset, len)
    }

    fn read_at_exact(&self, offset: u64, len: usize) -> Result<&[u8]> {
        self.read_at_exact(offset, len)
    }

    fn len(&self) -> u64 {
        self.len()
    }

    fn drop_cache(&self) {
        self.drop_cache();
    }
}
