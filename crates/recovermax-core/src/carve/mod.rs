use std::path::Path;

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::io::ImageReader;

/// Known file signatures for raw carving
struct Signature {
    name: &'static str,
    extension: &'static str,
    header: &'static [u8],
    footer: Option<&'static [u8]>,
    max_size: u64,
    /// Minimum distance from header start before a footer is accepted.
    /// Prevents false positives for short footers (JPEG 0xFF 0xD9, GIF 0x00 0x3B).
    min_footer_distance: usize,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        name: "JPEG",
        extension: "jpg",
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size: 50 * 1024 * 1024,
        min_footer_distance: 512,
    },
    Signature {
        name: "PNG",
        extension: "png",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size: 50 * 1024 * 1024,
        min_footer_distance: 0,
    },
    Signature {
        name: "PDF",
        extension: "pdf",
        header: b"%PDF",
        footer: Some(b"%%EOF"),
        max_size: 500 * 1024 * 1024,
        min_footer_distance: 0,
    },
    Signature {
        name: "ZIP",
        extension: "zip",
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: None,
        max_size: 500 * 1024 * 1024,
        min_footer_distance: 0,
    },
    Signature {
        name: "GIF",
        extension: "gif",
        header: b"GIF8",
        footer: Some(&[0x00, 0x3B]),
        max_size: 50 * 1024 * 1024,
        min_footer_distance: 64,
    },
    Signature {
        name: "ELF",
        extension: "elf",
        header: &[0x7F, 0x45, 0x4C, 0x46],
        footer: None,
        max_size: 100 * 1024 * 1024,
        min_footer_distance: 0,
    },
    Signature {
        name: "gzip",
        extension: "gz",
        header: &[0x1F, 0x8B, 0x08],
        footer: None,
        max_size: 10 * 1024 * 1024,
        min_footer_distance: 0,
    },
    Signature {
        name: "SQLite",
        extension: "sqlite",
        header: b"SQLite format 3\x00",
        footer: None,
        max_size: 1024 * 1024 * 1024,
        min_footer_distance: 0,
    },
    Signature {
        name: "tar",
        extension: "tar",
        header: &[], // special: "ustar" at offset 257
        footer: None,
        max_size: 500 * 1024 * 1024,
        min_footer_distance: 0,
    },
];

/// ZIP end-of-central-directory signature: PK\x05\x06
const ZIP_EOCD_SIG: &[u8] = &[0x50, 0x4B, 0x05, 0x06];
/// EOCD fixed-size portion is 22 bytes (signature + fields before comment)
const ZIP_EOCD_MIN_SIZE: usize = 22;

pub struct Carver<'a> {
    reader: &'a ImageReader,
    dest: &'a Path,
}

impl<'a> Carver<'a> {
    pub fn new(reader: &'a ImageReader, dest: &'a Path) -> Self {
        Self { reader, dest }
    }

    pub fn carve(&self, type_filter: Option<&[&str]>) -> Result<()> {
        std::fs::create_dir_all(self.dest)?;

        let sigs: Vec<&Signature> = SIGNATURES
            .iter()
            .filter(|s| {
                if let Some(filter) = type_filter {
                    filter.iter().any(|f| {
                        s.extension.eq_ignore_ascii_case(f) || s.name.eq_ignore_ascii_case(f)
                    })
                } else {
                    true
                }
            })
            .filter(|s| !s.header.is_empty()) // skip tar for now
            .collect();

        if sigs.is_empty() {
            println!("No matching file signatures to search for.");
            return Ok(());
        }

        println!(
            "Carving for: {}",
            sigs.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
        );

        let image_size = self.reader.len();
        let pb = ProgressBar::new(image_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{bar:50.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
        );

        let data = self.reader.as_bytes();
        let mut found_count = 0u64;
        let mut offset = 0usize;

        // Scan sector by sector (512-byte aligned)
        while offset + 16 < data.len() {
            for sig in &sigs {
                if data[offset..].starts_with(sig.header) {
                    if let Some(carved) = self.extract_file(data, offset, sig) {
                        let filename = format!("{:012x}.{}", offset, sig.extension);
                        let path = self.dest.join(&filename);
                        std::fs::write(&path, carved)?;
                        found_count += 1;
                        pb.set_message(format!("Found {} files", found_count));
                        tracing::info!(
                            "Carved {} at offset 0x{:x} ({} bytes)",
                            sig.name,
                            offset,
                            carved.len()
                        );
                    }
                }
            }

            offset += 512; // sector-aligned scan
            if offset % (64 * 1024 * 1024) == 0 {
                pb.set_position(offset as u64);
            }
        }

        pb.finish_with_message(format!("Done. {} files carved.", found_count));
        Ok(())
    }

    fn extract_file<'b>(&self, data: &'b [u8], start: usize, sig: &Signature) -> Option<&'b [u8]> {
        let max_end = (start + sig.max_size as usize).min(data.len());

        // Try format-aware size detection for footer-less formats
        match sig.name {
            "SQLite" => return self.extract_sqlite(data, start, max_end),
            "ELF" => return self.extract_elf(data, start, max_end),
            "ZIP" => return self.extract_zip(data, start, max_end),
            "gzip" => {
                // gzip is a stream format with no reliable size in header.
                // Use the (already reduced) max_size as a cap.
                let end = max_end;
                return Some(&data[start..end]);
            }
            _ => {}
        }

        if let Some(footer) = sig.footer {
            // Search for footer, respecting min_footer_distance
            let search_region = &data[start..max_end];
            let search_start = sig.header.len().max(sig.min_footer_distance);
            for i in search_start..search_region.len() {
                if search_region[i..].starts_with(footer) {
                    let carved_len = i + footer.len();
                    // JPEG: carved data must be at least 1KB
                    if sig.name == "JPEG" && carved_len < 1024 {
                        continue;
                    }
                    let end = start + carved_len;
                    return Some(&data[start..end]);
                }
            }
            // No valid footer found — take up to max_size
            Some(&data[start..max_end])
        } else {
            // No footer — take a fixed chunk (conservative)
            let end = max_end;
            Some(&data[start..end])
        }
    }

    /// Read SQLite page_size (offset 16, 2 bytes BE) and page_count (offset 28, 4 bytes BE)
    /// to compute actual database size = page_size * page_count.
    fn extract_sqlite<'b>(&self, data: &'b [u8], start: usize, max_end: usize) -> Option<&'b [u8]> {
        // Need at least 32 bytes for the header fields we read
        if start + 32 > data.len() {
            return Some(&data[start..max_end]);
        }

        let page_size_raw = u16::from_be_bytes([data[start + 16], data[start + 17]]);
        // SQLite uses 0 to mean 65536
        let page_size = if page_size_raw == 0 {
            65536u64
        } else {
            page_size_raw as u64
        };

        // page_size must be a power of 2 between 512 and 65536
        if page_size < 512 || (page_size & (page_size - 1)) != 0 {
            return Some(&data[start..max_end]);
        }

        let page_count = u32::from_be_bytes([
            data[start + 28],
            data[start + 29],
            data[start + 30],
            data[start + 31],
        ]) as u64;

        if page_count == 0 {
            // page_count 0 means "not yet computed" — fall back to max_size
            return Some(&data[start..max_end]);
        }

        let db_size = page_size * page_count;
        let end = (start as u64 + db_size).min(max_end as u64) as usize;
        Some(&data[start..end])
    }

    /// Read ELF header to compute file size from section header table:
    /// size = e_shoff + (e_shnum * e_shentsize)
    fn extract_elf<'b>(&self, data: &'b [u8], start: usize, max_end: usize) -> Option<&'b [u8]> {
        // Need at least the ELF header (minimum 52 bytes for 32-bit, 64 for 64-bit)
        if start + 6 > data.len() {
            return Some(&data[start..max_end]);
        }

        let ei_class = data[start + 4]; // 1 = 32-bit, 2 = 64-bit
        let ei_data = data[start + 5]; // 1 = little-endian, 2 = big-endian

        match (ei_class, ei_data) {
            (1, 1) => self.extract_elf32_le(data, start, max_end),
            (1, 2) => self.extract_elf32_be(data, start, max_end),
            (2, 1) => self.extract_elf64_le(data, start, max_end),
            (2, 2) => self.extract_elf64_be(data, start, max_end),
            _ => Some(&data[start..max_end]),
        }
    }

    fn extract_elf32_le<'b>(
        &self,
        data: &'b [u8],
        start: usize,
        max_end: usize,
    ) -> Option<&'b [u8]> {
        // 32-bit ELF header is 52 bytes
        if start + 52 > data.len() {
            return Some(&data[start..max_end]);
        }
        let d = &data[start..];
        let e_shoff = u32::from_le_bytes([d[32], d[33], d[34], d[35]]) as u64;
        let e_shentsize = u16::from_le_bytes([d[46], d[47]]) as u64;
        let e_shnum = u16::from_le_bytes([d[48], d[49]]) as u64;
        self.elf_size_from_sections(data, start, max_end, e_shoff, e_shentsize, e_shnum)
    }

    fn extract_elf32_be<'b>(
        &self,
        data: &'b [u8],
        start: usize,
        max_end: usize,
    ) -> Option<&'b [u8]> {
        if start + 52 > data.len() {
            return Some(&data[start..max_end]);
        }
        let d = &data[start..];
        let e_shoff = u32::from_be_bytes([d[32], d[33], d[34], d[35]]) as u64;
        let e_shentsize = u16::from_be_bytes([d[46], d[47]]) as u64;
        let e_shnum = u16::from_be_bytes([d[48], d[49]]) as u64;
        self.elf_size_from_sections(data, start, max_end, e_shoff, e_shentsize, e_shnum)
    }

    fn extract_elf64_le<'b>(
        &self,
        data: &'b [u8],
        start: usize,
        max_end: usize,
    ) -> Option<&'b [u8]> {
        // 64-bit ELF header is 64 bytes
        if start + 64 > data.len() {
            return Some(&data[start..max_end]);
        }
        let d = &data[start..];
        let e_shoff = u64::from_le_bytes([d[40], d[41], d[42], d[43], d[44], d[45], d[46], d[47]]);
        let e_shentsize = u16::from_le_bytes([d[58], d[59]]) as u64;
        let e_shnum = u16::from_le_bytes([d[60], d[61]]) as u64;
        self.elf_size_from_sections(data, start, max_end, e_shoff, e_shentsize, e_shnum)
    }

    fn extract_elf64_be<'b>(
        &self,
        data: &'b [u8],
        start: usize,
        max_end: usize,
    ) -> Option<&'b [u8]> {
        if start + 64 > data.len() {
            return Some(&data[start..max_end]);
        }
        let d = &data[start..];
        let e_shoff = u64::from_be_bytes([d[40], d[41], d[42], d[43], d[44], d[45], d[46], d[47]]);
        let e_shentsize = u16::from_be_bytes([d[58], d[59]]) as u64;
        let e_shnum = u16::from_be_bytes([d[60], d[61]]) as u64;
        self.elf_size_from_sections(data, start, max_end, e_shoff, e_shentsize, e_shnum)
    }

    fn elf_size_from_sections<'b>(
        &self,
        data: &'b [u8],
        start: usize,
        max_end: usize,
        e_shoff: u64,
        e_shentsize: u64,
        e_shnum: u64,
    ) -> Option<&'b [u8]> {
        if e_shoff == 0 || e_shnum == 0 || e_shentsize == 0 {
            return Some(&data[start..max_end]);
        }
        let elf_size = e_shoff + (e_shnum * e_shentsize);
        let end = (start as u64 + elf_size).min(max_end as u64) as usize;
        Some(&data[start..end])
    }

    /// Scan for ZIP end-of-central-directory signature (PK\x05\x06) to find the real end.
    /// The EOCD record contains a comment length field, so total = eocd_offset + 22 + comment_len.
    fn extract_zip<'b>(&self, data: &'b [u8], start: usize, max_end: usize) -> Option<&'b [u8]> {
        let search_region = &data[start..max_end];

        // Scan backwards from the end (EOCD is typically near the end).
        // But for simplicity and correctness, scan forward and take the last match.
        let mut last_eocd: Option<usize> = None;
        for i in 4..search_region.len() {
            if search_region[i..].starts_with(ZIP_EOCD_SIG) {
                last_eocd = Some(i);
            }
        }

        if let Some(eocd_offset) = last_eocd {
            // Read comment length at eocd_offset + 20 (2 bytes LE)
            let comment_len_offset = eocd_offset + 20;
            if comment_len_offset + 2 <= search_region.len() {
                let comment_len = u16::from_le_bytes([
                    search_region[comment_len_offset],
                    search_region[comment_len_offset + 1],
                ]) as usize;
                let end = start + eocd_offset + ZIP_EOCD_MIN_SIZE + comment_len;
                let end = end.min(max_end);
                return Some(&data[start..end]);
            }
            // EOCD found but truncated — take up to just past what we can read
            let end = (start + eocd_offset + ZIP_EOCD_MIN_SIZE).min(max_end);
            return Some(&data[start..end]);
        }

        // No EOCD found — fall back to max_size
        Some(&data[start..max_end])
    }
}
