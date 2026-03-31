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
}

const SIGNATURES: &[Signature] = &[
    Signature {
        name: "JPEG",
        extension: "jpg",
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size: 50 * 1024 * 1024,
    },
    Signature {
        name: "PNG",
        extension: "png",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size: 50 * 1024 * 1024,
    },
    Signature {
        name: "PDF",
        extension: "pdf",
        header: b"%PDF",
        footer: Some(b"%%EOF"),
        max_size: 500 * 1024 * 1024,
    },
    Signature {
        name: "ZIP",
        extension: "zip",
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: None,
        max_size: 500 * 1024 * 1024,
    },
    Signature {
        name: "GIF",
        extension: "gif",
        header: b"GIF8",
        footer: Some(&[0x00, 0x3B]),
        max_size: 50 * 1024 * 1024,
    },
    Signature {
        name: "ELF",
        extension: "elf",
        header: &[0x7F, 0x45, 0x4C, 0x46],
        footer: None,
        max_size: 100 * 1024 * 1024,
    },
    Signature {
        name: "gzip",
        extension: "gz",
        header: &[0x1F, 0x8B, 0x08],
        footer: None,
        max_size: 500 * 1024 * 1024,
    },
    Signature {
        name: "SQLite",
        extension: "sqlite",
        header: b"SQLite format 3\x00",
        footer: None,
        max_size: 1024 * 1024 * 1024,
    },
    Signature {
        name: "tar",
        extension: "tar",
        header: &[], // special: "ustar" at offset 257
        footer: None,
        max_size: 500 * 1024 * 1024,
    },
];

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

        println!("Carving for: {}", sigs.iter().map(|s| s.name).collect::<Vec<_>>().join(", "));

        let image_size = self.reader.len();
        let pb = ProgressBar::new(image_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:50.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
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
                        let filename = format!(
                            "{:012x}.{}",
                            offset, sig.extension
                        );
                        let path = self.dest.join(&filename);
                        std::fs::write(&path, carved)?;
                        found_count += 1;
                        pb.set_message(format!("Found {} files", found_count));
                        tracing::info!("Carved {} at offset 0x{:x} ({} bytes)", sig.name, offset, carved.len());
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

        if let Some(footer) = sig.footer {
            // Search for footer
            let search_region = &data[start..max_end];
            for i in sig.header.len()..search_region.len() {
                if search_region[i..].starts_with(footer) {
                    let end = start + i + footer.len();
                    return Some(&data[start..end]);
                }
            }
            // No footer found — take up to max_size
            Some(&data[start..max_end])
        } else {
            // No footer — take a fixed chunk (conservative)
            let end = (start + sig.max_size as usize).min(data.len());
            Some(&data[start..end])
        }
    }
}
