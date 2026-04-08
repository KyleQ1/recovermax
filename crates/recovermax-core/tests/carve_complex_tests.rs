//! Complex carving tests — edge cases that stress the carving engine.

use recovermax_core::carve::Carver;
use recovermax_core::io::ImageReader;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn carve_image(data: &[u8], type_filter: Option<&[&str]>) -> (TempDir, Vec<String>) {
    let img_file = create_test_image(data);
    let dest = TempDir::new().unwrap();
    let reader = ImageReader::open(img_file.path()).unwrap();
    let carver = Carver::new(&reader, dest.path());
    carver.carve(type_filter).unwrap();

    let mut files: Vec<String> = std::fs::read_dir(dest.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    files.sort();
    (dest, files)
}

// ===========================================================================
// BUG: Multiple footer candidates — carver picks the FIRST match, which may
// be a false positive embedded in file data. Real JPEGs often have 0xFF 0xD9
// in their entropy-coded data before the actual end.
// ===========================================================================

#[test]
fn jpeg_with_false_footer_in_data() {
    let mut img = vec![0u8; 8192];
    // JPEG header at sector 0
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;

    // False footer at offset 100 (inside the "image data", within 512 bytes of header)
    img[100] = 0xFF;
    img[101] = 0xD9;

    // Real footer at offset 2000
    img[2000] = 0xFF;
    img[2001] = 0xD9;

    let (dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // Smart carver skips the false footer at 100 (within 512 bytes of header)
    // and finds the real footer at 2000, giving carved length 2002.
    assert_eq!(
        carved.len(),
        2002,
        "Smart carver should skip false footer and find the real one at 2002."
    );
}

// ===========================================================================
// Back-to-back files on the same sector (second one gets missed)
// ===========================================================================

#[test]
fn back_to_back_files_same_sector() {
    // Two JPEG files starting at the same 512-byte sector boundary
    // but at different byte offsets. The second one will be missed
    // because carving only checks sector boundaries.
    let mut img = vec![0u8; 4096];

    // First JPEG at offset 0
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[200] = 0xFF;
    img[201] = 0xD9;

    // Second JPEG at offset 250 (NOT sector-aligned)
    img[250] = 0xFF;
    img[251] = 0xD8;
    img[252] = 0xFF;
    img[400] = 0xFF;
    img[401] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["jpg"]));

    // Only 1 should be found (sector-aligned scan misses offset 250)
    assert_eq!(files.len(), 1, "Only sector-aligned files should be found");
}

// ===========================================================================
// Signature at the very last sector of the image
// ===========================================================================

#[test]
fn signature_at_end_of_image() {
    let size = 8192;
    let mut img = vec![0u8; size];

    // JPEG header at sector 10 (offset 5120)
    // Footer at offset 6700 (distance 1580, well past the 512/1024 minimums)
    let start = 5120;
    img[start] = 0xFF;
    img[start + 1] = 0xD8;
    img[start + 2] = 0xFF;
    img[6700] = 0xFF;
    img[6701] = 0xD9;

    let (dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 6702 - start);
}

// ===========================================================================
// Truncated signature at end (header present, image ends before footer)
// ===========================================================================

#[test]
fn truncated_file_no_footer_before_eof() {
    let mut img = vec![0u8; 2048];
    // JPEG header but image ends before any footer
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    // No 0xFF 0xD9 anywhere

    let (dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);

    // Should carve up to end of image (or max_size, whichever is smaller)
    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(
        carved.len(),
        2048,
        "Should carve to end of image when no footer found"
    );
}

// ===========================================================================
// Overlapping file types at same offset (e.g., ZIP header also looks like DOCX)
// ===========================================================================

#[test]
fn overlapping_signatures_same_offset() {
    // ZIP and DOCX/XLSX/PPTX all start with PK\x03\x04.
    // Current engine should carve it as ZIP.
    let mut img = vec![0u8; 8192];
    img[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // PK header

    let (_dest, files) = carve_image(&img, None);
    let zip_files: Vec<_> = files.iter().filter(|f| f.ends_with(".zip")).collect();
    assert_eq!(zip_files.len(), 1, "Should detect ZIP header");
}

// ===========================================================================
// Very large carved file (tests that we don't OOM)
// ===========================================================================

#[test]
fn large_carved_file_respects_max_size() {
    // Create image much smaller than the max_size limit
    // Ensure we don't try to allocate beyond image bounds
    let size = 1024 * 1024; // 1MB
    let mut img = vec![0x42u8; size];

    // SQLite header (max_size = 1GB, but image is only 1MB)
    img[0..16].copy_from_slice(b"SQLite format 3\x00");

    let (dest, files) = carve_image(&img, Some(&["sqlite"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // Should be capped at image size, not max_size
    assert_eq!(carved.len(), size);
}

// ===========================================================================
// GIF false positive: 0x00 0x3B appears very frequently in random data
// ===========================================================================

#[test]
fn gif_false_footer_frequency() {
    let mut img = vec![0u8; 8192];
    // GIF header at sector 0
    img[0..4].copy_from_slice(b"GIF8");

    // Scatter 0x00 0x3B (GIF footer) throughout — first one at offset 10
    img[10] = 0x00;
    img[11] = 0x3B;
    img[500] = 0x00;
    img[501] = 0x3B;
    img[4000] = 0x00;
    img[4001] = 0x3B;

    let (dest, files) = carve_image(&img, Some(&["gif"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // Smart carver skips footer at offset 10 (within 64 bytes of header)
    // and finds the next one at offset 500.
    assert_eq!(
        carved.len(),
        502,
        "Should skip false footer at 10 and stop at the one at 500"
    );
}

// ===========================================================================
// Multiple files of same type at different offsets
// ===========================================================================

#[test]
fn multiple_jpegs_across_image() {
    let mut img = vec![0u8; 16384];

    // JPEG 1 at sector 0
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[300] = 0xFF;
    img[301] = 0xD9;

    // JPEG 2 at sector 4 (offset 2048)
    img[2048] = 0xFF;
    img[2049] = 0xD8;
    img[2050] = 0xFF;
    img[3000] = 0xFF;
    img[3001] = 0xD9;

    // JPEG 3 at sector 10 (offset 5120)
    img[5120] = 0xFF;
    img[5121] = 0xD8;
    img[5122] = 0xFF;
    img[6000] = 0xFF;
    img[6001] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 3, "Should find all 3 JPEGs");
}

// ===========================================================================
// Mixed types interleaved: JPEG footer appears in PNG data region
// ===========================================================================

#[test]
fn jpeg_footer_inside_png_data() {
    let mut img = vec![0u8; 16384];

    // PNG at sector 0
    let png_hdr = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let png_ftr = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
    img[0..8].copy_from_slice(&png_hdr);
    img[5000..5008].copy_from_slice(&png_ftr);

    // JPEG footer bytes randomly inside the PNG region
    img[2000] = 0xFF;
    img[2001] = 0xD9;

    // JPEG at sector 12 (offset 6144)
    img[6144] = 0xFF;
    img[6145] = 0xD8;
    img[6146] = 0xFF;
    img[7000] = 0xFF;
    img[7001] = 0xD9;

    let (_dest, files) = carve_image(&img, None);

    let png_count = files.iter().filter(|f| f.ends_with(".png")).count();
    let jpg_count = files.iter().filter(|f| f.ends_with(".jpg")).count();

    assert_eq!(png_count, 1, "Should find the PNG");
    assert_eq!(jpg_count, 1, "Should find the JPEG");
}

// ===========================================================================
// Partial header at the very end of the image (fewer bytes than header length)
// ===========================================================================

#[test]
fn partial_header_at_image_end() {
    // Image that ends 2 bytes into what would be a PNG header
    let mut img = vec![0u8; 4096 + 2];
    // Put PNG header start at the last sector (offset 4096)
    // but only 2 bytes fit
    img[4096] = 0x89;
    img[4097] = 0x50;

    let (_dest, files) = carve_image(&img, Some(&["png"]));
    // Should not crash, should not find anything
    assert_eq!(files.len(), 0);
}

// ===========================================================================
// Image smaller than one sector
// ===========================================================================

#[test]
fn image_smaller_than_sector() {
    let img = vec![0xFFu8; 256]; // less than 512 bytes
    let (_dest, files) = carve_image(&img, None);
    assert_eq!(files.len(), 0, "No sectors to scan");
}

// ===========================================================================
// Carve from image with ALL signature types present
// ===========================================================================

#[test]
fn all_signature_types_in_one_image() {
    let mut img = vec![0u8; 64 * 1024]; // 64KB

    let mut offset = 0usize;

    // JPEG at sector 0
    img[offset] = 0xFF;
    img[offset + 1] = 0xD8;
    img[offset + 2] = 0xFF;
    img[offset + 300] = 0xFF;
    img[offset + 301] = 0xD9;
    offset += 512;

    // PNG at sector 1
    img[offset..offset + 8].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    img[offset + 400..offset + 408]
        .copy_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    offset += 512;

    // PDF at sector 2
    img[offset..offset + 4].copy_from_slice(b"%PDF");
    img[offset + 400..offset + 405].copy_from_slice(b"%%EOF");
    offset += 512;

    // ZIP at sector 3
    img[offset..offset + 4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    offset += 512;

    // GIF at sector 4
    img[offset..offset + 4].copy_from_slice(b"GIF8");
    img[offset + 400] = 0x00;
    img[offset + 401] = 0x3B;
    offset += 512;

    // ELF at sector 5
    img[offset..offset + 4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
    offset += 512;

    // gzip at sector 6
    img[offset..offset + 3].copy_from_slice(&[0x1F, 0x8B, 0x08]);
    offset += 512;

    // SQLite at sector 7
    img[offset..offset + 16].copy_from_slice(b"SQLite format 3\x00");

    let (_dest, files) = carve_image(&img, None);

    assert!(files.iter().any(|f| f.ends_with(".jpg")), "Missing JPEG");
    assert!(files.iter().any(|f| f.ends_with(".png")), "Missing PNG");
    assert!(files.iter().any(|f| f.ends_with(".pdf")), "Missing PDF");
    assert!(files.iter().any(|f| f.ends_with(".zip")), "Missing ZIP");
    assert!(files.iter().any(|f| f.ends_with(".gif")), "Missing GIF");
    assert!(files.iter().any(|f| f.ends_with(".elf")), "Missing ELF");
    assert!(files.iter().any(|f| f.ends_with(".gz")), "Missing gzip");
    assert!(
        files.iter().any(|f| f.ends_with(".sqlite")),
        "Missing SQLite"
    );
}

// ===========================================================================
// Identical headers at consecutive sectors
// ===========================================================================

#[test]
fn identical_headers_consecutive_sectors() {
    let mut img = vec![0u8; 8192];

    // PDF at sector 0
    img[0..4].copy_from_slice(b"%PDF");
    img[400..405].copy_from_slice(b"%%EOF");

    // Another PDF at sector 1 (offset 512)
    img[512..516].copy_from_slice(b"%PDF");
    img[900..905].copy_from_slice(b"%%EOF");

    let (_dest, files) = carve_image(&img, Some(&["pdf"]));

    // First PDF's footer search will find %%EOF at 405.
    // Second PDF starts at 512. Its footer search finds %%EOF at 905.
    // BUT: the first PDF's footer search might also find the %%EOF at 905.
    // The first PDF should stop at 405, not at 905.
    assert_eq!(files.len(), 2, "Should find both PDFs");

    // Verify sizes
    let mut sizes: Vec<u64> = files
        .iter()
        .map(|f| {
            std::fs::metadata(std::path::Path::new(&format!(
                "{}",
                _dest.path().join(f).display()
            )))
            .unwrap()
            .len()
        })
        .collect();
    sizes.sort();

    // Both should be small (a few hundred bytes)
    assert!(
        sizes[0] < 1000,
        "First PDF should be small, got {}",
        sizes[0]
    );
    assert!(
        sizes[1] < 1000,
        "Second PDF should be small, got {}",
        sizes[1]
    );
}
