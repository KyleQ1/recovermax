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

// --- JPEG ---

#[test]
fn carve_jpeg_with_footer() {
    let mut img = vec![0u8; 4096];
    // JPEG at sector 0
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    // Footer at offset 1500 (past the 512-byte min distance and 1KB min size)
    img[1500] = 0xFF;
    img[1501] = 0xD9;
    let (dest, files) = carve_image(&img, Some(&["jpg"]));

    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".jpg"));

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 1502); // header to footer inclusive
    assert_eq!(&carved[0..3], &[0xFF, 0xD8, 0xFF]);
    assert_eq!(&carved[1500..1502], &[0xFF, 0xD9]);
}

// --- PNG ---

#[test]
fn carve_png_with_footer() {
    let mut img = vec![0u8; 4096];
    let png_hdr = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let png_ftr = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
    img[0..8].copy_from_slice(&png_hdr);
    img[1000..1008].copy_from_slice(&png_ftr);
    let (dest, files) = carve_image(&img, Some(&["png"]));

    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".png"));

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 1008);
}

// --- PDF ---

#[test]
fn carve_pdf_with_footer() {
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(b"%PDF");
    img[2000..2005].copy_from_slice(b"%%EOF");
    let (dest, files) = carve_image(&img, Some(&["pdf"]));

    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".pdf"));

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 2005);
}

// --- Multiple signatures in one image ---

#[test]
fn carve_multiple_types() {
    let mut img = vec![0u8; 8192];
    // JPEG at sector 0
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[200] = 0xFF;
    img[201] = 0xD9;
    // GIF at sector 1 (offset 512)
    img[512..516].copy_from_slice(b"GIF8");
    img[800] = 0x00;
    img[801] = 0x3B;
    // PDF at sector 4 (offset 2048)
    img[2048..2052].copy_from_slice(b"%PDF");
    img[3000..3005].copy_from_slice(b"%%EOF");

    let (_dest, files) = carve_image(&img, None);

    let jpg_count = files.iter().filter(|f| f.ends_with(".jpg")).count();
    let gif_count = files.iter().filter(|f| f.ends_with(".gif")).count();
    let pdf_count = files.iter().filter(|f| f.ends_with(".pdf")).count();

    assert_eq!(jpg_count, 1);
    assert_eq!(gif_count, 1);
    assert_eq!(pdf_count, 1);
}

// --- Type filtering ---

#[test]
fn carve_filter_only_jpg() {
    let mut img = vec![0u8; 4096];
    // JPEG
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[100] = 0xFF;
    img[101] = 0xD9;
    // PNG (should be skipped)
    img[512..520].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    let (_dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".jpg"));
}

#[test]
fn carve_filter_case_insensitive() {
    let mut img = vec![0u8; 4096];
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[100] = 0xFF;
    img[101] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["JPG"]));
    assert_eq!(files.len(), 1);
}

#[test]
fn carve_filter_by_name() {
    let mut img = vec![0u8; 4096];
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[100] = 0xFF;
    img[101] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["JPEG"]));
    assert_eq!(files.len(), 1);
}

#[test]
fn carve_filter_no_matches() {
    let mut img = vec![0u8; 4096];
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;
    img[100] = 0xFF;
    img[101] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["sqlite"]));
    assert_eq!(files.len(), 0);
}

// --- Empty / no signatures ---

#[test]
fn carve_empty_image() {
    let (_dest, files) = carve_image(&[0u8; 1024], None);
    assert_eq!(files.len(), 0);
}

#[test]
fn carve_no_signatures_found() {
    let img = vec![0x42u8; 4096]; // random data, no magic bytes
    let (_dest, files) = carve_image(&img, None);
    assert_eq!(files.len(), 0);
}

// --- Filename format ---

#[test]
fn carved_filename_has_hex_offset() {
    let mut img = vec![0u8; 2048];
    // JPEG at sector 2 (offset 1024 = 0x400)
    img[1024] = 0xFF;
    img[1025] = 0xD8;
    img[1026] = 0xFF;
    img[1500] = 0xFF;
    img[1501] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);
    assert!(files[0].starts_with("000000000400")); // hex offset
    assert!(files[0].ends_with(".jpg"));
}

// --- Sector alignment ---

#[test]
fn carve_only_finds_sector_aligned_signatures() {
    let mut img = vec![0u8; 4096];
    // JPEG at non-sector-aligned offset (offset 100, not on 512 boundary)
    img[100] = 0xFF;
    img[101] = 0xD8;
    img[102] = 0xFF;
    img[300] = 0xFF;
    img[301] = 0xD9;

    let (_dest, files) = carve_image(&img, Some(&["jpg"]));
    // Should NOT find it since carving scans on 512-byte boundaries
    assert_eq!(files.len(), 0);
}

// --- ELF ---

#[test]
fn carve_elf() {
    let mut img = vec![0u8; 2048];
    img[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
    let (_dest, files) = carve_image(&img, Some(&["elf"]));
    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".elf"));
}

// --- gzip ---

#[test]
fn carve_gzip() {
    let mut img = vec![0u8; 2048];
    img[0..3].copy_from_slice(&[0x1F, 0x8B, 0x08]);
    let (_dest, files) = carve_image(&img, Some(&["gz"]));
    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".gz"));
}

// --- ZIP ---

#[test]
fn carve_zip() {
    let mut img = vec![0u8; 2048];
    img[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    let (_dest, files) = carve_image(&img, Some(&["zip"]));
    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".zip"));
}

// --- SQLite ---

#[test]
fn carve_sqlite() {
    let mut img = vec![0u8; 2048];
    img[0..16].copy_from_slice(b"SQLite format 3\x00");
    let (_dest, files) = carve_image(&img, Some(&["sqlite"]));
    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with(".sqlite"));
}

// --- Destination directory creation ---

#[test]
fn carve_creates_dest_directory() {
    let img = vec![0u8; 1024];
    let img_file = create_test_image(&img);
    let dest = TempDir::new().unwrap();
    let nested = dest.path().join("a").join("b").join("c");

    let reader = ImageReader::open(img_file.path()).unwrap();
    let carver = Carver::new(&reader, &nested);
    carver.carve(None).unwrap();

    assert!(nested.exists());
}
