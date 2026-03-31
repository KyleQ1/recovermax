use std::io::Write;
use tempfile::NamedTempFile;
use recovermax_core::io::ImageReader;

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn open_valid_file() {
    let f = create_test_image(&[0u8; 512]);
    let reader = ImageReader::open(f.path()).unwrap();
    assert_eq!(reader.len(), 512);
    assert!(!reader.is_empty());
}

#[test]
fn open_empty_file() {
    let f = create_test_image(&[]);
    let reader = ImageReader::open(f.path()).unwrap();
    assert_eq!(reader.len(), 0);
    assert!(reader.is_empty());
}

#[test]
fn open_nonexistent_file() {
    let result = ImageReader::open(std::path::Path::new("/tmp/nonexistent_recovermax_test.img"));
    assert!(result.is_err());
}

#[test]
fn read_at_valid_offset() {
    let data: Vec<u8> = (0..=255).collect();
    let f = create_test_image(&data);
    let reader = ImageReader::open(f.path()).unwrap();

    let slice = reader.read_at(0, 4).unwrap();
    assert_eq!(slice, &[0, 1, 2, 3]);

    let slice = reader.read_at(100, 3).unwrap();
    assert_eq!(slice, &[100, 101, 102]);
}

#[test]
fn read_at_end_of_file() {
    let f = create_test_image(&[0xAA; 64]);
    let reader = ImageReader::open(f.path()).unwrap();

    // Request more than available — should return up to end
    let slice = reader.read_at(60, 100).unwrap();
    assert_eq!(slice.len(), 4);
    assert!(slice.iter().all(|&b| b == 0xAA));
}

#[test]
fn read_at_beyond_file() {
    let f = create_test_image(&[0u8; 64]);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = reader.read_at(1000, 1);
    assert!(result.is_err());
}

#[test]
fn read_array_exact() {
    let data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
    let f = create_test_image(&data);
    let reader = ImageReader::open(f.path()).unwrap();

    let arr: [u8; 4] = reader.read_array(0).unwrap();
    assert_eq!(arr, [0x10, 0x20, 0x30, 0x40]);
}

#[test]
fn read_array_short_read() {
    let f = create_test_image(&[0xFF, 0xEE]);
    let reader = ImageReader::open(f.path()).unwrap();

    let result = reader.read_array::<4>(0);
    assert!(result.is_err());
}

#[test]
fn read_u16_le() {
    // 0x0201 in little-endian = bytes [0x01, 0x02]
    let f = create_test_image(&[0x01, 0x02, 0x00, 0x00]);
    let reader = ImageReader::open(f.path()).unwrap();
    assert_eq!(reader.read_u16_le(0).unwrap(), 0x0201);
}

#[test]
fn read_u32_le() {
    let f = create_test_image(&[0x78, 0x56, 0x34, 0x12]);
    let reader = ImageReader::open(f.path()).unwrap();
    assert_eq!(reader.read_u32_le(0).unwrap(), 0x12345678);
}

#[test]
fn read_u64_le() {
    let f = create_test_image(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
    let reader = ImageReader::open(f.path()).unwrap();
    assert_eq!(reader.read_u64_le(0).unwrap(), 0x8000000000000001);
}

#[test]
fn as_bytes_returns_full_image() {
    let data = vec![1, 2, 3, 4, 5];
    let f = create_test_image(&data);
    let reader = ImageReader::open(f.path()).unwrap();
    assert_eq!(reader.as_bytes(), &[1, 2, 3, 4, 5]);
}

#[test]
fn read_at_zero_length() {
    let f = create_test_image(&[0u8; 64]);
    let reader = ImageReader::open(f.path()).unwrap();
    let slice = reader.read_at(0, 0).unwrap();
    assert_eq!(slice.len(), 0);
}
