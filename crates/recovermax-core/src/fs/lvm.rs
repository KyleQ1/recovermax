//! LVM2 Physical Volume detection and metadata parsing.
//!
//! Detects LVM PV labels ("LABELONE" magic), parses PV headers and MDA
//! (Metadata Area) text to extract VG/LV definitions, and computes the
//! disk offset of each logical volume so that filesystem probing can find
//! ext4 (or other filesystems) inside LVs.

use anyhow::{anyhow, Context, Result};

use crate::io::{DiskRead, ImageReader};

const PV_LABEL_MAGIC: &[u8; 8] = b"LABELONE";
const MDA_MAGIC: &[u8; 4] = b" LVM";

/// Physical Volume header parsed from disk.
#[derive(Debug, Clone)]
pub struct PvHeader {
    pub pv_uuid: String,
    /// Byte offset of the first data area relative to PV (partition) start.
    pub data_area_offset: u64,
    pub data_area_size: u64,
    /// All metadata area descriptors (primary + backup).
    pub mda_areas: Vec<MdaDescriptor>,
}

/// A metadata area descriptor from the PV header.
#[derive(Debug, Clone)]
pub struct MdaDescriptor {
    pub offset: u64,
    pub size: u64,
}

/// A single LV segment mapping logical extents to physical extents.
#[derive(Debug, Clone)]
pub struct LvSegment {
    /// Starting logical extent in the LV.
    pub start_le: u64,
    /// Number of extents in this segment.
    pub extent_count: u64,
    /// Starting physical extent on the PV.
    pub pv_start_pe: u64,
}

/// A logical volume discovered within an LVM PV.
#[derive(Debug, Clone)]
pub struct LvInfo {
    pub name: String,
    pub vg_name: String,
    /// Extent size in bytes.
    pub extent_size_bytes: u64,
    /// Absolute disk offset of PE 0 on this PV.
    pub pe_start_bytes: u64,
    /// Segments mapping LV extents to PV extents.
    pub segments: Vec<LvSegment>,
    /// Total LV size in bytes.
    pub total_size: u64,
    /// True if this LV uses thin provisioning (thin-pool or thin).
    pub is_thin: bool,
}

impl LvInfo {
    /// Compute the absolute disk byte offset where this LV's data begins.
    /// Only valid for single-segment LVs starting at PE 0.
    pub fn disk_offset(&self) -> Option<u64> {
        if self.segments.len() != 1 {
            return None;
        }
        let seg = &self.segments[0];
        Some(self.pe_start_bytes + seg.pv_start_pe * self.extent_size_bytes)
    }

    /// Total size in bytes (computed from segment extents).
    pub fn computed_size(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| s.extent_count * self.extent_size_bytes)
            .sum()
    }
}

/// Check if a partition contains an LVM PV by looking for "LABELONE" magic.
/// Searches sectors 0–3 (the label can be in any of the first 4 sectors).
// ---------------------------------------------------------------------------
// LvReader — virtual reader for multi-segment LVs
// ---------------------------------------------------------------------------

struct ResolvedSegment {
    lv_start_byte: u64,
    disk_offset: u64,
    length: u64,
}

/// Virtual disk reader for an LVM logical volume.
/// Translates LV-relative offsets to absolute disk offsets through the segment map.
pub struct LvReader<'a> {
    inner: &'a ImageReader,
    segments: Vec<ResolvedSegment>,
    total_size: u64,
}

impl<'a> LvReader<'a> {
    pub fn new(inner: &'a ImageReader, lv: &LvInfo) -> Self {
        let mut segments = Vec::with_capacity(lv.segments.len());
        let mut lv_pos = 0u64;
        for seg in &lv.segments {
            let disk_offset = lv.pe_start_bytes + seg.pv_start_pe * lv.extent_size_bytes;
            let length = seg.extent_count * lv.extent_size_bytes;
            segments.push(ResolvedSegment {
                lv_start_byte: lv_pos,
                disk_offset,
                length,
            });
            lv_pos += length;
        }
        Self {
            inner,
            segments,
            total_size: lv_pos,
        }
    }

    /// Build from a serialized LvmMap (for session reload).
    pub fn from_lvm_map(inner: &'a ImageReader, map: &super::LvmMap) -> Self {
        let mut segments = Vec::with_capacity(map.segments.len());
        let mut lv_pos = 0u64;
        for seg in &map.segments {
            let disk_offset = map.pe_start_bytes + seg.pv_start_pe * map.extent_size_bytes;
            let length = seg.extent_count * map.extent_size_bytes;
            segments.push(ResolvedSegment {
                lv_start_byte: lv_pos,
                disk_offset,
                length,
            });
            lv_pos += length;
        }
        Self {
            inner,
            segments,
            total_size: lv_pos,
        }
    }

    fn find_segment(&self, offset: u64) -> Result<(&ResolvedSegment, u64)> {
        for seg in &self.segments {
            if offset >= seg.lv_start_byte && offset < seg.lv_start_byte + seg.length {
                return Ok((seg, offset - seg.lv_start_byte));
            }
        }
        Err(anyhow!("LV offset {} is out of range (total size {})", offset, self.total_size))
    }
}

impl DiskRead for LvReader<'_> {
    fn read_at(&self, offset: u64, len: usize) -> Result<&[u8]> {
        let (seg, local_off) = self.find_segment(offset)?;
        let remaining = seg.length - local_off;
        if (len as u64) > remaining {
            anyhow::bail!(
                "LV read at offset {} of {} bytes crosses segment boundary ({} bytes remaining)",
                offset, len, remaining
            );
        }
        self.inner.read_at(seg.disk_offset + local_off, len)
    }

    fn read_at_exact(&self, offset: u64, len: usize) -> Result<&[u8]> {
        let (seg, local_off) = self.find_segment(offset)?;
        let remaining = seg.length - local_off;
        if (len as u64) > remaining {
            anyhow::bail!(
                "LV read at offset {} of {} bytes crosses segment boundary ({} bytes remaining)",
                offset, len, remaining
            );
        }
        self.inner.read_at_exact(seg.disk_offset + local_off, len)
    }

    fn len(&self) -> u64 {
        self.total_size
    }
}

// ---------------------------------------------------------------------------
// PV detection and parsing
// ---------------------------------------------------------------------------

pub fn detect_pv(reader: &ImageReader, partition_offset: u64) -> Option<PvHeader> {
    for sector in 0..4u64 {
        let offset = partition_offset + sector * 512;
        let data = reader.read_at(offset, 512).ok()?;
        if data.len() < 64 || &data[0..8] != PV_LABEL_MAGIC {
            continue;
        }

        // data[20..24]: offset of PV header from start of this sector
        let pv_header_offset = u32::from_le_bytes(
            data[20..24].try_into().ok()?,
        ) as usize;

        if pv_header_offset >= 480 {
            continue;
        }

        let hdr = &data[pv_header_offset..];
        if let Some(pv) = parse_pv_header(hdr) {
            return Some(pv);
        }
    }
    None
}

fn parse_pv_header(hdr: &[u8]) -> Option<PvHeader> {
    if hdr.len() < 40 {
        return None;
    }

    let pv_uuid = String::from_utf8_lossy(&hdr[0..32])
        .trim_end_matches('\0')
        .trim()
        .to_string();

    // Skip device_size at offset 32 (8 bytes)
    let mut pos = 40;

    // Parse data area descriptors: (offset: u64, size: u64) pairs, terminated by (0, 0)
    let mut data_area_offset = 0u64;
    let mut data_area_size = 0u64;
    while pos + 16 <= hdr.len() {
        let off = u64::from_le_bytes(hdr[pos..pos + 8].try_into().ok()?);
        let sz = u64::from_le_bytes(hdr[pos + 8..pos + 16].try_into().ok()?);
        pos += 16;
        if off == 0 && sz == 0 {
            break;
        }
        if data_area_offset == 0 {
            data_area_offset = off;
            data_area_size = sz;
        }
    }

    // Parse MDA descriptors: collect all (primary + backup)
    let mut mda_areas = Vec::new();
    while pos + 16 <= hdr.len() {
        let off = u64::from_le_bytes(hdr[pos..pos + 8].try_into().ok()?);
        let sz = u64::from_le_bytes(hdr[pos + 8..pos + 16].try_into().ok()?);
        pos += 16;
        if off == 0 && sz == 0 {
            break;
        }
        mda_areas.push(MdaDescriptor { offset: off, size: sz });
    }

    if mda_areas.is_empty() {
        return None;
    }

    Some(PvHeader {
        pv_uuid,
        data_area_offset,
        data_area_size,
        mda_areas,
    })
}

/// Parse the MDA (Metadata Area) to extract LV definitions.
/// Tries all MDA areas in order (primary first, then backup).
pub fn parse_mda(
    reader: &ImageReader,
    partition_offset: u64,
    pv: &PvHeader,
) -> Result<Vec<LvInfo>> {
    for (i, mda) in pv.mda_areas.iter().enumerate() {
        match try_parse_mda_at(reader, partition_offset, pv, mda) {
            Ok(lvs) if !lvs.is_empty() => return Ok(lvs),
            Ok(_) => {
                tracing::debug!("MDA {} at offset {} parsed but contained no LVs", i, mda.offset);
            }
            Err(err) => {
                tracing::debug!("MDA {} at offset {} failed: {}", i, mda.offset, err);
            }
        }
    }
    anyhow::bail!(
        "No valid MDA found (tried {} locations)",
        pv.mda_areas.len()
    )
}

fn try_parse_mda_at(
    reader: &ImageReader,
    partition_offset: u64,
    pv: &PvHeader,
    mda: &MdaDescriptor,
) -> Result<Vec<LvInfo>> {
    let mda_abs = partition_offset + mda.offset;
    let mda_header = reader
        .read_at_exact(mda_abs, 512)
        .context("Failed to read MDA header")?;

    if mda_header.len() < 40 || &mda_header[0..4] != MDA_MAGIC {
        anyhow::bail!("Invalid MDA magic at offset {}", mda_abs);
    }

    // raw_locn[0] starts at offset 24 in MDA header
    let text_offset = u64::from_le_bytes(mda_header[24..32].try_into()?);
    let text_size = u64::from_le_bytes(mda_header[32..40].try_into()?);

    if text_size == 0 || text_size > mda.size || text_size > 10 * 1024 * 1024 {
        anyhow::bail!("Invalid MDA text size: {}", text_size);
    }

    let text_abs = mda_abs + text_offset;
    let text_data = reader
        .read_at_exact(text_abs, text_size as usize)
        .context("Failed to read MDA config text")?;

    let config_text =
        std::str::from_utf8(text_data).context("MDA config text is not valid UTF-8")?;

    parse_vg_config(config_text, partition_offset, pv)
}

/// Parse the LVM VG config text (vgcfgbackup format) and extract LV definitions.
///
/// This is a simplified line-by-line parser that extracts extent_size, pe_start,
/// and per-LV segment mappings. It handles the standard Ubuntu/RHEL layout.
pub fn parse_vg_config(
    text: &str,
    partition_offset: u64,
    _pv: &PvHeader,
) -> Result<Vec<LvInfo>> {
    let mut vg_name = String::new();
    let mut extent_size_sectors: u64 = 8192; // default 4 MiB
    let mut pe_start_sectors: u64 = 2048; // default 1 MiB

    // First pass: extract VG-level fields
    let mut depth = 0i32;
    let mut in_physical_volumes = false;
    let mut in_pv = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.ends_with('{') {
            if depth == 0 && vg_name.is_empty() {
                vg_name = trimmed.trim_end_matches('{').trim().to_string();
            }
            if trimmed.starts_with("physical_volumes") {
                in_physical_volumes = true;
            }
            if in_physical_volumes && depth >= 2 {
                in_pv = true;
            }
            depth += 1;
            continue;
        }
        if trimmed == "}" {
            depth -= 1;
            if depth <= 1 {
                in_physical_volumes = false;
                in_pv = false;
            }
            continue;
        }

        if depth == 1 {
            if let Some(val) = parse_config_u64(trimmed, "extent_size") {
                extent_size_sectors = val;
            }
        }

        if in_pv {
            if let Some(val) = parse_config_u64(trimmed, "pe_start") {
                pe_start_sectors = val;
            }
        }
    }

    let extent_size_bytes = extent_size_sectors * 512;
    let pe_start_bytes = partition_offset + pe_start_sectors * 512;

    // Second pass: extract logical volumes
    let mut lvs = Vec::new();
    depth = 0;
    let mut in_logical_volumes = false;
    let mut current_lv_name = String::new();
    let mut current_segments: Vec<LvSegment> = Vec::new();
    let mut seg_start_extent: u64 = 0;
    let mut seg_extent_count: u64 = 0;
    let mut in_segment = false;
    let mut in_stripes = false;
    let mut stripe_values: Vec<String> = Vec::new();
    let mut lv_is_thin = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.ends_with('{') {
            if trimmed.starts_with("logical_volumes") {
                in_logical_volumes = true;
            }
            if in_logical_volumes && depth == 2 {
                current_lv_name = trimmed.trim_end_matches('{').trim().to_string();
                current_segments.clear();
                lv_is_thin = false;
            }
            if in_logical_volumes && depth >= 3 && trimmed.starts_with("segment") {
                in_segment = true;
                seg_start_extent = 0;
                seg_extent_count = 0;
                stripe_values.clear();
            }
            depth += 1;
            continue;
        }
        if trimmed == "}" || trimmed == "}," {
            depth -= 1;
            if in_segment && depth == 3 {
                // End of segment block — build LvSegment from stripes
                let pv_start_pe = parse_stripe_start_pe(&stripe_values);
                current_segments.push(LvSegment {
                    start_le: seg_start_extent,
                    extent_count: seg_extent_count,
                    pv_start_pe,
                });
                in_segment = false;
            }
            if in_logical_volumes && depth == 2 && !current_lv_name.is_empty() {
                // End of LV block
                let total_size: u64 = current_segments
                    .iter()
                    .map(|s| s.extent_count * extent_size_bytes)
                    .sum();
                if lv_is_thin {
                    tracing::info!(
                        "LVM thin pool/volume detected: {}/{}. Thin provisioning metadata parsing not yet supported.",
                        vg_name, current_lv_name
                    );
                }
                lvs.push(LvInfo {
                    name: current_lv_name.clone(),
                    vg_name: vg_name.clone(),
                    extent_size_bytes,
                    pe_start_bytes,
                    segments: current_segments.clone(),
                    total_size,
                    is_thin: lv_is_thin,
                });
                current_lv_name.clear();
            }
            if depth <= 1 {
                in_logical_volumes = false;
            }
            continue;
        }

        if in_segment {
            // Detect thin provisioning segment types
            if trimmed.starts_with("type") && trimmed.contains('=') {
                if trimmed.contains("thin-pool") || trimmed.contains("thin") {
                    lv_is_thin = true;
                }
            }
            if let Some(val) = parse_config_u64(trimmed, "start_extent") {
                seg_start_extent = val;
            }
            if let Some(val) = parse_config_u64(trimmed, "extent_count") {
                seg_extent_count = val;
            }

            // Parse stripes = ["pv0", 0] — may be on one line or multiple
            if trimmed.starts_with("stripes") && trimmed.contains('[') {
                in_stripes = true;
                stripe_values.clear();
                // Try to parse inline: stripes = ["pv0", 0]
                if let Some(bracket_content) = extract_bracket_content(trimmed) {
                    for part in bracket_content.split(',') {
                        let p = part.trim().trim_matches('"').to_string();
                        if !p.is_empty() {
                            stripe_values.push(p);
                        }
                    }
                    if trimmed.contains(']') {
                        in_stripes = false;
                    }
                }
            } else if in_stripes {
                let line_content = if trimmed.contains(']') {
                    in_stripes = false;
                    trimmed.trim_end_matches(']')
                } else {
                    trimmed
                };
                for part in line_content.split(',') {
                    let p = part.trim().trim_matches('"').to_string();
                    if !p.is_empty() {
                        stripe_values.push(p);
                    }
                }
            }
        }
    }

    Ok(lvs)
}

fn parse_config_u64(line: &str, key: &str) -> Option<u64> {
    let trimmed = line.trim();
    if !trimmed.starts_with(key) {
        return None;
    }
    let rest = trimmed[key.len()..].trim();
    if !rest.starts_with('=') {
        return None;
    }
    rest[1..].trim().parse::<u64>().ok()
}

fn extract_bracket_content(line: &str) -> Option<&str> {
    let start = line.find('[')?;
    let end = line.rfind(']').unwrap_or(line.len());
    Some(&line[start + 1..end])
}

fn parse_stripe_start_pe(values: &[String]) -> u64 {
    // stripes = ["pv0", 0] → values = ["pv0", "0"]
    // The second value (index 1) is the starting PE on the PV
    if values.len() >= 2 {
        values[1].trim().parse::<u64>().unwrap_or(0)
    } else {
        0
    }
}

/// Full detection: find PV, read MDA, parse config, return LV info.
pub fn detect(reader: &ImageReader, partition_offset: u64) -> Option<Vec<LvInfo>> {
    let pv = detect_pv(reader, partition_offset)?;
    match parse_mda(reader, partition_offset, &pv) {
        Ok(lvs) if !lvs.is_empty() => Some(lvs),
        Ok(_) => None,
        Err(err) => {
            tracing::debug!("LVM MDA parse failed at offset {}: {}", partition_offset, err);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vg_config_single_lv() {
        let config = r#"
ubuntu-vg {
    id = "abc123-def456-ghi789"
    seqno = 2
    format = "lvm2"
    status = ["READ", "WRITE"]
    extent_size = 8192

    physical_volumes {
        pv0 {
            id = "xyz000-aaa111-bbb222"
            device = "/dev/sda3"
            status = ["ALLOCATABLE"]
            pe_start = 2048
            pe_count = 476931
        }
    }

    logical_volumes {
        ubuntu-lv {
            id = "lv1234-5678-abcd"
            status = ["READ", "WRITE", "VISIBLE"]
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 476931
                type = "striped"
                stripe_count = 1
                stripes = [
                    "pv0", 0
                ]
            }
        }
    }
}
"#;
        let pv = PvHeader {
            pv_uuid: "test-uuid".into(),
            data_area_offset: 1024 * 1024,
            data_area_size: 0,
            mda_areas: vec![MdaDescriptor { offset: 4096, size: 1024 * 1024 }],
        };
        let lvs = parse_vg_config(config, 0, &pv).unwrap();
        assert_eq!(lvs.len(), 1);
        assert_eq!(lvs[0].name, "ubuntu-lv");
        assert_eq!(lvs[0].vg_name, "ubuntu-vg");
        assert_eq!(lvs[0].extent_size_bytes, 8192 * 512); // 4 MiB
        assert_eq!(lvs[0].pe_start_bytes, 2048 * 512); // 1 MiB
        assert_eq!(lvs[0].segments.len(), 1);
        assert_eq!(lvs[0].segments[0].extent_count, 476931);
        assert_eq!(lvs[0].segments[0].pv_start_pe, 0);
        assert_eq!(lvs[0].total_size, 476931 * 8192 * 512);

        let disk_off = lvs[0].disk_offset();
        assert!(disk_off.is_some());
        assert_eq!(disk_off.unwrap(), 2048 * 512); // pe_start + 0 * extent_size
    }

    #[test]
    fn parse_vg_config_multiple_lvs() {
        let config = r#"
pve {
    extent_size = 8192

    physical_volumes {
        pv0 {
            pe_start = 2048
            pe_count = 1000
        }
    }

    logical_volumes {
        root {
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 500
                type = "striped"
                stripe_count = 1
                stripes = [
                    "pv0", 0
                ]
            }
        }
        swap {
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 100
                type = "striped"
                stripe_count = 1
                stripes = [
                    "pv0", 500
                ]
            }
        }
    }
}
"#;
        let pv = PvHeader {
            pv_uuid: "test".into(),
            data_area_offset: 1024 * 1024,
            data_area_size: 0,
            mda_areas: vec![MdaDescriptor { offset: 4096, size: 65536 }],
        };
        let lvs = parse_vg_config(config, 0, &pv).unwrap();
        assert_eq!(lvs.len(), 2);
        assert_eq!(lvs[0].name, "root");
        assert_eq!(lvs[0].segments[0].extent_count, 500);
        assert_eq!(lvs[0].segments[0].pv_start_pe, 0);
        assert_eq!(lvs[1].name, "swap");
        assert_eq!(lvs[1].segments[0].extent_count, 100);
        assert_eq!(lvs[1].segments[0].pv_start_pe, 500);
    }

    #[test]
    fn parse_vg_config_inline_stripes() {
        let config = r#"
myvg {
    extent_size = 8192
    physical_volumes {
        pv0 {
            pe_start = 2048
        }
    }
    logical_volumes {
        data {
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 200
                type = "striped"
                stripe_count = 1
                stripes = ["pv0", 0]
            }
        }
    }
}
"#;
        let pv = PvHeader {
            pv_uuid: "test".into(),
            data_area_offset: 0,
            data_area_size: 0,
            mda_areas: vec![],
        };
        let lvs = parse_vg_config(config, 0, &pv).unwrap();
        assert_eq!(lvs.len(), 1);
        assert_eq!(lvs[0].segments[0].extent_count, 200);
    }

    #[test]
    fn multi_segment_lv_has_no_disk_offset() {
        let lv = LvInfo {
            name: "data".into(),
            vg_name: "vg".into(),
            extent_size_bytes: 4 * 1024 * 1024,
            pe_start_bytes: 1024 * 1024,
            segments: vec![
                LvSegment {
                    start_le: 0,
                    extent_count: 100,
                    pv_start_pe: 0,
                },
                LvSegment {
                    start_le: 100,
                    extent_count: 50,
                    pv_start_pe: 200,
                },
            ],
            total_size: 150 * 4 * 1024 * 1024,
            is_thin: false,
        };
        assert!(lv.disk_offset().is_none());
    }

    #[test]
    fn thin_pool_lv_detected() {
        let config = r#"
pve {
    extent_size = 8192
    physical_volumes {
        pv0 {
            pe_start = 2048
        }
    }
    logical_volumes {
        data {
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 500
                type = "thin-pool"
                stripe_count = 1
                stripes = [
                    "pv0", 0
                ]
            }
        }
        root {
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 100
                type = "striped"
                stripe_count = 1
                stripes = [
                    "pv0", 500
                ]
            }
        }
    }
}
"#;
        let pv = PvHeader {
            pv_uuid: "test".into(),
            data_area_offset: 0,
            data_area_size: 0,
            mda_areas: vec![],
        };
        let lvs = parse_vg_config(config, 0, &pv).unwrap();
        assert_eq!(lvs.len(), 2);
        assert!(lvs[0].is_thin, "data should be detected as thin");
        assert_eq!(lvs[0].name, "data");
        assert!(!lvs[1].is_thin, "root should not be thin");
        assert_eq!(lvs[1].name, "root");
    }

    #[test]
    fn lv_reader_translates_single_segment() {
        use crate::io::ImageReader;
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a 2 MiB image with known data at offset 1 MiB
        let mut img = vec![0u8; 2 * 1024 * 1024];
        let data_offset = 1024 * 1024usize;
        img[data_offset..data_offset + 5].copy_from_slice(b"HELLO");

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&img).unwrap();
        f.flush().unwrap();
        let reader = ImageReader::open(f.path()).unwrap();

        let lv = LvInfo {
            name: "test-lv".into(),
            vg_name: "test-vg".into(),
            extent_size_bytes: 1024 * 1024,
            pe_start_bytes: 1024 * 1024,
            segments: vec![LvSegment {
                start_le: 0,
                extent_count: 1,
                pv_start_pe: 0,
            }],
            total_size: 1024 * 1024,
            is_thin: false,
        };

        let lv_reader = LvReader::new(&reader, &lv);
        let data = lv_reader.read_at(0, 5).unwrap();
        assert_eq!(data, b"HELLO");
    }

    #[test]
    fn lv_reader_multi_segment_reads() {
        use crate::io::ImageReader;
        use std::io::Write;
        use tempfile::NamedTempFile;

        // 3 MiB image: segment 1 data at 1 MiB, segment 2 data at 2 MiB
        let mut img = vec![0u8; 3 * 1024 * 1024];
        let seg1_off = 1024 * 1024usize;
        let seg2_off = 2 * 1024 * 1024usize;
        img[seg1_off..seg1_off + 4].copy_from_slice(b"SEG1");
        img[seg2_off..seg2_off + 4].copy_from_slice(b"SEG2");

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&img).unwrap();
        f.flush().unwrap();
        let reader = ImageReader::open(f.path()).unwrap();

        let lv = LvInfo {
            name: "multi".into(),
            vg_name: "vg".into(),
            extent_size_bytes: 1024 * 1024,
            pe_start_bytes: 1024 * 1024,
            segments: vec![
                LvSegment { start_le: 0, extent_count: 1, pv_start_pe: 0 },
                LvSegment { start_le: 1, extent_count: 1, pv_start_pe: 1 },
            ],
            total_size: 2 * 1024 * 1024,
            is_thin: false,
        };

        let lv_reader = LvReader::new(&reader, &lv);
        assert_eq!(lv_reader.len(), 2 * 1024 * 1024);

        let seg1 = lv_reader.read_at(0, 4).unwrap();
        assert_eq!(seg1, b"SEG1");

        let seg2 = lv_reader.read_at(1024 * 1024, 4).unwrap();
        assert_eq!(seg2, b"SEG2");
    }

    #[test]
    fn lv_reader_cross_boundary_errors() {
        use crate::io::ImageReader;
        use std::io::Write;
        use tempfile::NamedTempFile;

        let img = vec![0u8; 3 * 1024 * 1024];
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&img).unwrap();
        f.flush().unwrap();
        let reader = ImageReader::open(f.path()).unwrap();

        let lv = LvInfo {
            name: "multi".into(),
            vg_name: "vg".into(),
            extent_size_bytes: 1024 * 1024,
            pe_start_bytes: 1024 * 1024,
            segments: vec![
                LvSegment { start_le: 0, extent_count: 1, pv_start_pe: 0 },
                LvSegment { start_le: 1, extent_count: 1, pv_start_pe: 1 },
            ],
            total_size: 2 * 1024 * 1024,
            is_thin: false,
        };

        let lv_reader = LvReader::new(&reader, &lv);

        // Read that spans the boundary between segment 0 and segment 1
        let result = lv_reader.read_at(1024 * 1024 - 10, 20);
        assert!(result.is_err(), "cross-boundary read should error");
    }
}
