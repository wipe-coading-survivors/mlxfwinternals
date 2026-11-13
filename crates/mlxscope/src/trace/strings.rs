//! Strings DB extraction from a CX-4 Lx FS3 image (MAIN_CODE de-clcrc).
//!
//! Geometry (docs/250-re/120-irisc/030-cx4lx-detour.md, live-verified L1/B1): MAIN_CODE lines are 68 bytes
//! (64 code + 2 zero-pad + 2 LE clcrc); `raw = 0x16d000 + line*68 + within`,
//! `dc = line*64 + within`, strings-DB rt address = dc + 0x800000.
//! A string may cross line boundaries — the 4-byte clcrc tail of each line is
//! skipped while reading. Verified pair (B1 §Phase 6): rt 0x00ADDB35 ->
//! raw 0x4788e5 -> "dispatcher_post_flow".

use std::path::Path;

pub const MAIN_CODE_FLASH_BASE: u64 = 0x16d000;
pub const LINE_RAW: u64 = 68;
pub const LINE_CODE: u64 = 64;
pub const RT_BASE: u64 = 0x800000;

/// Convert an rt address (dc + 0x800000) to a raw image offset.
pub fn rt_to_raw(rt: u64) -> u64 {
    let dc = rt - RT_BASE;
    MAIN_CODE_FLASH_BASE + (dc / LINE_CODE) * LINE_RAW + (dc % LINE_CODE)
}

pub struct StringsDb {
    pub image: Vec<u8>,
    /// (address, size) of db0 as reported by MTRC_CAP (rt addresses).
    #[cfg_attr(not(test), allow(dead_code))]
    pub db0: (u64, u64),
}

impl StringsDb {
    pub fn load(image_path: &Path, db0: (u64, u64)) -> anyhow::Result<Self> {
        let image = std::fs::read(image_path)
            .map_err(|e| anyhow::anyhow!("strings: read {}: {e}", image_path.display()))?;
        Ok(Self { image, db0 })
    }

    #[cfg(test)]
    pub fn from_parts(image: Vec<u8>, db0: (u64, u64)) -> Self {
        Self { image, db0 }
    }

    /// Read a NUL-terminated string starting at `rt`, de-clcrc'ing lines.
    /// Line layout: [64 code bytes][2 zero-pad][2 LE clcrc] — the string
    /// lives in the 64-byte code chunks; the 4-byte tail is skipped and its
    /// pad NULs are NOT terminators.
    pub fn string_at(&self, rt: u64) -> Option<String> {
        let mut out = Vec::new();
        let mut pos = rt_to_raw(rt);
        let end = self.image.len() as u64;
        for _ in 0..4096 {
            let line_start = line_raw_start(pos);
            let code_end = (line_start + LINE_CODE).min(end);
            while pos < code_end {
                let b = self.image[pos as usize];
                pos += 1;
                if b == 0 {
                    return Some(String::from_utf8_lossy(&out).into_owned());
                }
                out.push(b);
                if out.len() > 512 {
                    return Some(String::from_utf8_lossy(&out).into_owned());
                }
            }
            pos = line_start + LINE_RAW; // skip pad+crc tail
            if pos >= end {
                break;
            }
        }
        (!out.is_empty()).then(|| String::from_utf8_lossy(&out).into_owned())
    }

    #[cfg(test)]
    pub fn contains_rt(&self, rt: u64) -> bool {
        let (addr, size) = self.db0;
        rt >= addr && rt < addr + size
    }
}

/// Raw offset of the 68-byte line containing raw offset `pos`
/// (lines are aligned relative to MAIN_CODE_FLASH_BASE, which is not a
/// multiple of 68).
fn line_raw_start(pos: u64) -> u64 {
    MAIN_CODE_FLASH_BASE + ((pos - MAIN_CODE_FLASH_BASE) / LINE_RAW) * LINE_RAW
}

/// Render a format string with params (driver-style): substitute %x/%X/%d/%u
/// (plus FW precision forms like %.4x) in order with params; leftover params
/// appended as hex list; unknown specifiers left verbatim.
pub fn render_format(fmt: &str, params: &[u32]) -> String {
    let mut out = String::with_capacity(fmt.len() + 16);
    let bytes = fmt.as_bytes().to_vec();
    let mut i = 0usize;
    let mut idx = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        // parse: %[.N]conv
        let mut j = i + 1;
        let mut precision = 0usize;
        if j < bytes.len() && bytes[j] == b'.' {
            j += 1;
            let mut p = 0usize;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                p = p * 10 + (bytes[j] - b'0') as usize;
                j += 1;
            }
            precision = p;
        }
        let conv = bytes.get(j).map(|b| *b as char);
        match conv {
            Some('%') => {
                out.push('%');
                j += 1;
            }
            Some('x') | Some('X') => {
                if let Some(v) = params.get(idx) {
                    idx += 1;
                    let mut s = format!("{v:x}");
                    while s.len() < precision {
                        s.insert(0, '0');
                    }
                    out.push_str(&s);
                } else {
                    out.push_str("%x");
                }
                j += 1;
            }
            Some('d') | Some('u') => {
                if let Some(v) = params.get(idx) {
                    idx += 1;
                    out.push_str(&format!("{v}"));
                } else {
                    out.push_str("%d");
                }
                j += 1;
            }
            _ => {
                out.push('%');
                j = i + 1;
            }
        }
        i = j;
    }
    for p in &params[idx..] {
        out.push_str(&format!(" {p:#x}"));
    }
    out
}

#[cfg(test)]
pub fn synthetic_image_at(rt: u64, s: &[u8]) -> Vec<u8> {
    let raw = rt_to_raw(rt);
    let line = raw / LINE_RAW;
    let mut img = vec![0u8; (raw + s.len() as u64 + 256) as usize];
    let mut l = 0u64;
    while l <= line + 2 {
        for i in 0..4 {
            img[((l + 1) * LINE_RAW - 4 + i) as usize] = 0xAA;
        }
        l += 1;
    }
    // write de-clcrc'd: bytes into the 64-byte code chunk, then continue at
    // the next line's code start (pad+crc tail skipped)
    let mut pos = raw;
    let mut rest = s;
    loop {
        let line_start = line_raw_start(pos);
        let code_end = line_start + LINE_CODE;
        let take = ((code_end - pos) as usize).min(rest.len());
        img[pos as usize..pos as usize + take].copy_from_slice(&rest[..take]);
        rest = &rest[take..];
        if rest.is_empty() {
            img[pos as usize + take] = 0;
            break;
        }
        pos = line_start + LINE_RAW;
    }
    img
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic 68-byte-line image with a string crossing a line boundary.
    fn synthetic_image() -> Vec<u8> {
        // place string at dc of rt 0x00ADDB35 (within = 0x35 = 53 -> 11 bytes
        // in that line, then clcrc, then "post_flow")
        synthetic_image_at(0xADDB35, b"dispatcher_post_flow")
    }

    #[test]
    fn rt_to_raw_b1_verbatim_pair() {
        assert_eq!(rt_to_raw(0x00ADDB35), 0x4788e5);
        assert_eq!(rt_to_raw(0x00ad6900), 0x470f90);
    }

    #[test]
    fn string_crossing_line_boundary() {
        let db = StringsDb::from_parts(synthetic_image(), (0x00ad6900, 0x44a00));
        assert_eq!(db.string_at(0xADDB35).unwrap(), "dispatcher_post_flow");
        assert!(db.contains_rt(0xADDB35));
        assert!(!db.contains_rt(0x00ad6900 + 0x44a00));
    }

    #[test]
    fn string_out_of_image_is_none() {
        let db = StringsDb::from_parts(vec![0u8; 16], (0x00ad6900, 0x44a00));
        assert_eq!(db.string_at(0x00ad6900), None);
    }

    /// Anchors verified against the stock 14.32.1900 image (B1/L3 verbatim:
    /// dispatcher_post_flow pair from B1 §Phase 6, hook strings from docs/250-re/120-irisc/040-cx4lx-hook.md).
    #[test]
    fn real_image_anchors_when_present() {
        let p = std::path::Path::new(
            "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin",
        );
        if !p.exists() {
            return; // repo layout differs; synthetic tests still cover the logic
        }
        let db = StringsDb::load(p, (0x00ad6900, 0x44a00)).unwrap();
        assert_eq!(
            db.string_at(0x00ada88c).unwrap(),
            "icmd_generic_reg_access: reg_is_flash_reg_access=%d, register_id=0x%.4x"
        );
        assert_eq!(
            db.string_at(0x00ada612).unwrap(),
            "got an unexpected memory profile value, memory_profile = 0x%x"
        );
        assert_eq!(db.string_at(0x00ADDB35).unwrap(), "dispatcher_post_flow");
    }

    #[test]
    fn render_format_basic() {
        assert_eq!(render_format("register_id=0x%x", &[0x9040]), "register_id=0x9040");
        assert_eq!(render_format("n=%d", &[42]), "n=42");
        assert_eq!(render_format("a=%x b=%x", &[1, 2]), "a=1 b=2");
        assert_eq!(render_format("register_id=0x%.4x", &[0x9040]), "register_id=0x9040");
        assert_eq!(render_format("v=0x%.4x", &[0x12]), "v=0x0012");
    }

    #[test]
    fn render_format_leftover_and_missing() {
        assert_eq!(render_format("v=%x", &[1, 2, 3]), "v=1 0x2 0x3");
        assert_eq!(render_format("v=%x extra", &[]), "v=%x extra");
        assert_eq!(render_format("100%%", &[]), "100%");
    }
}
