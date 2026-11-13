pub const WIDE_RANGE: (u64, u64) = (0x1000_0000, 0x2000_0000);
pub const SCRATCH_TARGET: u64 = 0x1800_0000;
pub const SCRATCH_W: u32 = 0x60_0000;
pub const MARKER: [u32; 3] = [0x258c_5332, 0x6c04_638a, 0xfd00_1825];
pub const SELF_SPANS: [(u64, u64); 1] = [(0x10A2_E000, 0x10A2_E240)];

const _: () = assert!((SCRATCH_W as u64) << 6 == SCRATCH_TARGET);

/// Все вхождения `marker` (последовательность 32-бит слов) в `buf` (стартовые слово-индексы).
pub fn find_marker(buf: &[u32], marker: &[u32]) -> Vec<usize> {
    let mut out = Vec::new();
    if marker.is_empty() || marker.len() > buf.len() {
        return out;
    }
    let last = buf.len() - marker.len();
    for i in 0..=last {
        if buf[i..i + marker.len()] == marker[..] {
            out.push(i);
        }
    }
    out
}

pub const MARKER_BE: [u32; 3] = [
    MARKER[0].swap_bytes(),
    MARKER[1].swap_bytes(),
    MARKER[2].swap_bytes(),
];

const _: () = assert!(
    MARKER_BE[0] == 0x3253_8c25 && MARKER_BE[1] == 0x8a63_046c && MARKER_BE[2] == 0x2518_00fd
);

#[derive(Debug, PartialEq, Eq)]
pub enum Form {
    Be,
    Le,
}

impl Form {
    pub fn as_str(&self) -> &'static str {
        match self {
            Form::Be => "BE",
            Form::Le => "LE",
        }
    }
}

pub fn scan_wide(words: &[u32], base: u64, le_mode: bool) -> Vec<(u64, Form)> {
    let mut hits: Vec<(u64, Form)> = Vec::new();
    for idx in find_marker(words, &MARKER_BE) {
        hits.push((base + (idx as u64) * 4, Form::Be));
    }
    if le_mode {
        for idx in find_marker(words, &MARKER) {
            hits.push((base + (idx as u64) * 4, Form::Le));
        }
    }
    hits.sort_by_key(|h| h.0);
    hits
}

/// Офлайн-скан сырых байтов региона: нативное (LE) чтение слов + обе формы (BE+LE).
/// `base` — стартовый адрес региона (для офлайн — `WIDE_RANGE.0`).
pub fn scan_raw_words(bytes: &[u8], base: u64) -> Vec<(u64, Form)> {
    assert!(bytes.len() % 4 == 0, "byte slice not word-aligned");
    if bytes.is_empty() {
        return Vec::new();
    }
    let words = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u32, bytes.len() / 4) };
    scan_wide(words, base, true)
}

#[cfg(test)]
mod tests {
    use super::{find_marker, scan_raw_words, scan_wide, Form, MARKER, MARKER_BE};

    #[test]
    fn finds_single_occurrence() {
        let buf = [0u32, 0, 0x258c_5332, 0x6c04_638a, 0xfd00_1825, 0u32];
        let marker = [0x258c_5332, 0x6c04_638a, 0xfd00_1825];
        assert_eq!(find_marker(&buf, &marker), vec![2]);
    }

    #[test]
    fn no_occurrence_returns_empty() {
        assert!(find_marker(&[0u32, 0, 0], &[0x258c_5332, 0x6c04_638a, 0xfd00_1825]).is_empty());
    }

    #[test]
    fn multiple_occurrences() {
        let m = [0xaa_u32, 0xbb];
        let buf = [0xaa, 0xbb, 0, 0xaa, 0xbb];
        assert_eq!(find_marker(&buf, &m), vec![0, 3]);
    }

    #[test]
    fn marker_longer_than_buf_is_empty() {
        assert!(find_marker(&[0u32], &[0u32, 1, 2]).is_empty());
    }

    #[test]
    fn scan_wide_be_form_default() {
        let words = [0u32, MARKER_BE[0], MARKER_BE[1], MARKER_BE[2], 0u32];
        let hits = scan_wide(&words, 0x1000_0000, false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0x1000_0000 + 1 * 4);
        assert_eq!(hits[0].1, Form::Be);
    }

    #[test]
    fn scan_wide_le_form_only_when_enabled() {
        let words = [0u32, MARKER[0], MARKER[1], MARKER[2], 0u32];
        assert!(scan_wide(&words, 0x1000_0000, false).is_empty());
        let hits = scan_wide(&words, 0x1000_0000, true);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0x1000_0000 + 1 * 4);
        assert_eq!(hits[0].1, Form::Le);
    }

    #[test]
    fn scan_wide_both_forms_sorted_by_addr() {
        let words = [
            0u32,
            MARKER[0], MARKER[1], MARKER[2],
            0u32, 0u32,
            MARKER_BE[0], MARKER_BE[1], MARKER_BE[2],
            0u32,
        ];
        let hits = scan_wide(&words, 0x1000_0000, true);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 0x1000_0000 + 1 * 4);
        assert_eq!(hits[0].1, Form::Le);
        assert_eq!(hits[1].0, 0x1000_0000 + 6 * 4);
        assert_eq!(hits[1].1, Form::Be);
    }

    #[test]
    fn scan_wide_both_forms_sorted_by_addr_mirror() {
        let words = [
            0u32,
            MARKER_BE[0], MARKER_BE[1], MARKER_BE[2],
            0u32, 0u32,
            MARKER[0], MARKER[1], MARKER[2],
            0u32,
        ];
        let hits = scan_wide(&words, 0x1000_0000, true);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 0x1000_0000 + 1 * 4);
        assert_eq!(hits[0].1, Form::Be);
        assert_eq!(hits[1].0, 0x1000_0000 + 6 * 4);
        assert_eq!(hits[1].1, Form::Le);
    }

    #[test]
    fn scan_wide_none_is_empty() {
        let words = [0u32, 1, 2, 3, 4];
        assert!(scan_wide(&words, 0x1000_0000, false).is_empty());
        assert!(scan_wide(&words, 0x1000_0000, true).is_empty());
        assert!(scan_wide(&[], 0x1000_0000, true).is_empty());
    }

    #[test]
    fn scan_raw_words_be_form() {
        let words = [0u32, MARKER_BE[0], MARKER_BE[1], MARKER_BE[2], 0u32];
        let mut bytes = Vec::new();
        for w in words { bytes.extend_from_slice(&w.to_le_bytes()); }
        let hits = scan_raw_words(&bytes, 0x1000_0000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0x1000_0000 + 1 * 4);
        assert_eq!(hits[0].1, Form::Be);
    }

    #[test]
    fn scan_raw_words_le_form() {
        let words = [0u32, MARKER[0], MARKER[1], MARKER[2], 0u32];
        let mut bytes = Vec::new();
        for w in words { bytes.extend_from_slice(&w.to_le_bytes()); }
        let hits = scan_raw_words(&bytes, 0x1000_0000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, Form::Le);
    }

    #[test]
    fn scan_raw_words_empty_is_empty() {
        assert!(scan_raw_words(&[], 0x1000_0000).is_empty());
    }
}
