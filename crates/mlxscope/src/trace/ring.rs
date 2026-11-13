//! Trace-ring decoding (driverless) — empirical record format, live-derived
//! (B1b, CX-4 Lx 14.32.1900, ring1.bin dump).
//!
//! Ring = 8-byte entries, BE [hdr32][data32]:
//! - hdr[23:16] == 0xff: timestamp entry; data = 32-bit FW tick snapshot.
//! - hdr[23:16] == 0xa2/0xa3: string-transaction word. hdr[15:0] packs
//!   tdsn = bits[2:0] (word index within the event), tmsn = bits[11:3]
//!   (event number), cycle = bits[15:12] (ring-cycle epoch; 0xa3-type
//!   appeared together with cycle=1 mid-run). tdsn==0 carries the strings-DB
//!   rt address, tdsn 1..7 carry params — i.e. the CORE 8-word frame of
//!   docs/250-re/120-irisc/035-cx4lx-trace.md split into per-word entries, each followed by a timestamp
//!   entry. The [0x<a2>] prefix in our lines matches the driver's event_id
//!   field (L3 verbatim: `[0x85cd52804] 0 [0xa2] ...`).

/// Known rt anchors on detour-v3 (docs/250-re/120-irisc/040-cx4lx-hook.md, L3 live):
pub const RT_ICMD_GENERIC: u32 = 0x00ada88c; // icmd_generic_reg_access (hook site H0)
pub const RT_V3_MEMORY_PROFILE: u32 = 0x00ada612; // v3 marker string, param 0xbad
pub const RT_TS_UPDATE: u32 = 0x00aef674; // "TRACER: timestamp update"

pub fn anchor_name(rt: u32) -> Option<&'static str> {
    match rt {
        RT_ICMD_GENERIC => Some("icmd_generic_reg_access"),
        RT_V3_MEMORY_PROFILE => Some("v3_memory_profile"),
        RT_TS_UPDATE => Some("ts_update"),
        _ => None,
    }
}

pub const TYPE_STRING: u8 = 0xa2;
pub const TYPE_STRING_ALT: u8 = 0xa3;
pub const TYPE_TIMESTAMP: u8 = 0xff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    /// Ring byte offset of the tdsn==0 entry.
    pub ring_off: usize,
    /// Record type (driver event_id, e.g. 0xa2).
    pub event_id: u8,
    /// tmsn (event sequence within the cycle).
    pub tmsn: u32,
    /// ring-cycle epoch (hdr seq bits 15:12).
    pub cycle: u32,
    /// FW tick snapshot (timestamp entry following the rt word).
    pub ts: Option<u32>,
    pub rt: u32,
    pub params: Vec<u32>,
}

impl TraceEvent {
    /// ftrace-like line, driver-compatible (B1/L3 style):
    /// `[0x<fw-ts>] <lost> [0x<event_id>] <msg>` — dev_name is ours.
    pub fn render(&self, strings: Option<&crate::trace::strings::StringsDb>) -> String {
        let ts = self.ts.map(|t| format!("0x{t:08x}")).unwrap_or_else(|| "0x????????".into());
        let name = anchor_name(self.rt).unwrap_or("");
        let raw = match strings {
            Some(db) => match db.string_at(self.rt as u64) {
                Some(s) => crate::trace::strings::render_format(&s, &self.params),
                None => format!("<no-string rt=0x{:08x}>", self.rt),
            },
            None => format!("rt=0x{:08x}", self.rt),
        };
        format!(
            "[{ts}] 0 [0x{:02x}] {} {}",
            self.event_id, name, raw
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub hdr: u32,
    pub data: u32,
}

/// Parse one 8-byte BE entry.
pub fn parse_entry(bytes: &[u8], off: usize) -> Option<Entry> {
    let c = bytes.get(off..off + 8)?;
    Some(Entry {
        hdr: u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
        data: u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
    })
}

fn entry_type(e: &Entry) -> u8 {
    ((e.hdr >> 16) & 0xff) as u8
}

fn unpack_seq(hdr: u32) -> (u32, u32, u32) {
    let tdsn = (hdr & 0x7) as u32;
    let tmsn = ((hdr >> 3) & 0xff) as u32;
    let cycle = ((hdr >> 12) & 0xf) as u32;
    (tdsn, tmsn, cycle)
}

/// Decode events from a raw ring dump. Scans 8B-aligned entries; a string
/// transaction starts at tdsn==0 with data in the db0 range; params follow by
/// tdsn order until the next transaction/timestamp-only stretch. The event
/// timestamp is taken from the timestamp entry following the tdsn==0 word.
pub fn scan_ring(bytes: &[u8], db0: (u64, u64)) -> Vec<TraceEvent> {
    let mut out = Vec::new();
    let mut pending: Option<TraceEvent> = None;
    let n = bytes.len() / 8;
    for i in 0..n {
        let Some(e) = parse_entry(bytes, i * 8) else { break };
        match entry_type(&e) {
            TYPE_TIMESTAMP => {
                // the event timestamp is the TS entry right after tdsn==0
                if let Some(ev) = pending.as_mut() {
                    if ev.ts.is_none() && last_has_tdsn0_recent(ev, i) {
                        ev.ts = Some(e.data);
                    }
                }
            }
            TYPE_STRING | TYPE_STRING_ALT => {
                let (tdsn, tmsn, cycle) = unpack_seq(e.hdr);
                if tdsn == 0 {
                    let rt = e.data as u64;
                    if rt >= db0.0 && rt < db0.0 + db0.1 {
                        if let Some(ev) = pending.take() {
                            out.push(ev);
                        }
                        pending = Some(TraceEvent {
                            ring_off: i * 8,
                            event_id: entry_type(&e),
                            tmsn,
                            cycle,
                            ts: None,
                            rt: e.data,
                            params: Vec::new(),
                        });
                    }
                } else if let Some(ev) = pending.as_mut() {
                    ev.params.push(e.data);
                }
            }
            _ => {}
        }
    }
    if let Some(ev) = pending.take() {
        out.push(ev);
    }
    out
}

/// The ts entry for an event is the one immediately following its tdsn==0
/// word (verified on the live dump: every string word is followed by a
/// timestamp entry). We accept it only if the pending event started at the
/// previous entry.
fn last_has_tdsn0_recent(ev: &TraceEvent, cur_index: usize) -> bool {
    cur_index * 8 == ev.ring_off + 8
}

/// Self-check (precedent D1: a param equals a host-known value).
/// PASS when some event has `params[index] == value` (and rt matches, when given).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfCheck {
    pub value: u32,
    pub index: usize,
    pub rt: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub enum SelfCheckOutcome {
    Pass { ring_off: usize, rt: u32 },
    Fail { events: usize },
}

pub fn self_check(events: &[TraceEvent], check: &SelfCheck) -> SelfCheckOutcome {
    for e in events {
        if let Some(rt) = check.rt {
            if e.rt != rt {
                continue;
            }
        }
        if e.params.get(check.index).map(|v| *v == check.value).unwrap_or(false) {
            return SelfCheckOutcome::Pass {
                ring_off: e.ring_off,
                rt: e.rt,
            };
        }
    }
    SelfCheckOutcome::Fail { events: events.len() }
}

/// Dedupe helper for the live drain loop: remembers the last content seen at
/// each ring offset; an event is "new" when its offset was never seen or the
/// (ts, params) content changed (ring wrap rewrote the slot).
#[derive(Default)]
pub struct RingTracker {
    last: std::collections::HashMap<usize, u64>,
}

impl RingTracker {
    pub fn is_new(&mut self, e: &TraceEvent) -> bool {
        let key = e
            .ts
            .map(|t| ((t as u64) << 32) | (e.params.first().copied().unwrap_or(0) as u64))
            .unwrap_or_else(|| (e.params.first().copied().unwrap_or(0) as u64) << 32);
        match self.last.insert(e.ring_off, key) {
            Some(prev) => prev != key,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB0: (u64, u64) = (0x00ad6900, 0x44a00);

    fn entry(hdr: u32, data: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&hdr.to_be_bytes());
        v.extend_from_slice(&data.to_be_bytes());
        v
    }

    /// Verbatim fragment of the live dump (B1b arm1): one full icmd_generic
    /// event (rt + 2 params) and one v3 marker event, with per-word
    /// timestamp entries.
    fn live_fragment() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&entry(0x1ea20008, RT_ICMD_GENERIC));
        v.extend_from_slice(&entry(0xa3ff0000, 0x0dab629b));
        v.extend_from_slice(&entry(0x3da20009, 0x00000000));
        v.extend_from_slice(&entry(0xc0ff0000, 0x0dab62a0));
        v.extend_from_slice(&entry(0x4ea2000a, 0x00009040));
        v.extend_from_slice(&entry(0xd1ff0000, 0x0dab62a0));
        v.extend_from_slice(&entry(0x11a20010, RT_V3_MEMORY_PROFILE));
        v.extend_from_slice(&entry(0x14ff0000, 0x0dab62a1));
        v.extend_from_slice(&entry(0x23a20011, 0x00000bad));
        v.extend_from_slice(&entry(0x26ff0000, 0x0dab62a1));
        v
    }

    #[test]
    fn decodes_live_fragment() {
        let evs = scan_ring(&live_fragment(), DB0);
        assert_eq!(evs.len(), 2, "{evs:?}");
        assert_eq!(evs[0].rt, RT_ICMD_GENERIC);
        assert_eq!(evs[0].params, vec![0, 0x9040]);
        assert_eq!(evs[0].ts, Some(0x0dab629b));
        assert_eq!(evs[0].event_id, TYPE_STRING);
        assert_eq!(evs[0].tmsn, 1);
        assert_eq!(evs[1].rt, RT_V3_MEMORY_PROFILE);
        assert_eq!(evs[1].params, vec![0xbad]);
        assert_eq!(evs[1].ts, Some(0x0dab62a1));
    }

    #[test]
    fn alt_type_and_cycle_decode() {
        // a3/cycle=1 group from the live dump (post-wrap markers)
        let mut v = Vec::new();
        v.extend_from_slice(&entry(0x12a3_1008, RT_ICMD_GENERIC));
        v.extend_from_slice(&entry(0x96ff_0000, 0x0df03940));
        v.extend_from_slice(&entry(0x23a3_1009, 0x00000000));
        v.extend_from_slice(&entry(0xa6ff_0000, 0x0df03940));
        v.extend_from_slice(&entry(0x34a3_100a, 0x00009040));
        let evs = scan_ring(&v, DB0);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event_id, TYPE_STRING_ALT);
        assert_eq!(evs[0].params, vec![0, 0x9040]);
        assert_eq!(evs[0].ts, Some(0x0df03940));
    }

    #[test]
    fn ts_only_stretch_is_not_event() {
        let mut v = Vec::new();
        v.extend_from_slice(&entry(0x00ff0000, 0x0dc80000));
        v.extend_from_slice(&entry(0x00ff0000, 0x0dca0000));
        assert!(scan_ring(&v, DB0).is_empty());
    }

    #[test]
    fn out_of_db0_tdsn0_ignored() {
        let mut v = Vec::new();
        v.extend_from_slice(&entry(0x1ea20008, 0xdeadbeef));
        v.extend_from_slice(&entry(0x3da20009, 0x1));
        assert!(scan_ring(&v, DB0).is_empty());
    }

    #[test]
    fn self_check_pass_and_fail() {
        let evs = scan_ring(&live_fragment(), DB0);
        let check = SelfCheck {
            value: 0x9040,
            index: 1,
            rt: Some(RT_ICMD_GENERIC),
        };
        assert_eq!(
            self_check(&evs, &check),
            SelfCheckOutcome::Pass {
                ring_off: 0,
                rt: RT_ICMD_GENERIC
            }
        );
        let bad = SelfCheck {
            value: 0x9041,
            index: 1,
            rt: Some(RT_ICMD_GENERIC),
        };
        assert_eq!(self_check(&evs, &bad), SelfCheckOutcome::Fail { events: 2 });
    }

    #[test]
    fn tracker_dedup() {
        let v = live_fragment();
        let e1 = scan_ring(&v, DB0).remove(0);
        let mut t = RingTracker::default();
        assert!(t.is_new(&e1));
        assert!(!t.is_new(&e1));
        let e2 = TraceEvent {
            ts: Some(0x1234),
            ..e1.clone()
        };
        assert!(t.is_new(&e2));
    }

    #[test]
    fn render_matches_driver_format() {
        let img = crate::trace::strings::synthetic_image_at(
            RT_V3_MEMORY_PROFILE as u64,
            b"got an unexpected memory profile value, memory_profile = 0x%x",
        );
        let db = crate::trace::strings::StringsDb::from_parts(img, DB0);
        let e = scan_ring(&live_fragment(), DB0).remove(1);
        let line = e.render(Some(&db));
        assert_eq!(
            line,
            "[0x0dab62a1] 0 [0xa2] v3_memory_profile got an unexpected memory profile value, memory_profile = 0xbad"
        );
    }

    #[test]
    fn anchors_named() {
        assert_eq!(anchor_name(RT_ICMD_GENERIC), Some("icmd_generic_reg_access"));
        assert_eq!(anchor_name(RT_V3_MEMORY_PROFILE), Some("v3_memory_profile"));
        assert_eq!(anchor_name(RT_TS_UPDATE), Some("ts_update"));
        assert_eq!(anchor_name(0x1234), None);
    }
}
