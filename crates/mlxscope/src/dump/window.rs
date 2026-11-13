//! CR-reserve window: word-number access over the VSEC CR-space data port.
//!
//! Semantics ported from scripts/probes/cx4lx-dumpcycle/ra2_window_probe.py
//! on top of the `trace::vsec` semaphore discipline (base-relative offsets
//! from VSEC cap 0x09: CTRL +0x04 space-select, SEM/COUNTER +0x08/+0x0c,
//! ADDR +0x10, DATA +0x14, poll bit31 at ADDR — never absolute addresses).
//! Writes are restricted by a per-profile guard to the seed + response
//! zone; on the cx5 profile words 0x8d0/0x8d4 are additionally refused as
//! NOT-reserve (occupied handler slots, rb1 §1.5 canon).

use crate::trace::vsec::{self, VsecDev};

use super::{LAYOUT, Profile};

/// CR offset of a window word: offset = word * 4
/// (0x8c5 -> 0x2314, 0x8c8 -> 0x2320, 0x8cf -> 0x233c; rb1 §1.5 canon).
pub const fn cr_offset(word: u32) -> u32 {
    word * 4
}

/// CR-space window: word numbers only (CR offset = word * 4), borrowing the
/// VSEC device so ICMD and CR access can interleave on one open device.
pub struct CrWindow<'a> {
    dev: &'a VsecDev,
    profile: Profile,
}

impl<'a> CrWindow<'a> {
    /// Select CR space (CTRL space-select under the VSEC semaphore) with
    /// the default (lx) profile.
    pub fn new(dev: &'a VsecDev) -> anyhow::Result<Self> {
        Self::with_profile(dev, Profile::Lx)
    }

    /// Select CR space with an explicit profile (cx5 caps writes at 0x8cf
    /// and refuses 0x8d0/0x8d4 outright).
    pub fn with_profile(dev: &'a VsecDev, profile: Profile) -> anyhow::Result<Self> {
        dev.change_address_space(vsec::AS_CR_SPACE)?;
        Ok(Self { dev, profile })
    }

    pub fn read_word(&self, word: u32) -> anyhow::Result<u32> {
        self.dev.read_dword(cr_offset(word))
    }

    pub fn write_word(&self, word: u32, value: u32) -> anyhow::Result<()> {
        if self.profile.is_forbidden(word) {
            anyhow::bail!(
                "window: word 0x{word:04x} is NOT a reserve slot (occupied handler slot, \
                 rb1 canon; answer zone is 0x8c8..0x8cf) — write refused"
            );
        }
        anyhow::ensure!(
            self.profile.write_allowed(word),
            "window: write to word 0x{word:04x} refused (profile {:?} guard: 0x{:04x}..0x{:04x})",
            self.profile,
            LAYOUT::W_MAGIC,
            self.profile.w_last()
        );
        self.dev.write_dword(cr_offset(word), value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::vsec::VsecDev;
    use std::path::PathBuf;

    fn fake_vsec_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("s2dump-win-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = vec![0u8; 0x100];
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x09;
        std::fs::write(dir.join("config"), &cfg).unwrap();
        dir
    }

    #[test]
    fn write_guard_boundaries() {
        let lx = Profile::Lx;
        assert!(!lx.write_allowed(0x8c4), "below range");
        assert!(lx.write_allowed(0x8c5), "magic word");
        assert!(lx.write_allowed(0x8c6), "count/N word");
        assert!(lx.write_allowed(0x8c7), "first payload word p0");
        assert!(lx.write_allowed(0x8c8), "ready word");
        assert!(lx.write_allowed(0x8ce), "d5");
        assert!(lx.write_allowed(0x8cf), "payload word p8");
        assert!(lx.write_allowed(0x8d0), "last payload word p9");
        assert!(!lx.write_allowed(0x8d1), "above range");
        assert!(!lx.write_allowed(0), "word 0");
    }

    #[test]
    fn write_word_outside_guard_refused_before_io() {
        let dir = fake_vsec_dir("guard");
        let dev = VsecDev::open(&dir).unwrap();
        let win = CrWindow { dev: &dev, profile: Profile::Lx };
        for bad in [0x8c4u32, 0x8d1] {
            let e = win.write_word(bad, 0x600D0002).unwrap_err();
            let msg = e.to_string();
            assert!(msg.contains("refused"), "0x{bad:04x}: {msg}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cx5_guard_forbids_8d0_and_8d4() {
        // rb1 §1.5: 0x8d0/0x8d4 are occupied handler read slots, NOT
        // reserve — the cx5 guard must refuse them with the dedicated
        // NOT-reserve error, before the range guard and before any IO.
        // (No successful write is attempted here: the static fake config
        // file never clears the ADDR busy bit, so a real write_dword would
        // spin forever — same reason the pre-existing guard test only
        // exercises refusals. Writability of 0x8cf is covered by the
        // predicate test below.)
        let dir = fake_vsec_dir("cx5guard");
        let dev = VsecDev::open(&dir).unwrap();
        let win = CrWindow { dev: &dev, profile: Profile::Cx5 };
        for bad in [0x8d0u32, 0x8d4] {
            let e = win.write_word(bad, 0x600D0002).unwrap_err();
            let msg = e.to_string();
            assert!(msg.contains("NOT a reserve slot"), "0x{bad:04x}: {msg}");
            assert!(msg.contains(&format!("0x{bad:04x}")), "names the word: {msg}");
        }
        // above-bound 0x8d1 is the generic range refusal, not NOT-reserve
        let e = win.write_word(0x8d1, 0x1).unwrap_err();
        assert!(e.to_string().contains("refused"));
        assert!(!e.to_string().contains("NOT a reserve slot"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cx5_guard_boundaries() {
        let cx5 = Profile::Cx5;
        assert!(cx5.write_allowed(0x8c5), "magic word");
        assert!(cx5.write_allowed(0x8c8), "answer-zone start");
        assert!(cx5.write_allowed(0x8cf), "answer-zone end");
        assert!(!cx5.write_allowed(0x8d0), "NOT reserve (occupied)");
        assert!(!cx5.write_allowed(0x8d4), "NOT reserve (occupied)");
        assert!(!cx5.write_allowed(0x8d1), "above answer zone");
        assert!(cx5.is_forbidden(0x8d0));
        assert!(cx5.is_forbidden(0x8d4));
        assert!(!cx5.is_forbidden(0x8cf));
        assert!(!Profile::Lx.is_forbidden(0x8d0), "lx 0x8d0 is a legal payload word");
    }

    #[test]
    fn cr_offset_word_times_four() {
        // rb1 §1.5 canon cross-check: word * 4.
        assert_eq!(cr_offset(0x8c5), 0x2314, "magic word CR");
        assert_eq!(cr_offset(0x8c6), 0x2318, "addr/N word CR");
        assert_eq!(cr_offset(0x8c7), 0x231c, "N word CR");
        assert_eq!(cr_offset(0x8c8), 0x2320, "answer-zone start CR");
        assert_eq!(cr_offset(0x8cf), 0x233c, "answer-zone end CR");
        assert_eq!(cr_offset(0x8d0), 0x2340, "occupied handler slot CR (rb1)");
        assert_eq!(cr_offset(0x8d4), 0x2350, "occupied handler slot CR (rb1)");
        assert_eq!(cr_offset(0x8fe), 0x23f8, "free slot CR (rb1)");
        assert_eq!(cr_offset(0x8ff), 0x23fc, "door word CR (rb1)");
    }
}
