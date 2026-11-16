//! `ramread` mode (cx-5 rom phase 3): batched single-word reads of iRISC
//! RAM via the v5l exec channel — ONE VFIO session, one 36B TRIG frame per
//! address (the dump-C payload class, live-proven 24/24 in phase 2b):
//! `set2 base / ld.d / st.d -> CR 0x2388 / ret.r` call-site resume.
//!
//! Per-run nonce sits in the N slot (frame[0xC..0xE)); the v5l stub echoes
//! it to CR 0x2384 on every magic frame — a value read is accepted only
//! with status 0, CR 0x2380 == 0x5332 and CR 0x2384 == nonce (stale/garbage
//! CR detection). Any transport error or echo mismatch STOPS the batch
//! (fail-loud, no blind retries — s2 discipline).

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Args;
use mlxdirect::mtcr::{AddressSpace, Mtc};
use mlxdirect::session::Direct;

use crate::to_hex;

const OP_WORD: u32 = 0x0932_0000;
const MAGIC16: u16 = 0x5332;
const CR_MAGIC_ECHO: u32 = 0x2380;
const CR_NONCE_ECHO: u32 = 0x2384;
const CR_VALUE: u32 = 0x2388;
const OUTLEN: u32 = 0x10;

pub fn read_words(addr: u32) -> [u32; 4] {
    assert_eq!(addr % 4, 0, "addr must be 4-aligned");
    let hi = (addr >> 16) & 0xffff;
    let lo = addr & 0xffff;
    let (base_hi, off16) = if lo <= 0x7ffc {
        (hi, lo)
    } else {
        (hi + 1, lo.wrapping_sub(0x1_0000))
    };
    [
        0x240c_0000 | base_hi,
        0x658d_0000 | (off16 & 0xfffc) | 0x2,
        0x6c04_6b8a,
        0xfd00_1825,
    ]
}

pub fn build_frame(addr: u32, nonce: u16) -> Vec<u8> {
    let mut b = vec![0u8; 0x14];
    b[0..4].copy_from_slice(&OP_WORD.to_be_bytes());
    b[0x0c..0x0e].copy_from_slice(&nonce.to_be_bytes());
    b[0x12..0x14].copy_from_slice(&MAGIC16.to_be_bytes());
    for w in read_words(addr) {
        b.extend_from_slice(&w.to_be_bytes());
    }
    b
}

pub fn parse_addr(s: &str) -> anyhow::Result<u32> {
    let t = s.trim().trim_start_matches("0x");
    let v = u32::from_str_radix(t, 16)
        .map_err(|e| anyhow::anyhow!("address {s:?}: {e}"))?;
    anyhow::ensure!(v % 4 == 0, "address 0x{v:08x} not 4-aligned");
    Ok(v)
}

pub fn read_addr_file(path: &std::path::Path) -> anyhow::Result<Vec<u32>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("addr-file {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let v = parse_addr(l).map_err(|e| anyhow::anyhow!("addr-file:{}:{}", n + 1, e))?;
        out.push(v);
    }
    anyhow::ensure!(!out.is_empty(), "addr-file {}: no addresses", path.display());
    Ok(out)
}

fn nonce_base() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0);
    (1 + nanos % 0x7fff) as u16
}

#[derive(Args, Debug)]
pub struct RamreadArgs {
    /// Device sysfs path (VFIO-bound function)
    #[arg(short, long, default_value = "/sys/bus/pci/devices/0000:03:00.0")]
    pub dev: PathBuf,
    /// Comma-separated hex addresses (4-aligned), e.g. 0x800000,0x900000
    #[arg(long, value_parser = parse_addr, value_delimiter = ',')]
    pub addrs: Vec<u32>,
    /// File with one hex address per line ('#' comments)
    #[arg(long)]
    pub addr_file: Option<PathBuf>,
    /// Delay between frames, ms
    #[arg(long, default_value_t = 100)]
    pub delay_ms: u64,
}

pub fn run(args: &RamreadArgs) -> anyhow::Result<()> {
    let mut addrs = args.addrs.clone();
    if let Some(f) = &args.addr_file {
        addrs.extend(read_addr_file(f)?);
    }
    anyhow::ensure!(!addrs.is_empty(), "no addresses (--addrs or --addr-file)");
    println!(
        "[ramread] dev={} n={} delay_ms={}",
        args.dev.display(),
        addrs.len(),
        args.delay_ms
    );
    println!("[ramread] opening {} (reset+init)", args.dev.display());
    let cmdif = Direct::open_from_sysfs(&args.dev, true, true)?;
    let mtcr = Mtc::from_direct(&cmdif)?;
    mtcr.change_address_space(AddressSpace::CrSpace)?;
    let base = nonce_base();
    let t0 = Instant::now();
    for (i, &addr) in addrs.iter().enumerate() {
        let nonce = {
            let n = base.wrapping_add(i as u16);
            if n == 0 { 1 } else { n }
        };
        let frame = build_frame(addr, nonce);
        let tf = Instant::now();
        let (out, _st) = cmdif.try_exec_command(&frame, OUTLEN)?;
        let status = out.first().copied().unwrap_or(0xff);
        let cr_magic = mtcr.read_dword(CR_MAGIC_ECHO)?;
        let cr_nonce = mtcr.read_dword(CR_NONCE_ECHO)?;
        let cr_val = mtcr.read_dword(CR_VALUE)?;
        let echo_ok = cr_magic == MAGIC16 as u32 && cr_nonce == nonce as u32;
        if status != 0 || !echo_ok {
            anyhow::bail!(
                "ramread FAIL i={i} addr=0x{addr:08x} nonce=0x{nonce:04x} status=0x{status:02x} \
                 cr_magic=0x{cr_magic:08x} cr_nonce=0x{cr_nonce:08x} cr_val=0x{cr_val:08x} \
                 frame={} out={}",
                to_hex(&frame),
                to_hex(&out)
            );
        }
        println!(
            "0x{addr:08x} 0x{cr_val:08x} i={i} t_ms={}",
            tf.elapsed().as_millis()
        );
        if i + 1 < addrs.len() {
            std::thread::sleep(Duration::from_millis(args.delay_ms));
        }
    }
    let secs = t0.elapsed().as_secs_f64().max(1e-9);
    println!(
        "[ramread] done n={} ok={} elapsed_ms={} rate_per_s={:.1}",
        addrs.len(),
        addrs.len(),
        t0.elapsed().as_millis(),
        addrs.len() as f64 / secs
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn frame_golden_stub_word() {
        assert_eq!(
            hex(&build_frame(0x00B8D750, 4)),
            "0932000000000000000000000004000000005332240c00b9658dd7526c046b8afd001825"
        );
    }

    #[test]
    fn frame_golden_low_negative_split() {
        assert_eq!(
            hex(&build_frame(0x00008000, 4)),
            "0932000000000000000000000004000000005332240c0001658d80026c046b8afd001825"
        );
        assert_eq!(
            hex(&build_frame(0x00B9D35C, 4)),
            "0932000000000000000000000004000000005332240c00ba658dd35e6c046b8afd001825"
        );
    }

    #[test]
    fn frame_nonce_slot_and_len() {
        let f = build_frame(0x00800000, 0x1234);
        assert_eq!(f.len(), 36);
        assert_eq!(&f[0x0c..0x0e], &[0x12, 0x34]);
        assert_eq!(&f[0x12..0x14], &[0x53, 0x32]);
        assert_eq!(&f[0..4], &[0x09, 0x32, 0x00, 0x00]);
    }

    #[test]
    fn read_words_known_values() {
        assert_eq!(read_words(0x00800000), [0x240c0080, 0x658d0002, 0x6c046b8a, 0xfd001825]);
        assert_eq!(read_words(0x00000000), [0x240c0000, 0x658d0002, 0x6c046b8a, 0xfd001825]);
        assert_eq!(read_words(0x0009C748), [0x240c000a, 0x658dc74a, 0x6c046b8a, 0xfd001825]);
        assert_eq!(read_words(0x00007ffc), [0x240c0000, 0x658d7ffe, 0x6c046b8a, 0xfd001825]);
        assert_eq!(read_words(0x01000000), [0x240c0100, 0x658d0002, 0x6c046b8a, 0xfd001825]);
    }

    #[test]
    fn parse_addr_accepts_hex_forms() {
        assert_eq!(parse_addr("0x800000").unwrap(), 0x800000);
        assert_eq!(parse_addr("800000").unwrap(), 0x800000);
        assert_eq!(parse_addr(" 0x100 ").unwrap(), 0x100);
        assert!(parse_addr("0x100002").is_err());
        assert!(parse_addr("zz").is_err());
        assert!(parse_addr("").is_err());
    }

    #[test]
    fn addr_file_skips_comments_and_blank_lines() {
        let dir = std::env::temp_dir().join(format!("ramread-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("addrs.txt");
        std::fs::write(&p, "# comment\n\n0x800000\n7000\n  0xb9d35c  \n").unwrap();
        assert_eq!(read_addr_file(&p).unwrap(), vec![0x800000, 0x7000, 0xb9d35c]);
        let bad = dir.join("bad.txt");
        std::fs::write(&bad, "0x800001\n").unwrap();
        assert!(read_addr_file(&bad).is_err());
        let empty = dir.join("empty.txt");
        std::fs::write(&empty, "# only comments\n").unwrap();
        assert!(read_addr_file(&empty).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonce_base_nonzero() {
        for _ in 0..100 {
            assert!(nonce_base() != 0);
        }
    }
}
