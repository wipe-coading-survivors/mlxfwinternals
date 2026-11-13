//! `mlxscope trace` subcommands: arm / drain / status (phase VII B1b).
//!
//! - `arm` — full driverless mtrcdump flow on CX-4 Lx (VFIO window):
//!   AllocPD + CreateMKey(MTT) -> MTRC_CAP(owner) -> MTRC_CONF(mode+mkey) ->
//!   MTRC_CTRL(arm) + ICMD SET_ITRACE 0xf003 {mask,level,delay}; then drains
//!   its own ring until SIGINT (the VFIO process must stay alive for FW DMA).
//! - `drain` — offline decoder of a raw ring dump + self-check (precedent D1).
//! - `status` — MTRC_CAP/CONF/CTRL readback via config-space VSEC (works with
//!   mlx5 bound and driverless); classifies exclusive-ownership quirks.

pub mod arm;
pub mod ring;
pub mod strings;
pub mod vsec;

use std::path::{Path, PathBuf};

use anyhow::bail;
use clap::Args;

pub const DEFAULT_DB0: (u64, u64) = (0x00ad6900, 0x44a00);

#[derive(clap::Subcommand, Debug)]
pub enum TraceCmd {
    /// Arm the FW tracer driverless (mtrcdump flow) + drain until SIGINT
    Arm(ArmArgs),
    /// Offline-decode a raw ring dump (+ self-check)
    Drain(DrainArgs),
    /// MTRC_CAP/CONF/CTRL readback via config-space VSEC
    Status(StatusArgs),
}

fn parse_u32(s: &str) -> anyhow::Result<u32> {
    let t = s.trim();
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(h, 16)?
    } else {
        t.parse::<u32>()?
    };
    Ok(v)
}

/// Accept either a sysfs path or a bare BDF (0000:04:00.0).
pub fn normalize_dev(dev: &Path) -> PathBuf {
    if dev.as_os_str().is_empty() {
        return dev.to_path_buf();
    }
    if dev.exists() {
        return dev.to_path_buf();
    }
    let s = dev.to_string_lossy();
    let b = s.as_bytes();
    if s.len() == 12 && b[4] == b':' && b[7] == b':' && b[10] == b'.' {
        let p = PathBuf::from(format!("/sys/bus/pci/devices/{s}"));
        if p.exists() {
            return p;
        }
    }
    dev.to_path_buf()
}

#[derive(Args, Debug)]
pub struct ArmArgs {
    /// Device sysfs path or bare BDF
    #[arg(short, long, default_value = "/sys/bus/pci/devices/0000:81:00.0")]
    pub dev: PathBuf,
    /// ICMD SET_ITRACE unit_mask (hex, e.g. 0x4000000 = ICMD class)
    #[arg(short, long, default_value = "0x04000000", value_parser = parse_u32)]
    pub mask: u32,
    /// ICMD SET_ITRACE log_level (events with level >= N pass)
    #[arg(short, long, default_value_t = 1)]
    pub level: u8,
    /// ICMD SET_ITRACE log_delay (ts-update period)
    #[arg(long, default_value_t = 0)]
    pub delay: u16,
    /// log2 of trace buffer size in 4KB units (2 = 16KB, mtrcdump default)
    #[arg(short, long, default_value_t = 2)]
    pub size: u8,
    /// Decoded events output file (appended)
    #[arg(long)]
    pub out: PathBuf,
    /// Raw ring dump on exit
    #[arg(long)]
    pub raw_out: Option<PathBuf>,
    /// FW image for strings-DB decode
    #[arg(long)]
    pub image: Option<PathBuf>,
    /// Skip SET_ITRACE 0 at teardown (leave mask armed)
    #[arg(long)]
    pub keep_mask: bool,
    /// Do mtrcdump badc0ffe unlock at CR 0x23f0 (OFF by default: clobbers the
    /// detour-v3 boot marker on our card)
    #[arg(long)]
    pub badc_unlock: bool,
    /// Open VFIO without device reset (for timing runs)
    #[arg(long)]
    pub no_flr: bool,
    /// Drain poll period, ms
    #[arg(long, default_value_t = 200)]
    pub poll_ms: u64,
}

#[derive(Args, Debug)]
pub struct DrainArgs {
    /// Raw ring dump to decode
    #[arg(short, long)]
    pub input: PathBuf,
    /// FW image for strings-DB decode
    #[arg(long)]
    pub image: Option<PathBuf>,
    /// db0 base rt address (MTRC_CAP live value)
    #[arg(long, default_value_t = DEFAULT_DB0.0, allow_hyphen_values = false)]
    pub db0_addr: u64,
    /// db0 size
    #[arg(long, default_value_t = DEFAULT_DB0.1)]
    pub db0_size: u64,
    /// Self-check: expect some event param == VALUE (hex ok)
    #[arg(long, value_parser = parse_u32)]
    pub expect_param: Option<u32>,
    /// Param index for the self-check (icmd_generic register_id = 1)
    #[arg(long, default_value_t = 1)]
    pub expect_idx: usize,
    /// Restrict self-check to this rt (hex)
    #[arg(long, value_parser = parse_u32)]
    pub expect_rt: Option<u32>,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Device sysfs path or bare BDF
    #[arg(short, long, default_value = "/sys/bus/pci/devices/0000:81:00.0")]
    pub dev: PathBuf,
    /// Extra CR-space dwords to read (hex offsets)
    #[arg(long, num_args = 1.., value_parser = parse_u32)]
    pub cr: Vec<u32>,
}

pub fn run_drain(args: &DrainArgs) -> anyhow::Result<()> {
    use ring::{scan_ring, self_check, SelfCheck};

    let bytes = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("drain: read {}: {e}", args.input.display()))?;
    let strings = match &args.image {
        Some(p) => Some(strings::StringsDb::load(p, (args.db0_addr, args.db0_size))?),
        None => None,
    };
    let events = scan_ring(&bytes, (args.db0_addr, args.db0_size));
    println!(
        "[trace-drain] input={} bytes={} db0=0x{:08x}/0x{:x} events={}",
        args.input.display(),
        bytes.len(),
        args.db0_addr,
        args.db0_size,
        events.len()
    );
    for e in &events {
        println!("[trace-drain] {}", e.render(strings.as_ref()));
    }
    if let Some(value) = args.expect_param {
        let check = SelfCheck {
            value,
            index: args.expect_idx,
            rt: args.expect_rt,
        };
        match self_check(&events, &check) {
            ring::SelfCheckOutcome::Pass { ring_off, rt } => {
                println!(
                    "[trace-drain] self-check PASS: param[{}]==0x{:x} at ring+0x{:05x} rt=0x{:08x}",
                    args.expect_idx, value, ring_off, rt
                );
            }
            ring::SelfCheckOutcome::Fail { events } => {
                println!(
                    "[trace-drain] self-check FAIL: no param[{}]==0x{:x} among {events} events",
                    args.expect_idx, value
                );
                bail!("self-check failed");
            }
        }
    }
    Ok(())
}

pub fn run_status(args: &StatusArgs) -> anyhow::Result<()> {
    use deku::DekuContainerRead;
    use mlxdirect::regs::mtrc::{MtrcCapReg, MtrcConfReg, MtrcCtrlReg};

    let dev_path = normalize_dev(&args.dev);
    let dev = vsec::VsecDev::open(&dev_path)?;
    println!(
        "[trace-status] dev={} vsec_base=0x{:02x}",
        dev_path.display(),
        dev.vsec_base
    );
    let icmd = vsec::IcmdClient::open(dev)?;
    println!("[trace-status] icmd max_cmd_size={:#x}", icmd.max_cmd_size);

    // Register sizes match mstflint reg_access_hca_layouts.h (CAP 0x84,
    // CONF 0x80, CTRL 0x40) — mstreg sends these; short buffers get a
    // TLV-level error. Deku structs cover the leading fields only.
    match icmd.access_register(tlv_method_get(), 0x9040, &vec![0u8; 0x84])? {
        Ok((data, st)) => {
            let (_, cap) = MtrcCapReg::from_bytes((&data, 0))
                .map_err(|e| anyhow::anyhow!("cap decode: {e:?}"))?;
            let st = if st != 0 { format!(" (tlv-status 0x{st:x})") } else { String::new() };
            println!(
                "[trace-status] MTRC_CAP:{} trace_owner={} trace_to_memory={} trc_ver={} log_max=0x{:x} num_db={} first_str=0x{:x} num_str=0x{:x}",
                st,
                cap.trace_owner as u8,
                cap.trace_to_memory as u8,
                cap.trc_ver,
                cap.log_max_trace_buffer_size,
                cap.num_string_db,
                cap.first_string_trace,
                cap.num_string_trace
            );
            for (i, p) in cap.string_db_param.iter().enumerate() {
                if p.size > 0 {
                    println!(
                        "[trace-status]   db{i}: rt 0x{:08x} size 0x{:x}",
                        p.address, p.size
                    );
                }
            }
        }
        Err(e) => println!("[trace-status] MTRC_CAP: FAILED: {e}"),
    }

    // MTRC_CONF GET
    match icmd.access_register(tlv_method_get(), 0x9041, &vec![0u8; 0x80])? {
        Ok((data, _)) => {
            let (_, conf) = MtrcConfReg::from_bytes((&data, 0))
                .map_err(|e| anyhow::anyhow!("conf decode: {e:?}"))?;
            println!(
                "[trace-status] MTRC_CONF: trace_mode={} log_size=0x{:x} trace_mkey=0x{:08x}",
                conf.trace_mode, conf.log_trace_buffer_size, conf.trace_mkey
            );
        }
        Err(e) => println!("[trace-status] MTRC_CONF: {e}"),
    }

    // MTRC_CTRL GET
    match icmd.access_register(tlv_method_get(), 0x9043, &vec![0u8; 0x40])? {
        Ok((data, _)) => {
            let (_, ctrl) = MtrcCtrlReg::from_bytes((&data, 0))
                .map_err(|e| anyhow::anyhow!("ctrl decode: {e:?}"))?;
            println!(
                "[trace-status] MTRC_CTRL: trace_status={} arm_event={} mfs=0x{:x} ts=0x{:08x}{:08x}",
                ctrl.trace_status,
                ctrl.arm_event as u8,
                ctrl.modify_field_select,
                ctrl.timestamp_hi,
                ctrl.timestamp_lo
            );
        }
        Err(e) => println!("[trace-status] MTRC_CTRL: {e}"),
    }

    if !args.cr.is_empty() {
        let dev = icmd.into_dev();
        dev.change_address_space(vsec::AS_CR_SPACE)?;
        for addr in &args.cr {
            let v = dev.read_dword(*addr)?;
            println!("[trace-status] CR 0x{:04x} = 0x{:08x}", addr, v);
        }
    }
    Ok(())
}

fn tlv_method_get() -> u8 {
    vsec::tlv::METHOD_GET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u32_hex_and_dec() {
        assert_eq!(parse_u32("0x4000000").unwrap(), 0x4000000);
        assert_eq!(parse_u32("0X4000000").unwrap(), 0x4000000);
        assert_eq!(parse_u32("67108864").unwrap(), 0x4000000);
        assert!(parse_u32("0xzz").is_err());
        assert!(parse_u32("-1").is_err());
    }

    #[test]
    fn normalize_dev_bdf_maps_to_sysfs() {
        // Not asserting existence on arbitrary hosts: only the mapping shape.
        let p = normalize_dev(Path::new("0000:81:00.0"));
        assert!(
            p == PathBuf::from("/sys/bus/pci/devices/0000:81:00.0")
                || p == PathBuf::from("0000:81:00.0")
        );
        assert_eq!(normalize_dev(Path::new("0000:81:0.0")), PathBuf::from("0000:81:0.0")); // malformed BDF unchanged
        let p = normalize_dev(Path::new("/sys/bus/pci/devices/0000:81:00.0"));
        assert!(p.starts_with("/sys/") || p == PathBuf::from("/sys/bus/pci/devices/0000:81:00.0"));
    }

    fn parse_cli(args: &[&str]) -> TraceCmd {
        use clap::Parser;
        let c = crate::CliArgs::try_parse_from(args).unwrap();
        match c.command.expect("subcommand") {
            crate::Command::Trace { cmd } => cmd,
            _ => panic!("expected trace subcommand"),
        }
    }

    #[test]
    fn arm_defaults_match_b1_masks() {
        let TraceCmd::Arm(a) = parse_cli(&["mlxscope", "trace", "arm", "--out", "/tmp/x.log"]) else {
            panic!("arm");
        };
        assert_eq!(a.mask, 0x04000000);
        assert_eq!(a.level, 1);
        assert_eq!(a.delay, 0);
        assert_eq!(a.size, 2);
        assert!(!a.keep_mask);
        assert!(!a.badc_unlock);
        assert!(!a.no_flr);
        assert_eq!(a.poll_ms, 200);
    }

    #[test]
    fn arm_mask_override_parses() {
        let TraceCmd::Arm(a) = parse_cli(&[
            "mlxscope",
            "trace",
            "arm",
            "--mask",
            "0xffffffff",
            "--level",
            "0",
            "--out",
            "x",
        ])
        else {
            panic!("arm");
        };
        assert_eq!(a.mask, 0xffffffff);
        assert_eq!(a.level, 0);
    }

    #[test]
    fn drain_self_check_args() {
        let TraceCmd::Drain(d) = parse_cli(&[
            "mlxscope",
            "trace",
            "drain",
            "--input",
            "ring.bin",
            "--expect-param",
            "0x9040",
            "--expect-idx",
            "1",
        ])
        else {
            panic!("drain");
        };
        assert_eq!(d.expect_param, Some(0x9040));
        assert_eq!(d.expect_idx, 1);
        assert_eq!(d.db0_addr, DEFAULT_DB0.0);
        assert_eq!(d.db0_size, DEFAULT_DB0.1);
    }
}
