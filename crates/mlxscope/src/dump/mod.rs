//! `mlxscope dump` subcommands: CR-reserve dump cycle (phase IX R-A3/R-A4;
//! phase R-E adds the CX-5 4030 profile).
//!
//! Host side of the dump-cycle protocol: seed words in the CR reserve
//! (R-A2 verdict: the reserve holds writes) — `seed`/`run` write the
//! addr-dump request (magic @0x8c5, addr @0x8c6), `exec` seeds a generic
//! payload (magic @0x8c5, N @0x8c6, words @0x8c7..) — then fire the
//! stub via an ICMD GET MTRC_CAP (the same send path `trace arm`/`status`
//! use for CAP reads) and read the response zone (READY = magic echo at
//! 0x8c8). Word numbers only — CR offset = word * 4; the VSEC
//! base-relative protocol lives in `trace::vsec`.
//!
//! Two profiles: `lx` (CX-4 Lx, bazzite 04:00.0 — payload zone grows to
//! 0x8d0, the phase-IX precedent) and `cx5` (ConnectX-5 4030 door-detour,
//! 81:00.0 — answer zone capped at 0x8cf; 0x8d0/0x8d4 are NOT reserve
//! there, occupied by handler reads (rb1 §1.5), and are refused by the
//! write guard with a dedicated error).
//!
//! `run` drives the full CX-5 cycle in one invocation (Task 4): seed
//! magic+addr+N=1 (Task 1 SEED_LAYOUT) → answer-slot pre-clear → ICMD
//! trigger → poll 0x8c8 out of its pre-cleared 0 → readback → host-clear.
//! The CX-5 B-form stub stores the dumped word itself at 0x8c8 (no MAGIC
//! echo), so the answer value is the slot value.

pub mod ops;
pub mod window;

use std::cell::RefCell;
use std::path::PathBuf;

use clap::Args;

use crate::trace::{normalize_dev, vsec};

/// CR-reserve layout (Global Constraints — verbatim values, do not change).
/// CR offset of a word = word * 4.
pub struct LAYOUT;

impl LAYOUT {
    /// Seed/response magic (READY echoes it).
    pub const MAGIC: u32 = 0x4455_4D31;
    /// Word: seeded magic (CR 0x2314).
    pub const W_MAGIC: u32 = 0x8c5;
    /// Word: exec payload count N (`seed` writes its --addr here; CR 0x2318).
    pub const W_COUNT: u32 = 0x8c6;
    /// Word: first payload word (CR 0x231C).
    pub const W_PLD: u32 = 0x8c7;
    /// Max payload words on the Lx profile (0x8c7..=0x8d0).
    pub const PLD_MAX: usize = 10;
    /// Word: READY = magic echo; response zone start (CR 0x2320).
    pub const W_RESP: u32 = 0x8c8;
    /// Response zone size: ready + d0..d5.
    pub const RESP_WORDS: usize = 7;
    /// CX-5 answer-zone end: response growth NEVER passes 0x8cf (0x8d0 and
    /// 0x8d4 are occupied handler slots, not reserve — rb1 §1.5 canon).
    pub const CX5_ANSWER_LAST: u32 = 0x8cf;
}

/// Default device of the Lx profile: the CX-4 Lx dump-cycle card on
/// bazzite (ra2 probe DEV) — the `lx` profile keeps it unchanged.
const DEV_DEFAULT: &str = "/sys/bus/pci/devices/0000:04:00.0";
/// Default device of the cx5 profile: the door-detour card on
/// root-mellanox (R-E Global Constraints).
const DEV_DEFAULT_CX5: &str = "/sys/bus/pci/devices/0000:81:00.0";

/// Card profile: which dump-cycle card (and reserve geometry) is targeted.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// CX-4 Lx on bazzite (phase IX): payload zone 0x8c7..=0x8d0.
    Lx,
    /// ConnectX-5 4030 door-detour (phase R-E): answer zone 0x8c8..=0x8cf,
    /// 0x8d0/0x8d4 forbidden (occupied, rb1 §1.5).
    Cx5,
}

impl Profile {
    /// Profile default device (used when --dev is absent).
    pub fn dev_default(self) -> &'static str {
        match self {
            Profile::Lx => DEV_DEFAULT,
            Profile::Cx5 => DEV_DEFAULT_CX5,
        }
    }

    /// Last writable word (write-guard upper bound; also the clear bound).
    pub fn w_last(self) -> u32 {
        match self {
            Profile::Lx => LAYOUT::W_PLD + LAYOUT::PLD_MAX as u32 - 1,
            Profile::Cx5 => LAYOUT::CX5_ANSWER_LAST,
        }
    }

    /// Max payload words (exec --words cap; checked before any write).
    pub fn pld_max(self) -> usize {
        match self {
            Profile::Lx => LAYOUT::PLD_MAX,
            Profile::Cx5 => (LAYOUT::CX5_ANSWER_LAST - LAYOUT::W_PLD + 1) as usize,
        }
    }

    /// Write guard: only the seed + payload/answer words may be written.
    pub fn write_allowed(self, word: u32) -> bool {
        word >= LAYOUT::W_MAGIC && word <= self.w_last()
    }

    /// Words that are explicitly NOT reserve on this profile (occupied):
    /// the cx5 guard refuses them with a dedicated error, before the
    /// range guard. On lx 0x8d0 is a legal payload word (phase IX layout).
    pub fn is_forbidden(self, word: u32) -> bool {
        match self {
            Profile::Lx => false,
            Profile::Cx5 => word == 0x8d0 || word == 0x8d4,
        }
    }

    /// Reserve words observed by `read` (canon rb1 §1.5 on cx5: 52 slots,
    /// 0x8d0/0x8d4 skipped; lx keeps the phase-IX 12-word view).
    pub fn reserve_words(self) -> Vec<u32> {
        match self {
            Profile::Lx => (LAYOUT::W_MAGIC..=self.w_last()).collect(),
            Profile::Cx5 => {
                let mut w: Vec<u32> = Vec::with_capacity(52);
                w.extend(LAYOUT::W_MAGIC..=LAYOUT::CX5_ANSWER_LAST);
                w.extend(0x8d1..=0x8d3);
                w.extend(0x8d5..=0x8f9);
                w.push(0x8fe);
                debug_assert_eq!(w.len(), 52, "rb1 canon: 11+3+37+1 = 52 reserve slots");
                w
            }
        }
    }

    /// Read-only control words appended by the cx5 `read` matrix: the
    /// three special slots around the reserve (unlock marker, flash
    /// semaphore, door word) and one off-window slot last (unmapped-
    /// discriminator check, ra2 §2 precedent — last so an unexpected
    /// hang on it cannot cost the rest of the sweep).
    pub fn control_words(self) -> [u32; 4] {
        match self {
            Profile::Lx => [0, 0, 0, 0],
            Profile::Cx5 => [0x8fc, 0x8fd, 0x8ff, 0x7f0],
        }
    }
}

/// Label of one word in the cx5 `read` matrix output.
pub fn word_label(word: u32) -> String {
    match word {
        w if w == LAYOUT::W_MAGIC => "magic".to_string(),
        w if w == LAYOUT::W_COUNT => "addr".to_string(),
        w if w == LAYOUT::W_PLD => "n".to_string(),
        w if (LAYOUT::W_RESP..=LAYOUT::CX5_ANSWER_LAST).contains(&w) => {
            format!("r{}", w - LAYOUT::W_RESP)
        }
        0x7f0 => "off".to_string(),
        0x8fc => "unlck".to_string(),
        0x8fd => "flsem".to_string(),
        0x8ff => "door".to_string(),
        _ => "res".to_string(),
    }
}

/// `run`/`exec` readback lines, profile-correct (Task 4 fix of the
/// Task-2-review finding): lx keeps the phase-IX 12-word ReadView
/// (0x8c5..=0x8d0, byte-identical to `ops::format_read`); cx5 shows the
/// seed + answer zone only — words 0x8c5..=0x8cf with the cx5 matrix
/// labels — the occupied handler slots 0x8d0/0x8d4 never appear as ours.
fn format_readback<R>(profile: Profile, mut read: R) -> anyhow::Result<String>
where
    R: FnMut(u32) -> anyhow::Result<u32>,
{
    match profile {
        Profile::Lx => Ok(ops::format_read(&ops::read_view(read)?)),
        Profile::Cx5 => {
            let mut out = String::new();
            for word in LAYOUT::W_MAGIC..=LAYOUT::CX5_ANSWER_LAST {
                out.push_str(&format!(
                    "[dump-read] 0x{:04x} {:<5} 0x{:08x}\n",
                    word,
                    word_label(word),
                    read(word)?
                ));
            }
            Ok(out)
        }
    }
}

/// Resolve --dev against the profile default (None -> profile device).
pub fn dev_path(profile: Profile, dev: &Option<PathBuf>) -> PathBuf {
    match dev {
        Some(p) => p.clone(),
        None => PathBuf::from(profile.dev_default()),
    }
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

/// Parsed `--words` value: 1..=PLD_MAX hex u32 payload words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Words(pub Vec<u32>);

fn parse_words(s: &str) -> anyhow::Result<Words> {
    let mut out = Vec::new();
    for p in s.split(',') {
        let t = p.trim();
        if t.is_empty() {
            anyhow::bail!("dump exec: empty word in --words {s:?}");
        }
        let w = ops::parse_hex_u32(t)
            .map_err(|e| anyhow::anyhow!("dump exec: bad word {t:?} in --words: {e}"))?;
        out.push(w);
    }
    anyhow::ensure!(
        out.len() <= LAYOUT::PLD_MAX,
        "dump exec: --words accepts 1..={} words, got {}",
        LAYOUT::PLD_MAX,
        out.len()
    );
    Ok(Words(out))
}

#[derive(clap::Subcommand, Debug)]
pub enum DumpCmd {
    /// Seed the CR reserve: magic (0x8c5) + addr (0x8c6)
    Seed(SeedArgs),
    /// Fire the dump trigger: ICMD GET MTRC_CAP (0x9040)
    Trigger(DevArgs),
    /// Print observable reserve words (lx: 0x8c5..0x8d0; cx5: rb1 canon
    /// 52 slots + 4 controls, 0x8d0/0x8d4 skipped)
    Read(DevArgs),
    /// Zero the writable reserve words (lx: 0x8c5..0x8d0; cx5: 0x8c5..0x8cf)
    Clear(DevArgs),
    /// Full addr-dump cycle: clear-response, seed, trigger, poll, read, clear-all
    /// (cx5: seed magic+addr+N=1 per the Task 1 layout, poll the answer slot
    /// 0x8c8 out of its pre-cleared 0 — the stub stores the dumped word
    /// itself there, no MAGIC echo)
    Run(RunArgs),
    /// Generic payload exec: seed N+words, readback-verify, trigger, poll, read
    Exec(ExecArgs),
}

#[derive(Args, Debug)]
pub struct DevArgs {
    /// Device sysfs path or bare BDF (default: profile device)
    #[arg(short, long)]
    pub dev: Option<PathBuf>,
    /// Card profile: lx (CX-4 Lx, bazzite 04:00.0) or cx5 (door-detour, 81:00.0)
    #[arg(long, value_enum, default_value_t = Profile::Lx)]
    pub profile: Profile,
}

#[derive(Args, Debug)]
pub struct SeedArgs {
    /// Device sysfs path or bare BDF (default: profile device)
    #[arg(short, long)]
    pub dev: Option<PathBuf>,
    /// Card profile: lx (CX-4 Lx, bazzite 04:00.0) or cx5 (door-detour, 81:00.0)
    #[arg(long, value_enum, default_value_t = Profile::Lx)]
    pub profile: Profile,
    /// RAM address to dump (4-byte aligned, 4..=0xFFFFFFFC, hex ok)
    #[arg(long, value_parser = parse_u32)]
    pub addr: u32,
    /// Magic seeded at 0x8c5 (default 0x44554D31)
    #[arg(long, default_value = "0x44554D31", value_parser = parse_u32)]
    pub magic: u32,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Device sysfs path or bare BDF (default: profile device)
    #[arg(short, long)]
    pub dev: Option<PathBuf>,
    /// Card profile: lx (CX-4 Lx, bazzite 04:00.0) or cx5 (door-detour, 81:00.0)
    #[arg(long, value_enum, default_value_t = Profile::Lx)]
    pub profile: Profile,
    /// RAM address to dump (4-byte aligned, 4..=0xFFFFFFFC, hex ok)
    #[arg(long, value_parser = parse_u32)]
    pub addr: u32,
    /// Magic seeded at 0x8c5 (default 0x44554D31)
    #[arg(long, default_value = "0x44554D31", value_parser = parse_u32)]
    pub magic: u32,
}

#[derive(Args, Debug)]
pub struct ExecArgs {
    /// Device sysfs path or bare BDF (default: profile device)
    #[arg(short, long)]
    pub dev: Option<PathBuf>,
    /// Card profile: lx (CX-4 Lx, bazzite 04:00.0) or cx5 (door-detour, 81:00.0)
    #[arg(long, value_enum, default_value_t = Profile::Lx)]
    pub profile: Profile,
    /// Comma-separated payload words (hex u32; lx 1..=10, cx5 1..=9)
    #[arg(long, value_parser = parse_words)]
    pub words: Words,
    /// Value expected at W_RESP after the trigger (default 0x44554D31)
    #[arg(long, default_value = "0x44554D31", value_parser = parse_u32)]
    pub expect: u32,
}

pub fn run_cmd(cmd: DumpCmd) -> anyhow::Result<()> {
    match cmd {
        DumpCmd::Seed(a) => run_seed(&a),
        DumpCmd::Trigger(a) => run_trigger(&a),
        DumpCmd::Read(a) => run_read(&a),
        DumpCmd::Clear(a) => run_clear(&a),
        DumpCmd::Run(a) => run_run(&a),
        DumpCmd::Exec(a) => run_exec(&a),
    }
}

fn open_dev(dev: &PathBuf) -> anyhow::Result<vsec::VsecDev> {
    let path = normalize_dev(dev);
    vsec::VsecDev::open(&path)
}

fn run_seed(args: &SeedArgs) -> anyhow::Result<()> {
    let addr = ops::validate_addr(args.addr)?;
    let dev = open_dev(&dev_path(args.profile, &args.dev))?;
    let win = window::CrWindow::with_profile(&dev, args.profile)?;
    println!(
        "[dump-seed] profile={:?} dev={} vsec_base=0x{:02x} magic=0x{:08x} addr=0x{:08x}",
        args.profile,
        dev.sysfs.display(),
        dev.vsec_base,
        args.magic,
        addr
    );
    ops::seed(
        |word, v| win.write_word(word, v),
        addr,
        args.magic,
    )?;
    let (rb_magic, rb_addr) = (
        win.read_word(LAYOUT::W_MAGIC)?,
        win.read_word(LAYOUT::W_COUNT)?,
    );
    if rb_magic == args.magic && rb_addr == addr {
        println!(
            "[dump-seed] readback OK: 0x8c5=0x{rb_magic:08x} 0x8c6=0x{rb_addr:08x}"
        );
    } else {
        println!(
            "[dump-seed] WARN readback mismatch: 0x8c5=0x{rb_magic:08x} 0x8c6=0x{rb_addr:08x} (write filtered?)"
        );
    }
    Ok(())
}

/// ICMD GET MTRC_CAP: the dump trigger. Returns the VsecDev back (in ICMD
/// address space — callers re-select CR space via `CrWindow::new`).
fn trigger_icmd(dev: vsec::VsecDev) -> anyhow::Result<vsec::VsecDev> {
    let hint = "mstreg -d <dev> --reg_name MTRC_CAP -g";
    let icmd = vsec::IcmdClient::open(dev)?;
    let res = icmd.access_register(
        vsec::tlv::METHOD_GET,
        ops::REG_MTRC_CAP,
        &vec![0u8; ops::MTRC_CAP_GET_LEN],
    );
    let dev = icmd.into_dev();
    match res {
        Ok(Ok(_)) => Ok(dev),
        Ok(Err(e)) => anyhow::bail!("dump-trigger: ICMD MTRC_CAP GET failed: {e}; fallback: {hint}"),
        Err(e) => anyhow::bail!("dump-trigger: ICMD MTRC_CAP transport error: {e}; fallback: {hint}"),
    }
}

fn run_trigger(args: &DevArgs) -> anyhow::Result<()> {
    let dev = open_dev(&dev_path(args.profile, &args.dev))?;
    trigger_icmd(dev)?;
    println!(
        "[dump-trigger] ICMD GET MTRC_CAP (reg 0x{:04x}) ok -> dump stub triggered",
        ops::REG_MTRC_CAP
    );
    Ok(())
}

fn run_read(args: &DevArgs) -> anyhow::Result<()> {
    let dev = open_dev(&dev_path(args.profile, &args.dev))?;
    let win = window::CrWindow::with_profile(&dev, args.profile)?;
    match args.profile {
        Profile::Lx => {
            let view = ops::read_view(|word| win.read_word(word))?;
            print!("{}", ops::format_read(&view));
        }
        Profile::Cx5 => {
            // Reserve-canon matrix (rb1 §1.5): 52 slots, 0x8d0/0x8d4 skipped,
            // + 4 read-only controls (off-window discriminator check,
            // unlock marker, flash semaphore, door word).
            let mut words = args.profile.reserve_words();
            words.extend_from_slice(&args.profile.control_words());
            for word in words {
                println!(
                    "[dump-read] 0x{:04x} {:<5} 0x{:08x}",
                    word,
                    word_label(word),
                    win.read_word(word)?
                );
            }
        }
    }
    Ok(())
}

fn run_clear(args: &DevArgs) -> anyhow::Result<()> {
    let dev = open_dev(&dev_path(args.profile, &args.dev))?;
    let win = window::CrWindow::with_profile(&dev, args.profile)?;
    ops::clear_all(|word, v| win.write_word(word, v), args.profile)?;
    match args.profile {
        Profile::Lx => println!("[dump-clear] zeroed words 0x8c5..0x8d0"),
        Profile::Cx5 => println!("[dump-clear] zeroed words 0x8c5..0x8cf (cx5)"),
    }
    Ok(())
}

fn run_run(args: &RunArgs) -> anyhow::Result<()> {
    let addr = ops::validate_addr(args.addr)?;
    let dev = open_dev(&dev_path(args.profile, &args.dev))?;
    println!(
        "[dump-run] profile={:?} dev={} vsec_base=0x{:02x} magic=0x{:08x} addr=0x{:08x}",
        args.profile,
        dev.sysfs.display(),
        dev.vsec_base,
        args.magic,
        addr
    );
    match args.profile {
        Profile::Lx => {
            {
                let win = window::CrWindow::with_profile(&dev, args.profile)?;
                ops::clear_response(|word, v| win.write_word(word, v), args.profile)?;
                ops::seed(
                    |word, v| win.write_word(word, v),
                    addr,
                    args.magic,
                )?;
                println!("[dump-run] response cleared + seeded (0x8c5/0x8c6)");
            }
            let dev = trigger_icmd(dev)?;
            println!("[dump-run] trigger fired (ICMD GET MTRC_CAP)");
            let win = window::CrWindow::with_profile(&dev, args.profile)?;
            let attempts = ops::poll_ready(
                ops::RUN_POLL_TIMEOUT,
                ops::POLL_INTERVAL,
                LAYOUT::MAGIC,
                || win.read_word(LAYOUT::W_RESP),
                std::thread::sleep,
            )?;
            println!("[dump-run] READY==MAGIC after {attempts} poll(s)");
            let view = ops::read_view(|word| win.read_word(word))?;
            print!("{}", ops::format_read(&view));
            ops::clear_all(
                |word, v| win.write_word(word, v),
                args.profile,
            )?;
            let mut parts = vec![format!("ready=0x{:08x}", view.ready())];
            for (i, d) in view.resp_data().iter().enumerate() {
                parts.push(format!("d{i}=0x{d:08x}"));
            }
            println!("[dump-run] [{}]", parts.join(", "));
        }
        Profile::Cx5 => {
            // Full CX-5 cycle in one invocation (Task 4) over injected IO —
            // the same RefCell wiring discipline as `exec` (every CR access
            // re-selects CR space; the trigger runs on a fresh handle).
            // No arm branch: Task 2 live verdict — armed == unarmed.
            let dev = RefCell::new(dev);
            let (attempts, answer) = ops::run_cycle_cx5(
                addr,
                args.magic,
                ops::RUN_POLL_TIMEOUT,
                ops::POLL_INTERVAL,
                |word, v| {
                    window::CrWindow::with_profile(&dev.borrow(), args.profile)?
                        .write_word(word, v)
                },
                || {
                    let d = open_dev(&dev_path(args.profile, &args.dev))?;
                    trigger_icmd(d)?;
                    Ok(())
                },
                || {
                    window::CrWindow::with_profile(&dev.borrow(), args.profile)?
                        .read_word(LAYOUT::W_RESP)
                },
                std::thread::sleep,
            )?;
            println!(
                "[dump-run] cx5 cycle: answer zone cleared + seeded (0x8c5/0x8c6/0x8c7=N1); trigger fired; answered after {attempts} poll(s)"
            );
            {
                let d = dev.borrow();
                let win = window::CrWindow::with_profile(&d, args.profile)?;
                print!(
                    "{}",
                    format_readback(Profile::Cx5, |word| win.read_word(word))?
                );
                ops::clear_all(|word, v| win.write_word(word, v), args.profile)?;
            }
            println!("[dump-run] host-clear: writable words zeroed (0x8c5..0x8cf)");
            println!("[dump-run] [answer=0x{answer:08x}]");
        }
    }
    Ok(())
}

fn run_exec(args: &ExecArgs) -> anyhow::Result<()> {
    let words = args.words.0.clone();
    anyhow::ensure!(
        !words.is_empty() && words.len() <= args.profile.pld_max(),
        "dump exec: profile {:?} accepts 1..={} words, got {}",
        args.profile,
        args.profile.pld_max(),
        words.len()
    );
    let dev = open_dev(&dev_path(args.profile, &args.dev))?;
    println!(
        "[dump-exec] profile={:?} dev={} vsec_base=0x{:02x} n={} expect=0x{:08x} words=[{}]",
        args.profile,
        dev.sysfs.display(),
        dev.vsec_base,
        words.len(),
        args.expect,
        words
            .iter()
            .map(|w| format!("0x{w:08x}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    // The ICMD trigger moves its device handle through ICMD address space,
    // so it fires on a freshly re-opened handle; every CR access below
    // re-selects CR space (CrWindow::new) and the VSEC semaphore keeps the
    // two handles serialized.
    let dev = RefCell::new(dev);
    let (attempts, view) = ops::exec_cycle(
        &words,
        args.expect,
        args.profile,
        |word, v| {
            window::CrWindow::with_profile(&dev.borrow(), args.profile)?.write_word(word, v)
        },
        |word| window::CrWindow::new(&dev.borrow())?.read_word(word),
        || {
            let d = open_dev(&dev_path(args.profile, &args.dev))?;
            trigger_icmd(d)?;
            Ok(())
        },
        |word| window::CrWindow::new(&dev.borrow())?.read_word(word),
        std::thread::sleep,
    )?;
    println!(
        "[dump-exec] seeded + readback-verified; trigger fired; W_RESP==0x{:08x} after {attempts} poll(s)",
        args.expect
    );
    // Profile-correct readback (Task 4 fix): cx5 shows the seed + answer
    // zone only (0x8c5..=0x8cf) — the occupied slots 0x8d0/0x8d4 never
    // appear as ours; lx keeps the 12-word phase-IX view.
    match args.profile {
        Profile::Lx => print!("{}", ops::format_read(&view)),
        Profile::Cx5 => print!(
            "{}",
            format_readback(Profile::Cx5, |word| {
                Ok(view.to_words()[(word - LAYOUT::W_MAGIC) as usize])
            })?
        ),
    }
    {
        let d = dev.borrow();
        let win = window::CrWindow::with_profile(&d, args.profile)?;
        ops::clear_all(|word, v| win.write_word(word, v), args.profile)?;
    }
    println!("[dump-exec] zeroed writable words (profile {:?})", args.profile);
    let mut parts = vec![format!("resp=0x{:08x}", view.ready())];
    let words = view.to_words();
    for (i, w) in words[..2 + args.profile.pld_max()].iter().enumerate() {
        parts.push(format!("d0x{:04x}=0x{w:08x}", LAYOUT::W_MAGIC + i as u32));
    }
    println!("[dump-exec] [{}]", parts.join(", "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CliArgs;
    use clap::Parser;
    use std::path::PathBuf;

    fn parse_cli(args: &[&str]) -> DumpCmd {
        let c = CliArgs::try_parse_from(args).unwrap();
        match c.command.expect("subcommand") {
            crate::Command::Dump { cmd } => cmd,
            other => panic!("expected dump, got {other:?}"),
        }
    }

    #[test]
    fn cli_seed_parses_hex_addr_and_default_magic() {
        let DumpCmd::Seed(a) = parse_cli(&["mlxscope", "dump", "seed", "--addr", "0xB19850"])
        else {
            panic!("seed");
        };
        assert_eq!(a.addr, 0xB19850);
        assert_eq!(a.magic, LAYOUT::MAGIC);
        assert_eq!(a.profile, Profile::Lx, "lx stays the default profile");
        assert_eq!(
            dev_path(a.profile, &a.dev),
            PathBuf::from("/sys/bus/pci/devices/0000:04:00.0"),
            "lx default dev unchanged (bazzite 04:00.0)"
        );
    }

    #[test]
    fn cli_seed_magic_override_and_decimal_addr() {
        let DumpCmd::Seed(a) = parse_cli(&[
            "mlxscope",
            "dump",
            "seed",
            "--addr",
            "11638864",
            "--magic",
            "0xdeadbeef",
        ]) else {
            panic!("seed");
        };
        assert_eq!(a.addr, 0xB19850);
        assert_eq!(a.magic, 0xdeadbeef);
    }

    #[test]
    fn cli_seed_requires_addr() {
        assert!(CliArgs::try_parse_from(["mlxscope", "dump", "seed"]).is_err());
    }

    #[test]
    fn cli_run_requires_addr() {
        assert!(CliArgs::try_parse_from(["mlxscope", "dump", "run"]).is_err());
        let DumpCmd::Run(a) = parse_cli(&["mlxscope", "dump", "run", "--addr", "0x2314"])
        else {
            panic!("run");
        };
        assert_eq!(a.addr, 0x2314);
        assert_eq!(a.magic, LAYOUT::MAGIC);
    }

    #[test]
    fn cli_run_cx5_shape_and_no_armed_flag() {
        let DumpCmd::Run(a) = parse_cli(&[
            "mlxscope",
            "dump",
            "run",
            "--profile",
            "cx5",
            "--addr",
            "0x106390",
        ]) else {
            panic!("run");
        };
        assert_eq!(a.profile, Profile::Cx5);
        assert_eq!(a.addr, 0x106390);
        assert_eq!(a.magic, LAYOUT::MAGIC);
        assert_eq!(
            dev_path(a.profile, &a.dev),
            PathBuf::from("/sys/bus/pci/devices/0000:81:00.0"),
            "cx5 run defaults to the root-mellanox door-detour card"
        );
        // R5 (Task 2 verdict: armed == unarmed byte-identical) — no arm
        // branch, no --armed flag.
        assert!(
            CliArgs::try_parse_from([
                "mlxscope",
                "dump",
                "run",
                "--addr",
                "4",
                "--armed"
            ])
            .is_err(),
            "--armed must not exist (R5: arm is not required)"
        );
    }

    #[test]
    fn format_readback_cx5_seed_and_answer_zone_only() {
        let mut seen = Vec::new();
        let text = format_readback(Profile::Cx5, |word| {
            seen.push(word);
            Ok(word * 4)
        })
        .unwrap();
        assert_eq!(
            seen,
            (0x8c5..=0x8cf).collect::<Vec<_>>(),
            "11 words: seed + answer zone"
        );
        assert_eq!(text.lines().count(), 11);
        assert_eq!(
            text.lines().next().unwrap(),
            "[dump-read] 0x08c5 magic 0x00002314"
        );
        assert_eq!(
            text.lines().last().unwrap(),
            "[dump-read] 0x08cf r7    0x0000233c"
        );
        assert!(!text.contains("0x08d0"), "occupied slot never shown as ours");
        assert!(!text.contains("0x08d4"), "occupied slot never shown as ours");
    }

    #[test]
    fn format_readback_lx_is_the_phase_ix_view() {
        let read = |word: u32| Ok(word * 4);
        let a = format_readback(Profile::Lx, read).unwrap();
        let b = ops::format_read(&ops::read_view(read).unwrap());
        assert_eq!(a, b, "lx readback stays byte-identical to format_read");
        assert_eq!(a.lines().count(), 12);
    }

    #[test]
    fn exec_summary_word_cap_is_profile_correct() {
        assert_eq!(2 + Profile::Lx.pld_max(), 12, "lx summary: 0x8c5..0x8d0");
        assert_eq!(
            2 + Profile::Cx5.pld_max(),
            11,
            "cx5 summary: 0x8c5..0x8cf (no 0x8d0)"
        );
    }

    #[test]
    fn cli_dev_arg_overrides_default() {
        let DumpCmd::Read(a) = parse_cli(&[
            "mlxscope",
            "dump",
            "read",
            "--dev",
            "/sys/bus/pci/devices/0000:81:00.0",
        ]) else {
            panic!("read");
        };
        assert_eq!(
            dev_path(a.profile, &a.dev),
            PathBuf::from("/sys/bus/pci/devices/0000:81:00.0")
        );
        let DumpCmd::Read(a2) = parse_cli(&["mlxscope", "dump", "read", "-d", "0000:04:00.0"])
        else {
            panic!("read");
        };
        assert_eq!(dev_path(a2.profile, &a2.dev), PathBuf::from("0000:04:00.0"));
    }

    #[test]
    fn profile_dev_defaults() {
        assert_eq!(
            Profile::Lx.dev_default(),
            "/sys/bus/pci/devices/0000:04:00.0",
            "lx default stays the bazzite dump-cycle card"
        );
        assert_eq!(
            Profile::Cx5.dev_default(),
            "/sys/bus/pci/devices/0000:81:00.0",
            "cx5 default is the root-mellanox door-detour card"
        );
    }

    #[test]
    fn cli_profile_cx5_resolves_dev() {
        let DumpCmd::Read(a) = parse_cli(&["mlxscope", "dump", "read", "--profile", "cx5"])
        else {
            panic!("read");
        };
        assert_eq!(a.profile, Profile::Cx5);
        assert_eq!(
            dev_path(a.profile, &a.dev),
            PathBuf::from("/sys/bus/pci/devices/0000:81:00.0")
        );
        // explicit --dev wins over the profile default
        let DumpCmd::Read(a2) = parse_cli(&[
            "mlxscope",
            "dump",
            "read",
            "--profile",
            "cx5",
            "-d",
            "0000:81:00.1",
        ]) else {
            panic!("read");
        };
        assert_eq!(dev_path(a2.profile, &a2.dev), PathBuf::from("0000:81:00.1"));
        // bad profile name must be a clap error
        assert!(CliArgs::try_parse_from([
            "mlxscope", "dump", "read", "--profile", "cx4"
        ])
        .is_err());
    }

    #[test]
    fn cli_seed_profile_cx5_shape() {
        let DumpCmd::Seed(a) = parse_cli(&[
            "mlxscope",
            "dump",
            "seed",
            "--profile",
            "cx5",
            "--addr",
            "0x106390",
        ]) else {
            panic!("seed");
        };
        assert_eq!(a.profile, Profile::Cx5);
        assert_eq!(a.addr, 0x106390);
        assert_eq!(a.magic, LAYOUT::MAGIC);
    }

    #[test]
    fn cx5_reserve_canon() {
        let w = Profile::Cx5.reserve_words();
        assert_eq!(w.len(), 52, "rb1 canon: 11 + 3 + 37 + 1 reserve slots");
        assert!(!w.contains(&0x8d0), "0x8d0 is NOT reserve (occupied)");
        assert!(!w.contains(&0x8d4), "0x8d4 is NOT reserve (occupied)");
        assert_eq!(w.first(), Some(&0x8c5));
        assert_eq!(w[10], 0x8cf, "first run ends at the answer-zone end");
        assert_eq!(w[11], 0x8d1);
        assert_eq!(w[13], 0x8d3);
        assert_eq!(w[14], 0x8d5);
        assert_eq!(w[50], 0x8f9);
        assert_eq!(w[51], 0x8fe, "canon tail: free slot 0x8fe");
        assert!(w.windows(2).all(|p| p[1] > p[0]), "sorted, no repeats");
        let runs: Vec<u32> = w
            .windows(2)
            .filter_map(|p| (p[1] != p[0] + 1).then_some(p[1]))
            .collect();
        assert_eq!(runs, vec![0x8d1, 0x8d5, 0x8fe], "exactly three canon gaps");
        assert_eq!(Profile::Cx5.control_words(), [0x8fc, 0x8fd, 0x8ff, 0x7f0]);
    }

    #[test]
    fn profile_bounds() {
        assert_eq!(Profile::Lx.w_last(), 0x8d0);
        assert_eq!(Profile::Cx5.w_last(), 0x8cf, "cx5 growth stops before 0x8d0");
        assert_eq!(Profile::Lx.pld_max(), 10);
        assert_eq!(Profile::Cx5.pld_max(), 9, "cx5 payload 0x8c7..=0x8cf");
        let lx = Profile::Lx.reserve_words();
        assert_eq!(lx, (0x8c5..=0x8d0).collect::<Vec<_>>(), "lx view unchanged");
    }

    #[test]
    fn word_labels_cx5_matrix() {
        assert_eq!(word_label(0x8c5), "magic");
        assert_eq!(word_label(0x8c6), "addr");
        assert_eq!(word_label(0x8c7), "n");
        assert_eq!(word_label(0x8c8), "r0");
        assert_eq!(word_label(0x8cf), "r7");
        assert_eq!(word_label(0x8d1), "res");
        assert_eq!(word_label(0x8f9), "res");
        assert_eq!(word_label(0x8fe), "res");
        assert_eq!(word_label(0x7f0), "off");
        assert_eq!(word_label(0x8fc), "unlck");
        assert_eq!(word_label(0x8fd), "flsem");
        assert_eq!(word_label(0x8ff), "door");
    }

    #[test]
    fn cli_clear_and_trigger_shapes() {
        assert!(matches!(
            parse_cli(&["mlxscope", "dump", "clear"]),
            DumpCmd::Clear(_)
        ));
        assert!(matches!(
            parse_cli(&["mlxscope", "dump", "trigger"]),
            DumpCmd::Trigger(_)
        ));
    }

    #[test]
    fn cli_words_option_is_not_introduced() {
        let r = CliArgs::try_parse_from([
            "mlxscope",
            "dump",
            "seed",
            "--addr",
            "4",
            "--words",
            "6",
        ]);
        assert!(r.is_err(), "--words belongs to exec only; seed stays addr-based");
    }

    #[test]
    fn cli_exec_parses_words_and_expect_default_magic() {
        let DumpCmd::Exec(a) = parse_cli(&[
            "mlxscope",
            "dump",
            "exec",
            "--words",
            "0xA,B,0xC0FFEE",
        ]) else {
            panic!("exec");
        };
        assert_eq!(a.words.0, vec![0xA, 0xB, 0xC0FFEE]);
        assert_eq!(a.expect, LAYOUT::MAGIC);
        assert_eq!(dev_path(a.profile, &a.dev), PathBuf::from(DEV_DEFAULT));
    }

    #[test]
    fn cli_exec_expect_override_and_ten_words_ok() {
        let ten = "1,2,3,4,5,6,7,8,9,a";
        let DumpCmd::Exec(a) = parse_cli(&[
            "mlxscope",
            "dump",
            "exec",
            "--words",
            ten,
            "--expect",
            "0xE",
        ]) else {
            panic!("exec");
        };
        assert_eq!(a.words.0.len(), LAYOUT::PLD_MAX);
        assert_eq!(a.words.0.last(), Some(&0xa));
        assert_eq!(a.expect, 0xE);
    }

    #[test]
    fn cli_exec_words_guards() {
        assert!(
            CliArgs::try_parse_from(["mlxscope", "dump", "exec"]).is_err(),
            "--words is required"
        );
        assert!(
            CliArgs::try_parse_from(["mlxscope", "dump", "exec", "--words", ""]).is_err(),
            "0 words must be a clap error"
        );
        assert!(
            CliArgs::try_parse_from(["mlxscope", "dump", "exec", "--words", "0x1,,2"]).is_err(),
            "empty word must be a clap error"
        );
        let eleven = "1,2,3,4,5,6,7,8,9,a,b";
        assert!(
            CliArgs::try_parse_from(["mlxscope", "dump", "exec", "--words", eleven]).is_err(),
            "11 words > PLD_MAX must be a clap error"
        );
        assert!(
            CliArgs::try_parse_from(["mlxscope", "dump", "exec", "--words", "0x1,zz"]).is_err(),
            "non-hex word must be a clap error"
        );
    }

    #[test]
    fn cli_exec_words_are_hex_even_without_prefix() {
        let DumpCmd::Exec(a) =
            parse_cli(&["mlxscope", "dump", "exec", "--words", "10,0x10"]) else {
            panic!("exec");
        };
        assert_eq!(a.words.0, vec![0x10, 0x10], "bare '10' is hex 0x10");
    }

    #[test]
    fn parse_words_rejects_empty_token_and_bad_hex() {
        assert!(parse_words("0xA,,0xB").is_err());
        assert!(parse_words("0xA,zz").is_err());
        assert!(parse_words("").is_err());
        assert_eq!(
            parse_words(" 0xA , B ").unwrap().0,
            vec![0xA, 0xB],
            "tokens are trimmed"
        );
    }
}
