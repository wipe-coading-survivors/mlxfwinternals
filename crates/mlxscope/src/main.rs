mod dump;
mod dumps;
mod flowtable;
mod fuzzvec;
mod scan;
mod trace;

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Parser;
use mlxdirect::mtcr::{AddressSpace, Mtc};
use mlxdirect::session::Direct;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum DetourMode {
    A,
    B,
}

impl std::fmt::Display for DetourMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetourMode::A => f.write_str("A"),
            DetourMode::B => f.write_str("B"),
        }
    }
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// FW tracer control (arm / drain / status)
    Trace {
        #[command(subcommand)]
        cmd: trace::TraceCmd,
    },
    /// CR-reserve dump cycle control (seed / trigger / read / clear / run)
    Dump {
        #[command(subcommand)]
        cmd: dump::DumpCmd,
    },
    /// Flow-table create/query/destroy sequence via VFIO cmdif
    Flowtable(flowtable::FlowtableArgs),
    /// Fuzz-vector run: CR seed + sentinel, CREATE → Qcreated(40B payload)
    /// → DESTROY, dual-channel verify (echo zone + CR readback)
    Fuzzvec(fuzzvec::FuzzvecArgs),
}

#[derive(Parser, Debug)]
struct CliArgs {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(short, long, default_value = "/sys/bus/pci/devices/0000:81:00.0")]
    device: PathBuf,
    #[arg(long)]
    input_hex: Option<String>,
    #[arg(long, default_value_t = DetourMode::A, ignore_case = true)]
    detour_mode: DetourMode,
    #[arg(long)]
    dump_raw: Option<PathBuf>,
    #[arg(long)]
    dump_deltas: Option<String>,
    #[arg(long, num_args = 1..)]
    scan_raw: Vec<PathBuf>,
    #[arg(long)]
    le_wide_search: bool,
    #[arg(long, default_value_t = 0x10)]
    outlen: u32,
}

fn validate_detour_mode(input_hex: Option<&str>, mode: DetourMode) -> anyhow::Result<()> {
    if mode == DetourMode::B && input_hex.is_none() {
        anyhow::bail!("--detour-mode B требует --input-hex (кадр режима B); дефолтный кадр — режим A");
    }
    Ok(())
}

const TRIG_WORDS: [u32; 9] = [
    0x0932_0000,
    0x0000_0000,
    0x0000_0000,
    0x0004_0000,
    0x0000_5332,
    scan::SCRATCH_W,
    scan::MARKER[0],
    scan::MARKER[1],
    scan::MARKER[2],
];

fn to_hex(data: &[u8]) -> String {
    let mut hex = String::with_capacity(data.len() * 2);
    for b in data {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

fn unhex(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    anyhow::ensure!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| Ok(u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?))
        .collect()
}

fn default_trig_frame() -> Vec<u8> {
    let mut out = Vec::with_capacity(TRIG_WORDS.len() * 4);
    for w in TRIG_WORDS {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out
}

pub(crate) fn wide_search(cmdif: &Direct, le_mode: bool) -> anyhow::Result<()> {
    let (lo, hi) = scan::WIDE_RANGE;
    let base = cmdif
        .dma_region_base()
        .ok_or_else(|| anyhow::anyhow!("wide-search: dma region base unavailable"))?;
    if base as u64 != lo {
        return Err(anyhow::anyhow!(
            "wide-search: dma region base {:#x} != WIDE_RANGE.0 {:#x}",
            base as u64,
            lo
        ));
    }
    let len = (hi - lo) as usize;
    let bytes = unsafe { std::slice::from_raw_parts(base, len) };
    let words =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u32, bytes.len() / 4) };
    let hits = scan::scan_wide(words, lo, le_mode);
    let marker: Vec<String> = scan::MARKER.iter().map(|w| format!("{:08x}", w)).collect();
    let form = if le_mode { "be+le" } else { "be" };
    println!(
        "[wide-search] range={:#x}..{:#x} marker={} form={} hits={}",
        lo,
        hi,
        marker.join(" "),
        form,
        hits.len()
    );
    if hits.is_empty() {
        println!("[wide-search] NOT FOUND");
    }
    for (k, (addr, f)) in hits.iter().enumerate() {
        let tag = if scan::SELF_SPANS.iter().any(|(s, e)| *addr >= *s && *addr < *e) {
            "SELF"
        } else {
            "POST"
        };
        println!(
            "[wide-search] hit #{} @ 0x{:08x} {} {}",
            k + 1,
            addr,
            tag,
            f.as_str()
        );
    }
    Ok(())
}

fn scan_raw_file(path: &Path) -> anyhow::Result<()> {
    let (lo, hi) = scan::WIDE_RANGE;
    let bytes = std::fs::read(path)
        .with_context(|| format!("scan-raw: read {}", path.display()))?;
    let want = (hi - lo) as usize;
    anyhow::ensure!(
        bytes.len() == want,
        "scan-raw: {} is {} bytes, expected {} (full WIDE_RANGE)",
        path.display(),
        bytes.len(),
        want
    );
    let hits = scan::scan_raw_words(&bytes, lo);
    println!("[scan-raw] path={} form=be+le hits={}", path.display(), hits.len());
    if hits.is_empty() {
        println!("[scan-raw] NOT FOUND");
    }
    for (k, (addr, f)) in hits.iter().enumerate() {
        let tag = if scan::SELF_SPANS.iter().any(|(s, e)| *addr >= *s && *addr < *e) {
            "SELF"
        } else {
            "POST"
        };
        println!("[scan-raw] hit #{} @ 0x{:08x} {} {}", k + 1, addr, tag, f.as_str());
    }
    Ok(())
}

const DUMP_CHUNK: usize = 1 << 20;

// md5 = "0.7" (stainless-steel): API = Context::new() / consume() / compute() -> Digest;
// format!("{:x}", Digest) = 32 нижн.-рег. hex (проверено по docs.rs md5 0.7.0).
fn dump_and_hash(bytes: &[u8], path: &Path, chunk: usize) -> anyhow::Result<String> {
    let mut f = std::fs::File::create(path)?;
    let mut ctx = md5::Context::new();
    for c in bytes.chunks(chunk) {
        ctx.consume(c);
        f.write_all(c)?;
    }
    f.sync_all()?;
    Ok(format!("{:x}", ctx.compute()))
}

fn write_raw_chunks(data: &[u8], path: &Path, chunk: usize) -> anyhow::Result<()> {
    dump_and_hash(data, path, chunk).map(|_| ())
}

pub(crate) fn wide_dump(cmdif: &Direct, path: &Path) -> anyhow::Result<()> {
    let (lo, hi) = scan::WIDE_RANGE;
    let base = cmdif
        .dma_region_base()
        .ok_or_else(|| anyhow::anyhow!("wide-dump: dma region base unavailable"))?;
    if base as u64 != lo {
        return Err(anyhow::anyhow!(
            "wide-dump: dma region base {:#x} != WIDE_RANGE.0 {:#x}",
            base as u64,
            lo
        ));
    }
    let len = (hi - lo) as usize;
    let bytes = unsafe { std::slice::from_raw_parts(base, len) };
    write_raw_chunks(bytes, path, DUMP_CHUNK)
        .with_context(|| format!("wide-dump: write to {}", path.display()))?;
    println!(
        "[wide-dump] range={:#x}..{:#x} bytes={} path={}",
        lo,
        hi,
        len,
        path.display()
    );
    Ok(())
}

fn run_dump_ladder(cmdif: &Direct, base: &Path, deltas: &[u64]) -> anyhow::Result<()> {
    let prefix = base.to_string_lossy();
    let (lo, hi) = scan::WIDE_RANGE;
    let base_ptr = cmdif
        .dma_region_base()
        .ok_or_else(|| anyhow::anyhow!("wide-dump: dma region base unavailable"))?;
    if base_ptr as u64 != lo {
        return Err(anyhow::anyhow!(
            "wide-dump: dma region base {:#x} != WIDE_RANGE.0 {:#x}",
            base_ptr as u64,
            lo
        ));
    }
    let len = (hi - lo) as usize;
    let bytes = unsafe { std::slice::from_raw_parts(base_ptr, len) };
    let t0 = std::time::Instant::now();
    for &d in deltas {
        let deadline = std::time::Duration::from_secs(d);
        while t0.elapsed() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let path = dumps::dump_path(&prefix, d);
        let dt = std::time::Instant::now();
        let md5hex = dump_and_hash(bytes, Path::new(&path), DUMP_CHUNK)
            .with_context(|| format!("wide-dump: write to {path}"))?;
        println!(
            "[wide-dump] t+{d:02}s path={path} md5={md5hex} size={len} elapsed_ms={}",
            dt.elapsed().as_millis()
        );
    }
    Ok(())
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn default_trig_frame_byte_exact() {
        assert_eq!(
            to_hex(&default_trig_frame()),
            "093200000000000000000000000400000000533200600000258c53326c04638afd001825"
        );
    }
}

#[cfg(test)]
mod dump_tests {
    use super::write_raw_chunks;

    #[test]
    fn dump_raw_chunks_full_content_and_length() {
        let chunk = 7usize;
        let buf: Vec<u8> = (0..20u32).map(|i| (i * 37 + 1) as u8).collect();
        let path = std::env::temp_dir().join(format!(
            "s2trig-dump-{}-{}.bin",
            std::process::id(),
            buf.len()
        ));
        write_raw_chunks(&buf, &path, chunk).expect("dump write should succeed");
        let written = std::fs::read(&path).expect("read back dump");
        let _ = std::fs::remove_file(&path);
        assert_eq!(written.len(), buf.len(), "length mismatch");
        assert_eq!(written, buf, "content mismatch");
    }

    #[test]
    fn dump_raw_chunks_unwritable_path_is_err() {
        let path = std::env::temp_dir()
            .join(format!("s2trig-no-such-dir-{}", std::process::id()))
            .join("x.bin");
        let buf = [1u8, 2, 3, 4];
        assert!(
            write_raw_chunks(&buf, &path, 2).is_err(),
            "expected error for path under nonexistent dir"
        );
    }
}

#[cfg(test)]
mod detour_tests {
    use super::*;

    #[test]
    fn detour_mode_b_without_frame_is_err() {
        // B без --input-hex = ошибка (дефолтный кадр — режим A)
        let r = validate_detour_mode(None, DetourMode::B);
        assert!(r.is_err(), "B without --input-hex must be rejected");
    }

    #[test]
    fn detour_mode_b_with_frame_is_ok() {
        let r = validate_detour_mode(Some("0000"), DetourMode::B);
        assert!(r.is_ok());
    }

    #[test]
    fn detour_mode_a_is_always_ok() {
        assert!(validate_detour_mode(None, DetourMode::A).is_ok());
        assert!(validate_detour_mode(Some("0000"), DetourMode::A).is_ok());
    }

    #[test]
    fn detour_mode_default_is_a() {
        let a = CliArgs::try_parse_from(vec!["mlxscope"]).unwrap();
        assert_eq!(a.detour_mode, DetourMode::A);
    }

    #[test]
    fn detour_mode_b_parses_from_cli() {
        // ValueEnum по умолчанию даёт kebab-case ("a"/"b"); ignore_case=true принимает "B"/"A"
        let a = CliArgs::try_parse_from(vec![
            "mlxscope",
            "--detour-mode=B",
            "--input-hex=0000",
        ])
        .unwrap();
        assert_eq!(a.detour_mode, DetourMode::B);
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();
    match args.command {
        Some(Command::Trace { cmd }) => {
            return match cmd {
                trace::TraceCmd::Arm(a) => trace::arm::run(&a),
                trace::TraceCmd::Drain(a) => trace::run_drain(&a),
                trace::TraceCmd::Status(a) => trace::run_status(&a),
            }
        }
        Some(Command::Dump { cmd }) => return dump::run_cmd(cmd),
        Some(Command::Flowtable(args)) => return flowtable::run(&args),
        Some(Command::Fuzzvec(args)) => return fuzzvec::run(&args),
        None => {}
    }
    validate_detour_mode(args.input_hex.as_deref(), args.detour_mode)?;
    if !args.scan_raw.is_empty() {
        for p in &args.scan_raw {
            scan_raw_file(p)?;
        }
        return Ok(());
    }
    let input = match &args.input_hex {
        Some(hex) => unhex(hex)?,
        None => default_trig_frame(),
    };
    let input_hex = to_hex(&input);

    println!("[s2trig] opening {} (reset+init)", args.device.display());
    let mut cmdif = Direct::open_from_sysfs(&args.device, true, true)?;
    cmdif.dump_bufs = true;

    println!(
        "[s2trig] exec_command len={} outlen={:#x} input={}",
        input.len(),
        args.outlen,
        input_hex
    );
    let (out, _status) = cmdif.try_exec_command(&input, args.outlen)?;
    let syndrome = u32::from_be_bytes([out[4], out[5], out[6], out[7]]);
    println!("[s2trig] status={} syndrome=0x{:x}", out[0], syndrome);
    if args.detour_mode == DetourMode::B {
        println!("[s2trig] detour-mode=B: frame from --input-hex; outbox is not payload (error completion expected)");
    }
    println!("[s2trig] outbox len={} hex={}", out.len(), to_hex(&out));

    match (&args.dump_deltas, &args.dump_raw) {
        (Some(deltas_str), Some(base)) => {
            let deltas = dumps::parse_deltas(deltas_str)?;
            run_dump_ladder(&cmdif, base, &deltas)?;
        }
        (None, Some(path)) => {
            wide_dump(&cmdif, path)?;
        }
        (Some(_), None) => {
            anyhow::bail!("--dump-deltas требует --dump-raw <BASE>");
        }
        (None, None) => {}
    }
    wide_search(&cmdif, args.le_wide_search)?;

    let mtcr = Mtc::from_direct(&cmdif)?;
    mtcr.change_address_space(AddressSpace::CrSpace)?;
    for (name, addr) in [
        ("echo_magic", 0x2380u32),
        ("echo_len", 0x2384),
        ("s2ok", 0x2388),
        ("r5", 0x238c),
        ("flag", 0x2390),
        ("s0", 0x23f0),
    ] {
        println!(
            "[s2trig] CR 0x{:04x} ({}) = 0x{:08x}",
            addr,
            name,
            mtcr.read_dword(addr)?
        );
    }

    Ok(())
}
