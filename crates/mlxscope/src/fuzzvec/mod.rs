//! `fuzzvec` mode (fuzz-4 T1, spec §3 / C-F4.1): one fuzz vector per run —
//! VSEC seed + sentinel in the CR reserve, then the CREATE → Qcreated →
//! DESTROY ladder carrying the 40B payload as QUERY input[0x18..0x40).
//!
//! Word0 assumption: `[fr+0x14]` = table_id of the created table (rc12);
//! the live fact is created_id == 0, which makes payload word0 = 0x00000000
//! = nop. The tool REFUSES (no QUERY sent) when CREATE returns id != 0 —
//! otherwise word0 would be an arbitrary addi.
//!
//! Dual-channel verify: (1) out_mb echo zone — QUERY response [0x10..0x38)
//! plus the 0x6f28 canary @0x3a (stock golden echo is the stale-negative);
//! (2) CR readback of the result slots 0x8c8..0x8cf (CR 0x2320..0x233c):
//! host fills 0xdeadbeef before the command, and `sentinel_overwritten`
//! lists every slot whose value differs afterwards (empty = stale, a live
//! write is not proven). CR transport is the dump-module wiring
//! (RefCell<VsecDev> + CrWindow closures) — no new transport.

use std::cell::RefCell;
use std::path::PathBuf;

use clap::Args;
use mlxdirect::session::Direct;

use crate::dump::{ops, window, LAYOUT, Profile};
use crate::flowtable::{
    build_create, build_destroy, build_query_payload, canary_6f28, parse_payload_hex, parse_status,
    parse_table_id, verify_echo,
};
use crate::to_hex;
use crate::trace::{normalize_dev, vsec};

/// Host-side stale marker for the result slots (spec §3).
pub const SENTINEL: u32 = 0xdeadbeef;
/// Seed slots (CR reserve): 0x8c6 = rt 0x2318, 0x8c7 = rt 0x231c.
pub const SEED_SLOTS: [u32; 2] = [LAYOUT::W_COUNT, LAYOUT::W_PLD];
/// Result slots 0x8c8..=0x8cf (CR 0x2320..0x233c), 8 words.
pub const CR_RESULT_WORDS: usize = (LAYOUT::CX5_ANSWER_LAST - LAYOUT::W_RESP + 1) as usize;

const QUERY_OUTLEN: u32 = 0x40;
const CREATE_OUTLEN: u32 = 0x40;
const DESTROY_OUTLEN: u32 = 0x10;

/// One `--seed slot=VAL` entry (both parts hex, 0x prefix optional).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedSpec {
    pub slot: u32,
    pub value: u32,
}

/// Verdict of one fuzzvec run (T6 runner consumes `format_summary` output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzvecOutcome {
    pub created_id: u32,
    pub query_err: u8,
    pub status: u8,
    pub syndrome: u32,
    pub echo_ok: bool,
    pub canary: bool,
    pub echo_zone: [u8; 0x28],
    pub cr_post: [u32; CR_RESULT_WORDS],
    pub sentinel_overwritten: Vec<u32>,
    pub destroy_err: u8,
}

#[derive(Args, Debug)]
pub struct FuzzvecArgs {
    /// Device sysfs path or bare BDF (default: the root-mellanox cx5 card)
    #[arg(short, long, default_value = "/sys/bus/pci/devices/0000:81:00.0")]
    pub dev: PathBuf,
    /// Table type for the CREATE/QUERY/DESTROY ladder
    #[arg(long, default_value_t = 0)]
    pub tt: u8,
    /// log_size argument of CREATE
    #[arg(long, default_value_t = 4)]
    pub log_size: u8,
    /// 40B vector payload as exactly 80 hex chars (QUERY input[0x18..0x40))
    #[arg(long)]
    pub payload_hex: String,
    /// Seed slot write, repeatable: <slot=0xVAL> (slots 0x8c6/0x8c7, hex)
    #[arg(long = "seed", value_parser = parse_seed)]
    pub seeds: Vec<SeedSpec>,
    /// Fill 0xdeadbeef into 0x8c8..0x8cf before the command (true/false)
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    pub sentinel: bool,
}

pub fn parse_seed(s: &str) -> anyhow::Result<SeedSpec> {
    let t = s.trim();
    let (slot_s, val_s) = t
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("fuzzvec seed: expected <slot=0xVAL>, got {t:?}"))?;
    let slot = ops::parse_hex_u32(slot_s.trim())
        .map_err(|e| anyhow::anyhow!("fuzzvec seed: bad slot {slot_s:?}: {e}"))?;
    let value = ops::parse_hex_u32(val_s.trim())
        .map_err(|e| anyhow::anyhow!("fuzzvec seed: bad value {val_s:?}: {e}"))?;
    ensure_seed_slot(slot)?;
    Ok(SeedSpec { slot, value })
}

fn ensure_seed_slot(slot: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        SEED_SLOTS.contains(&slot),
        "fuzzvec seed: slot 0x{slot:04x} is not a seed slot (allowed: 0x8c6, 0x8c7; \
         0x8c5 is the magic slot, 0x8c8..0x8cf are the result slots)"
    );
    Ok(())
}

pub fn validate_seeds(seeds: &[SeedSpec]) -> anyhow::Result<()> {
    for (i, a) in seeds.iter().enumerate() {
        ensure_seed_slot(a.slot)?;
        anyhow::ensure!(
            !seeds[..i].iter().any(|b| b.slot == a.slot),
            "fuzzvec seed: duplicate slot 0x{:04x}",
            a.slot
        );
    }
    Ok(())
}

pub fn clear_result_slots<W>(mut write: W) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    for word in LAYOUT::W_RESP..=LAYOUT::CX5_ANSWER_LAST {
        write(word, 0)?;
    }
    Ok(())
}

pub fn fill_sentinel<W>(mut write: W) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    for word in LAYOUT::W_RESP..=LAYOUT::CX5_ANSWER_LAST {
        write(word, SENTINEL)?;
    }
    Ok(())
}

pub fn sentinel_overwritten(cr_post: &[u32; CR_RESULT_WORDS], baseline: u32) -> Vec<u32> {
    cr_post
        .iter()
        .enumerate()
        .filter(|(_, &v)| v != baseline)
        .map(|(i, _)| LAYOUT::W_RESP + i as u32)
        .collect()
}

pub fn ensure_created_id_zero(created_id: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        created_id == 0,
        "fuzzvec: created_id={created_id} != 0 — word0 (input[0x14..0x18) = table_id) \
         would not decode as nop; QUERY refused (word0-nop assumption)"
    );
    Ok(())
}

fn log_cycle_command(name: &str, input: &[u8], out: &[u8], err: u8, table_id: Option<u32>) {
    let (status, syndrome) = parse_status(out);
    println!(
        "[fuzzvec] {} in_len={:#x} in_hex={}",
        name,
        input.len(),
        to_hex(input)
    );
    println!(
        "[fuzzvec] {} err={} status={} syndrome=0x{:x} outlen={:#x} out_hex={}",
        name,
        err,
        status,
        syndrome,
        out.len(),
        to_hex(&out[..out.len().min(0x40)])
    );
    if let Some(id) = table_id {
        println!("[fuzzvec] {} table_id={}", name, id);
    }
}

pub fn fuzzvec_cycle<W, R, X>(
    payload: &[u8; 0x28],
    seeds: &[SeedSpec],
    sentinel: bool,
    tt: u8,
    log_size: u8,
    mut cr_write: W,
    mut cr_read: R,
    mut exec: X,
) -> anyhow::Result<FuzzvecOutcome>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
    R: FnMut(u32) -> anyhow::Result<u32>,
    X: FnMut(&[u8], u32) -> anyhow::Result<(Vec<u8>, u8)>,
{
    validate_seeds(seeds)?;

    println!("[fuzzvec] pre-clear result slots 0x8c8..0x8cf = 0");
    clear_result_slots(|word, v| cr_write(word, v))?;
    if sentinel {
        println!("[fuzzvec] sentinel fill 0x8c8..0x8cf = 0x{:08x}", SENTINEL);
        fill_sentinel(|word, v| cr_write(word, v))?;
    } else {
        println!("[fuzzvec] sentinel disabled (result slots stay at pre-clear 0)");
    }
    for s in seeds {
        println!("[fuzzvec] seed 0x{:04x} = 0x{:08x}", s.slot, s.value);
        cr_write(s.slot, s.value)?;
    }

    let create = build_create(tt, log_size);
    let (out, err) = exec(&create, CREATE_OUTLEN)?;
    let created_id = parse_table_id(&out);
    log_cycle_command("create", &create, &out, err, Some(created_id));

    if let Err(e) = ensure_created_id_zero(created_id) {
        let destroy = build_destroy(tt, created_id);
        let _ = exec(&destroy, DESTROY_OUTLEN);
        return Err(e);
    }

    let query = build_query_payload(tt, created_id, payload);
    let (out, query_err) = match exec(&query, QUERY_OUTLEN) {
        Ok(r) => r,
        Err(e) => {
            let destroy = build_destroy(tt, created_id);
            let _ = exec(&destroy, DESTROY_OUTLEN);
            return Err(e);
        }
    };
    log_cycle_command("query(created)", &query, &out, query_err, None);
    let (status, syndrome) = parse_status(&out);
    let echo_ok = verify_echo(&out, payload);
    let canary = canary_6f28(&out);
    println!(
        "[fuzzvec] query(created) echo_ok={} canary={}",
        echo_ok, canary
    );

    let destroy = build_destroy(tt, created_id);
    let (dout, destroy_err) = exec(&destroy, DESTROY_OUTLEN)?;
    log_cycle_command("destroy", &destroy, &dout, destroy_err, None);

    let mut cr_post = [0u32; CR_RESULT_WORDS];
    for (i, w) in cr_post.iter_mut().enumerate() {
        let word = LAYOUT::W_RESP + i as u32;
        *w = cr_read(word)?;
        println!("[fuzzvec] cr-post 0x{:04x} = 0x{:08x}", word, *w);
    }
    let baseline = if sentinel { SENTINEL } else { 0 };
    let overwritten = sentinel_overwritten(&cr_post, baseline);
    println!(
        "[fuzzvec] sentinel_overwritten: [{}] (empty = stale, live write not proven)",
        overwritten
            .iter()
            .map(|w| format!("0x{w:04x}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut echo_zone = [0u8; 0x28];
    echo_zone.copy_from_slice(out.get(0x10..0x38).unwrap_or(&[0u8; 0x28]));
    println!("[fuzzvec] echo_zone: {}", to_hex(&echo_zone));

    let outcome = FuzzvecOutcome {
        created_id,
        query_err,
        status,
        syndrome,
        echo_ok,
        canary,
        echo_zone,
        cr_post,
        sentinel_overwritten: overwritten,
        destroy_err,
    };
    println!("{}", format_summary(&outcome).trim_end());
    Ok(outcome)
}

pub fn format_summary(o: &FuzzvecOutcome) -> String {
    format!(
        "[fuzzvec] summary: created_id={} query_err={} status={} syndrome=0x{:08x} \
         echo_ok={} canary={} sentinel_overwritten=[{}] cr_post=[{}] echo_zone={} destroy_err={}",
        o.created_id,
        o.query_err,
        o.status,
        o.syndrome,
        o.echo_ok,
        o.canary,
        o.sentinel_overwritten
            .iter()
            .map(|w| format!("0x{w:04x}"))
            .collect::<Vec<_>>()
            .join(","),
        o.cr_post
            .iter()
            .map(|w| format!("0x{w:08x}"))
            .collect::<Vec<_>>()
            .join(","),
        to_hex(&o.echo_zone),
        o.destroy_err,
    )
}

// Summary consumer group: parse_summary is the output-contract consumer
// for scripts/tests (the T6 runner) — not called by the binary itself
// (the ops::parse_read precedent).
#[allow(dead_code)]
fn parse_summary_kv<'a>(fields: &'a [&'a str], idx: usize, key: &str) -> anyhow::Result<&'a str> {
    let (k, v) = fields
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("parse_summary: field {} missing", idx))?
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("parse_summary: field {} is not key=value", idx))?;
    anyhow::ensure!(
        k == key,
        "parse_summary: field {} is `{}`, expected `{}`",
        idx,
        k,
        key
    );
    Ok(v)
}

#[allow(dead_code)]
fn parse_summary_bool(v: &str) -> anyhow::Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => anyhow::bail!("parse_summary: expected true/false, got {v:?}"),
    }
}

#[allow(dead_code)]
fn parse_summary_list(v: &str, what: &str) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        v.starts_with('[') && v.ends_with(']'),
        "parse_summary: {what} must be bracketed, got {v:?}"
    );
    let inner = &v[1..v.len() - 1];
    Ok(if inner.is_empty() {
        Vec::new()
    } else {
        inner.split(',').map(|s| s.trim().to_string()).collect()
    })
}

#[allow(dead_code)]
pub fn parse_summary(line: &str) -> anyhow::Result<FuzzvecOutcome> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    anyhow::ensure!(
        fields.len() >= 2 && fields[0] == "[fuzzvec]" && fields[1] == "summary:",
        "parse_summary: not a fuzzvec summary line: {line:?}"
    );
    anyhow::ensure!(
        fields.len() == 12,
        "parse_summary: got {} fields, expected 12",
        fields.len()
    );
    let created_id = parse_summary_kv(&fields, 2, "created_id")?.parse::<u32>()?;
    let query_err = parse_summary_kv(&fields, 3, "query_err")?.parse::<u8>()?;
    let status = parse_summary_kv(&fields, 4, "status")?.parse::<u8>()?;
    let syndrome = {
        let v = parse_summary_kv(&fields, 5, "syndrome")?;
        let h = v
            .strip_prefix("0x")
            .ok_or_else(|| anyhow::anyhow!("parse_summary: syndrome must be 0x-hex, got {v:?}"))?;
        u32::from_str_radix(h, 16)?
    };
    let echo_ok = parse_summary_bool(parse_summary_kv(&fields, 6, "echo_ok")?)?;
    let canary = parse_summary_bool(parse_summary_kv(&fields, 7, "canary")?)?;
    let sentinel_overwritten = parse_summary_list(
        parse_summary_kv(&fields, 8, "sentinel_overwritten")?,
        "sentinel_overwritten",
    )?
    .iter()
    .map(|s| {
        let h = s.strip_prefix("0x").ok_or_else(|| {
            anyhow::anyhow!("parse_summary: sentinel slot must be 0x-hex, got {s:?}")
        })?;
        Ok(u32::from_str_radix(h, 16)?)
    })
    .collect::<anyhow::Result<Vec<u32>>>()?;
    let cr_post_list =
        parse_summary_list(parse_summary_kv(&fields, 9, "cr_post")?, "cr_post")?;
    anyhow::ensure!(
        cr_post_list.len() == CR_RESULT_WORDS,
        "parse_summary: cr_post has {} words, expected {CR_RESULT_WORDS}",
        cr_post_list.len()
    );
    let mut cr_post = [0u32; CR_RESULT_WORDS];
    for (i, s) in cr_post_list.iter().enumerate() {
        let h = s
            .strip_prefix("0x")
            .ok_or_else(|| anyhow::anyhow!("parse_summary: cr_post word must be 0x-hex, got {s:?}"))?;
        cr_post[i] = u32::from_str_radix(h, 16)?;
    }
    let echo_zone = parse_payload_hex(parse_summary_kv(&fields, 10, "echo_zone")?)?;
    let destroy_err = parse_summary_kv(&fields, 11, "destroy_err")?.parse::<u8>()?;
    Ok(FuzzvecOutcome {
        created_id,
        query_err,
        status,
        syndrome,
        echo_ok,
        canary,
        echo_zone,
        cr_post,
        sentinel_overwritten,
        destroy_err,
    })
}

pub fn run(args: &FuzzvecArgs) -> anyhow::Result<()> {
    let payload = parse_payload_hex(&args.payload_hex)?;
    validate_seeds(&args.seeds)?;
    println!(
        "[s2trig] fuzzvec dev={} tt={} log_size={} sentinel={} payload=40B seeds=[{}]",
        args.dev.display(),
        args.tt,
        args.log_size,
        args.sentinel,
        args.seeds
            .iter()
            .map(|s| format!("0x{:04x}=0x{:08x}", s.slot, s.value))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("[s2trig] opening {} (reset+init)", args.dev.display());
    let cmdif = Direct::open_from_sysfs(&args.dev, true, true)?;
    let cr_dev = vsec::VsecDev::open(&normalize_dev(&args.dev))?;
    let cr_dev = RefCell::new(cr_dev);
    fuzzvec_cycle(
        &payload,
        &args.seeds,
        args.sentinel,
        args.tt,
        args.log_size,
        |word, v| {
            window::CrWindow::with_profile(&cr_dev.borrow(), Profile::Cx5)?.write_word(word, v)
        },
        |word| window::CrWindow::new(&cr_dev.borrow())?.read_word(word),
        |frame: &[u8], outlen: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            Ok(cmdif.try_exec_command(frame, outlen)?)
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CliArgs;
    use clap::Parser;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    fn payload_40b() -> [u8; 0x28] {
        std::array::from_fn(|i| (i * 3 + 5) as u8)
    }

    #[test]
    fn constants_verbatim() {
        assert_eq!(SENTINEL, 0xdeadbeef);
        assert_eq!(SEED_SLOTS, [0x8c6, 0x8c7], "seed slots only");
        assert_eq!(CR_RESULT_WORDS, 8, "result slots 0x8c8..0x8cf");
        assert_eq!(crate::dump::window::cr_offset(0x8c6), 0x2318);
        assert_eq!(crate::dump::window::cr_offset(0x8c7), 0x231c);
        assert_eq!(crate::dump::window::cr_offset(0x8c8), 0x2320);
        assert_eq!(crate::dump::window::cr_offset(0x8cf), 0x233c);
    }

    #[test]
    fn payload_parser_requires_exactly_80_hex() {
        // fuzzvec consumes the flowtable 40B parser — pin the contract
        assert_eq!(parse_payload_hex(&"ab".repeat(40)).unwrap().len(), 0x28);
        assert!(parse_payload_hex(&"ab".repeat(39)).is_err());
        assert!(parse_payload_hex(&"ab".repeat(41)).is_err());
        assert!(parse_payload_hex(&"zz".repeat(40)).is_err());
    }

    #[test]
    fn parse_seed_accepts_both_seed_slots() {
        assert_eq!(
            parse_seed("0x8c6=0x12345678").unwrap(),
            SeedSpec { slot: 0x8c6, value: 0x12345678 }
        );
        assert_eq!(
            parse_seed("8c7=5a").unwrap(),
            SeedSpec { slot: 0x8c7, value: 0x5a },
            "bare hex (no 0x) like dump --words"
        );
        assert_eq!(
            parse_seed(" 0x8c6 = 0x00000000 ").unwrap(),
            SeedSpec { slot: 0x8c6, value: 0 },
            "whitespace tolerated, zero value is legal"
        );
    }

    #[test]
    fn parse_seed_rejects_non_seed_slots() {
        for bad in ["0x8c5=1", "0x8c8=1", "0x8cf=1", "0x100=1", "8c4=1"] {
            assert!(parse_seed(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn parse_seed_rejects_malformed() {
        for bad in ["8c6", "8c6=", "=5", "8c6=zz", "", "8c6=1=2"] {
            assert!(parse_seed(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn validate_seeds_rejects_duplicate_slots_and_bad_slots() {
        assert!(validate_seeds(&[]).is_ok());
        assert!(
            validate_seeds(&[
                SeedSpec { slot: 0x8c6, value: 1 },
                SeedSpec { slot: 0x8c7, value: 2 },
            ])
            .is_ok()
        );
        assert!(
            validate_seeds(&[
                SeedSpec { slot: 0x8c6, value: 1 },
                SeedSpec { slot: 0x8c6, value: 2 },
            ])
            .is_err(),
            "duplicate slot must be rejected"
        );
        assert!(
            validate_seeds(&[SeedSpec { slot: 0x8c8, value: 1 }]).is_err(),
            "non-seed slot must be rejected for programmatic callers too"
        );
    }

    #[test]
    fn clear_result_slots_writes_only_8c8_8cf_zeros() {
        let mut w = Vec::new();
        clear_result_slots(|word, v| {
            w.push((word, v));
            Ok(())
        })
        .unwrap();
        let expect: Vec<(u32, u32)> = (0x8c8..=0x8cf).map(|x| (x, 0)).collect();
        assert_eq!(w, expect, "pre-clear touches ONLY 0x8c8..0x8cf");
    }

    #[test]
    fn fill_sentinel_writes_only_8c8_8cf_deadbeef() {
        let mut w = Vec::new();
        fill_sentinel(|word, v| {
            w.push((word, v));
            Ok(())
        })
        .unwrap();
        let expect: Vec<(u32, u32)> = (0x8c8..=0x8cf).map(|x| (x, SENTINEL)).collect();
        assert_eq!(w, expect, "sentinel fill touches ONLY 0x8c8..0x8cf");
        assert!(
            !w.contains(&(0x8c5, SENTINEL)),
            "magic slot 0x8c5 must never be touched"
        );
    }

    #[test]
    fn sentinel_overwritten_empty_when_all_stale() {
        let post = [SENTINEL; CR_RESULT_WORDS];
        assert!(sentinel_overwritten(&post, SENTINEL).is_empty(), "stale");
    }

    #[test]
    fn sentinel_overwritten_picks_exact_slots() {
        let mut post = [SENTINEL; CR_RESULT_WORDS];
        post[1] = 0x600d_0002;
        post[7] = 0;
        assert_eq!(sentinel_overwritten(&post, SENTINEL), vec![0x8c9, 0x8cf]);
    }

    #[test]
    fn sentinel_overwritten_baseline_zero_for_no_sentinel_mode() {
        let mut post = [0u32; CR_RESULT_WORDS];
        assert!(sentinel_overwritten(&post, 0).is_empty(), "no write = stale");
        post[3] = 0x1234;
        assert_eq!(sentinel_overwritten(&post, 0), vec![0x8cb]);
    }

    #[test]
    fn ensure_created_id_zero_gate() {
        assert!(ensure_created_id_zero(0).is_ok());
        let e = ensure_created_id_zero(0x2a).unwrap_err().to_string();
        assert!(e.contains("created_id"), "names the gate: {e}");
        assert!(e.contains("word0"), "names the assumption: {e}");
    }

    struct MockBus {
        ops: Rc<RefCell<Vec<String>>>,
        mem: Rc<RefCell<HashMap<u32, u32>>>,
    }

    impl MockBus {
        fn new() -> Self {
            Self {
                ops: Rc::new(RefCell::new(Vec::new())),
                mem: Rc::new(RefCell::new(HashMap::new())),
            }
        }

        fn cr_write(&self) -> impl FnMut(u32, u32) -> anyhow::Result<()> + '_ {
            let ops = self.ops.clone();
            let mem = self.mem.clone();
            move |word, v| {
                ops.borrow_mut().push(format!("w:{word:04x}={v:08x}"));
                mem.borrow_mut().insert(word, v);
                Ok(())
            }
        }

        fn cr_read(&self) -> impl FnMut(u32) -> anyhow::Result<u32> + '_ {
            let ops = self.ops.clone();
            let mem = self.mem.clone();
            move |word| {
                ops.borrow_mut().push(format!("r:{word:04x}"));
                Ok(*mem.borrow().get(&word).unwrap_or(&0))
            }
        }
    }

    /// exec mock: create → table id from `created_id`; query → success out
    /// with echo zone + canary, and (simulating the stub) a live CR write of
    /// `stub_word` into result slot `stub_slot`; destroy → 0x10 out.
    fn exec_mock(
        bus: &MockBus,
        payload: [u8; 0x28],
        created_id: u32,
        stub_slot: u32,
        stub_word: u32,
    ) -> impl FnMut(&[u8], u32) -> anyhow::Result<(Vec<u8>, u8)> + '_ {
        let ops = bus.ops.clone();
        let mem = bus.mem.clone();
        move |frame: &[u8], outlen: u32| {
            let op = match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x30)) => "create",
                (Some(&0x09), Some(&0x31)) => "destroy",
                (Some(&0x09), Some(&0x32)) => "query",
                _ => anyhow::bail!("fuzzvec mock: unknown frame {}", to_hex(frame)),
            };
            ops.borrow_mut().push(format!("x:{op}:{outlen:02x}"));
            let mut out = vec![0u8; outlen as usize];
            match op {
                "create" => {
                    out[8..12].copy_from_slice(&created_id.to_be_bytes());
                }
                "query" => {
                    out.truncate(0x40);
                    out.resize(0x40, 0);
                    out[0x10..0x38].copy_from_slice(&payload);
                    out[0x3a..0x3c].copy_from_slice(&[0x6f, 0x28]);
                    mem.borrow_mut().insert(stub_slot, stub_word);
                }
                _ => {}
            }
            Ok((out, 0))
        }
    }

    fn seeds_two() -> Vec<SeedSpec> {
        vec![
            SeedSpec { slot: 0x8c6, value: 0x1234_5678 },
            SeedSpec { slot: 0x8c7, value: 0x9abc_def0 },
        ]
    }

    #[test]
    fn cycle_happy_path_full_sequence_and_outcome() {
        let payload = payload_40b();
        let bus = MockBus::new();
        let exec = exec_mock(&bus, payload, 0, 0x8c9, 0x600d_0002);
        let o = fuzzvec_cycle(
            &payload,
            &seeds_two(),
            true,
            0,
            4,
            bus.cr_write(),
            bus.cr_read(),
            exec,
        )
        .unwrap();

        let mut expect_ops: Vec<String> = (0x8c8..=0x8cf)
            .map(|w| format!("w:{w:04x}=00000000"))
            .collect();
        expect_ops.extend((0x8c8..=0x8cf).map(|w| format!("w:{w:04x}=deadbeef")));
        expect_ops.push("w:08c6=12345678".to_string());
        expect_ops.push("w:08c7=9abcdef0".to_string());
        expect_ops.push("x:create:40".to_string());
        expect_ops.push("x:query:40".to_string());
        expect_ops.push("x:destroy:10".to_string());
        expect_ops.extend((0x8c8..=0x8cf).map(|w| format!("r:{w:04x}")));
        assert_eq!(*bus.ops.borrow(), expect_ops, "brief-order: pre-clear, sentinel, seeds, ladder, CR readback");

        assert_eq!(o.created_id, 0);
        assert_eq!(o.query_err, 0);
        assert_eq!(o.status, 0);
        assert_eq!(o.syndrome, 0);
        assert!(o.echo_ok, "echo zone byte-exact");
        assert!(o.canary, "canary 0x6f28 @0x3a");
        assert_eq!(o.echo_zone, payload);
        let mut cr_expect = [SENTINEL; CR_RESULT_WORDS];
        cr_expect[1] = 0x600d_0002;
        assert_eq!(o.cr_post, cr_expect);
        assert_eq!(o.sentinel_overwritten, vec![0x8c9]);
        assert_eq!(o.destroy_err, 0);
    }

    #[test]
    fn cycle_query_frame_is_build_query_payload_id0() {
        let payload = payload_40b();
        let bus = MockBus::new();
        let ops = bus.ops.clone();
        let exec = move |frame: &[u8], _o: u32| {
            if frame.first() == Some(&0x09) && frame.get(1) == Some(&0x32) {
                assert_eq!(frame, &crate::flowtable::build_query_payload(0, 0, &payload)[..]);
            }
            ops.borrow_mut().push(format!("x:{}", to_hex(&frame[..2])));
            Ok((vec![0u8; 0x40], 0))
        };
        fuzzvec_cycle(&payload, &[], true, 0, 4, bus.cr_write(), bus.cr_read(), exec)
            .unwrap();
    }

    #[test]
    fn cycle_refuses_nonzero_created_id_without_query() {
        let payload = payload_40b();
        let bus = MockBus::new();
        let exec = exec_mock(&bus, payload, 0x2a, 0x8c9, 0x1);
        let r = fuzzvec_cycle(
            &payload,
            &[],
            true,
            0,
            4,
            bus.cr_write(),
            bus.cr_read(),
            exec,
        );
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("created_id"), "gate error: {msg}");
        let ops = bus.ops.borrow();
        assert!(
            !ops.iter().any(|o| o.starts_with("x:query")),
            "no QUERY may be sent on refuse"
        );
        assert!(
            ops.iter().any(|o| o == "x:destroy:10"),
            "session hygiene: best-effort DESTROY on refuse"
        );
        assert!(
            !ops.iter().any(|o| o.starts_with("r:")),
            "no verdict reads after refuse"
        );
    }

    #[test]
    fn cycle_query_transport_error_propagates_and_destroys() {
        let payload = payload_40b();
        let bus = MockBus::new();
        let ops = bus.ops.clone();
        let exec = move |frame: &[u8], _o: u32| match (frame.first(), frame.get(1)) {
            (Some(&0x09), Some(&0x32)) => Err(anyhow::anyhow!("fuzzvec transport fail")),
            (Some(&0x09), Some(&0x31)) => {
                ops.borrow_mut().push("x:destroy:10".to_string());
                Ok((vec![0u8; 0x10], 0))
            }
            _ => Ok((vec![0u8; 0x40], 0)),
        };
        let r = fuzzvec_cycle(&payload, &[], true, 0, 4, bus.cr_write(), bus.cr_read(), exec);
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("fuzzvec transport fail"), "original error: {msg}");
        assert!(bus.ops.borrow().iter().any(|o| o == "x:destroy:10"));
    }

    #[test]
    fn cycle_no_sentinel_leaves_zero_baseline() {
        let payload = payload_40b();
        let bus = MockBus::new();
        let exec = exec_mock(&bus, payload, 0, 0x8c8, 0); // stub writes nothing
        let o = fuzzvec_cycle(
            &payload,
            &[],
            false,
            0,
            4,
            bus.cr_write(),
            bus.cr_read(),
            exec,
        )
        .unwrap();
        assert!(
            !bus.ops.borrow().iter().any(|o| o.contains("deadbeef")),
            "no sentinel fill when --sentinel=false"
        );
        assert_eq!(o.cr_post, [0u32; CR_RESULT_WORDS]);
        assert!(o.sentinel_overwritten.is_empty(), "all-zero = stale");
    }

    #[test]
    fn cycle_refuses_nonzero_created_id_without_query_uses_created_id_from_create() {
        let payload = payload_40b();
        let bus = MockBus::new();
        let exec = exec_mock(&bus, payload, 0xff_123456, 0x8c9, 0x1);
        let r = fuzzvec_cycle(
            &payload,
            &[],
            true,
            0,
            4,
            bus.cr_write(),
            bus.cr_read(),
            exec,
        );
        assert!(r.unwrap_err().to_string().contains("created_id=1193046"), "masked id in message");
    }

    fn sample_outcome() -> FuzzvecOutcome {
        let mut cr_post = [SENTINEL; CR_RESULT_WORDS];
        cr_post[1] = 0x600d_0002;
        FuzzvecOutcome {
            created_id: 0,
            query_err: 0,
            status: 0,
            syndrome: 0x001c_2b78,
            echo_ok: true,
            canary: true,
            echo_zone: payload_40b(),
            cr_post,
            sentinel_overwritten: vec![0x8c9],
            destroy_err: 0,
        }
    }

    #[test]
    fn summary_format_shape() {
        let s = format_summary(&sample_outcome());
        assert!(s.starts_with("[fuzzvec] summary: created_id=0 query_err=0 status=0 syndrome=0x001c2b78 echo_ok=true canary=true "), "{s}");
        assert!(
            s.contains("sentinel_overwritten=[0x08c9] cr_post=[0xdeadbeef,0x600d0002,"),
            "{s}"
        );
        assert!(s.ends_with(&format!("echo_zone={} destroy_err=0", to_hex(&payload_40b()))), "{s}");
    }

    #[test]
    fn summary_parse_roundtrip_rich_and_stale() {
        let rich = sample_outcome();
        assert_eq!(parse_summary(&format_summary(&rich)).unwrap(), rich);

        let stale = FuzzvecOutcome {
            syndrome: 0,
            echo_ok: false,
            canary: false,
            echo_zone: [0u8; 0x28],
            cr_post: [SENTINEL; CR_RESULT_WORDS],
            sentinel_overwritten: vec![],
            destroy_err: 3,
            ..sample_outcome()
        };
        assert_eq!(parse_summary(&format_summary(&stale)).unwrap(), stale);
    }

    #[test]
    fn summary_parse_rejects_garbage() {
        assert!(parse_summary("").is_err());
        assert!(parse_summary("hello world").is_err());
        assert!(parse_summary("[dump-read] 0x08c5 magic 0x44554d31").is_err());
        let good = format_summary(&sample_outcome());
        let truncated = good.split(" cr_post=").next().unwrap().to_string();
        assert!(parse_summary(&truncated).is_err(), "missing fields");
        assert!(
            parse_summary(&good.replace("echo_ok=true", "echo_ok=yes")).is_err(),
            "non-bool echo_ok"
        );
        let bad_cr = good.replace(
            "cr_post=[0xdeadbeef,0x600d0002,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef]",
            "cr_post=[0x1]",
        );
        assert!(parse_summary(&bad_cr).is_err(), "1-word cr_post must fail");
        assert!(
            parse_summary(&good.replace("status=0", "status=zz")).is_err(),
            "non-numeric status"
        );
        assert!(
            parse_summary(&good.replace("created_id=0", "created_id=0x0")).is_err(),
            "created_id is strict decimal"
        );
    }

    fn parse_cli(args: &[&str]) -> FuzzvecArgs {
        let c = CliArgs::try_parse_from(args).unwrap();
        match c.command.expect("subcommand") {
            crate::Command::Fuzzvec(a) => a,
            other => panic!("expected fuzzvec, got {other:?}"),
        }
    }

    #[test]
    fn cli_payload_hex_is_required() {
        assert!(CliArgs::try_parse_from(["mlxscope", "fuzzvec"]).is_err());
    }

    #[test]
    fn cli_parses_seeds_defaults() {
        let a = parse_cli(&[
            "mlxscope",
            "fuzzvec",
            "--payload-hex",
            &"ab".repeat(40),
            "--seed",
            "0x8c6=0x12345678",
            "--seed",
            "8c7=5a",
        ]);
        assert_eq!(
            a.seeds,
            vec![
                SeedSpec { slot: 0x8c6, value: 0x12345678 },
                SeedSpec { slot: 0x8c7, value: 0x5a },
            ]
        );
        assert!(a.sentinel, "sentinel defaults to true");
        assert_eq!(a.tt, 0);
        assert_eq!(a.log_size, 4);
        assert_eq!(
            a.dev,
            PathBuf::from("/sys/bus/pci/devices/0000:81:00.0"),
            "default dev is the root-mellanox cx5 card"
        );
    }

    #[test]
    fn cli_sentinel_false_and_true() {
        let a = parse_cli(&[
            "mlxscope",
            "fuzzvec",
            "--payload-hex",
            &"ab".repeat(40),
            "--sentinel=false",
        ]);
        assert!(!a.sentinel);
        let b = parse_cli(&[
            "mlxscope",
            "fuzzvec",
            "--payload-hex",
            &"ab".repeat(40),
            "--sentinel=true",
        ]);
        assert!(b.sentinel);
    }

    #[test]
    fn cli_bad_seed_is_clap_error() {
        for bad in ["0x8c5=1", "0x8c8=1", "8c6", "8c6=zz"] {
            assert!(
                CliArgs::try_parse_from([
                    "mlxscope", "fuzzvec", "--payload-hex", &"ab".repeat(40), "--seed", bad,
                ])
                .is_err(),
                "seed {bad:?} must be a clap error"
            );
        }
    }
}
