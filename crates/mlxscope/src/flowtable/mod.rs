use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Args;
use mlxdirect::session::Direct;

use crate::to_hex;

const QUERY_OUTLEN: u32 = 0x40;
const CREATE_OUTLEN: u32 = 0x40;
const DESTROY_OUTLEN: u32 = 0x10;

const TABLE_ID_MASK: u32 = 0x00ff_ffff;

const PAYLOAD_LEN: usize = 0x28;
const QUERY_PAYLOAD_LEN: usize = 0x40;
const CANARY: [u8; 2] = [0x6f, 0x28];
const KB_MIN: usize = 26;

pub const RD2_MAGIC16: u16 = 0x55AA;
pub const RD2_MAGIC_OFF: usize = 0x18;
pub const RD2_MARKER_OFF: usize = 0x1a;
pub const RD2_TRIG_LEN: usize = 0x40;

#[derive(Args, Debug)]
pub struct FlowtableArgs {
    #[arg(long, default_value = "/sys/bus/pci/devices/0000:81:00.0")]
    pub dev: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub tt: u8,
    #[arg(long, default_value_t = 4)]
    pub log_size: u8,
    #[arg(long)]
    pub payload_hex: Option<String>,
    #[arg(long)]
    pub kb_demo: Option<usize>,
    #[arg(long)]
    pub rd2_trig: bool,
    #[arg(long)]
    pub rd2_dump_raw: Option<PathBuf>,
}

pub fn build_query(tt: u8, id: u32) -> Vec<u8> {
    let mut out = vec![0u8; 0x18];
    out[0x00..0x02].copy_from_slice(&0x0932u16.to_be_bytes());
    out[0x06..0x08].copy_from_slice(&0x0000u16.to_be_bytes());
    out[0x10] = tt;
    out[0x14..0x18].copy_from_slice(&(id & TABLE_ID_MASK).to_be_bytes());
    out
}

pub fn build_create(tt: u8, log_size: u8) -> Vec<u8> {
    let mut out = vec![0u8; 0x40];
    out[0x00..0x02].copy_from_slice(&0x0930u16.to_be_bytes());
    out[0x06..0x08].copy_from_slice(&0x0000u16.to_be_bytes());
    out[0x10] = tt;
    out[0x18..0x1c].copy_from_slice(&(log_size as u32).to_be_bytes());
    out
}

pub fn build_destroy(tt: u8, id: u32) -> Vec<u8> {
    let mut out = vec![0u8; 0x40];
    out[0x00..0x02].copy_from_slice(&0x0931u16.to_be_bytes());
    out[0x06..0x08].copy_from_slice(&0x0000u16.to_be_bytes());
    out[0x10] = tt;
    out[0x14..0x18].copy_from_slice(&(id & TABLE_ID_MASK).to_be_bytes());
    out
}

pub fn build_query_payload(tt: u8, id: u32, payload: &[u8; PAYLOAD_LEN]) -> Vec<u8> {
    let mut out = build_query(tt, id);
    out.resize(QUERY_PAYLOAD_LEN, 0);
    out[0x18..0x40].copy_from_slice(payload);
    out
}

pub fn parse_payload_hex(s: &str) -> anyhow::Result<[u8; PAYLOAD_LEN]> {
    let s = s.trim();
    anyhow::ensure!(
        s.is_ascii(),
        "payload-hex must be ASCII hex, got non-ASCII input"
    );
    anyhow::ensure!(
        s.len() == PAYLOAD_LEN * 2,
        "payload-hex must be exactly {} hex chars ({} bytes), got {}",
        PAYLOAD_LEN * 2,
        PAYLOAD_LEN,
        s.len()
    );
    let mut out = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

pub fn verify_echo(out: &[u8], payload: &[u8]) -> bool {
    payload.len() == PAYLOAD_LEN && out.get(0x10..0x38) == Some(payload)
}

pub fn canary_6f28(out: &[u8]) -> bool {
    out.get(0x3a..0x3c) == Some(&CANARY[..])
}

pub fn kb_payload(i: usize) -> [u8; PAYLOAD_LEN] {
    std::array::from_fn(|j| ((i * 0x28 + j) % 251 + 1) as u8)
}

#[derive(Debug, Clone, Copy)]
pub struct KbResult {
    pub err: u8,
    pub status: u8,
    pub echo_ok: bool,
}

pub fn kb_tally(results: &[KbResult]) -> (usize, usize) {
    let losses = results
        .iter()
        .filter(|r| r.err != 0 || r.status != 0 || !r.echo_ok)
        .count();
    (results.len() - losses, losses)
}

pub fn parse_status(out: &[u8]) -> (u8, u32) {
    (
        out[0],
        u32::from_be_bytes([out[4], out[5], out[6], out[7]]),
    )
}

pub fn parse_table_id(out: &[u8]) -> u32 {
    u32::from_be_bytes([out[8], out[9], out[10], out[11]]) & TABLE_ID_MASK
}

fn log_command(name: &str, input: &[u8], out: &[u8], err: u8, table_id: Option<u32>) {
    let (status, syndrome) = parse_status(out);
    println!(
        "[s2trig] {} in_len={:#x} in_hex={}",
        name,
        input.len(),
        to_hex(input)
    );
    println!(
        "[s2trig] {} err={} status={} syndrome=0x{:x} outlen={:#x}",
        name, err, status, syndrome, out.len()
    );
    println!(
        "[s2trig] {} out_hex={}",
        name,
        to_hex(&out[..out.len().min(0x40)])
    );
    if let Some(id) = table_id {
        println!("[s2trig] {} table_id={}", name, id);
    }
}

fn log_verdict(name: &str, out: &[u8], payload: &[u8]) {
    println!(
        "[s2trig] {} echo_ok={} canary={}",
        name,
        verify_echo(out, payload),
        canary_6f28(out)
    );
}

pub fn kb_run(
    tt: u8,
    n: usize,
    created_id: u32,
    exec: &mut dyn FnMut(&[u8], u32) -> anyhow::Result<(Vec<u8>, u8)>,
) -> anyhow::Result<(Vec<KbResult>, Duration)> {
    let mut results: Vec<KbResult> = Vec::with_capacity(n);
    let mut cmd_time = Duration::ZERO;
    for i in 0..n {
        let p = kb_payload(i);
        let query = build_query_payload(tt, created_id, &p);
        let name = format!("query(created,kb={})", i + 1);
        let t = Instant::now();
        let (out, err) = match exec(&query, QUERY_OUTLEN) {
            Ok(r) => r,
            Err(e) => {
                let destroy = build_destroy(tt, created_id);
                let _ = exec(&destroy, DESTROY_OUTLEN);
                return Err(e);
            }
        };
        cmd_time += t.elapsed();
        let (status, _syndrome) = parse_status(&out);
        let echo_ok = verify_echo(&out, &p);
        log_command(&name, &query, &out, err, None);
        log_verdict(&name, &out, &p);
        results.push(KbResult {
            err,
            status,
            echo_ok,
        });
    }

    let destroy = build_destroy(tt, created_id);
    let (out, err) = exec(&destroy, DESTROY_OUTLEN)?;
    log_command("destroy", &destroy, &out, err, None);

    Ok((results, cmd_time))
}

pub fn ensure_kb_clean(losses: usize) -> anyhow::Result<()> {
    anyhow::ensure!(losses == 0, "kb-demo finished with {} loss(es)", losses);
    Ok(())
}

pub fn validate_flowtable_args(
    payload: bool,
    kb: Option<usize>,
    rd2_trig: bool,
    rd2_dump_raw: bool,
) -> anyhow::Result<()> {
    if kb.is_some() {
        anyhow::ensure!(
            !payload,
            "--kb-demo and --payload-hex are mutually exclusive (kb-demo uses its own P_i payloads)"
        );
        anyhow::ensure!(
            !rd2_trig,
            "--kb-demo and --rd2-trig are mutually exclusive"
        );
    }
    if rd2_trig {
        anyhow::ensure!(
            !payload,
            "--rd2-trig and --payload-hex are mutually exclusive (rd2-trig builds its own frames)"
        );
    } else {
        anyhow::ensure!(
            !rd2_dump_raw,
            "--rd2-dump-raw requires --rd2-trig"
        );
    }
    Ok(())
}

pub fn rd2_marker_bytes() -> [u8; 12] {
    let mut out = [0u8; 12];
    for (i, w) in crate::scan::MARKER.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

pub fn build_query_rd2_trig(tt: u8, id: u32) -> Vec<u8> {
    let mut out = build_query(tt, id);
    out.resize(RD2_TRIG_LEN, 0);
    out[RD2_MAGIC_OFF..RD2_MAGIC_OFF + 2].copy_from_slice(&RD2_MAGIC16.to_be_bytes());
    out[RD2_MARKER_OFF..RD2_MARKER_OFF + 12].copy_from_slice(&rd2_marker_bytes());
    out
}

pub fn rd2_neg_out_ok(out: &[u8]) -> bool {
    out.len() == 0x40
        && out[0] == 0x03
        && out[4..8] == [0x00, 0x1c, 0x2b, 0x78]
        && out[8..].iter().all(|&b| b == 0)
}

pub fn rd2_readback_byte() -> u8 {
    (crate::scan::MARKER[0] >> 8) as u8
}

pub fn rd2_readback_ok(out: &[u8]) -> bool {
    out.len() == 0x40 && out[0x1b] == rd2_readback_byte()
}

pub fn rd2_marker_absent(out: &[u8]) -> bool {
    let m = rd2_marker_bytes();
    !out.windows(12).any(|w| w == m)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rd2Verdicts {
    pub trig_err: u8,
    pub followup_err: u8,
    pub destroy_err: u8,
    pub readback_ok: bool,
}

pub fn rd2_run(
    tt: u8,
    created_id: u32,
    exec: &mut dyn FnMut(&[u8], u32) -> anyhow::Result<(Vec<u8>, u8)>,
    after_trig: &mut dyn FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<Rd2Verdicts> {
    let trig = build_query_rd2_trig(tt, created_id);
    let (out, trig_err) = match exec(&trig, QUERY_OUTLEN) {
        Ok(r) => r,
        Err(e) => {
            let destroy = build_destroy(tt, created_id);
            let _ = exec(&destroy, DESTROY_OUTLEN);
            return Err(e);
        }
    };
    log_command("query(created,rd2-trig)", &trig, &out, trig_err, None);
    if let Err(e) = after_trig() {
        let destroy = build_destroy(tt, created_id);
        let _ = exec(&destroy, DESTROY_OUTLEN);
        return Err(e);
    }

    let followup = build_query(tt, created_id);
    let (fout, followup_err) = match exec(&followup, QUERY_OUTLEN) {
        Ok(r) => r,
        Err(e) => {
            let destroy = build_destroy(tt, created_id);
            let _ = exec(&destroy, DESTROY_OUTLEN);
            return Err(e);
        }
    };
    log_command("query(created,followup)", &followup, &fout, followup_err, None);
    let readback_ok = rd2_readback_ok(&fout);
    println!(
        "[s2trig] rd2 readback out[0x1b]=0x{:02x} expect=0x{:02x} ok={} window_0x18_0x22={}",
        fout.get(0x1b).copied().unwrap_or(0),
        rd2_readback_byte(),
        readback_ok,
        to_hex(&fout[0x18..fout.len().min(0x22)])
    );

    let destroy = build_destroy(tt, created_id);
    let (dout, destroy_err) = exec(&destroy, DESTROY_OUTLEN)?;
    log_command("destroy", &destroy, &dout, destroy_err, None);

    Ok(Rd2Verdicts {
        trig_err,
        followup_err,
        destroy_err,
        readback_ok,
    })
}

pub fn run(args: &FlowtableArgs) -> anyhow::Result<()> {
    let payload = match &args.payload_hex {
        Some(hex) => Some(parse_payload_hex(hex)?),
        None => None,
    };
    validate_flowtable_args(
        payload.is_some(),
        args.kb_demo,
        args.rd2_trig,
        args.rd2_dump_raw.is_some(),
    )?;
    let kb_n = match args.kb_demo {
        Some(n) => {
            anyhow::ensure!(n >= KB_MIN, "--kb-demo must be >= {}, got {}", KB_MIN, n);
            Some(n)
        }
        None => None,
    };
    println!(
        "[s2trig] flowtable dev={} tt={} log_size={}",
        args.dev.display(),
        args.tt,
        args.log_size
    );
    if payload.is_some() {
        println!("[s2trig] payload mode on: both queries are 0x40B with 40B payload");
    }
    if let Some(n) = kb_n {
        println!("[s2trig] kb-demo N={} (CREATE -> N x query(created,P_i) -> DESTROY)", n);
    }
    if args.rd2_trig {
        println!(
            "[s2trig] rd2-trig mode on: neg -> create -> trig(magic+marker) -> followup -> destroy (full window dumps)"
        );
    }
    println!("[s2trig] opening {} (reset+init)", args.dev.display());
    let mut cmdif = Direct::open_from_sysfs(&args.dev, true, true)?;
    if args.rd2_trig {
        cmdif.dump_bufs = true;
    }

    let query0 = match &payload {
        Some(p) => build_query_payload(args.tt, 0, p),
        None => build_query(args.tt, 0),
    };
    let (out, err) = cmdif.try_exec_command(&query0, QUERY_OUTLEN)?;
    log_command("query(id=0)", &query0, &out, err, None);
    if let Some(p) = &payload {
        log_verdict("query(id=0)", &out, p);
    }
    let mut rd2_neg_ok = false;
    let mut rd2_neg_marker_absent = true;
    if args.rd2_trig {
        rd2_neg_ok = rd2_neg_out_ok(&out);
        rd2_neg_marker_absent = rd2_marker_absent(&out);
        println!(
            "[s2trig] rd2 neg_ok={} neg_marker_absent={}",
            rd2_neg_ok, rd2_neg_marker_absent
        );
    }

    let create = build_create(args.tt, args.log_size);
    let (out, err) = cmdif.try_exec_command(&create, CREATE_OUTLEN)?;
    let created_id = parse_table_id(&out);
    log_command("create", &create, &out, err, Some(created_id));

    if let Some(n) = kb_n {
        let mut exec = |f: &[u8], outlen: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            Ok(cmdif.try_exec_command(f, outlen)?)
        };
        let (results, cmd_time) = kb_run(args.tt, n, created_id, &mut exec)?;

        let (ok, losses) = kb_tally(&results);
        let secs = cmd_time.as_secs_f64().max(1e-9);
        println!(
            "kb: N={} ok={} losses={} cmd/s={:.1} B/s={:.1}",
            n,
            ok,
            losses,
            n as f64 / secs,
            (n * PAYLOAD_LEN) as f64 / secs
        );
        ensure_kb_clean(losses)?;
        return Ok(());
    }

    if args.rd2_trig {
        println!(
            "[s2trig] rd2 marker={} magic=0x{:04x}@0x{:02x} readback_expect=0x{:02x}@0x1b",
            to_hex(&rd2_marker_bytes()),
            RD2_MAGIC16,
            RD2_MAGIC_OFF,
            rd2_readback_byte()
        );
        let dump_raw = args.rd2_dump_raw.clone();
        let mut exec = |f: &[u8], outlen: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            Ok(cmdif.try_exec_command(f, outlen)?)
        };
        let mut after_trig = || -> anyhow::Result<()> {
            crate::wide_search(&cmdif, true)?;
            if let Some(p) = &dump_raw {
                crate::wide_dump(&cmdif, p)?;
            }
            Ok(())
        };
        let v = rd2_run(args.tt, created_id, &mut exec, &mut after_trig)?;
        println!(
            "[s2trig] rd2 summary: neg_ok={} neg_marker_absent={} trig_err={} followup_err={} destroy_err={} readback_ok={}",
            rd2_neg_ok,
            rd2_neg_marker_absent,
            v.trig_err,
            v.followup_err,
            v.destroy_err,
            v.readback_ok
        );
        return Ok(());
    }

    let query_created = match &payload {
        Some(p) => build_query_payload(args.tt, created_id, p),
        None => build_query(args.tt, created_id),
    };
    let (out, err) = cmdif.try_exec_command(&query_created, QUERY_OUTLEN)?;
    log_command("query(created)", &query_created, &out, err, None);
    if let Some(p) = &payload {
        log_verdict("query(created)", &out, p);
    }

    let destroy = build_destroy(args.tt, created_id);
    let (out, err) = cmdif.try_exec_command(&destroy, DESTROY_OUTLEN)?;
    log_command("destroy", &destroy, &out, err, None);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(rows: &[&str]) -> String {
        rows.concat()
    }

    #[test]
    fn build_query_golden_zero() {
        assert_eq!(
            to_hex(&build_query(0, 0)),
            golden(&[
                "09320000000000000000000000000000",
                "0000000000000000",
            ])
        );
    }

    #[test]
    fn build_query_golden_tt1_id0x2a() {
        assert_eq!(
            to_hex(&build_query(1, 0x2a)),
            golden(&[
                "09320000000000000000000000000000",
                "010000000000002a",
            ])
        );
    }

    #[test]
    fn build_query_masks_table_id_to_24_bits() {
        assert_eq!(
            to_hex(&build_query(0, 0xff123456)),
            golden(&[
                "09320000000000000000000000000000",
                "0000000000123456",
            ])
        );
    }

    #[test]
    fn build_create_golden_tt0_log4() {
        assert_eq!(
            to_hex(&build_create(0, 4)),
            golden(&[
                "09300000000000000000000000000000",
                "00000000000000000000000400000000",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
            ])
        );
    }

    #[test]
    fn build_create_golden_tt1_log6() {
        assert_eq!(
            to_hex(&build_create(1, 6)),
            golden(&[
                "09300000000000000000000000000000",
                "01000000000000000000000600000000",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
            ])
        );
    }

    #[test]
    fn build_destroy_golden_tt0_id0x2a() {
        assert_eq!(
            to_hex(&build_destroy(0, 0x2a)),
            golden(&[
                "09310000000000000000000000000000",
                "000000000000002a0000000000000000",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
            ])
        );
    }

    #[test]
    fn build_destroy_golden_tt1_id0() {
        assert_eq!(
            to_hex(&build_destroy(1, 0)),
            golden(&[
                "09310000000000000000000000000000",
                "01000000000000000000000000000000",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
            ])
        );
    }

    #[test]
    fn parse_status_ok() {
        let out = [0x00, 0, 0, 0, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_status(&out), (0, 0x0000_0000));
    }

    #[test]
    fn parse_status_bad_param() {
        let out = [0x03, 0, 0, 0, 0x00, 0x1c, 0x2b, 0x78];
        assert_eq!(parse_status(&out), (3, 0x001C_2B78));
    }

    #[test]
    fn parse_table_id_zero() {
        let out = [0u8; 0x10];
        assert_eq!(parse_table_id(&out), 0);
    }

    #[test]
    fn parse_table_id_0x2a() {
        let mut out = [0u8; 0x10];
        out[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x2a]);
        assert_eq!(parse_table_id(&out), 0x2a);
    }

    #[test]
    fn parse_table_id_masks_to_24_bits() {
        let mut out = [0u8; 0x10];
        out[8..12].copy_from_slice(&[0xff, 0x00, 0x00, 0x2a]);
        assert_eq!(parse_table_id(&out), 0x2a);
    }

    #[test]
    fn build_query_payload_golden() {
        let payload = std::array::from_fn::<u8, 0x28, _>(|i| (i + 1) as u8);
        let q = build_query_payload(0, 0, &payload);
        assert_eq!(q.len(), 0x40);
        assert_eq!(&q[..0x18], &build_query(0, 0)[..]);
        assert_eq!(&q[0x18..0x40], &payload[..]);

        let q2 = build_query_payload(1, 0x2a, &payload);
        assert_eq!(&q2[..0x18], &build_query(1, 0x2a)[..]);
        assert_eq!(&q2[0x18..0x40], &payload[..]);
        assert_eq!(
            to_hex(&q2),
            golden(&[
                "09320000000000000000000000000000",
                "010000000000002a0102030405060708",
                "090a0b0c0d0e0f101112131415161718",
                "191a1b1c1d1e1f202122232425262728",
            ])
        );
    }

    #[test]
    fn verify_echo_true() {
        let payload: Vec<u8> = (0..0x28).map(|i| (i * 7 + 3) as u8).collect();
        let mut out = vec![0u8; 0x40];
        out[0x10..0x38].copy_from_slice(&payload);
        assert!(verify_echo(&out, &payload));
    }

    #[test]
    fn verify_echo_false_off_by_one() {
        let payload: Vec<u8> = (0..0x28).map(|i| (i * 7 + 3) as u8).collect();
        let mut out = vec![0u8; 0x40];
        out[0x11..0x39].copy_from_slice(&payload);
        assert!(!verify_echo(&out, &payload));
        assert!(!verify_echo(&out[..0x37], &payload));
        assert!(!verify_echo(&out, &payload[..0x27]));
    }

    #[test]
    fn verify_echo_8b_boundary() {
        let payload: Vec<u8> = (0..0x28)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect();
        let mut out = vec![0u8; 0x40];
        out[0x10..0x38].copy_from_slice(&payload);
        assert!(verify_echo(&out, &payload));

        let mut flipped = out.clone();
        let mut word: [u8; 8] = flipped[0x10..0x18].try_into().unwrap();
        word.reverse();
        flipped[0x10..0x18].copy_from_slice(&word);
        assert!(!verify_echo(&flipped, &payload));

        let mut bitflip = out;
        bitflip[0x10 + 3] ^= 0x01;
        assert!(!verify_echo(&bitflip, &payload));
    }

    #[test]
    fn canary_present() {
        let mut out = vec![0u8; 0x40];
        out[0x3a] = 0x6f;
        out[0x3b] = 0x28;
        assert!(canary_6f28(&out));
    }

    #[test]
    fn canary_absent() {
        assert!(!canary_6f28(&vec![0u8; 0x40]));
        let mut out = vec![0u8; 0x40];
        out[0x3a] = 0x6f;
        out[0x3b] = 0x29;
        assert!(!canary_6f28(&out));
        assert!(!canary_6f28(&[0u8; 0x3b]));
    }

    #[test]
    fn kb_loss_counting() {
        let seq = vec![
            KbResult {
                err: 0,
                status: 0,
                echo_ok: true,
            },
            KbResult {
                err: 1,
                status: 0,
                echo_ok: true,
            },
            KbResult {
                err: 0,
                status: 3,
                echo_ok: true,
            },
            KbResult {
                err: 0,
                status: 0,
                echo_ok: false,
            },
            KbResult {
                err: 0,
                status: 0,
                echo_ok: true,
            },
        ];
        let (ok, losses) = kb_tally(&seq);
        assert_eq!(ok, 2);
        assert_eq!(losses, 3);
        assert_eq!(kb_tally(&[]), (0, 0));
    }

    #[test]
    fn kb_payload_pattern_matches_formula_and_nonzero() {
        for i in [0usize, 1, 5, 26, 1000] {
            let p = kb_payload(i);
            for (j, &b) in p.iter().enumerate() {
                assert_eq!(b, ((i * 0x28 + j) % 251 + 1) as u8);
                assert_ne!(b, 0);
            }
        }
    }

    #[test]
    fn parse_payload_hex_rejects_non_ascii_80b() {
        let s = format!("ab{}", "日".repeat(26));
        let r = parse_payload_hex(&s);
        assert!(r.is_err());
    }

    #[test]
    fn kb_run_destroy_on_mid_loop_error() {
        let mut destroy_calls = 0usize;
        let mut exec = |frame: &[u8], _outlen: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x31)) => {
                    destroy_calls += 1;
                    Ok((vec![0u8; 0x10], 0))
                }
                (Some(&0x09), Some(&0x32)) => Err(anyhow::anyhow!("kb transport fail")),
                _ => unreachable!(),
            }
        };
        let r = kb_run(5, 5, 0x2a, &mut exec);
        assert!(r.is_err() && destroy_calls == 1);
    }

    #[test]
    fn kb_run_err_carries_original_message() {
        let mut destroy_calls = 0usize;
        let mut queries = 0usize;
        let mut exec = |frame: &[u8], _outlen: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x31)) => {
                    destroy_calls += 1;
                    Ok((vec![0u8; 0x10], 0))
                }
                (Some(&0x09), Some(&0x32)) => {
                    queries += 1;
                    if queries == 3 {
                        Err(anyhow::anyhow!("kb transport fail"))
                    } else {
                        Ok((vec![0u8; 0x40], 0))
                    }
                }
                _ => unreachable!(),
            }
        };
        let r = kb_run(5, 5, 0x2a, &mut exec);
        assert!(r.is_err());
        assert_eq!(destroy_calls, 1);
        assert_eq!(queries, 3);
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("kb transport fail"), "unexpected error: {}", msg);
    }

    #[test]
    fn ensure_kb_clean_zero_ok_losses_err() {
        assert!(ensure_kb_clean(0).is_ok());
        assert!(ensure_kb_clean(3).is_err());
    }

    #[test]
    fn payload_hex_requires_exactly_80_hex_chars() {
        let good = parse_payload_hex(&"ab".repeat(40)).expect("80 hex chars must parse");
        assert_eq!(good.len(), 0x28);
        assert_eq!(good[0], 0xab);
        assert!(parse_payload_hex(&"ab".repeat(39)).is_err());
        assert!(parse_payload_hex(&"ab".repeat(41)).is_err());
        assert!(parse_payload_hex(&"zz".repeat(40)).is_err());
    }

    // ---------- rd2-trig mode (R-D2 live verdict) ----------

    #[test]
    fn build_query_rd2_trig_golden_zero() {
        assert_eq!(
            to_hex(&build_query_rd2_trig(0, 0)),
            golden(&[
                "0932000000000000",
                "0000000000000000",
                "00000000",
                "00000000",
                "55aa",
                "258c53326c04638afd001825",
                "0000000000000000000000000000000000000000000000000000",
            ])
        );
    }

    #[test]
    fn build_query_rd2_trig_golden_tt1_id0x2a() {
        let f = build_query_rd2_trig(1, 0x2a);
        assert_eq!(f.len(), RD2_TRIG_LEN);
        assert_eq!(RD2_TRIG_LEN, 0x40);
        assert_eq!(&f[..0x18], &build_query(1, 0x2a)[..]);
        assert_eq!(f[0x12..0x14], [0u8, 0]);
        assert_eq!(&f[0x14..0x18], &[0x00, 0x00, 0x00, 0x2a]);
        assert_eq!(&f[0x18..0x1a], &[0x55, 0xaa]);
        assert_eq!(&f[0x1a..0x26], &rd2_marker_bytes());
        assert!(f[0x26..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_query_rd2_trig_marker_clear_of_magic_halfword() {
        let f = build_query_rd2_trig(0, 0);
        assert_eq!(&f[0x18..0x1a], &[0x55, 0xaa]);
        assert_eq!(&f[0x1a..0x26], &rd2_marker_bytes());
        let m = rd2_marker_bytes();
        assert!(!m.windows(2).any(|w| w == [0x55, 0xaa]));
    }

    #[test]
    fn build_query_rd2_trig_masks_table_id_to_24_bits() {
        let f = build_query_rd2_trig(0, 0xff123456);
        assert_eq!(&f[0x14..0x18], &[0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn rd2_neg_out_ok_byte_exact_vs_stock_golden() {
        let mut g = vec![0u8; 0x40];
        g[0] = 0x03;
        g[5] = 0x1c;
        g[6] = 0x2b;
        g[7] = 0x78;
        assert!(rd2_neg_out_ok(&g));
        let mut dirty_tail = g.clone();
        dirty_tail[0x20] = 0x01;
        assert!(!rd2_neg_out_ok(&dirty_tail));
        let mut bad_syndrome = g.clone();
        bad_syndrome[6] = 0x2c;
        assert!(!rd2_neg_out_ok(&bad_syndrome));
        let mut ok_status = g.clone();
        ok_status[0] = 0x00;
        assert!(!rd2_neg_out_ok(&ok_status));
        assert!(!rd2_neg_out_ok(&g[..0x30]));
    }

    #[test]
    fn rd2_readback_byte_is_marker_word0_bits_15_8() {
        assert_eq!(rd2_readback_byte(), 0x53);
        assert_eq!(
            rd2_readback_byte() as u32,
            (crate::scan::MARKER[0] >> 8) & 0xff
        );
    }

    #[test]
    fn rd2_readback_ok_requires_marker_byte_at_0x1b() {
        let mut out = vec![0u8; 0x40];
        out[0x1b] = 0x53;
        assert!(rd2_readback_ok(&out));
        out[0x1b] = 0x04;
        assert!(!rd2_readback_ok(&out));
        assert!(!rd2_readback_ok(&out[..0x1c]));
    }

    #[test]
    fn rd2_marker_absent_checks_all_window_positions() {
        let m = rd2_marker_bytes();
        let mut out = vec![0u8; 0x40];
        assert!(rd2_marker_absent(&out));
        out[0x0a..0x16].copy_from_slice(&m);
        assert!(!rd2_marker_absent(&out));
        assert!(rd2_marker_absent(&out[..0x0a]));
    }

    #[test]
    fn rd2_run_orchestration_order_and_outlens() {
        let mut calls: Vec<(Vec<u8>, u32)> = Vec::new();
        let mut after_trig_calls = 0usize;
        let mut exec = |frame: &[u8], outlen: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            calls.push((frame.to_vec(), outlen));
            Ok((vec![0u8; 0x40], 0))
        };
        let mut after_trig = || -> anyhow::Result<()> {
            after_trig_calls += 1;
            Ok(())
        };
        let v = rd2_run(1, 0x2a, &mut exec, &mut after_trig).unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, build_query_rd2_trig(1, 0x2a));
        assert_eq!(calls[0].1, QUERY_OUTLEN);
        assert_eq!(calls[1].0, build_query(1, 0x2a));
        assert_eq!(calls[1].1, QUERY_OUTLEN);
        assert_eq!(calls[2].0, build_destroy(1, 0x2a));
        assert_eq!(calls[2].1, DESTROY_OUTLEN);
        assert_eq!(after_trig_calls, 1);
        assert_eq!(v.destroy_err, 0);
    }

    #[test]
    fn rd2_run_readback_verdict_from_followup_out() {
        let mut followup_out = vec![0u8; 0x40];
        followup_out[0x1b] = 0x53;
        let mut seq = 0usize;
        let mut exec = |frame: &[u8], _o: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            seq += 1;
            match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x32)) if seq == 2 => Ok((followup_out.clone(), 0)),
                (Some(&0x09), Some(&0x32)) => Ok((vec![0u8; 0x40], 0)),
                (Some(&0x09), Some(&0x31)) => Ok((vec![0u8; 0x10], 0)),
                _ => unreachable!(),
            }
        };
        let mut after_trig = || -> anyhow::Result<()> { Ok(()) };
        let v = rd2_run(0, 7, &mut exec, &mut after_trig).unwrap();
        assert!(v.readback_ok);
        assert_eq!(v.trig_err, 0);
        assert_eq!(v.followup_err, 0);
        assert_eq!(v.destroy_err, 0);
    }

    #[test]
    fn rd2_run_verdicts_record_fw_err_flags() {
        let mut seq = 0usize;
        let mut exec = |_frame: &[u8], _o: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            seq += 1;
            Ok((vec![0u8; 0x40], if seq == 1 { 3 } else { 0 }))
        };
        let mut after_trig = || -> anyhow::Result<()> { Ok(()) };
        let v = rd2_run(0, 0, &mut exec, &mut after_trig).unwrap();
        assert_eq!(v.trig_err, 3);
        assert_eq!(v.followup_err, 0);
        assert_eq!(v.destroy_err, 0);
        assert!(!v.readback_ok);
    }

    #[test]
    fn rd2_run_destroy_on_trig_transport_error() {
        let mut destroy_calls = 0usize;
        let mut exec = |frame: &[u8], _o: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x31)) => {
                    destroy_calls += 1;
                    Ok((vec![0u8; 0x10], 0))
                }
                (Some(&0x09), Some(&0x32)) => Err(anyhow::anyhow!("rd2 transport fail")),
                _ => unreachable!(),
            }
        };
        let mut after_trig = || -> anyhow::Result<()> { Ok(()) };
        let r = rd2_run(0, 0x2a, &mut exec, &mut after_trig);
        assert!(r.is_err() && destroy_calls == 1);
    }

    #[test]
    fn rd2_run_destroy_on_followup_transport_error() {
        let mut destroy_calls = 0usize;
        let mut queries = 0usize;
        let mut exec = |frame: &[u8], _o: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x31)) => {
                    destroy_calls += 1;
                    Ok((vec![0u8; 0x10], 0))
                }
                (Some(&0x09), Some(&0x32)) => {
                    queries += 1;
                    if queries == 2 {
                        Err(anyhow::anyhow!("rd2 followup transport fail"))
                    } else {
                        Ok((vec![0u8; 0x40], 0))
                    }
                }
                _ => unreachable!(),
            }
        };
        let mut after_trig = || -> anyhow::Result<()> { Ok(()) };
        let r = rd2_run(0, 0x2a, &mut exec, &mut after_trig);
        assert!(r.is_err());
        assert_eq!(destroy_calls, 1);
        assert_eq!(queries, 2);
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("rd2 followup transport fail"));
    }

    #[test]
    fn rd2_run_destroy_on_after_trig_error() {
        let mut destroy_calls = 0usize;
        let mut exec = |frame: &[u8], _o: u32| -> anyhow::Result<(Vec<u8>, u8)> {
            match (frame.first(), frame.get(1)) {
                (Some(&0x09), Some(&0x31)) => {
                    destroy_calls += 1;
                    Ok((vec![0u8; 0x10], 0))
                }
                _ => Ok((vec![0u8; 0x40], 0)),
            }
        };
        let mut after_trig = || -> anyhow::Result<()> { Err(anyhow::anyhow!("wide dump io fail")) };
        let r = rd2_run(0, 0x2a, &mut exec, &mut after_trig);
        assert!(r.is_err() && destroy_calls == 1);
    }

    #[test]
    fn cli_rd2_trig_parses_with_optional_dump_raw() {
        use clap::Parser;
        let c = crate::CliArgs::try_parse_from(["mlxscope", "flowtable", "--rd2-trig"])
            .unwrap();
        let crate::Command::Flowtable(a) = c.command.expect("subcommand") else {
            panic!("flowtable");
        };
        assert!(a.rd2_trig);
        assert!(a.rd2_dump_raw.is_none());
        let c2 = crate::CliArgs::try_parse_from([
            "mlxscope",
            "flowtable",
            "--rd2-trig",
            "--rd2-dump-raw",
            "/tmp/x.raw",
        ])
        .unwrap();
        let crate::Command::Flowtable(a2) = c2.command.expect("subcommand") else {
            panic!("flowtable");
        };
        assert!(a2.rd2_trig);
        assert_eq!(a2.rd2_dump_raw, Some(std::path::PathBuf::from("/tmp/x.raw")));
    }

    #[test]
    fn validate_flowtable_args_mode_exclusions() {
        assert!(validate_flowtable_args(false, None, false, false).is_ok());
        assert!(validate_flowtable_args(true, None, false, false).is_ok());
        assert!(validate_flowtable_args(false, Some(30), false, false).is_ok());
        assert!(validate_flowtable_args(false, None, true, false).is_ok());
        assert!(validate_flowtable_args(false, None, true, true).is_ok());
        assert!(validate_flowtable_args(true, Some(30), false, false).is_err());
        assert!(validate_flowtable_args(true, None, true, false).is_err());
        assert!(validate_flowtable_args(false, Some(30), true, false).is_err());
        assert!(validate_flowtable_args(false, None, false, true).is_err());
    }
}
