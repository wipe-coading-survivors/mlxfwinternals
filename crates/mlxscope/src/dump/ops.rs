//! Pure dump-cycle logic: addr validation, seed/clear word plans, the
//! generic exec cycle (seed + readback-verify + poll with an injectable
//! reader), and the `read` output (de)serializer. No device IO here —
//! callers inject closures over the CR window.

use std::time::Duration;

use anyhow::{bail, ensure};

use super::{LAYOUT, Profile};

/// MTRC_CAP register id used as the dump trigger (ICMD GET, the same CAP
/// read `trace arm`/`status` perform).
pub const REG_MTRC_CAP: u16 = 0x9040;
/// MTRC_CAP GET register data length (matches trace status; reg_access_hca).
pub const MTRC_CAP_GET_LEN: usize = 0x84;

pub const RUN_POLL_TIMEOUT: Duration = Duration::from_secs(2);
pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Fixed word count of the CX-5 1-word dump: N=1 at W_PLD (Task 1
/// SEED_LAYOUT — host-side layout compatibility; the B-form stub reads
/// only 0x8c5/0x8c6).
pub const DUMP_N: u32 = 1;

/// Last payload word p9 == last WRITABLE word (write guard upper bound).
pub const W_PLD_LAST: u32 = LAYOUT::W_PLD + LAYOUT::PLD_MAX as u32 - 1;
/// Last response data word d5 (response zone end).
pub const W_D_LAST: u32 = LAYOUT::W_RESP + LAYOUT::RESP_WORDS as u32 - 1;
/// Last observable word (== last payload word).
pub const OBS_LAST: u32 = W_PLD_LAST;
/// Words printed by `read` (0x8c5..=0x8d0).
pub const OBS_WORDS: usize = (OBS_LAST - LAYOUT::W_MAGIC + 1) as usize;

pub const MAX_ADDR: u32 = 0xFFFF_FFFC;

/// CLI/seed guard: a real, 4-byte-aligned RAM address that a 6-word read
/// window still fits under.
pub fn validate_addr(addr: u32) -> anyhow::Result<u32> {
    if addr == 0 {
        bail!("dump: --addr 0 is invalid (a real RAM address is required)");
    }
    if addr % 4 != 0 {
        bail!("dump: addr 0x{addr:08x} is not 4-byte aligned");
    }
    if addr > MAX_ADDR {
        bail!("dump: addr 0x{addr:08x} > 0x{MAX_ADDR:08x}");
    }
    Ok(addr)
}

/// Seed the addr-dump request: magic at W_MAGIC, addr at W_COUNT (word
/// 0x8c6 carries N in the generic-exec layout; the payload zone from
/// 0x8c7 is not written here).
pub fn seed<W>(mut write: W, addr: u32, magic: u32) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    let addr = validate_addr(addr)?;
    write(LAYOUT::W_MAGIC, magic)?;
    write(LAYOUT::W_COUNT, addr)?;
    Ok(())
}

/// Seed the CX-5 addr-dump request (Task 1 SEED_LAYOUT): magic at
/// W_MAGIC, addr-dc at W_COUNT, N = DUMP_N at W_PLD. Address guards run
/// before the first write (same contract as `seed`).
pub fn seed_cx5<W>(mut write: W, addr: u32, magic: u32) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    let addr = validate_addr(addr)?;
    write(LAYOUT::W_MAGIC, magic)?;
    write(LAYOUT::W_COUNT, addr)?;
    write(LAYOUT::W_PLD, DUMP_N)?;
    Ok(())
}

/// Seed the generic exec request: magic at W_MAGIC, N = words.len() at
/// W_COUNT, payload words at W_PLD..  Guards (1..=profile.pld_max()) run
/// before the first write.
pub fn exec_seed<W>(mut write: W, words: &[u32], profile: Profile) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    ensure!(!words.is_empty(), "exec: empty payload");
    ensure!(
        words.len() <= profile.pld_max(),
        "exec: {} payload words > profile {:?} max {}",
        words.len(),
        profile,
        profile.pld_max()
    );
    write(LAYOUT::W_MAGIC, LAYOUT::MAGIC)?;
    write(LAYOUT::W_COUNT, words.len() as u32)?;
    for (i, w) in words.iter().enumerate() {
        write(LAYOUT::W_PLD + i as u32, *w)?;
    }
    Ok(())
}

/// Readback-verify a seeded exec request (magic + N + payload words).
/// Runs BEFORE the trigger so a filtered write never reaches the stub.
pub fn exec_verify<R>(words: &[u32], mut read: R) -> anyhow::Result<()>
where
    R: FnMut(u32) -> anyhow::Result<u32>,
{
    let magic = read(LAYOUT::W_MAGIC)?;
    ensure!(
        magic == LAYOUT::MAGIC,
        "exec: readback magic 0x{magic:08x} != 0x{:08x} (write filtered?)",
        LAYOUT::MAGIC
    );
    let n = read(LAYOUT::W_COUNT)?;
    ensure!(
        n == words.len() as u32,
        "exec: readback N 0x{n:08x} != {}",
        words.len()
    );
    for (i, w) in words.iter().enumerate() {
        let got = read(LAYOUT::W_PLD + i as u32)?;
        ensure!(
            got == *w,
            "exec: readback word 0x{:04x} = 0x{got:08x} != 0x{w:08x} (write filtered?)",
            LAYOUT::W_PLD + i as u32
        );
    }
    Ok(())
}

/// Generic exec cycle over injected IO (the CLI wires real device access):
/// clear-response, seed, readback-verify (an error here precedes `fire` —
/// the trigger is never sent on a bad seed), trigger, poll `expect` at
/// W_RESP, read back the observable zone. Returns (poll attempts, view).
pub fn exec_cycle<PW, PR, F, QR, S>(
    words: &[u32],
    expect: u32,
    profile: Profile,
    mut pre_write: PW,
    mut pre_read: PR,
    fire: F,
    mut post_read: QR,
    sleep: S,
) -> anyhow::Result<(usize, ReadView)>
where
    PW: FnMut(u32, u32) -> anyhow::Result<()>,
    PR: FnMut(u32) -> anyhow::Result<u32>,
    F: FnOnce() -> anyhow::Result<()>,
    QR: FnMut(u32) -> anyhow::Result<u32>,
    S: FnMut(Duration),
{
    clear_response(|word, v| pre_write(word, v), profile)?;
    exec_seed(|word, v| pre_write(word, v), words, profile)?;
    exec_verify(words, |word| pre_read(word))?;
    fire()?;
    let attempts = poll_ready(
        RUN_POLL_TIMEOUT,
        POLL_INTERVAL,
        expect,
        || post_read(LAYOUT::W_RESP),
        sleep,
    )?;
    let view = read_view(|word| post_read(word))?;
    Ok((attempts, view))
}

/// CX-5 full dump cycle over injected IO (the CLI wires the VSEC window
/// and the ICMD trigger; tests wire fakes — the `exec_cycle` precedent):
/// pre-clear the answer zone, seed magic+addr+N=1, fire the trigger,
/// poll the answer slot out of its pre-cleared 0. No arm step — Task 2
/// live verdict: armed == unarmed byte-identical. Returns (poll
/// attempts, answer word); timeout/interval are parameters so the
/// timeout path is testable on short durations.
pub fn run_cycle_cx5<W, F, R, S>(
    addr: u32,
    magic: u32,
    timeout: Duration,
    interval: Duration,
    mut write: W,
    fire: F,
    read_resp: R,
    sleep: S,
) -> anyhow::Result<(usize, u32)>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
    F: FnOnce() -> anyhow::Result<()>,
    R: FnMut() -> anyhow::Result<u32>,
    S: FnMut(Duration),
{
    clear_response(|word, v| write(word, v), Profile::Cx5)?;
    seed_cx5(|word, v| write(word, v), addr, magic)?;
    fire()?;
    poll_answer(timeout, interval, read_resp, sleep)
}

/// Zero the response zone + stale payload tail: W_RESP..=profile.w_last()
/// (nothing past the profile bound may survive into the next cycle's
/// readback-verify; on cx5 the bound is 0x8cf — 0x8d0 is never written).
pub fn clear_response<W>(mut write: W, profile: Profile) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    for word in LAYOUT::W_RESP..=profile.w_last() {
        write(word, 0)?;
    }
    Ok(())
}

/// Zero everything writable: request + payload zone (lx: 0x8c5..=0x8d0;
/// cx5: 0x8c5..=0x8cf — 0x8d0/0x8d4 excluded).
pub fn clear_all<W>(mut write: W, profile: Profile) -> anyhow::Result<()>
where
    W: FnMut(u32, u32) -> anyhow::Result<()>,
{
    for word in LAYOUT::W_MAGIC..=profile.w_last() {
        write(word, 0)?;
    }
    Ok(())
}

/// One `read` observation of the full observable zone 0x8c5..=0x8d0:
/// magic, N, payload words p0..p9. After a trigger the response zone
/// (ready + d0..d5, W_RESP..=W_D_LAST) overlays p1..p7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadView {
    pub magic: u32,
    pub n: u32,
    pub pld: [u32; LAYOUT::PLD_MAX],
}

pub const READ_LABELS: [&str; OBS_WORDS] = [
    "magic", "n", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9",
];

impl ReadView {
    pub fn from_words(words: [u32; OBS_WORDS]) -> Self {
        Self {
            magic: words[0],
            n: words[1],
            pld: words[2..].try_into().unwrap(),
        }
    }

    pub fn to_words(self) -> [u32; OBS_WORDS] {
        let mut w = [0u32; OBS_WORDS];
        w[0] = self.magic;
        w[1] = self.n;
        w[2..].copy_from_slice(&self.pld);
        w
    }

    /// READY word (the response zone start overlays W_RESP == p1).
    pub fn ready(&self) -> u32 {
        self.pld[(LAYOUT::W_RESP - LAYOUT::W_PLD) as usize]
    }

    /// Response data words d0..d5 (W_RESP+1..=W_D_LAST == p2..p7).
    pub fn resp_data(&self) -> [u32; LAYOUT::RESP_WORDS - 1] {
        let off = (LAYOUT::W_RESP + 1 - LAYOUT::W_PLD) as usize;
        let end = (W_D_LAST - LAYOUT::W_PLD + 1) as usize;
        let mut d = [0u32; LAYOUT::RESP_WORDS - 1];
        d.copy_from_slice(&self.pld[off..end]);
        d
    }
}

/// Read the 12 observable words (0x8c5..=0x8d0) through `read(word)`.
pub fn read_view<R>(mut read: R) -> anyhow::Result<ReadView>
where
    R: FnMut(u32) -> anyhow::Result<u32>,
{
    let mut words = [0u32; OBS_WORDS];
    for (i, w) in words.iter_mut().enumerate() {
        *w = read(LAYOUT::W_MAGIC + i as u32)?;
    }
    Ok(ReadView::from_words(words))
}

/// `read` output: one line per observable word —
/// `[dump-read] 0x08c5 magic 0x44554d31`.
pub fn format_read(v: &ReadView) -> String {
    let mut out = String::new();
    for (i, word) in v.to_words().iter().enumerate() {
        out.push_str(&format!(
            "[dump-read] 0x{:04x} {:<5} 0x{:08x}\n",
            LAYOUT::W_MAGIC + i as u32,
            READ_LABELS[i],
            word
        ));
    }
    out
}

/// Hex u32 with or without a 0x/0X prefix (CLI `--words` tokens).
pub fn parse_hex_u32(s: &str) -> anyhow::Result<u32> {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    Ok(u32::from_str_radix(t, 16)?)
}

/// Parse the 12-line `read` output back into a ReadView (strict: word
/// addresses, labels and line count must match). Consumer of the output
/// contract for scripts/tests — not called by the binary itself.
#[allow(dead_code)]
pub fn parse_read(text: &str) -> anyhow::Result<ReadView> {
    let mut words = [0u32; OBS_WORDS];
    let mut n = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        anyhow::ensure!(n < OBS_WORDS, "parse_read: more than {OBS_WORDS} lines");
        let fields: Vec<&str> = line.split_whitespace().collect();
        anyhow::ensure!(
            fields.len() == 4 && fields[0] == "[dump-read]",
            "parse_read: malformed line {line:?}"
        );
        let word = parse_hex_u32(fields[1])?;
        anyhow::ensure!(
            word == LAYOUT::W_MAGIC + n as u32,
            "parse_read: line {} has word 0x{word:04x}, expected 0x{:04x}",
            n + 1,
            LAYOUT::W_MAGIC + n as u32
        );
        anyhow::ensure!(
            fields[2] == READ_LABELS[n],
            "parse_read: line {} label mismatch",
            n + 1
        );
        words[n] = parse_hex_u32(fields[3])?;
        n += 1;
    }
    anyhow::ensure!(n == OBS_WORDS, "parse_read: got {n} words, expected {OBS_WORDS}");
    Ok(ReadView::from_words(words))
}

/// Poll W_RESP until it equals `expect` (the stub's READY marker echoes
/// MAGIC by default; P2/P3-class responses may echo their own value).
/// Returns the number of attempts taken. `sleep` is injected for tests.
pub fn poll_ready<R, S>(
    timeout: Duration,
    interval: Duration,
    expect: u32,
    mut read_resp: R,
    mut sleep: S,
) -> anyhow::Result<usize>
where
    R: FnMut() -> anyhow::Result<u32>,
    S: FnMut(Duration),
{
    let start = std::time::Instant::now();
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let v = read_resp()?;
        if v == expect {
            return Ok(attempts);
        }
        if start.elapsed() >= timeout {
            bail!(
                "poll: READY@0x{:04x} != 0x{expect:08x}: last 0x{v:08x} after {attempts} attempt(s) ({timeout:?})",
                LAYOUT::W_RESP
            );
        }
        sleep(interval);
    }
}

/// Poll W_RESP until it leaves its pre-cleared 0 — the CX-5 answer
/// protocol: the B-form stub (Task 1) stores the dumped word itself at
/// 0x8c8, no MAGIC echo, so "answered" == "slot != 0". Returns (poll
/// attempts, the answer word). NB: a RAM word that reads 0 is
/// indistinguishable from no answer and surfaces as the timeout error
/// (GT words of the dump targets are nonzero). `sleep` is injected for
/// tests.
pub fn poll_answer<R, S>(
    timeout: Duration,
    interval: Duration,
    mut read_resp: R,
    mut sleep: S,
) -> anyhow::Result<(usize, u32)>
where
    R: FnMut() -> anyhow::Result<u32>,
    S: FnMut(Duration),
{
    let start = std::time::Instant::now();
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let v = read_resp()?;
        if v != 0 {
            return Ok((attempts, v));
        }
        if start.elapsed() >= timeout {
            bail!(
                "poll: answer@0x{:04x} still 0x{v:08x} after {attempts} attempt(s) ({timeout:?}) — stub did not answer or the RAM word is 0",
                LAYOUT::W_RESP
            );
        }
        sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn layout_constants_verbatim() {
        assert_eq!(LAYOUT::MAGIC, 0x44554D31);
        assert_eq!(LAYOUT::W_MAGIC, 0x8c5);
        assert_eq!(LAYOUT::W_COUNT, 0x8c6);
        assert_eq!(LAYOUT::W_PLD, 0x8c7);
        assert_eq!(LAYOUT::PLD_MAX, 10);
        assert_eq!(LAYOUT::W_RESP, 0x8c8);
        assert_eq!(LAYOUT::RESP_WORDS, 7);
    }

    #[test]
    fn derived_word_math() {
        assert_eq!(
            LAYOUT::W_COUNT + 1,
            LAYOUT::W_PLD,
            "payload zone starts right after N"
        );
        assert_eq!(LAYOUT::W_RESP + 1, 0x8c9, "d0");
        assert_eq!(W_D_LAST, 0x8ce, "d5 / last response word");
        assert_eq!(W_PLD_LAST, 0x8d0, "p9 / last writable");
        assert_eq!(OBS_LAST, W_PLD_LAST, "last observable == last payload word");
        assert_eq!(OBS_WORDS, 12);
        assert_eq!(OBS_WORDS, 2 + LAYOUT::PLD_MAX);
        assert!(
            LAYOUT::W_RESP >= LAYOUT::W_PLD && LAYOUT::W_RESP <= W_PLD_LAST,
            "response zone overlays the payload zone"
        );
        assert_eq!(W_D_LAST - LAYOUT::W_RESP + 1, LAYOUT::RESP_WORDS as u32);
    }

    #[test]
    fn validate_addr_rejects_misaligned() {
        for bad in [0xB19852u32, 0x8c7, 0xFFFF_FFFF, 2] {
            assert!(validate_addr(bad).is_err(), "0x{bad:08x} must be rejected");
        }
    }

    #[test]
    fn validate_addr_rejects_zero() {
        assert!(validate_addr(0).is_err(), "addr 0 must be rejected");
    }

    #[test]
    fn validate_addr_rejects_above_max() {
        for bad in [0xFFFF_FFFDu32, 0xFFFF_FFFE, 0xFFFF_FFFF] {
            assert!(validate_addr(bad).is_err(), "0x{bad:08x} > 0xFFFFFFFC");
        }
    }

    #[test]
    fn validate_addr_accepts_valid_range() {
        assert_eq!(validate_addr(4).unwrap(), 4);
        assert_eq!(validate_addr(0x2314).unwrap(), 0x2314);
        assert_eq!(validate_addr(0xB19850).unwrap(), 0xB19850);
        assert_eq!(validate_addr(0xFFFF_FFFC).unwrap(), 0xFFFF_FFFC);
    }

    #[test]
    fn seed_writes_magic_then_addr() {
        let mut w = Vec::new();
        seed(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            0xB19850,
            LAYOUT::MAGIC,
        )
        .unwrap();
        assert_eq!(w, vec![(0x8c5, LAYOUT::MAGIC), (0x8c6, 0xB19850)]);
    }

    #[test]
    fn seed_cx5_writes_magic_addr_n() {
        let mut w = Vec::new();
        seed_cx5(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            0x106390,
            LAYOUT::MAGIC,
        )
        .unwrap();
        assert_eq!(
            w,
            vec![
                (LAYOUT::W_MAGIC, LAYOUT::MAGIC),
                (LAYOUT::W_COUNT, 0x106390),
                (LAYOUT::W_PLD, 1),
            ],
            "Task 1 SEED_LAYOUT: magic / addr-dc / N=1"
        );
    }

    #[test]
    fn seed_cx5_rejects_bad_addr_without_writes() {
        let mut w = Vec::new();
        assert!(seed_cx5(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            0x8c7,
            LAYOUT::MAGIC
        )
        .is_err());
        assert!(w.is_empty(), "no write may happen for an invalid addr");
    }

    #[test]
    fn seed_rejects_bad_addr_without_writes() {
        let mut w = Vec::new();
        assert!(seed(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            0x8c7,
            LAYOUT::MAGIC
        )
        .is_err());
        assert!(w.is_empty(), "no write may happen for an invalid addr");
    }

    #[test]
    fn clear_response_zeros_words_8c8_8d0() {
        let mut w = Vec::new();
        clear_response(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            Profile::Lx,
        )
        .unwrap();
        let expect: Vec<(u32, u32)> = (0x8c8..=0x8d0).map(|x| (x, 0)).collect();
        assert_eq!(w, expect);
        assert!(w.contains(&(0x8cf, 0)), "payload tail 0x8cf must be cleared");
        assert!(w.contains(&(0x8d0, 0)), "payload tail 0x8d0 must be cleared");
    }

    #[test]
    fn clear_all_zeros_words_8c5_8d0() {
        let mut w = Vec::new();
        clear_all(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            Profile::Lx,
        )
        .unwrap();
        let expect: Vec<(u32, u32)> = (0x8c5..=0x8d0).map(|x| (x, 0)).collect();
        assert_eq!(w, expect);
        assert!(w.contains(&(0x8cf, 0)));
        assert!(w.contains(&(0x8d0, 0)));
    }

    #[test]
    fn cx5_clear_never_touches_8d0() {
        let mut resp = Vec::new();
        clear_response(
            |word, v| {
                resp.push((word, v));
                Ok(())
            },
            Profile::Cx5,
        )
        .unwrap();
        assert_eq!(
            resp,
            (0x8c8..=0x8cf).map(|x| (x, 0)).collect::<Vec<_>>(),
            "cx5 response clear stops at 0x8cf"
        );
        let mut all = Vec::new();
        clear_all(
            |word, v| {
                all.push((word, v));
                Ok(())
            },
            Profile::Cx5,
        )
        .unwrap();
        assert_eq!(
            all,
            (0x8c5..=0x8cf).map(|x| (x, 0)).collect::<Vec<_>>(),
            "cx5 clear-all stops at 0x8cf (0x8d0/0x8d4 forbidden)"
        );
        assert!(!all.iter().any(|&(w, _)| w == 0x8d0 || w == 0x8d4));
    }

    #[test]
    fn read_view_word_roundtrip() {
        let words: [u32; OBS_WORDS] = [
            0x44554D31, 3, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 0xdeadbeef,
        ];
        let v = ReadView::from_words(words);
        assert_eq!(v.magic, 0x44554D31);
        assert_eq!(v.n, 3);
        assert_eq!(
            v.pld,
            [0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 0xdeadbeef],
            "p0..p9 = words 0x8c7..0x8d0"
        );
        assert_eq!(v.ready(), 0xB, "ready overlays W_RESP == p1 (0x8c8)");
        assert_eq!(
            v.resp_data(),
            [0xC, 0xD, 0xE, 0xF, 1, 2],
            "d0..d5 overlay p2..p7 (0x8c9..0x8ce)"
        );
        assert_eq!(v.to_words(), words);
    }

    #[test]
    fn read_view_reads_observable_range_in_order() {
        let mut seen = Vec::new();
        let v = read_view(|word| {
            seen.push(word);
            Ok(word * 4)
        })
        .unwrap();
        let expect: Vec<u32> = (0x8c5..=0x8d0).collect();
        assert_eq!(seen, expect);
        assert_eq!(v.magic, 0x8c5 * 4);
        assert_eq!(v.n, 0x8c6 * 4);
        assert_eq!(v.pld[0], 0x8c7 * 4);
        assert_eq!(v.pld[9], 0x8d0 * 4);
    }

    #[test]
    fn format_parse_roundtrip() {
        let v = ReadView {
            magic: 0x44554D31,
            n: 2,
            pld: [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
                1, 2, 3, 4,
            ],
        };
        let text = format_read(&v);
        assert_eq!(text.lines().count(), OBS_WORDS);
        assert_eq!(text.lines().count(), 12);
        let back = parse_read(&text).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn format_read_first_line_shape() {
        let v = ReadView {
            magic: LAYOUT::MAGIC,
            n: 0,
            pld: [0; LAYOUT::PLD_MAX],
        };
        let text = format_read(&v);
        assert_eq!(
            text.lines().next().unwrap(),
            "[dump-read] 0x08c5 magic 0x44554d31"
        );
    }

    #[test]
    fn format_read_last_line_shape() {
        let v = ReadView {
            magic: 0,
            n: 0,
            pld: [0; LAYOUT::PLD_MAX],
        };
        let text = format_read(&v);
        assert_eq!(
            text.lines().last().unwrap(),
            "[dump-read] 0x08d0 p9    0x00000000"
        );
    }

    #[test]
    fn parse_read_rejects_wrong_word_count() {
        let text = "[dump-read] 0x8c5 magic 0x44554d31\n";
        assert!(parse_read(text).is_err(), "1 of 12 words must fail");
    }

    #[test]
    fn parse_read_rejects_wrong_word_addr() {
        let mut lines = Vec::new();
        for i in 0..OBS_WORDS {
            lines.push(format!(
                "[dump-read] 0x{:04x} {:<5} 0x{:08x}",
                0x8c5 + i as u32 + 1,
                READ_LABELS[i],
                0
            ));
        }
        assert!(parse_read(&lines.join("\n")).is_err());
    }

    #[test]
    fn parse_read_rejects_garbage() {
        assert!(parse_read("hello world").is_err());
        assert!(parse_read("[dump-read] 0x8c5 magic 0xzzzzzzzz").is_err());
        assert!(parse_read("").is_err());
    }

    #[test]
    fn poll_ready_succeeds_on_third_attempt() {
        let mut calls = 0;
        let mut sleeps = 0;
        let attempts = poll_ready(
            Duration::from_secs(2),
            Duration::from_millis(1),
            LAYOUT::MAGIC,
            || {
                calls += 1;
                Ok(if calls >= 3 { LAYOUT::MAGIC } else { 0 })
            },
            |_| {
                sleeps += 1;
            },
        )
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(calls, 3);
        assert_eq!(sleeps, 2);
        assert!(attempts <= 10, "poll_ok must land within a small N");
    }

    #[test]
    fn poll_ready_times_out_when_never_ready() {
        let mut calls = 0;
        let r = poll_ready(
            Duration::from_millis(40),
            Duration::from_millis(5),
            LAYOUT::MAGIC,
            || {
                calls += 1;
                Ok(0)
            },
            std::thread::sleep,
        );
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("44554d31"), "expected value in message: {msg}");
        assert!(calls >= 1);
    }

    #[test]
    fn poll_ready_matches_non_magic_expect_value() {
        let expect = 0x0E0E_0E0E;
        let mut calls = 0;
        let attempts = poll_ready(
            Duration::from_secs(2),
            Duration::from_millis(1),
            expect,
            || {
                calls += 1;
                Ok(if calls >= 3 { expect } else { 0 })
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(calls, 3);
        assert!(attempts <= 10, "0,0,expect must land within a small N");
    }

    #[test]
    fn poll_ready_rejects_magic_when_expect_differs() {
        // P2/P3-class responses may echo their own marker, not MAGIC: the
        // match must be exact, MAGIC alone must not satisfy a different
        // expect.
        let r = poll_ready(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0x0E0E_0E0E,
            || Ok(LAYOUT::MAGIC),
            std::thread::sleep,
        );
        assert!(r.is_err(), "exact-value match required: MAGIC != expect");
    }

    #[test]
    fn poll_answer_succeeds_on_third_attempt() {
        let mut calls = 0;
        let mut sleeps = 0;
        let (attempts, v) = poll_answer(
            Duration::from_secs(2),
            Duration::from_millis(1),
            || {
                calls += 1;
                Ok(if calls >= 3 { 0x600d_0002 } else { 0 })
            },
            |_| {
                sleeps += 1;
            },
        )
        .unwrap();
        assert_eq!((attempts, v), (3, 0x600d_0002));
        assert_eq!(calls, 3);
        assert_eq!(sleeps, 2, "sleep runs between attempts only");
    }

    #[test]
    fn poll_answer_zero_word_is_timeout_by_design() {
        // The cx5 stub stores the dumped word itself at 0x8c8 (no MAGIC
        // echo): a RAM word that reads 0 is indistinguishable from "no
        // answer" — by design it surfaces as the timeout error.
        let r = poll_answer(
            Duration::from_millis(15),
            Duration::from_millis(5),
            || Ok(0),
            std::thread::sleep,
        );
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("0x08c8"), "names the answer slot: {msg}");
        assert!(msg.contains("00000000"), "names the last value: {msg}");
    }

    #[test]
    fn exec_seed_writes_magic_n_then_words() {
        let words = [0xA, 0xB, 0xC];
        let mut w = Vec::new();
        exec_seed(
            |word, v| {
                w.push((word, v));
                Ok(())
            },
            &words,
            Profile::Lx,
        )
        .unwrap();
        let expect = vec![
            (LAYOUT::W_MAGIC, LAYOUT::MAGIC),
            (LAYOUT::W_COUNT, 3),
            (LAYOUT::W_PLD, 0xA),
            (LAYOUT::W_PLD + 1, 0xB),
            (LAYOUT::W_PLD + 2, 0xC),
        ];
        assert_eq!(w, expect);
    }

    #[test]
    fn exec_seed_accepts_pld_max_words() {
        let words: Vec<u32> = (0..LAYOUT::PLD_MAX as u32).collect();
        let mut count = 0;
        exec_seed(
            |_, _| {
                count += 1;
                Ok(())
            },
            &words,
            Profile::Lx,
        )
        .unwrap();
        assert_eq!(count, 2 + LAYOUT::PLD_MAX);
    }

    #[test]
    fn exec_seed_rejects_empty_and_oversized_without_writes() {
        for bad in [&[][..], &(0..11u32).collect::<Vec<u32>>()[..]] {
            let mut w = Vec::new();
            assert!(
                exec_seed(
                    |word, v| {
                        w.push((word, v));
                        Ok(())
                    },
                    bad,
                    Profile::Lx,
                )
                .is_err(),
                "{bad:?} words must be rejected"
            );
            assert!(w.is_empty(), "no write may happen for a bad payload");
        }
    }

    #[test]
    fn exec_seed_cx5_caps_at_nine_words() {
        // cx5 payload zone is 0x8c7..=0x8cf: 9 words; a 10th would land on
        // the forbidden 0x8d0 and must be rejected before any write.
        let nine: Vec<u32> = (0..9u32).collect();
        let mut count = 0;
        exec_seed(
            |_, _| {
                count += 1;
                Ok(())
            },
            &nine,
            Profile::Cx5,
        )
        .unwrap();
        assert_eq!(count, 2 + 9);
        let ten: Vec<u32> = (0..10u32).collect();
        let mut w = Vec::new();
        assert!(
            exec_seed(
                |word, v| {
                    w.push((word, v));
                    Ok(())
                },
                &ten,
                Profile::Cx5,
            )
            .is_err(),
            "10 words do not fit the cx5 payload zone (0x8d0 forbidden)"
        );
        assert!(w.is_empty(), "no write may happen for an oversized payload");
    }

    #[test]
    fn exec_verify_ok_on_echoed_seed() {
        let words = [0xA, 0xB, 0xC];
        exec_verify(&words, |word| {
            Ok(match word {
                w if w == LAYOUT::W_MAGIC => LAYOUT::MAGIC,
                w if w == LAYOUT::W_COUNT => words.len() as u32,
                w => words[(w - LAYOUT::W_PLD) as usize],
            })
        })
        .unwrap();
    }

    #[test]
    fn exec_verify_rejects_corrupted_word() {
        let words = [0xA, 0xB, 0xC];
        let r = exec_verify(&words, |word| {
            Ok(match word {
                w if w == LAYOUT::W_MAGIC => LAYOUT::MAGIC,
                w if w == LAYOUT::W_COUNT => words.len() as u32,
                w if w == LAYOUT::W_PLD + 1 => 0xdead_beef,
                w => words[(w - LAYOUT::W_PLD) as usize],
            })
        });
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("0x08c8"), "failing word named: {msg}");
    }

    #[test]
    fn exec_cycle_happy_path_order_and_result() {
        let words: Vec<u32> = vec![0xA, 0xB, 0xC];
        let expect = 0x0E0E_0E0E;
        let mut writes = Vec::new();
        let mut fired = 0usize;
        let mut polls = 0usize;
        let (attempts, view) = exec_cycle(
            &words,
            expect,
            Profile::Lx,
            |word, v| {
                writes.push((word, v));
                Ok(())
            },
            |word| {
                Ok(match word {
                    w if w == LAYOUT::W_MAGIC => LAYOUT::MAGIC,
                    w if w == LAYOUT::W_COUNT => words.len() as u32,
                    w => words[(w - LAYOUT::W_PLD) as usize],
                })
            },
            || {
                fired += 1;
                Ok(())
            },
            |word| {
                if word == LAYOUT::W_RESP {
                    polls += 1;
                    Ok(expect)
                } else {
                    Ok(word * 4 + 1)
                }
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(fired, 1, "trigger fires exactly once");
        assert_eq!(polls, 2, "one poll attempt + the read sweep over W_RESP");
        assert_eq!(attempts, 1);
        let mut expect_writes: Vec<(u32, u32)> =
            (LAYOUT::W_RESP..=W_PLD_LAST).map(|w| (w, 0)).collect();
        expect_writes.push((LAYOUT::W_MAGIC, LAYOUT::MAGIC));
        expect_writes.push((LAYOUT::W_COUNT, words.len() as u32));
        for (i, w) in words.iter().enumerate() {
            expect_writes.push((LAYOUT::W_PLD + i as u32, *w));
        }
        assert_eq!(
            writes, expect_writes,
            "clear-response first, then the seed writes"
        );
        assert_eq!(view.magic, LAYOUT::W_MAGIC * 4 + 1, "post-trigger words");
        assert_eq!(view.n, LAYOUT::W_COUNT * 4 + 1, "post-trigger words");
        assert_eq!(view.pld[0], LAYOUT::W_PLD * 4 + 1, "post-trigger words");
        assert_eq!(view.pld[9], W_PLD_LAST * 4 + 1);
        assert_eq!(view.ready(), expect);
    }

    #[test]
    fn exec_cycle_corrupt_readback_blocks_trigger() {
        let words: Vec<u32> = vec![0xA, 0xB, 0xC];
        let mut fired = 0usize;
        let mut post_reads = 0usize;
        let r = exec_cycle(
            &words,
            LAYOUT::MAGIC,
            Profile::Lx,
            |_, _| Ok(()),
            |word| {
                Ok(match word {
                    w if w == LAYOUT::W_MAGIC => LAYOUT::MAGIC,
                    w if w == LAYOUT::W_COUNT => words.len() as u32,
                    w if w == LAYOUT::W_PLD + 1 => 0xdead_beef,
                    w => words[(w - LAYOUT::W_PLD) as usize],
                })
            },
            || {
                fired += 1;
                Ok(())
            },
            |word| {
                post_reads += 1;
                let _ = word;
                Ok(0)
            },
            |_| {},
        );
        assert!(r.is_err(), "corrupt readback word must fail the cycle");
        assert_eq!(fired, 0, "trigger must NOT fire on a failed readback-verify");
        assert_eq!(post_reads, 0, "no post-trigger reads may happen");
    }

    #[test]
    fn run_cycle_cx5_happy_path_plan_and_answer() {
        let mut writes = Vec::new();
        let mut fired = 0usize;
        let mut polls = 0usize;
        let (attempts, answer) = run_cycle_cx5(
            0x106390,
            LAYOUT::MAGIC,
            Duration::from_secs(2),
            Duration::from_millis(1),
            |word, v| {
                writes.push((word, v));
                Ok(())
            },
            || {
                fired += 1;
                Ok(())
            },
            || {
                polls += 1;
                Ok(0x94fc_5373)
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(fired, 1, "trigger fires exactly once");
        assert_eq!(attempts, 1, "a present answer lands on the first poll");
        assert_eq!(answer, 0x94fc_5373, "the answer word is the poll's value");
        assert_eq!(polls, 1);
        let mut expect: Vec<(u32, u32)> = (LAYOUT::W_RESP..=LAYOUT::CX5_ANSWER_LAST)
            .map(|x| (x, 0))
            .collect();
        expect.push((LAYOUT::W_MAGIC, LAYOUT::MAGIC));
        expect.push((LAYOUT::W_COUNT, 0x106390));
        expect.push((LAYOUT::W_PLD, 1));
        assert_eq!(
            writes, expect,
            "answer-zone pre-clear first, then the 3-word seed"
        );
        assert!(
            writes.iter().all(|&(w, _)| (LAYOUT::W_MAGIC..=LAYOUT::CX5_ANSWER_LAST).contains(&w)),
            "guard invariant: the cycle never writes outside 0x8c5..=0x8cf (0x8d0/0x8d4 forbidden)"
        );
    }

    #[test]
    fn run_cycle_cx5_polls_until_nonzero() {
        let mut calls = 0;
        let mut sleeps = 0;
        let (attempts, answer) = run_cycle_cx5(
            4,
            LAYOUT::MAGIC,
            Duration::from_secs(2),
            Duration::from_millis(1),
            |_, _| Ok(()),
            || Ok(()),
            || {
                calls += 1;
                Ok(if calls >= 3 { 0xdead_beef } else { 0 })
            },
            |_| {
                sleeps += 1;
            },
        )
        .unwrap();
        assert_eq!((attempts, answer), (3, 0xdead_beef));
        assert_eq!(sleeps, 2);
    }

    #[test]
    fn run_cycle_cx5_timeout_fires_once_and_names_slot() {
        let mut fired = 0usize;
        let mut polls = 0usize;
        let r = run_cycle_cx5(
            4,
            LAYOUT::MAGIC,
            Duration::from_millis(30),
            Duration::from_millis(5),
            |_, _| Ok(()),
            || {
                fired += 1;
                Ok(())
            },
            || {
                polls += 1;
                Ok(0)
            },
            std::thread::sleep,
        );
        let msg = r.unwrap_err().to_string();
        assert_eq!(fired, 1, "trigger fires exactly once, before the poll");
        assert!(polls >= 1);
        assert!(msg.contains("0x08c8"), "names the answer slot: {msg}");
        assert!(msg.contains("00000000"), "names the last value: {msg}");
    }

    #[test]
    fn run_cycle_cx5_write_failure_blocks_trigger() {
        let mut fired = 0usize;
        let r = run_cycle_cx5(
            4,
            LAYOUT::MAGIC,
            Duration::from_secs(1),
            Duration::from_millis(1),
            |word, _| {
                if word == LAYOUT::W_PLD {
                    Err(anyhow::anyhow!("write filtered"))
                } else {
                    Ok(())
                }
            },
            || {
                fired += 1;
                Ok(())
            },
            || Ok(0x1),
            |_| {},
        );
        assert!(r.is_err());
        assert_eq!(fired, 0, "trigger must NOT fire on a failed seed write");
    }
}
