// Источник: mstflint mtcr_ul/mtcr_ul_icmd_cif.c (set_opcode / set_and_poll_on_busy_bit /
// translate_status / check_msg_size, icmd_send_command_com; VCR-лейаут icmd_init_vcr
// :1338-1372 + VCR_CTRL/CMD_ADDR :122-124); cmdif/icmd_cif_common.h (GCIF_STATUS_*).
// Статус/syndrome (fix round 4, live-gate H-B): статус = ctrl-регистр биты 8..16
// (STATUS_BITOFF=8/:120, извлечение в icmd_send_command_com :875), syndrome —
// регистр syndrome_addr (VCR: VCR_SYNDROME_OFFSET=0x1008/:126, CR-флейвор:
// SYNDROME_OFFSET=0x3f8 от cmd_addr/:127,127+; get_syndrome :371-383 — читается
// ТОЛЬКО при статусе≠0, маска 0x00ff_ffff / SYNDROME_BITLEN=24) — НЕ из out[0]:
// FW не пишет out-кадр для отброшенных команд (live-gate попытки 2-3: RX==TX,
// «статус»-байт = байт опкода in-кадра). Канон то же в нашем vsec.rs
// (status = (final_ctrl >> 8) & 0xff, syndrome & 0x00ff_ffff).
// Out-буфер: payload с офсета 8 — wire-факт фикстр Task 1 (testdata/wire/*.txt;
// в фикстрах out[0]/out[4..8] дублируют ctrl-статус/syndrome — теперь эти ЗНАЧЕНИЯ
// ассертятся через мок ctrl/syndrome-reg, payload-ассерты не менялись).
// Эндianness: транспортное слово = LE-нагрузка 4 байтов провода в адресном
// порядке (VfioTransport = read_le_u32/write_le_u32); кадр мейнлбокса кладём
// в АДРЕСНОМ порядке (from_le_bytes/to_le_bytes) — нетто-эффект mstflint
// mwrite_buffer_ul (endianness-fix + mwrite4): байты кадра на проводе по порядку.
// Битовые поля ctrl-регистра (go-бит 0, opcode 16..32, статус 8..16) живут на
// ЗНАЧЕНИИ регистра (BE-интерпретация, = порт-дворд VSEC-шлюза), а не на сыром
// слове транспорта: живой канон crates/mlxscope/src/trace/vsec.rs send_direct.
// Fix round 5 (live-gate попытка 4): машина лейаут-агностична (адреса — в
// Mailbox), но СЕССИЯ использует CR-лейаут (cmd@CR cmd_ptr, ctrl@cmd+0x3fc,
// syndrome@cmd+0x3f8 — icmd_init_cr) для ВСЕХ обменов HCA-класса: VCR ctrl @
// AS_ICMD+0 — домен GCIF/tool-опкодов (HCA-опкод → status=1 invalid opcode,
// живой свидетель A4-5); VCR-лейаут остаётся discovery-only (см. session.rs).

use crate::err::{CmdStatusErr, Error, Result};

/// AS_CR_SPACE (mstflint address_space_t, mtcr_com_defs.h:377-395).
const AS_CR_SPACE: u16 = 0x2;

/// Транспорт 32-битных регистров (байтовые офсеты, как в mstflint mread4/mwrite4).
/// Мок — в тестах; VSEC-шлюз — в session.rs.
pub trait Transport {
    fn read32(&self, off: usize) -> Result<u32>;
    fn write32(&self, off: usize, v: u32) -> Result<()>;

    /// Переключение адресного пространства (functional-VSEC шлюз:
    /// mstflint mset_addr_space / mtcr_pciconf_set_addr_space). Транспорт без
    /// шлюза: CR-space (0x2) нативен, прочие — Err(Unsupported).
    fn set_address_space(&self, raw: u16) -> Result<()> {
        if raw == AS_CR_SPACE {
            Ok(())
        } else {
            Err(Error::Unsupported(format!(
                "адресное пространство {raw:#x} недоступно (транспорт без functional-VSEC шлюза)"
            )))
        }
    }
}

/// Лимит поллов go-бита до Err(Timeout); сон между поллами — политика транспорта
/// (мок не спит, тесты быстрые). Аналог таймаута mstflint (ICMD_DEFAULT_TIMEOUT).
pub const MAX_GO_POLLS: usize = 1000;

/// Статус busy из translate_status (mstflint): 0x5 → ME_ICMD_BUSY.
/// Сессионный слой CMDQ (Task 10) сохраняет паритет: один повтор при busy.
pub(crate) const STATUS_BUSY: u8 = 0x05;

/// Размер icmd-мейнлбокса: ICMD_MAX_CMD_SIZE (mstflint include/mtcr_ul/mtcr_com_defs.h).
pub const ICMD_MAX_CMD_SIZE: usize = 0x340;

const OPCODE_BITOFF: u32 = 16;
const GO_BIT: u32 = 1;
const STATUS_BITOFF: u32 = 8;
const STATUS_BITLEN: u32 = 8;
const SYNDROME_BITLEN: u32 = 24;

/// Icmd-мейнлбокс: статус-машина go/opcode/poll + out-копирование.
/// CR-лейаут (icmd_init_cr): ctrl = cmd_addr + 0x3fc, syndrome = cmd_addr + 0x3f8;
/// VCR-лейаут (icmd_init_vcr, VSEC-путь): cmd_addr = 0x100000, ctrl_addr = 0,
/// syndrome = VCR_SYNDROME_OFFSET = 0x1008.
#[derive(Debug, Clone)]
pub struct Mailbox {
    /// Адрес мейнлбокса (CR: cmd_ptr из reg@0; VCR: VCR_CMD_ADDR = 0x100000).
    pub cmd_addr: usize,
    /// Адрес ctrl-регистра (CR: cmd_addr + 0x3fc; VCR: 0).
    pub ctrl_addr: usize,
    /// Адрес syndrome-регистра (CR: cmd_addr + 0x3f8; VCR: 0x1008) —
    /// mstflint mf->icmd.syndrome_addr (:1233 CR / :1352 VCR).
    pub syndrome_addr: usize,
    /// Максимум команды (CR: ICMD_MAX_CMD_SIZE; VCR: читается из VCR_CMD_SIZE_ADDR).
    pub max_cmd_size: usize,
}

/// Ctrl-доступ на ЗНАЧЕНИИ регистра (BE-интерпретация = порт-дворд шлюза):
/// битовые поля go/opcode/status живут там, не на сыром слове транспорта.
fn read_ctrl(t: &dyn Transport, ctrl: usize) -> Result<u32> {
    Ok(t.read32(ctrl)?.swap_bytes())
}

fn write_ctrl(t: &dyn Transport, ctrl: usize, v: u32) -> Result<()> {
    t.write32(ctrl, v.swap_bytes())
}

impl Mailbox {
    /// Кадр в мейнлбокс: байты кадра — в адресном порядке провода, поэтому
    /// транспортное слово (LE-нагрузка) собираем from_le_bytes.
    fn write_frame(&self, t: &dyn Transport, frame: &[u8]) -> Result<()> {
        for (i, w) in frame.chunks(4).enumerate() {
            let mut b = [0u8; 4];
            b[..w.len()].copy_from_slice(w);
            t.write32(self.cmd_addr + i * 4, u32::from_le_bytes(b))?;
        }
        Ok(())
    }

    /// Out-копия: to_le_bytes даёт байты провода в адресном порядке.
    fn read_out(&self, t: &dyn Transport, outlen: u32) -> Result<Vec<u8>> {
        let outlen = outlen as usize;
        let mut out = Vec::with_capacity(outlen);
        for i in 0..outlen.div_ceil(4) {
            let w = t.read32(self.cmd_addr + i * 4)?.to_le_bytes();
            out.extend_from_slice(&w);
        }
        out.truncate(outlen);
        Ok(out)
    }

    /// Один обмен: opcode → frame в мейнлбокс → go → poll → out-копия;
    /// (out, статус из ctrl битов 8..16, syndrome из syndrome-регистра при
    /// статусе≠0 — H-B).
    fn exchange_once(
        &self,
        t: &dyn Transport,
        frame: &[u8],
        outlen: u32,
        dump: bool,
    ) -> Result<(Vec<u8>, u8, u32)> {
        if frame.len() < 8 {
            return Err(Error::Size(format!(
                "frame короче 8-байтового заголовка мейнлбокса: {}",
                frame.len()
            )));
        }
        if frame.len() > self.max_cmd_size || outlen as usize > self.max_cmd_size {
            return Err(Error::Size(format!(
                "frame {} / outlen {} против max_cmd_size {}",
                frame.len(),
                outlen,
                self.max_cmd_size
            )));
        }
        let opcode = u16::from_be_bytes([frame[0], frame[1]]);
        let ctrl = self.ctrl_addr;

        let reg = read_ctrl(t, ctrl)?;
        write_ctrl(
            t,
            ctrl,
            (reg & !(0xffff << OPCODE_BITOFF)) | ((opcode as u32) << OPCODE_BITOFF),
        )?;
        self.write_frame(t, frame)?;

        let reg = read_ctrl(t, ctrl)?;
        if reg & GO_BIT != 0 {
            return Err(Error::Busy);
        }
        write_ctrl(t, ctrl, reg | GO_BIT)?;

        let mut reg = read_ctrl(t, ctrl)?;
        let mut polls = 0;
        while reg & GO_BIT != 0 {
            polls += 1;
            if polls >= MAX_GO_POLLS {
                log::warn!(
                    "go-бит не сбросился за {} поллов (cmd_addr={:#x})",
                    MAX_GO_POLLS,
                    self.cmd_addr
                );
                return Err(Error::Timeout);
            }
            reg = read_ctrl(t, ctrl)?;
        }

        // Статус — из ctrl-регистра (STATUS_BITOFF=8), НЕ из out[0] (H-B):
        // get_syndrome только при статусе≠0, маска 0x00ff_ffff.
        let status = ((reg >> STATUS_BITOFF) & ((1 << STATUS_BITLEN) - 1)) as u8;
        let syndrome = if status != 0 {
            t.read32(self.syndrome_addr)?.swap_bytes() & ((1 << SYNDROME_BITLEN) - 1)
        } else {
            0
        };

        let out = self.read_out(t, outlen)?;
        if dump {
            eprintln!("TX {}", wire_hex(frame));
            eprintln!("RX {}", wire_hex(&out));
        }
        Ok((out, status, syndrome))
    }

    /// Обмен с retry и полным результатом (внутренний): busy-статус (0x5) →
    /// ровно один повтор, затем итог как есть.
    fn try_exec_full(
        &self,
        t: &dyn Transport,
        frame: &[u8],
        outlen: u32,
        dump: bool,
    ) -> Result<(Vec<u8>, u8, u32)> {
        let mut attempt = 0;
        loop {
            let r = self.exchange_once(t, frame, outlen, dump)?;
            attempt += 1;
            if r.1 != STATUS_BUSY || attempt > 1 {
                return Ok(r);
            }
            log::debug!("icmd busy (status 0x5), повторяю обмен (попытка 2)");
        }
    }

    /// Обмен с retry: busy-статус (0x5) → ровно один повтор, затем итог как есть.
    pub fn try_exec(
        &self,
        t: &dyn Transport,
        frame: &[u8],
        outlen: u32,
        dump: bool,
    ) -> Result<(Vec<u8>, u8)> {
        let (out, status, _syndrome) = self.try_exec_full(t, frame, outlen, dump)?;
        Ok((out, status))
    }

    /// Payload-вариант: out[8..] при статусе 0; статус≠0 → Err(Command) со
    /// статусом из ctrl-регистра и syndrome из syndrome-регистра (H-B).
    pub fn exec_command(
        &self,
        t: &dyn Transport,
        frame: &[u8],
        outlen: u32,
        dump: bool,
    ) -> Result<Vec<u8>> {
        let (out, status, syndrome) = self.try_exec_full(t, frame, outlen, dump)?;
        if status != 0 {
            return Err(Error::Command(CmdStatusErr { status, syndrome }));
        }
        Ok(out.get(8..).map(<[u8]>::to_vec).unwrap_or_default())
    }
}

/// Hex-строка байтов — формат фикстр (слитный lowercase hex).
pub(crate) fn wire_hex(buf: &[u8]) -> String {
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use super::*;

    const MOCK_CMD_ADDR: usize = 0x1000;
    /// CR-лейаут ctrl-регистра (icmd_init_cr): ctrl = cmd_addr + 0x3fc,
    /// syndrome = cmd_addr + 0x3f8.
    const CTRL_OFFSET: usize = 0x3fc;
    const SYNDROME_OFFSET: usize = 0x3f8;

    const FLOWTABLE_FIX: &str = include_str!("../testdata/wire/flowtable.txt");
    const TRIG_P0SAFE_FIX: &str = include_str!("../testdata/wire/trig-p0safe.txt");
    const MTRC_SET_FIX: &str = include_str!("../testdata/wire/mtrc-set.txt");
    const ALLOC_PD_MKEY_FIX: &str = include_str!("../testdata/wire/alloc-pd-mkey.txt");

    #[derive(Clone)]
    struct MockCompletion {
        /// Полный out-кадр (заголовок status/syndrome + payload), кладётся в
        /// мейнлбокс как есть — реплей wire-захвата.
        out: Vec<u8>,
        /// Статус в ctrl-регистре (биты 8..16) — H-B: источник статуса машины.
        status: u8,
        /// Syndrome-регистр (значение; читается только при статусе≠0).
        syndrome: u32,
    }

    /// Мок устройства: на фронт go-бита мгновенно завершает команду — кладёт
    /// out-кадр в мейнлбокс и сбрасывает go.
    #[derive(Default)]
    struct MockTransport {
        mem: RefCell<Vec<u32>>,
        completions: RefCell<VecDeque<MockCompletion>>,
        stuck: Cell<bool>,
        ctrl_reads: Cell<usize>,
    }

    impl MockTransport {
        fn new(completions: Vec<MockCompletion>) -> Self {
            // CR-space: мейнлбокс + ctrl-регистр (CR-лейаут: ctrl = cmd + 0x3fc).
            let len = (MOCK_CMD_ADDR + CTRL_OFFSET + ICMD_MAX_CMD_SIZE) / 4 + 4;
            MockTransport {
                mem: RefCell::new(vec![0u32; len]),
                completions: RefCell::new(completions.into()),
                stuck: Cell::new(false),
                ctrl_reads: Cell::new(0),
            }
        }

        fn ctrl_addr(&self) -> usize {
            MOCK_CMD_ADDR + CTRL_OFFSET
        }

        fn word(&self, off: usize) -> u32 {
            self.mem.borrow()[off / 4]
        }

        fn set_word(&self, off: usize, v: u32) {
            self.mem.borrow_mut()[off / 4] = v;
        }

        fn complete(&self, ctrl_word_v: u32) {
            let c = self
                .completions
                .borrow_mut()
                .pop_front()
                .expect("mock: no completion scripted");
            for (i, w) in c.out.chunks(4).enumerate() {
                let mut b = [0u8; 4];
                b[..w.len()].copy_from_slice(w);
                self.set_word(MOCK_CMD_ADDR + i * 4, u32::from_le_bytes(b));
            }
            // Ctrl-регистр хранится как сырое слово транспорта (LE-нагрузка),
            // значение регистра = swap: сброс go-бита в пространстве значения
            // + статус в битах 8..16 (H-B) и syndrome-регистр при статусе≠0.
            let ctrl_v = (ctrl_word_v & !GO_BIT & !0xff_00) | ((c.status as u32) << 8);
            self.set_word(self.ctrl_addr(), ctrl_v.swap_bytes());
            if c.status != 0 {
                self.set_word(MOCK_CMD_ADDR + SYNDROME_OFFSET, c.syndrome.swap_bytes());
            }
        }
    }

    impl Transport for MockTransport {
        fn read32(&self, off: usize) -> Result<u32> {
            if off == self.ctrl_addr() {
                self.ctrl_reads.set(self.ctrl_reads.get() + 1);
            }
            Ok(self.word(off))
        }

        fn write32(&self, off: usize, v: u32) -> Result<()> {
            let prev_v = self.word(off).swap_bytes();
            self.set_word(off, v);
            let v_ctrl = v.swap_bytes();
            if off == self.ctrl_addr()
                && v_ctrl & GO_BIT != 0
                && prev_v & GO_BIT == 0
                && !self.stuck.get()
            {
                self.complete(v_ctrl);
            }
            Ok(())
        }
    }

    struct WireBlock {
        ctx: String,
        tx: Vec<u8>,
        rx: Vec<u8>,
        tx_hex: String,
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Парсер фикстр: только строки TX/RX (hex), NOTE игнорируются
    /// (известный quirk: радикс NOTE несогласован между файлами).
    fn parse_wire(text: &str) -> Vec<WireBlock> {
        let mut blocks = Vec::new();
        let mut cur: Option<WireBlock> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(ctx) = line.strip_prefix("# ") {
                if let Some(b) = cur.take() {
                    blocks.push(b);
                }
                cur = Some(WireBlock {
                    ctx: ctx.to_string(),
                    tx: Vec::new(),
                    rx: Vec::new(),
                    tx_hex: String::new(),
                });
                continue;
            }
            let Some(b) = cur.as_mut() else { continue };
            if let Some(hex) = line.strip_prefix("TX ") {
                b.tx_hex = hex.to_string();
                b.tx = unhex(hex);
            } else if let Some(hex) = line.strip_prefix("RX ") {
                b.rx = unhex(hex);
            }
        }
        if let Some(b) = cur {
            blocks.push(b);
        }
        blocks
    }

    fn block<'a>(blocks: &'a [WireBlock], needle: &str) -> &'a WireBlock {
        blocks
            .iter()
            .find(|b| b.ctx.contains(needle))
            .unwrap_or_else(|| panic!("блок '{needle}' не найден"))
    }

    /// Комплитка из RX-фикстры: wire-ЗНАЧЕНИЯ статуса/syndrome теперь
    /// скриптуются в ctrl/syndrome-reg мока (H-B); out-кадр — как есть.
    fn completion_from_rx(rx: &[u8]) -> MockCompletion {
        let status = rx.first().copied().unwrap_or(0);
        let syndrome = rx
            .get(4..8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0);
        MockCompletion {
            out: rx.to_vec(),
            status,
            syndrome,
        }
    }

    fn busy_completion() -> MockCompletion {
        MockCompletion {
            out: vec![0u8; 16],
            status: 0x05,
            syndrome: 0,
        }
    }

    fn mb() -> Mailbox {
        Mailbox {
            cmd_addr: MOCK_CMD_ADDR,
            ctrl_addr: MOCK_CMD_ADDR + CTRL_OFFSET,
            syndrome_addr: MOCK_CMD_ADDR + SYNDROME_OFFSET,
            max_cmd_size: ICMD_MAX_CMD_SIZE,
        }
    }

    fn flowtable() -> Vec<WireBlock> {
        parse_wire(FLOWTABLE_FIX)
    }

    #[test]
    fn exec_returns_payload_from_offset_8_on_flowtable_create() {
        let blocks = flowtable();
        let b = block(&blocks, "flowtable create");
        let mock = MockTransport::new(vec![completion_from_rx(&b.rx)]);
        let out = mb()
            .exec_command(&mock, &b.tx, b.rx.len() as u32, false)
            .unwrap();
        assert_eq!(out, b.rx[8..]);
        assert_eq!(&out[..4], &[0x28, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn exec_nonzero_status_yields_command_err_with_fixture_values() {
        let blocks = flowtable();
        let b = block(&blocks, "NONEXISTENT");
        let mock = MockTransport::new(vec![completion_from_rx(&b.rx)]);
        let err = mb()
            .exec_command(&mock, &b.tx, b.rx.len() as u32, false)
            .unwrap_err();
        assert_eq!(
            err,
            Error::Command(CmdStatusErr {
                status: 0x03,
                syndrome: 0x001c_2b78,
            })
        );
    }

    #[test]
    fn stuck_go_bit_times_out_after_bounded_polls() {
        let blocks = flowtable();
        let b = block(&blocks, "flowtable create");
        let mock = MockTransport::new(vec![busy_completion()]);
        mock.stuck.set(true);
        let err = mb()
            .exec_command(&mock, &b.tx, b.rx.len() as u32, false)
            .unwrap_err();
        assert_eq!(err, Error::Timeout);
        let reads = mock.ctrl_reads.get();
        assert!(
            reads >= MAX_GO_POLLS,
            "poll-цикл должен отработать бюджет поллов, reads={reads}"
        );
        assert!(
            reads <= MAX_GO_POLLS + 4,
            "poll-цикл обязан быть ограниченным, reads={reads}"
        );
    }

    #[test]
    fn busy_status_is_retried_once_then_succeeds() {
        let blocks = flowtable();
        let b = block(&blocks, "flowtable create");
        let busy = busy_completion();
        let ok = completion_from_rx(&b.rx);
        let mock = MockTransport::new(vec![busy, ok]);
        let out = mb()
            .exec_command(&mock, &b.tx, b.rx.len() as u32, false)
            .unwrap();
        assert_eq!(out, b.rx[8..]);
        assert_eq!(mock.completions.borrow().len(), 0);
    }

    #[test]
    fn persistent_busy_reports_command_err_after_single_retry() {
        let blocks = flowtable();
        let b = block(&blocks, "flowtable create");
        let mock = MockTransport::new(vec![busy_completion(), busy_completion()]);
        let err = mb()
            .exec_command(&mock, &b.tx, b.rx.len() as u32, false)
            .unwrap_err();
        assert_eq!(
            err,
            Error::Command(CmdStatusErr {
                status: 0x05,
                syndrome: 0,
            })
        );
        assert_eq!(
            mock.completions.borrow().len(),
            0,
            "ровно один retry: обе busy-комплитки потреблены"
        );
    }

    #[test]
    fn wire_fixtures_roundtrip_through_mailbox() {
        let files = [
            ("flowtable", FLOWTABLE_FIX),
            ("trig-p0safe", TRIG_P0SAFE_FIX),
            ("mtrc-set", MTRC_SET_FIX),
            ("alloc-pd-mkey", ALLOC_PD_MKEY_FIX),
        ];
        for (name, text) in files {
            for b in parse_wire(text) {
                let mock = MockTransport::new(vec![completion_from_rx(&b.rx)]);
                let (out, status) = mb()
                    .try_exec(&mock, &b.tx, b.rx.len() as u32, false)
                    .unwrap_or_else(|e| panic!("{name}/{}: {e}", b.ctx));
                assert_eq!(status, b.rx[0], "{name}/{}: статус-байт", b.ctx);
                assert_eq!(out, b.rx, "{name}/{}: out-буфер", b.ctx);

                let mock = MockTransport::new(vec![completion_from_rx(&b.rx)]);
                let res = mb().exec_command(&mock, &b.tx, b.rx.len() as u32, false);
                if b.rx[0] == 0 {
                    assert_eq!(res.unwrap(), b.rx[8..], "{name}/{}: payload", b.ctx);
                } else {
                    let syndrome = u32::from_be_bytes([b.rx[4], b.rx[5], b.rx[6], b.rx[7]]);
                    assert_eq!(
                        res.unwrap_err(),
                        Error::Command(CmdStatusErr {
                            status: b.rx[0],
                            syndrome,
                        }),
                        "{name}/{}: err-комплит",
                        b.ctx
                    );
                }
            }
        }
    }

    #[test]
    fn wire_hex_matches_fixture_line_format() {
        for b in flowtable() {
            assert_eq!(wire_hex(&b.tx), b.tx_hex);
        }
    }
}
