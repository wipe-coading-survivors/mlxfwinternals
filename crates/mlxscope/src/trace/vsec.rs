//! Direct sysfs config-space VSEC access (no VFIO): works with mlx5 bound and driverless.
//!
//! Framing follows mstflint user-space sources (refs/src/mstflint):
//! - register access over ICMD = opcode 0x9001 (FLASH_REG_ACCESS,
//!   include/mtcr_ul/mtcr_com_defs.h:39), payload = OperationTlv(16B) +
//!   reg_tlv(4B) + register data (mtcr_ul/mtcr_ul_com.c mreg_send_raw,
//!   mtcr_ul/packets_layout.c pack functions).
//! - ICMD error syndrome: dword at ICMD offset 0x1008, 24 bits
//!   (mtcr_ul/mtcr_ul_icmd_cif.c:126 VCR_SYNDROME_OFFSET, :371 get_syndrome).
//! - ICMD space layout (mstflint mtcr_ul): ctrl@0x0 (opcode<<16|go),
//!   max_cmd_size@0x1000, command words@0x100000.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{bail, Context};
use mlxdirect::err::Error as DirectError;
use mlxdirect::icmd::Icmd;
use mlxdirect::mtcr::{AddressSpace, Mtc};

pub const AS_CR_SPACE: u16 = 0x2;
pub const AS_ICMD: u16 = 0x3;

pub const VCR_CTRL_ADDR: u32 = 0x0;
pub const VCR_CMD_SIZE_ADDR: u32 = 0x1000;
pub const VCR_CMD_ADDR: u32 = 0x100000;
pub const VCR_SYNDROME_ADDR: u32 = 0x1008;

pub const ICMD_ACCESS_REG: u16 = 0x9001;
#[allow(dead_code)]
pub const ICMD_SET_ITRACE: u16 = 0xf003;

/// Exclusive-ownership quirk syndromes (live-verified B1: GET MTRC_CONF/CTRL
/// from user space on CX-4 Lx while the tracer is owned — driver bound or our
/// own VFIO arm — fails with ICMD error 0x3 + these syndromes; same as CX-5,
/// docs/250-re/100-formats/065-fw-trace.md).
pub const QUIRK_CONF_SYNDROME: u32 = 0x6c64fe;
pub const QUIRK_CTRL_SYNDROME: u32 = 0xb63790;

pub fn classify_icmd_error(status: u8, syndrome: u32) -> String {
    let base = match status {
        0x0 => "ok",
        0x1 => "invalid opcode",
        0x2 => "invalid command",
        0x3 => "operational error",
        0x4 => "bad parameter",
        0x5 => "busy",
        0x6 => "ICM not available",
        0x7 => "write protected",
        _ => "unknown status",
    };
    let quirk = match syndrome {
        QUIRK_CONF_SYNDROME => Some("exclusive-ownership quirk (MTRC_CONF path)"),
        QUIRK_CTRL_SYNDROME => Some("exclusive-ownership quirk (MTRC_CTRL path)"),
        _ => None,
    };
    match quirk {
        Some(q) => format!("icmd error 0x{status:x}, syndrome 0x{syndrome:06x} -> {q}"),
        None => format!("icmd error 0x{status:x}, syndrome 0x{syndrome:06x} ({base})"),
    }
}

fn read_le_u32_at(f: &mut &File, off: u64) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    f.seek(SeekFrom::Start(off))?;
    f.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_le_u32_at(f: &mut &File, off: u64, v: u32) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(off))?;
    f.write_all(&v.to_le_bytes())
}

/// PCI capability walk over a config-space byte image: returns offset of the
/// first capability with `cap_id` (0x09 = vendor-specific / VSEC for Mellanox).
pub fn find_cap_offset(config: &[u8], cap_id: u8) -> Option<u16> {
    if config.len() < 0x40 {
        return None;
    }
    let mut next = config[0x34];
    for _ in 0..48 {
        if next == 0 || next < 0x40 || (next as usize + 2) > config.len() {
            return None;
        }
        let off = next as usize;
        let (id, n) = (config[off], config[off + 1]);
        if id == cap_id {
            return Some(off as u16);
        }
        next = n;
    }
    None
}

/// mstflint OperationTlv (16 bytes) + reg_tlv (4 bytes) framing, bit-exact
/// port of packets_layout.c pack functions (MSB-first bit packing, BE bytes).
pub mod tlv {
    pub const TLV_OPERATION: u8 = 1;
    pub const TLV_REG: u8 = 3;
    pub const MAD_CLASS_1_REG_ACCESS: u8 = 1;
    pub const METHOD_GET: u8 = 1;
    #[allow(dead_code)]
    pub const METHOD_SET: u8 = 2;

    /// MSB-first bit packing, port of push_to_buff/INSERTF_8 (packets_common.c):
    /// bit 0 = MSB of byte 0; a field's MSB lands at the lowest bit position.
    fn push_msb(buf: &mut [u8], bit_offset: usize, field_size: usize, value: u32) {
        let mut bit = bit_offset;
        let mut remaining = field_size;
        while remaining > 0 {
            let byte = bit / 8;
            let off = bit % 8;
            let take = std::cmp::min(8 - off, remaining);
            let shift = remaining - take;
            let v = ((value >> shift) as u8) & (((1u16 << take) - 1) as u8);
            buf[byte] |= v << (8 - off - take);
            bit += take;
            remaining -= take;
        }
    }

    /// OperationTlv_pack: 16 bytes.
    pub fn op_tlv(method: u8, register_id: u16, len_dwords: u16) -> [u8; 16] {
        let mut b = [0u8; 16];
        push_msb(&mut b, 5, 11, len_dwords as u32);
        push_msb(&mut b, 0, 5, TLV_OPERATION as u32);
        push_msb(&mut b, 56, 8, MAD_CLASS_1_REG_ACCESS as u32);
        push_msb(&mut b, 49, 7, method as u32);
        push_msb(&mut b, 32, 16, register_id as u32);
        b
    }

    /// reg_tlv_pack: 4 bytes; len is total (reg data + 4B reg_tlv header) in dwords.
    pub fn reg_tlv(reg_data_len: usize) -> [u8; 4] {
        let mut b = [0u8; 4];
        let len_dwords = ((reg_data_len + 4) / 4) as u32;
        push_msb(&mut b, 5, 11, len_dwords);
        push_msb(&mut b, 0, 5, TLV_REG as u32);
        b
    }

    /// Full ICMD 0x9001 register payload: op_tlv + reg_tlv + register data.
    pub fn access_reg_frame(method: u8, register_id: u16, reg_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + reg_data.len());
        out.extend_from_slice(&op_tlv(method, register_id, 4));
        out.extend_from_slice(&reg_tlv(reg_data.len()));
        out.extend_from_slice(reg_data);
        out
    }

    /// Extract OperationTlv.status (bits 8..14) from a response buffer.
    pub fn op_tlv_status(buf: &[u8]) -> u8 {
        if buf.len() < 2 {
            return 0;
        }
        (buf[1] >> 1) & 0x7f
    }
}

/// VSEC-over-sysfs device: config space file of one PCI function.
pub struct VsecDev {
    config: File,
    #[allow(dead_code)]
    pub sysfs: PathBuf,
    pub vsec_base: u16,
}

impl VsecDev {
    pub fn open(sysfs: &Path) -> anyhow::Result<Self> {
        let cfg_path = sysfs.join("config");
        let mut config = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cfg_path)
            .with_context(|| format!("vsec: open {}", cfg_path.display()))?;
        let mut head = vec![0u8; 0x100];
        config.read_exact(&mut head).context("vsec: read config head")?;
        let vsec_base = find_cap_offset(&head, 0x09)
            .ok_or_else(|| anyhow::anyhow!("vsec: capability 0x09 not found at {}", sysfs.display()))?;
        Ok(Self {
            config,
            sysfs: sysfs.to_path_buf(),
            vsec_base,
        })
    }

    pub fn vsec_read_raw(&self, off: u64) -> std::io::Result<u32> {
        let mut f = &self.config;
        read_le_u32_at(&mut f, self.vsec_base as u64 + off)
    }

    pub fn vsec_write_raw(&self, off: u64, v: u32) -> std::io::Result<()> {
        let mut f = &self.config;
        write_le_u32_at(&mut f, self.vsec_base as u64 + off, v)
    }

    /// VSEC cap9 semaphore (mtcr_pciconf_cap9_sem): take via ticket-counter,
    /// release by writing 0. Held around every VSEC data-port access — the
    /// same protocol mlx5 tools use to coexist with each other.
    fn sem_take(&self) -> std::io::Result<()> {
        for _ in 0..1024 {
            let s = self.vsec_read_raw(0xc)?;
            if s != 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            let counter = self.vsec_read_raw(0x8)?;
            self.vsec_write_raw(0xc, counter)?;
            let s2 = self.vsec_read_raw(0xc)?;
            if s2 == counter {
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "vsec semaphore busy",
        ))
    }

    fn sem_release(&self) -> std::io::Result<()> {
        self.vsec_write_raw(0xc, 0)
    }

    pub fn change_address_space(&self, address_space: u16) -> anyhow::Result<()> {
        self.sem_take()?;
        let r = (|| {
            let ctrl = self.vsec_read_raw(0x4)?;
            self.vsec_write_raw(0x4, (ctrl & 0xffff_0000) | address_space as u32)?;
            let ctrl = self.vsec_read_raw(0x4)?;
            if (ctrl >> 29) & 0x7 == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("address space {address_space} not supported (ctrl=0x{ctrl:08x})"),
                ));
            }
            Ok(())
        })();
        self.sem_release()?;
        r.map_err(|e| anyhow::anyhow!("vsec: {e}"))
    }

    pub fn read_dword(&self, address: u32) -> anyhow::Result<u32> {
        self.sem_take()?;
        let r = (|| -> std::io::Result<u32> {
            let addr = address & 0x3fff_ffff;
            self.vsec_write_raw(0x10, addr)?;
            loop {
                let a = self.vsec_read_raw(0x10)?;
                if (a >> 31) & 1 == 1 {
                    break;
                }
            }
            self.vsec_read_raw(0x14)
        })();
        self.sem_release()?;
        Ok(r?)
    }

    pub fn write_dword(&self, address: u32, data: u32) -> anyhow::Result<()> {
        self.sem_take()?;
        let r = (|| -> std::io::Result<()> {
            self.vsec_write_raw(0x14, data)?;
            let addr = (address & 0x3fff_ffff) | (1 << 31);
            self.vsec_write_raw(0x10, addr)?;
            loop {
                let a = self.vsec_read_raw(0x10)?;
                if (a >> 31) & 1 == 0 {
                    break;
                }
            }
            Ok(())
        })();
        self.sem_release()?;
        r.map_err(|e| anyhow::anyhow!("vsec write 0x{address:x}: {e}"))
    }
}

/// Result of a raw ICMD exchange.
pub struct IcmdResult {
    pub status: u8,
    pub syndrome: u32,
    /// Command area contents after the exchange (same length as the payload).
    pub data: Vec<u32>,
}

impl IcmdResult {
    pub fn is_ok(&self) -> bool {
        self.status == 0
    }
}

/// ICMD client over VsecDev (functional VSEC path).
/// NOTE: the ICMD ctrl dword lives IN ICMD address space (offset 0x0,
/// accessed through the address/data port like the mstflint ICMD client) —
/// the VSEC
/// cap+4 register is the address-space selector, not the ICMD ctrl.
pub struct IcmdClient {
    dev: VsecDev,
    pub max_cmd_size: u32,
}

impl IcmdClient {
    pub fn open(dev: VsecDev) -> anyhow::Result<Self> {
        let mut c = Self { max_cmd_size: 0, dev };
        c.dev.change_address_space(AS_ICMD)?;
        c.max_cmd_size = c.dev.read_dword(VCR_CMD_SIZE_ADDR)?;
        Ok(c)
    }

    pub fn send(&self, opcode: u16, words: &[u32], out_words: usize) -> anyhow::Result<IcmdResult> {
        let total = out_words.max(words.len());
        if total as u32 > self.max_cmd_size {
            bail!(
                "icmd: payload {total} words > max_cmd_size {} (opcode 0x{opcode:x})",
                self.max_cmd_size
            );
        }
        // icmd ctrl @0x0: clear go, set opcode
        let ctrl = self.dev.read_dword(VCR_CTRL_ADDR)?;
        self.dev
            .write_dword(VCR_CTRL_ADDR, (ctrl & 0x0000_ffff) | ((opcode as u32) << 16))?;
        for (i, w) in words.iter().enumerate() {
            self.dev.write_dword(VCR_CMD_ADDR + 4 * i as u32, *w)?;
        }
        // pad remaining area with zeros so stale words don't leak into output
        for i in words.len()..total {
            self.dev.write_dword(VCR_CMD_ADDR + 4 * i as u32, 0)?;
        }
        // set go bit
        let ctrl = self.dev.read_dword(VCR_CTRL_ADDR)?;
        self.dev.write_dword(VCR_CTRL_ADDR, ctrl | 1)?;
        loop {
            let c = self.dev.read_dword(VCR_CTRL_ADDR)?;
            if c & 1 == 0 {
                break;
            }
        }
        let final_ctrl = self.dev.read_dword(VCR_CTRL_ADDR)?;
        let status = ((final_ctrl >> 8) & 0xff) as u8;
        let syndrome = if status == 0 {
            0
        } else {
            self.dev.read_dword(VCR_SYNDROME_ADDR).unwrap_or(0) & 0x00ff_ffff
        };
        let mut data = Vec::with_capacity(total);
        for i in 0..total {
            data.push(self.dev.read_dword(VCR_CMD_ADDR + 4 * i as u32)?);
        }
        Ok(IcmdResult { status, syndrome, data })
    }

    /// Register access via ICMD 0x9001 with mstflint TLV framing.
    /// Returns (register data bytes (BE), TLV reg-status) — the status is
    /// INFORMATIONAL: mstflint's REG_ACCESS macro returns only rc and ignores
    /// the response reg-status (verified live: CAP GET returns valid data
    /// with reg-status 2; mstreg prints the fields).
    ///
    /// Byte-order note: MWRITE_BUF_ICMD -> mwrite_buffer_ul applies
    /// mtcr_fix_endianness (bswap of every dword) before writing numeric
    /// dwords through the VSEC data port — so a device dword equals the
    /// BE-load of the 4 TLV stream bytes (and back for reads).
    pub fn access_register(
        &self,
        method: u8,
        register_id: u16,
        reg_data: &[u8],
    ) -> anyhow::Result<Result<(Vec<u8>, u8), String>> {
        let frame = tlv::access_reg_frame(method, register_id, reg_data);
        let words: Vec<u32> = frame
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let res = self.send(ICMD_ACCESS_REG, &words, words.len())?;
        if !res.is_ok() {
            return Ok(Err(classify_icmd_error(res.status, res.syndrome)));
        }
        let bytes: Vec<u8> = res.data.iter().flat_map(|w| w.to_be_bytes()).collect();
        let tlv_status = tlv::op_tlv_status(&bytes);
        Ok(Ok((
            bytes.get(20..).map(|r| r.to_vec()).unwrap_or_default(),
            tlv_status,
        )))
    }

    #[allow(dead_code)]
    /// SET_ITRACE (0xf003): payload {unit_mask, (delay<<16)|level} — the
    /// mtrcdump framing (live-proven on CX-5).
    pub fn set_itrace(&self, mask: u32, level: u8, delay: u16) -> anyhow::Result<IcmdResult> {
        let res = self.send(ICMD_SET_ITRACE, &[mask, ((delay as u32) << 16) | level as u32], 8)?;
        if !res.is_ok() {
            bail!(
                "set_itrace failed: {}",
                classify_icmd_error(res.status, res.syndrome)
            );
        }
        Ok(res)
    }

    pub fn into_dev(self) -> VsecDev {
        self.dev
    }
}

/// Wall-clock budget of the go-poll in [`send_direct`] (live gate attempt 12:
/// the unbounded canon poll hung the exchange and the watchdog SIGKILL then
/// leaked the semaphores; style of mlxdirect CMDQ_CQE_DEADLINE, 60 s
/// kernel-grade).
const SET_ITRACE_GO_DEADLINE: Duration = Duration::from_secs(60);

/// One raw ICMD exchange over mlxdirect `Mtc` dwords: the protocol of
/// [`IcmdClient::send`] (ICMD space: ctrl@0x0 = opcode<<16|go, command
/// words@0x100000, syndrome@0x1008), with the VSEC address/data-port
/// transport replaced by direct dword access through the session `Mtc`.
/// The VCR-domain dwords run under [`under_icmd_space`] (gateway switched
/// to AS_ICMD; live gate attempt 13: in AS_CR_SPACE "ctrl@0x0" is the
/// cmd_ptr register). The go-poll is bounded by [`SET_ITRACE_GO_DEADLINE`]
/// and abortable via `stop` (SIGINT); every error unwinds through
/// `Icmd::run_exclusive`, which releases the ICMD semaphore on all paths.
fn send_direct(
    mtc: &Mtc,
    opcode: u16,
    words: &[u32],
    out_words: usize,
    stop: &AtomicBool,
) -> mlxdirect::err::Result<IcmdResult> {
    under_icmd_space(
        |space| mtc.change_address_space(space),
        || vcr_exchange(mtc, opcode, words, out_words, stop),
    )
}

/// AS_ICMD ↔ AS_CR_SPACE sandwich around the VCR-domain exchange (live gate
/// attempt 13 fix). Canon: `IcmdClient::open` switches the VSEC gateway to
/// AS_ICMD once at open; the direct session stays in AS_CR_SPACE, so the
/// exchange MUST switch to Icmd first and restore CrSpace after — on ALL
/// paths (ok, err, deadline, stop). Switch-in failure mirrors
/// `run_exclusive` take semantics: the exchange does not run, no restore is
/// attempted (the gateway never left CR space). Restore failure after a
/// successful exchange is returned; after a failed exchange the original
/// error wins (restore failure only warned, not masking — the dword_rw/
/// run_exclusive discipline).
fn under_icmd_space<T>(
    mut set_space: impl FnMut(AddressSpace) -> mlxdirect::err::Result<()>,
    exchange: impl FnOnce() -> mlxdirect::err::Result<T>,
) -> mlxdirect::err::Result<T> {
    set_space(AddressSpace::Icmd)?;
    let r = exchange();
    let restore = set_space(AddressSpace::CrSpace);
    match (r, restore) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), rel) => {
            if let Err(rel) = rel {
                eprintln!("[vsec] WARN AS_CR_SPACE restore failed after exchange error: {rel}");
            }
            Err(e)
        }
        (Ok(_), Err(e)) => Err(e),
    }
}

/// The VCR-domain protocol statements of [`IcmdClient::send`], verbatim:
/// ctrl@0x0 clear-go+opcode<<16 → payload words@0x100000 → zero-pad →
/// set go → bounded go-poll → status/syndrome@0x1008 → readback words.
/// Runs ONLY inside [`under_icmd_space`] (ICMD address space).
fn vcr_exchange(
    mtc: &Mtc,
    opcode: u16,
    words: &[u32],
    out_words: usize,
    stop: &AtomicBool,
) -> mlxdirect::err::Result<IcmdResult> {
    let total = out_words.max(words.len());
    // icmd ctrl @0x0: clear go, set opcode
    let ctrl = mtc.read_dword(VCR_CTRL_ADDR)?;
    mtc.write_dword(
        VCR_CTRL_ADDR,
        (ctrl & 0x0000_ffff) | ((opcode as u32) << 16),
    )?;
    for (i, w) in words.iter().enumerate() {
        mtc.write_dword(VCR_CMD_ADDR + 4 * i as u32, *w)?;
    }
    // pad remaining area with zeros so stale words don't leak into output
    for i in words.len()..total {
        mtc.write_dword(VCR_CMD_ADDR + 4 * i as u32, 0)?;
    }
    // set go bit
    let ctrl = mtc.read_dword(VCR_CTRL_ADDR)?;
    mtc.write_dword(VCR_CTRL_ADDR, ctrl | 1)?;
    await_go_clear(SET_ITRACE_GO_DEADLINE, stop, || {
        mtc.read_dword(VCR_CTRL_ADDR)
    })?;
    let final_ctrl = mtc.read_dword(VCR_CTRL_ADDR)?;
    let status = ((final_ctrl >> 8) & 0xff) as u8;
    let syndrome = if status == 0 {
        0
    } else {
        mtc.read_dword(VCR_SYNDROME_ADDR).unwrap_or(0) & 0x00ff_ffff
    };
    let mut data = Vec::with_capacity(total);
    for i in 0..total {
        data.push(mtc.read_dword(VCR_CMD_ADDR + 4 * i as u32)?);
    }
    Ok(IcmdResult {
        status,
        syndrome,
        data,
    })
}

/// Bounded SIGINT-checkable go-poll (live gate attempt 12 fix): read the
/// ctrl dword via `read_ctrl` until the go bit (bit 0) clears. Wall-clock
/// `deadline` budget (ladder sleep 1ms→10ms, mlxdirect CMDQ CQE poll
/// style); `stop` set → clean error, so a SIGINT never needs a watchdog
/// SIGKILL (which leaks the semaphores mid-critical-section). Both error
/// paths unwind through `run_exclusive` → ICMD-semaphore release.
fn await_go_clear(
    deadline: Duration,
    stop: &AtomicBool,
    mut read_ctrl: impl FnMut() -> mlxdirect::err::Result<u32>,
) -> mlxdirect::err::Result<()> {
    let started = std::time::Instant::now();
    let mut polls = 0usize;
    loop {
        let c = read_ctrl()?;
        if c & 1 == 0 {
            return Ok(());
        }
        polls += 1;
        if stop.load(Ordering::SeqCst) {
            return Err(DirectError::Io(format!(
                "go-poll interrupted (SIGINT) after {polls} polls over {:?}, go still set",
                started.elapsed()
            )));
        }
        if started.elapsed() >= deadline {
            return Err(DirectError::Io(format!(
                "go bit stuck: {polls} polls over {:?} (deadline {deadline:?})",
                started.elapsed()
            )));
        }
        let interval = if polls <= 16 { 1 } else { 10 };
        std::thread::sleep(Duration::from_millis(interval));
    }
}

/// SET_ITRACE (0xf003) over the direct BAR0 session (mlxdirect `Icmd`): the
/// ICMD exchange protocol of [`IcmdClient::set_itrace`] (see
/// [`send_direct`]), executed under the per-op ICMD CR-semaphore through
/// mlxdirect's `Icmd::run_exclusive` extension point. `stop` (the trace-arm
/// SIGINT flag) aborts the go-poll with a clean error.
pub fn set_itrace_direct(
    icmd: &Icmd,
    mask: u32,
    level: u8,
    delay: u16,
    stop: &AtomicBool,
) -> anyhow::Result<IcmdResult> {
    let words = [mask, ((delay as u32) << 16) | level as u32];
    let res = icmd
        .run_exclusive(|mtc| send_direct(mtc, ICMD_SET_ITRACE, &words, 8, stop))
        .map_err(|e| anyhow::anyhow!("set_itrace: {e}"))?;
    if !res.is_ok() {
        bail!(
            "set_itrace failed: {}",
            classify_icmd_error(res.status, res.syndrome)
        );
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_walk_finds_vsec() {
        // minimal config: cap ptr at 0x34 -> cap at 0x40 (id 0x10) -> cap at 0x50 (id 0x09)
        let mut cfg = vec![0u8; 0x60];
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x10;
        cfg[0x41] = 0x50;
        cfg[0x50] = 0x09;
        cfg[0x51] = 0x00;
        assert_eq!(find_cap_offset(&cfg, 0x09), Some(0x50));
        assert_eq!(find_cap_offset(&cfg, 0x10), Some(0x40));
        assert_eq!(find_cap_offset(&cfg, 0x11), None);
    }

    #[test]
    fn cap_walk_rejects_loops_and_short() {
        let mut cfg = vec![0u8; 0x60];
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x09;
        cfg[0x41] = 0x40; // loop
        assert_eq!(find_cap_offset(&cfg, 0x09), Some(0x40)); // first match wins
        assert_eq!(find_cap_offset(&cfg, 0x63), None);
        assert_eq!(find_cap_offset(&[0u8; 8], 0x09), None);
        let mut bad = vec![0u8; 0x40];
        bad[0x34] = 0x10; // below 0x40
        assert_eq!(find_cap_offset(&bad, 0x09), None);
    }

    #[test]
    fn op_tlv_get_bytes_exact() {
        // GET (method 1), reg 0x9040, len 4 dwords:
        // byte0 = Type(1)<<3 | len>>8, byte1 = len & 0xff,
        // bytes 4-5 = reg id BE, byte6 = r<<7|method, byte7 = tlv_class
        let b = tlv::op_tlv(tlv::METHOD_GET, 0x9040, 4);
        assert_eq!(
            b,
            [
                0x08, 0x04, 0x00, 0x00, 0x90, 0x40, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn op_tlv_set_method_byte() {
        let b = tlv::op_tlv(tlv::METHOD_SET, 0x9041, 4);
        assert_eq!(b[6], 0x02); // method 2
        assert_eq!(&b[4..6], &[0x90, 0x41]);
        assert_eq!(b[7], 0x01); // MAD_CLASS_1_REG_ACCESS
    }

    #[test]
    fn reg_tlv_len_dwords() {
        // reg data 80 bytes -> len = (80+4)/4 = 21 dwords; Type=3 (TLV_REG)
        let b = tlv::reg_tlv(80);
        assert_eq!(b, [0x18, 0x15, 0x00, 0x00]);
        let b12 = tlv::reg_tlv(12);
        assert_eq!(b12, [0x18, 0x04, 0x00, 0x00]); // len 4
    }

    #[test]
    fn access_reg_frame_layout() {
        let reg = [0xaau8; 8];
        let f = tlv::access_reg_frame(tlv::METHOD_GET, 0x1337, &reg);
        assert_eq!(f.len(), 20 + 8);
        assert_eq!(&f[0..4], &[0x08, 0x04, 0x00, 0x00]);
        assert_eq!(&f[4..8], &[0x13, 0x37, 0x01, 0x01]);
        assert_eq!(&f[16..20], &[0x18, 0x03, 0x00, 0x00]); // len 3 dwords
        assert_eq!(&f[20..], &[0xaa; 8]);
    }

    #[test]
    fn op_tlv_status_extract() {
        // status occupies bits 8..14 -> byte1 bits [7:1]
        let mut buf = vec![0u8; 16];
        buf[1] = 0x2a; // 0x2a>>1 = 0x15
        assert_eq!(tlv::op_tlv_status(&buf), 0x15);
        buf[1] = 0x00;
        assert_eq!(tlv::op_tlv_status(&buf), 0);
    }

    #[test]
    fn quirk_classification() {
        let s = classify_icmd_error(0x3, QUIRK_CONF_SYNDROME);
        assert!(s.contains("exclusive-ownership quirk (MTRC_CONF path)"), "{s}");
        let s = classify_icmd_error(0x3, QUIRK_CTRL_SYNDROME);
        assert!(s.contains("exclusive-ownership quirk (MTRC_CTRL path)"), "{s}");
        let s = classify_icmd_error(0x4, 0x1);
        assert!(s.contains("bad parameter") && s.contains("0x000001"), "{s}");
    }

    // ---------- await_go_clear (live gate attempt 12 fix) ----------

    #[test]
    fn go_poll_returns_once_go_bit_clears() {
        let mut reads = 0u32;
        let r = await_go_clear(Duration::from_secs(60), &AtomicBool::new(false), || {
            reads += 1;
            Ok(if reads == 1 { 1 } else { 0 })
        });
        assert!(r.is_ok());
        assert_eq!(reads, 2, "one busy read + one clear read");
    }

    #[test]
    fn go_poll_deadline_expires_with_clean_error() {
        // go never clears → bounded Err after the injected (short) deadline,
        // not an infinite loop; ladder sleeps keep this fast (~20ms).
        let started = std::time::Instant::now();
        let r = await_go_clear(Duration::from_millis(5), &AtomicBool::new(false), || {
            Ok(0xf003_0001)
        });
        assert!(
            matches!(r, Err(DirectError::Io(_))),
            "deadline error: {r:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "poll must be bounded, took {:?}",
            started.elapsed()
        );
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("go bit stuck"), "diagnostic message: {msg}");
    }

    #[test]
    fn go_poll_stop_flag_interrupts_with_clean_error() {
        // SIGINT flag set mid-poll → clean abort before the (long) deadline.
        let stop = AtomicBool::new(false);
        let mut reads = 0u32;
        let r = await_go_clear(Duration::from_secs(60), &stop, || {
            reads += 1;
            if reads >= 2 {
                stop.store(true, Ordering::SeqCst);
            }
            Ok(1)
        });
        assert!(
            matches!(r, Err(DirectError::Io(_))),
            "interrupt error: {r:?}"
        );
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("SIGINT"), "diagnostic message: {msg}");
        assert!(reads >= 2, "at least one busy poll before the stop check");
    }

    #[test]
    fn go_poll_propagates_read_error() {
        let r = await_go_clear(Duration::from_secs(60), &AtomicBool::new(false), || {
            Err(DirectError::Timeout)
        });
        assert!(matches!(r, Err(DirectError::Timeout)));
    }

    // ---------- under_icmd_space (live gate attempt 13 fix) ----------

    /// Recording mock: one shared trace of space switches and the exchange.
    struct SpaceTrace {
        calls: std::cell::RefCell<Vec<String>>,
        /// Fail the Nth space switch (1-based), if any.
        fail_nth: Option<usize>,
        switches: std::cell::Cell<usize>,
    }

    impl SpaceTrace {
        fn new(fail_nth: Option<usize>) -> Self {
            SpaceTrace {
                calls: std::cell::RefCell::new(Vec::new()),
                fail_nth,
                switches: std::cell::Cell::new(0),
            }
        }

        fn set_space(&self, space: AddressSpace) -> mlxdirect::err::Result<()> {
            self.switches.set(self.switches.get() + 1);
            self.calls
                .borrow_mut()
                .push(format!("space:{}", space.raw()));
            match self.fail_nth {
                Some(n) if n == self.switches.get() => {
                    Err(DirectError::Io(format!("mock: switch {n} fails")))
                }
                _ => Ok(()),
            }
        }
    }

    #[test]
    fn icmd_sandwich_switches_before_and_restores_after_ok_exchange() {
        // Order is the discipline: AS_ICMD (0x3) BEFORE the VCR dwords,
        // AS_CR_SPACE (0x2) restored after — the attempt-13 root cause was
        // the missing 0x3 ("ctrl@0x0" landed on CR 0 = cmd_ptr register).
        let tr = SpaceTrace::new(None);
        let r: mlxdirect::err::Result<u32> = under_icmd_space(
            |space| tr.set_space(space),
            || {
                tr.calls.borrow_mut().push("xchg".into());
                Ok(0x42)
            },
        );
        assert_eq!(r.unwrap(), 0x42);
        assert_eq!(
            *tr.calls.borrow(),
            vec![
                "space:3".to_string(),
                "xchg".to_string(),
                "space:2".to_string()
            ],
            "0x3 before the exchange, 0x2 restored after"
        );
    }

    #[test]
    fn icmd_sandwich_restores_cr_space_on_exchange_error() {
        // Deadline/stop/protocol errors inside the exchange must STILL
        // restore AS_CR_SPACE (live finding: gateway left in Icmd space
        // wedges every CR tool afterwards).
        let tr = SpaceTrace::new(None);
        let r: mlxdirect::err::Result<()> = under_icmd_space(
            |space| tr.set_space(space),
            || Err(DirectError::Io("go bit stuck".into())),
        );
        assert!(r.is_err(), "original exchange error wins");
        assert_eq!(
            *tr.calls.borrow(),
            vec!["space:3".to_string(), "space:2".to_string()],
            "restore happens on the error path"
        );
    }

    #[test]
    fn icmd_sandwich_switch_in_failure_skips_exchange_and_restore() {
        // run_exclusive take semantics: the switch-in failed, the gateway
        // never entered Icmd space → no exchange, no restore attempt.
        let tr = SpaceTrace::new(Some(1));
        let ran = std::cell::Cell::new(false);
        let r: mlxdirect::err::Result<()> = under_icmd_space(
            |space| tr.set_space(space),
            || {
                ran.set(true);
                Ok(())
            },
        );
        assert!(matches!(r, Err(DirectError::Io(_))), "switch error: {r:?}");
        assert!(!ran.get(), "exchange must not run");
        assert_eq!(*tr.calls.borrow(), vec!["space:3".to_string()]);
    }

    #[test]
    fn icmd_sandwich_restore_failure_after_ok_exchange_is_returned() {
        // Not swallowed (dword_rw / fix-round-5 discipline): a successful
        // exchange with a failed restore is an error.
        let tr = SpaceTrace::new(Some(2));
        let r: mlxdirect::err::Result<()> =
            under_icmd_space(|space| tr.set_space(space), || Ok(()));
        assert!(matches!(r, Err(DirectError::Io(_))), "restore error: {r:?}");
        assert_eq!(
            *tr.calls.borrow(),
            vec!["space:3".to_string(), "space:2".to_string()]
        );
    }
}
