//! `trace arm`: driverless tracer arming (mtrcdump flow port) + drain loop.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use mlxdirect::cmds::mkey::{AccessMode, CreateMKey, MKeyContext};
use mlxdirect::cmds::pd::AllocPD;
use mlxdirect::icmd::Icmd;
use mlxdirect::mtcr::{AddressSpace, Mtc};
use mlxdirect::regs::mtrc::{MtrcCapReg, MtrcConfReg, MtrcCtrlReg};
use mlxdirect::session::Direct;

use super::ring::{scan_ring, RingTracker};
use super::strings::StringsDb;
use super::ArmArgs;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn wall_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn mark(t0: Instant, what: &str) {
    println!(
        "[trace-arm] t=+{:>7.3}s wall={} {}",
        t0.elapsed().as_secs_f64(),
        wall_ms(),
        what
    );
}

const MKEY_KEY: u8 = 0x42;

fn clear_region(mem: &mlxdirect::dma::AllocationGuard) -> anyhow::Result<()> {
    use pci_driver::regions::PciRegion;
    for i in 0..mem.len() {
        mem.write_u8(i as u64, 0)?;
    }
    Ok(())
}

/// mtrcdump-parity MTT mkey over `pages` 4KB pages.
fn create_mtt_mkey(
    cmdif: &Direct,
    pd: u32,
    pages: usize,
) -> anyhow::Result<(u32, mlxdirect::dma::AllocationGuard)> {
    let memory = cmdif
        .dma_allocator
        .alloc(pages)
        .ok_or_else(|| anyhow::anyhow!("arm: dma alloc of {pages} pages failed"))?;
    clear_region(&memory)?;
    let mkey_index = cmdif
        .do_command(CreateMKey {
            pg_access: false,
            umem_valid: false,
            context: MKeyContext {
                free: false,
                umr_en: false,
                a: false,
                rw: false,
                rr: false,
                lw: true,
                lr: true,
                access_mode: AccessMode::MTT,
                qpn: 0xffffff,
                mkey: MKEY_KEY,
                length64: false,
                pd,
                start_addr: 0x0000,
                len: 0x1000 * pages as u64,
                bsf_octword_size: 0,
                translation_octword_size: pages as u32 / 2,
                log_entry_size: 12,
            },
            translation_octwords_actual_size: pages as u32 / 2,
            translation_entries: (0..pages)
                .map(|i| (memory.as_ptr().unwrap() as u64 + 0x1000 * (i as u64)) | 0)
                .collect(),
        })?
        .mkey_index;
    Ok(((mkey_index << 8) | (MKEY_KEY as u32), memory))
}

pub fn run(args: &ArmArgs) -> anyhow::Result<()> {
    let t0 = Instant::now();
    let dev = super::normalize_dev(&args.dev);
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
    println!(
        "[trace-arm] dev={} mask={:#x} level={} delay={} size={} out={} flr={}",
        dev.display(),
        args.mask,
        args.level,
        args.delay,
        args.size,
        args.out.display(),
        !args.no_flr
    );

    mark(t0, "opening VFIO (reset+init)");
    let cmdif = Direct::open_from_sysfs(&dev, !args.no_flr, true)?;
    mark(t0, "VFIO open+init done");

    if args.badc_unlock {
        let mtcr = Mtc::from_direct(&cmdif)?;
        mtcr.change_address_space(AddressSpace::CrSpace)?;
        let before = mtcr.read_dword(0x23f0)?;
        mtcr.write_dword(0x23f0, 0xbadc0ffe)?;
        let after = mtcr.read_dword(0x23f0)?;
        mark(
            t0,
            &format!("badc0ffe unlock: 0x23f0 0x{before:08x} -> 0x{after:08x}"),
        );
    }

    mark(t0, "AllocPD");
    let pd = cmdif.do_command(AllocPD {})?.pd;
    mark(t0, &format!("AllocPD pd={pd}"));

    let pages = 1usize << args.size;
    mark(t0, "CreateMKey(MTT)");
    let (trace_mkey, trace_mem) = create_mtt_mkey(&cmdif, pd, pages)?;
    mark(
        t0,
        &format!("CreateMKey mkey=0x{trace_mkey:x} pages={pages}"),
    );

    mark(t0, "MTRC_CAP SET trace_owner=1");
    let cap = cmdif.write_register(
        MtrcCapReg {
            trace_owner: true,
            ..Default::default()
        },
        0,
    )?;
    if cap.log_max_trace_buffer_size < args.size {
        anyhow::bail!(
            "arm: log_max_trace_buffer_size={} < requested size {}",
            cap.log_max_trace_buffer_size,
            args.size
        );
    }
    let db0 = cap
        .string_db_param
        .iter()
        .map(|p| (p.address as u64, p.size as u64))
        .max_by_key(|&(a, s)| (s, a))
        .filter(|&(a, s)| s > 0 && a >= 0x00800000)
        .unwrap_or(super::DEFAULT_DB0);
    mark(
        t0,
        &format!(
            "MTRC_CAP readback: trc_ver={} log_max=0x{:x} db0=0x{:08x}/0x{:x}",
            cap.trc_ver, cap.log_max_trace_buffer_size, db0.0, db0.1
        ),
    );

    mark(t0, "MTRC_CONF SET mode=1");
    let conf = cmdif.write_register(
        MtrcConfReg {
            trace_mode: 1,
            trace_mkey,
            log_trace_buffer_size: args.size,
        },
        0,
    )?;
    mark(
        t0,
        &format!(
            "MTRC_CONF readback: mode={} log_size=0x{:x} mkey=0x{:08x}",
            conf.trace_mode, conf.log_trace_buffer_size, conf.trace_mkey
        ),
    );

    mark(t0, "MTRC_CTRL SET arm");
    let ctrl = cmdif.write_register(
        MtrcCtrlReg {
            trace_status: 1,
            arm_event: true,
            modify_field_select: 1,
            ..Default::default()
        },
        0,
    )?;
    mark(
        t0,
        &format!(
            "MTRC_CTRL readback: status={} arm={}",
            ctrl.trace_status, ctrl.arm_event as u8
        ),
    );

    mark(t0, "SET_ITRACE 0xf003");
    let mtc = Mtc::from_direct(&cmdif)?;
    let icmd = Icmd::from_mtc(mtc)?;
    super::vsec::set_itrace_direct(&icmd, args.mask, args.level, args.delay, &STOP)?;
    mark(
        t0,
        &format!("SET_ITRACE done mask={:#x} level={}", args.mask, args.level),
    );

    // Drain loop: the VFIO process must stay alive while FW DMAs into the ring.
    let strings = match &args.image {
        Some(p) => Some(StringsDb::load(p, db0)?),
        None => None,
    };
    let ring_len = pages * 0x1000;
    let mut ring_buf = vec![0u8; ring_len];
    let mut tracker = RingTracker::default();
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.out)
        .with_context_append(&args.out)?;
    println!(
        "[trace-arm] draining (poll {} ms, SIGINT to stop) ring={} bytes db0=0x{:08x}/0x{:x}",
        args.poll_ms, ring_len, db0.0, db0.1
    );

    let mut total_events = 0usize;
    let mut first_event_at: Option<Instant> = None;
    while !STOP.load(Ordering::SeqCst) {
        use pci_driver::regions::PciRegion;
        trace_mem.read_bytes(0, &mut ring_buf)?;
        let events = scan_ring(&ring_buf, db0);
        let mut fresh = 0usize;
        for e in &events {
            if tracker.is_new(e) {
                fresh += 1;
                if first_event_at.is_none() {
                    first_event_at = Some(Instant::now());
                    mark(
                        t0,
                        &format!(
                            "FIRST EVENT ring+0x{:05x} rt=0x{:08x}",
                            e.ring_off, e.rt
                        ),
                    );
                }
                let line = e.render(strings.as_ref());
                writeln!(out, "{} {}", wall_ms(), line)?;
                println!("[trace-arm] ev {}", line);
            }
        }
        total_events += fresh;
        if fresh > 0 {
            out.flush()?;
            println!(
                "[trace-arm] poll: +{fresh} (total {total_events}) events in ring scan"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(args.poll_ms));
    }

    // Teardown. Re-arm the STOP flag semantics: the drain stop was consumed;
    // a SECOND SIGINT now aborts a hung teardown exchange (bounded go-poll
    // in set_itrace_direct) instead of needing a watchdog SIGKILL.
    STOP.store(false, Ordering::SeqCst);
    mark(t0, "SIGINT: teardown");
    let disarm = cmdif.write_register(
        MtrcCtrlReg {
            trace_status: 0,
            arm_event: false,
            modify_field_select: 1,
            ..Default::default()
        },
        0,
    );
    match disarm {
        Ok(c) => mark(
            t0,
            &format!("disarm readback: status={}", c.trace_status),
        ),
        Err(e) => println!("[trace-arm] WARN disarm failed: {e:?}"),
    }
    if !args.keep_mask {
        let mtc = Mtc::from_direct(&cmdif)?;
        let icmd = Icmd::from_mtc(mtc)?;
        match super::vsec::set_itrace_direct(&icmd, 0, 0, 0, &STOP) {
            Ok(_) => mark(t0, "SET_ITRACE 0 done (mask cleared)"),
            Err(e) => println!("[trace-arm] WARN mask clear failed: {e:?}"),
        }
    }
    if let Some(raw) = &args.raw_out {
        use pci_driver::regions::PciRegion;
        trace_mem.read_bytes(0, &mut ring_buf)?;
        std::fs::write(raw, &ring_buf)?;
        mark(t0, &format!("raw ring dump {} bytes -> {}", ring_len, raw.display()));
    }
    println!(
        "[trace-arm] done: total_events={total_events} first_event={}",
        first_event_at
            .map(|i| format!("+{:.3}s", i.duration_since(t0).as_secs_f64()))
            .unwrap_or_else(|| "never".into())
    );
    Ok(())
}

trait WithContextAppend {
    fn with_context_append(self, p: &Path) -> anyhow::Result<std::fs::File>;
}

impl WithContextAppend for std::io::Result<std::fs::File> {
    fn with_context_append(self, p: &Path) -> anyhow::Result<std::fs::File> {
        self.map_err(|e| anyhow::anyhow!("arm: open out {}: {e}", p.display()))
    }
}
