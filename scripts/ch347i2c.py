#!/usr/bin/env python3
"""ch347i2c.py — userspace I2C master для CH347T mode#1 (1a86:55db), чистый
ctypes поверх libusb-1.0 (без pyusb: на целевом хосте bazzite нет ни pyusb,
ни pip; системная libusb-1.0.so.0 есть).

USB: interface #2 (I2C), bulk OUT EP 0x06 / IN EP 0x86 (sysfs 3-2:1.2,
bazzite 2026-11-21); IF0/IF1 заняты cdc_acm (UART). Канон интерфейса —
WCH ch34x_mphsi_master_usb.c (USB_DEVICE_INTERFACE_NUMBER(1a86,55db,0x02),
55db → CHIP_CH347T).

Два семейства транзакций (--family):

1. `legacy` (DEFAULT) — AA-стрим (токены 0x74/0x75/0x80|N/0xC0|N/
   0x60|spd/0x00), канон i2c-ch347.c (aystarik/ch347_vcp патч-серия)
   + WCH ch341_i2c_stream/ch347_i2c_stream (ch34x_mphsi_master_i2c.c:
   59/173 — единственная семья для CH347T по диспетчеру :550-561).
   **ЕДИНСТВЕННАЯ РАБОЧАЯ на fw 5.44**: live-ACK @0x48 (CX-5,
   2026-11-21) на 20/100 кГц, стабильность 10/10. Честность клока —
   латентностным полом: @20 кГц проба 0.65-0.75 мс ≥ 0.45 мс (9 клоков
   адресной фазы) + USB; пресеты масштабируются (100/400/750 кГц →
   0.21/0.12/0.11 мс). Раунды 2-5 журнала (суб-полные 0.1-0.2 мс при
   заявленных 20 кГц, «фабрикация») — двигатель был в деградированном
   состоянии (SET не действовал); универсальный вердикт «фабрикация»
   ОТЗЫВАН после измерения честного пола; причина тогдашних NAK не
   установлена однозначно (кандидаты: поздняя активация I2C-слейва
   карты при буте/линке, пересев контактов владельцем, состояние fw).

2. `mphsi` — пакетный формат 0xD9/~0xD9 с 2-байтным ack-счётчиком
   (WCH ch34x_mphsi_master_i2c.c:322-499 `ch9341_i2c_stream`; формат в
   mphsi_transact). На fw 5.44 МЕРТВ: 0xDB INIT и 0xD9-стрим не
   получают НИКАКОГО ответа на IN-эндпоинте (таймаут) — fw игнорирует
   не-AA пакеты молча. Драйвер шлёт эту семью только CH9341C
   (диспетчер :550-561). Оставлен для референса/будущих fw.

Скорость: AA SET|spd (`ch34x_mphsi_i2c_init`, :677-687);
дополнительно при mphsi шлётся 0xDB INIT (форма CH9341C, :657-676) —
без ответа на этой fw (non-fatal).

Чанк одной транзакции: 0x3F (CH347_CMD_I2C_STM_MAX, ch34x_mphsi.h:136).
Write-примитив есть, но по write-политике цикла 2 против карты НЕ
применяется (только будущий таск 5).

CR-слой (legacy; канон docs/250-re/140-oob-i2c/100-protocol.md §2.1/§2.3):
`crread`/`devid` — combined-транзакция `S [addrW BE32(cr)] Sr [addrR NБ] P`,
OUT|N = N байт после токена (адресный включён), статус-байт 0x01 на каждый
OUT-байт (проверяются все), данные BE. Честные полы клока @20 кГц (honesty-
гейт, 9 клоков/байт): mread4 = 10Б = 4.5 мс; блок 16Б = 22Б = 9.9 мс;
блок 64Б = 70Б = 31.5 мс — латентность ниже пола = двигателю не верить.

GW-слой (канон §2.2/§7.3/§12.3): `crwrite`-примитив mwrite4 (`AA STA OUT|9
addrW BE32(cr) BE32(val) STO END`, 9 статус-байт, пол @20 кГц 4.05 мс);
GW-циклы `gwsmoke`/`gwres`/`gwread` — под lock/unlock-обёрткой §7.3 (poll
CMD@0xf0400 бит31 → RMW cache-rep-en@0xf0420; unlock в finally: restore
RMW + CMD=0). Между Go (CMD-write) и DATA-read паузы НЕТ — семантика
busy-poll skip канона §7.4 (честный O9-замер).

W1 (спека транспорта §3.3, T5): `w1` — write-механика GW DATA без Go под
обёрткой §7.3: фоновое чтение DATA-окна + варианты 1–5 (кадр 26 Б как
есть / ZLP / multi-OUT-токены / OUT-продолжение кадрами / re-addressed
mwrite4-split) c read-back-верификацией доставки; `--variants` — выбор
подмножества (v2/ZLP гейтен --allow-zlp: на fw 5.44 ВРЕДЕН — валит
IN-эндпоинт адаптера, вердикт T5 r3).

Дамп/H-ROM (T6, FNP-окно): `gwdump` — полный дамп flash циклами канона
§8.2 (на 16Б-блок: lock → ADDR → CMD READ 0xC003041D → DATA 16Б →
unlock), прогресс-маркеры, sidecar `.progress` (next_block) для
--resume, bounded self-stop (deadline/max-blocks; kill недопустим —
850-howto/100 §1.2), восстановление адаптера после wedge
(libusb_reset_device — урок T5 r3); `hrom` — bounded-скан H-ROM
кандидат-адресов (boot-кандидаты phase-XIII 030/130-доков + контроли
декодирования) с критериями данные/мусор/NAK (повторяемость ×2,
data_sane, энтропия окна).
"""
import argparse
import ctypes
import ctypes.util
import sys

VID, PID = 0x1A86, 0x55DB
IFACE = 2
EP_OUT, EP_IN = 0x06, 0x86
CMD_STREAM = 0xAA
STM_STA, STM_STO, STM_OUT, STM_IN, STM_SET, STM_END = 0x74, 0x75, 0x80, 0xC0, 0x60, 0x00
MAX_XFER = 0x3F
TIMEOUT = 2000
SPEEDS = {0: 20000, 1: 100000, 2: 400000, 3: 750000}
SPEED_NAMES = {0: "20kHz", 1: "100kHz", 2: "400kHz", 3: "750kHz"}

M9_STREAM, M9_INIT = 0xD9, 0xDB
M9_START, M9_STOP, M9_OUT, M9_IN_N, M9_IN_A, M9_ADDR = 0x03, 0x04, 0x05, 0x06, 0x07, 0x08


class Usb:
    def __init__(self):
        self.lib = ctypes.CDLL(ctypes.util.find_library("usb-1.0"), use_errno=True)
        self.lib.libusb_init.restype = ctypes.c_int
        rc = self.lib.libusb_init(None)
        if rc != 0:
            sys.exit(f"libusb_init failed: {rc}")
        self.handle = None

    def open_dev(self):
        lib = self.lib
        lib.libusb_get_device_list.restype = ctypes.c_ssize_t
        lib.libusb_get_device_list.argtypes = [ctypes.c_void_p,
                                               ctypes.POINTER(ctypes.c_void_p)]
        lst = ctypes.c_void_p()
        cnt = lib.libusb_get_device_list(None, ctypes.byref(lst))
        if cnt < 0:
            raise OSError(f"libusb_get_device_list failed: {cnt}")
        lib.libusb_get_device_descriptor.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.libusb_open.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        dev = None
        desc = (ctypes.c_ubyte * 18)()
        arr = (ctypes.c_void_p * cnt).from_address(lst.value)
        for i in range(cnt):
            if lib.libusb_get_device_descriptor(arr[i], desc) != 0:
                continue
            vend = desc[8] | (desc[9] << 8)
            prod = desc[10] | (desc[11] << 8)
            if vend == VID and prod == PID:
                h = ctypes.c_void_p()
                if lib.libusb_open(arr[i], ctypes.byref(h)) == 0:
                    dev = h
                break
        lib.libusb_free_device_list(lst, 1)
        if dev is None:
            raise OSError(f"CH347 ({VID:04x}:{PID:04x}) не найден в USB")
        self.handle = dev
        lib.libusb_kernel_driver_active.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_detach_kernel_driver.argtypes = [ctypes.c_void_p, ctypes.c_int]
        if lib.libusb_kernel_driver_active(self.handle, IFACE):
            lib.libusb_detach_kernel_driver(self.handle, IFACE)
        lib.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        rc = lib.libusb_claim_interface(self.handle, IFACE)
        if rc != 0:
            raise OSError(f"claim_interface({IFACE}) failed: {rc}")
        return self

    def bulk(self, ep_out, data, rlen):
        lib = self.lib
        lib.libusb_bulk_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p, ctypes.c_int,
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
        transferred = ctypes.c_int(0)
        buf = ctypes.create_string_buffer(bytes(data), max(len(data), 1))
        rc = lib.libusb_bulk_transfer(self.handle, ep_out, buf, len(data),
                                      ctypes.byref(transferred), TIMEOUT)
        if rc != 0 or transferred.value != len(data):
            raise OSError(f"bulk OUT ep 0x{ep_out:02x}: rc={rc}, "
                          f"sent={transferred.value}/{len(data)}")
        if rlen > 0:
            buf = ctypes.create_string_buffer(rlen)
            rc = lib.libusb_bulk_transfer(self.handle, EP_IN, buf, rlen,
                                          ctypes.byref(transferred), TIMEOUT)
            if rc != 0 or transferred.value != rlen:
                raise OSError(f"bulk IN ep 0x{EP_IN:02x}: rc={rc}, "
                              f"got={transferred.value}/{rlen}")
            return buf.raw[:rlen]
        return b""

    def close(self):
        if self.handle:
            self.lib.libusb_release_interface(self.handle, IFACE)
            self.lib.libusb_close(self.handle)
        self.lib.libusb_exit(None)


# --- legacy AA-семья (симулируется fw 5.44; референс) ---

def frame(tokens):
    return bytes([CMD_STREAM] + tokens)


def set_speed_legacy(u, speed):
    u.bulk(EP_OUT, frame([STM_SET | (speed & 3), STM_END]), 0)


def probe_legacy(u, addr, read_direction=False):
    if read_direction:
        fr = frame([STM_STA, STM_OUT, (addr << 1) | 1, STM_IN, STM_STO, STM_END])
        st = u.bulk(EP_OUT, fr, 2)
    else:
        fr = frame([STM_STA, STM_OUT, (addr << 1) & 0xFE, STM_STO, STM_END])
        st = u.bulk(EP_OUT, fr, 1)
    return st[0] == 0x01, st


def read_legacy(u, addr, n):
    out = b""
    off = 0
    while off < n:
        take = min(n - off, MAX_XFER)
        tokens = [STM_STA, STM_OUT | 1, (addr << 1) | 1]
        if take > 1:
            tokens.append(STM_IN | (take - 1))
        tokens += [STM_IN, STM_STO, STM_END]
        buf = u.bulk(EP_OUT, frame(tokens), take + 1)
        if buf[0] != 0x01:
            raise OSError(f"read status != ACK: 0x{buf[0]:02x}")
        out += buf[1:]
        off += take
    return out


# --- CR-слой поверх legacy (канон 100-protocol §2, WCH ch347_i2c_stream) ---

def cr_read_frames(addr, cr_addr, n):
    """Кадр combined CR-чтения (канон §2.1, спека транспорта §3.2, WCH
    ch34x_mphsi_master_i2c.c:173-300):
    `AA STA OUT|5 addrW BE32(cr) STA OUT|1 addrR IN|(k-1) ... IN STO END`
    — repeated START между фазами, без STOP; OUT|N = N байт после токена
    (адресный включён); IN|k = k байт с ACK, голый IN = последний байт с
    NAK; IN-токены ≤ MAX_XFER. Возвращает (кадр, ackbits).
    """
    tokens = [CMD_STREAM, STM_STA, STM_OUT | 5, (addr << 1) & 0xFE]
    tokens += list((cr_addr & 0xFFFFFFFF).to_bytes(4, "big"))
    tokens += [STM_STA, STM_OUT | 1, (addr << 1) | 1]
    remaining = n
    while remaining > 0:
        take = min(remaining, MAX_XFER)
        if remaining - take > 0 and take == MAX_XFER:
            tokens.append(STM_IN | take)
        elif take > 1:
            tokens.append(STM_IN | (take - 1))
            tokens.append(STM_IN)
        else:
            tokens.append(STM_IN)
        remaining -= take
    tokens += [STM_STO, STM_END]
    return bytes(tokens), 6


def cr_read(u, addr, cr_addr, n, note=None):
    """Combined CR-read n байт (канон §2.1/§2.3): транзакция целиком,
    статус-байт на каждый OUT-байт (6 шт), каждый обязан быть 0x01
    (CH347-семантика; урок T1: нулевым данным без валидации не верить).
    Возвращает (данные, латентность_мс)."""
    import time
    fr, ackbits = cr_read_frames(addr, cr_addr, n)
    t0 = time.time()
    buf = u.bulk(EP_OUT, fr, ackbits + n)
    ms = (time.time() - t0) * 1000
    for k in range(ackbits):
        if buf[k] != 0x01:
            raise OSError(f"cr_read@0x{cr_addr:08x}: NAK статус-байт {k}: "
                          f"0x{buf[k]:02x} (raw={buf.hex()})")
    if note:
        print(f"  {note}: frame={fr.hex()} -> data={buf[ackbits:].hex()} "
              f"[{ms:.2f} ms]")
    return buf[ackbits:], ms


def cr_read32(u, addr, cr_addr):
    data, ms = cr_read(u, addr, cr_addr, 4)
    return int.from_bytes(data, "big"), data, ms


# --- GW-слой поверх legacy (канон 100-protocol §7.1 legacy / §7.3 / §12.3) ---

GW_CMD, GW_ADDR, GW_DATA, GW_LOCK_EN = 0xF0400, 0xF0404, 0xF0410, 0xF0420
CMD_RDID, CMD_RES, CMD_READ16 = 0xC09F0215, 0xC0AB0215, 0xC003041D
JEDEC_VENDORS = {0x01: "Spansion", 0x04: "Fujitsu", 0x20: "Micron",
                 0x37: "AMIC", 0x62: "Sanyo", 0x9d: "ISSI",
                 0xc2: "Macronix", 0xef: "Winbond"}


class GwSemaphoreHeld(OSError):
    """CMD@0xf0400 бит31=1 весь таймаут — семафор держит живой FW (факт R2)."""


GW_FORCED_LOCKS = 0


def cr_write_frames(addr, cr_addr, value):
    """Кадр mwrite4 (канон §2.2): `AA STA OUT|9 addrW BE32(cr) BE32(val)
    STO END` — одна write-фаза; статус-байт на каждый из 9 OUT-байт.
    Честный пол клока @20 кГц: 9 Б × 9 клоков = 4.05 мс."""
    tokens = [CMD_STREAM, STM_STA, STM_OUT | 9, (addr << 1) & 0xFE]
    tokens += list((cr_addr & 0xFFFFFFFF).to_bytes(4, "big"))
    tokens += list((value & 0xFFFFFFFF).to_bytes(4, "big"))
    tokens += [STM_STO, STM_END]
    return bytes(tokens), 9


def cr_write(u, addr, cr_addr, value, note=None):
    """mwrite4 с валидацией статусов (9×0x01); возвращает латентность_мс."""
    import time
    fr, ackbits = cr_write_frames(addr, cr_addr, value)
    t0 = time.time()
    buf = u.bulk(EP_OUT, fr, ackbits)
    ms = (time.time() - t0) * 1000
    for k in range(ackbits):
        if buf[k] != 0x01:
            raise OSError(f"cr_write@0x{cr_addr:08x}=0x{value:08x}: NAK "
                          f"статус-байт {k}: 0x{buf[k]:02x} (raw={buf.hex()})")
    if note:
        print(f"  {note}: frame={fr.hex()} -> {ackbits}x01 [{ms:.2f} ms]")
    return ms


def gw_lock(u, addr, pause, poll_ms=100, timeout_s=5.0, quiet=False,
            force=False):
    """lock-обёртка канона §7.3 п.1/§12.3-1: poll CMD@0xf0400 бит31==0 →
    RMW-disable cache-rep-en@0xf0420 (бит0=0). Каденс 100 мс вместо
    канонических 1 мс mflash — защита fw 5.44 от молотения (уроки T1/T2);
    на факт «взял/таймаут 5 с» каденс не влияет. quiet=True — без
    print-строк (дамп-цикл: 65536 блоков × 3 строки — флад лога).
    force=True — FNP/livefish-путь (T15-прецедент: в FNP семафор держит
    HW/recovery-agent, mstflint сам берёт lock с warning): при бит31=1
    без ожидания — release stale (W CMD=0) + повторное чтение → RMW
    вопреки биту. Возвращает (исходный dword 0xf0420, dword CMD первого
    опроса, число опросов)."""
    import time
    deadline = time.time() + timeout_s
    dword, _, _ = cr_read32(u, addr, GW_CMD)
    polls = 1
    if not quiet:
        print(f"  lock: poll CMD@0xf0400 = 0x{dword:08x} бит31="
              f"{(dword >> 31) & 1} (опрос 1)")
    while (dword >> 31) & 1:
        if force:
            global GW_FORCED_LOCKS
            GW_FORCED_LOCKS += 1
            if GW_FORCED_LOCKS == 1:
                print("  lock: FORCE — семафор занят; release stale "
                      "(W CMD=0) + proceed с warning (T15-прецедент, "
                      "FNP; повторные force — молча, счётчик "
                      "GW_FORCED_LOCKS)", flush=True)
            cr_write(u, addr, GW_CMD, 0,
                     note=None if quiet else
                     "force: W CMD@0xf0400=0 (release stale)")
            pause()
            dword, _, _ = cr_read32(u, addr, GW_CMD)
            break
        if time.time() >= deadline:
            raise GwSemaphoreHeld(
                f"CMD@0xf0400=0x{dword:08x}: бит31=1 после {polls} опросов "
                f"за {timeout_s} с — семафор держит живой FW")
        time.sleep(poll_ms / 1000)
        dword, _, _ = cr_read32(u, addr, GW_CMD)
        polls += 1
        if not quiet:
            print(f"  lock: poll CMD@0xf0400 = 0x{dword:08x} бит31="
                  f"{(dword >> 31) & 1} (опрос {polls})")
    pause()
    orig_b, _ = cr_read(u, addr, GW_LOCK_EN, 4,
                        note=None if quiet else
                        "lock: R cache-rep-en@0xf0420")
    orig = int.from_bytes(orig_b, "big")
    pause()
    cr_write(u, addr, GW_LOCK_EN, orig & ~1,
             note=None if quiet else
             f"lock: W cache-rep-en disable (0x{orig & ~1:08x})")
    return orig, dword, polls


def gw_unlock(u, addr, pause, quiet=False):
    """unlock канона §7.3 п.6/§12.3-1: RMW-restore @0xf0420 (R → W бит0=1,
    чтение свежего значения) + запись CMD@0xf0400=0. Вызывается в finally
    каждого GW-цикла. quiet=True — без print-строк (дамп-цикл)."""
    pause()
    cur_b, _ = cr_read(u, addr, GW_LOCK_EN, 4,
                       note=None if quiet else
                       "unlock: R cache-rep-en@0xf0420")
    cur = int.from_bytes(cur_b, "big")
    pause()
    cr_write(u, addr, GW_LOCK_EN, cur | 1,
             note=None if quiet else
             f"unlock: W cache-rep-en restore (0x{cur | 1:08x})")
    pause()
    cr_write(u, addr, GW_CMD, 0,
             note=None if quiet else "unlock: W CMD@0xf0400=0")


# --- W1: write-механика CH347 (спека §3.3 варианты 1–5, T5) ---

def cr_write_block_frames(addr, cr_addr, data, split_out=False):
    """Кадр одной write-транзакции §2.4 (mwrite4_block, канон §7.3 п.2):
    `AA STA OUT|N addrW BE32(cr) data STO END`, N = 1+4+len(data)
    (адресный байт включён), статус-байт на каждый OUT-байт.

    split_out=True — вариант 3 §3.3: два OUT-токена
    `… OUT|5 addrW BE32 OUT|M data …` (STA/STO между токенами НЕТ —
    последовательные шинные действия, wire-эквивалентно варианту 1)."""
    m = len(data)
    n_head = 5 if split_out else 5 + m
    tokens = [CMD_STREAM, STM_STA, STM_OUT | n_head, (addr << 1) & 0xFE]
    tokens += list((cr_addr & 0xFFFFFFFF).to_bytes(4, "big"))
    if split_out:
        tokens += [STM_OUT | m] + list(data)
    else:
        tokens += list(data)
    tokens += [STM_STO, STM_END]
    return bytes(tokens), 5 + m


def cr_write_block(u, addr, cr_addr, data, note=None, split_out=False,
                   zlp=False):
    """§2.4-блок одной транзакцией с валидацией статусов (все 0x01);
    zlp=True — вариант 2 §3.3: zero-length packet после длинного кадра.
    Возвращает латентность_мс."""
    import time
    fr, ackbits = cr_write_block_frames(addr, cr_addr, data, split_out)
    t0 = time.time()
    buf = u.bulk(EP_OUT, fr, ackbits)
    if zlp:
        u.bulk(EP_OUT, b"", 0)
    ms = (time.time() - t0) * 1000
    for k in range(ackbits):
        if buf[k] != 0x01:
            raise OSError(f"cr_write_block@0x{cr_addr:08x}: NAK "
                          f"статус-байт {k}: 0x{buf[k]:02x} "
                          f"(raw={buf.hex()})")
    if note:
        print(f"  {note}: frame={fr.hex()} ({len(fr)} B) -> {ackbits}x01 "
              f"[{ms:.2f} ms]")
    return ms


def cr_write_block_cont_frames(addr, cr_addr, data, chunk=8):
    """Вариант 4 §3.3 — OUT-продолжение кадрами (как IN-продолжение для
    чтения): кадр-голова `AA STA OUT|5 addrW BE32` БЕЗ STO/END, затем кадры
    `AA OUT|N data`, STO/END только в последнем. Возвращает
    (голова, [кадры], всего_статусов)."""
    head = bytes([CMD_STREAM, STM_STA, STM_OUT | 5, (addr << 1) & 0xFE]
                 + list((cr_addr & 0xFFFFFFFF).to_bytes(4, "big")))
    frames = []
    off = 0
    while off < len(data):
        take = min(chunk, len(data) - off)
        toks = [CMD_STREAM, STM_OUT | take] + list(data[off:off + take])
        if off + take >= len(data):
            toks += [STM_STO, STM_END]
        frames.append(bytes(toks))
        off += take
    return head, frames, 5 + len(data)


def cr_write_block_cont(u, addr, cr_addr, data, note=None):
    """Вариант 4 §3.3: отправка голова+кадры; статусы (5+M шт) читаем
    одним bulk-стримом после последнего кадра (движок может отдавать их
    только по END). Возвращает латентность_мс."""
    import time
    head, frames, ackbits = cr_write_block_cont_frames(addr, cr_addr, data)
    t0 = time.time()
    u.bulk(EP_OUT, head, 0)
    for fr in frames[:-1]:
        u.bulk(EP_OUT, fr, 0)
    buf = u.bulk(EP_OUT, frames[-1], ackbits)
    ms = (time.time() - t0) * 1000
    for k in range(ackbits):
        if buf[k] != 0x01:
            raise OSError(f"cr_write_block_cont@0x{cr_addr:08x}: NAK "
                          f"статус-байт {k}: 0x{buf[k]:02x} "
                          f"(raw={buf.hex()})")
    if note:
        print(f"  {note}: head={head.hex()} + "
              + " ".join(f.hex() for f in frames)
              + f" -> {ackbits}x01 [{ms:.2f} ms]")
    return ms


def probe_alive(u, addr, pause, tries=3):
    """Hang-детектор T5: probe ×tries с паузами; (все ACK, [результаты])."""
    res = []
    for _ in range(tries):
        ok, _st = probe_legacy(u, addr)
        res.append(ok)
        pause()
    return all(res), res


def gw_cold_lock(u, addr, pause, rmw_pause_s=0.15):
    """Cold-start lock (round-3 дизайн, журнал task-05 r2/r3): ПЕРВОЕ
    GW-прикосновение бута — чтение базиса RMW @0xf0420; CMD@0xf0400 НЕ
    трогаем до установки disable. Последовательность:
    R@0xf0420 (базис) → 150 мс → W@0xf0420 bit0=0 (disable) → пауза →
    ОДНО чтение CMD@0xf0400 (verify бит31).
    Контрольные точки (фальсифицируемые): (C1) если CMD бит31=1 на verify
    — либо RMW-областные чтения тоже провоцируют (захват успел до/вопреки
    disable), либо disable не предотвращает установку бита; (C2) если
    бит31=0 — disable стоит, lock считаем взятым (выживание disable против
    провоцированного захвата проверяется исходом сессии). Провал:
    восстановление ТОЧНОГО базиса @0xf0420, БЕЗ записи CMD (чужое не
    отпускаем). Возвращает (ok, basis, cmd_verify_dword)."""
    import time
    basis_b, ms = cr_read(u, addr, GW_LOCK_EN, 4,
                          note="cold: R basis@0xf0420 (первое "
                               "GW-прикосновение бута)")
    basis = int.from_bytes(basis_b, "big")
    time.sleep(rmw_pause_s)
    cr_write(u, addr, GW_LOCK_EN, basis & ~1,
             note=f"cold: W disable (0x{basis & ~1:08x})")
    pause()
    cmd_b, _ = cr_read(u, addr, GW_CMD, 4,
                       note="cold: R CMD@0xf0400 verify (одиночное)")
    cmd = int.from_bytes(cmd_b, "big")
    if (cmd >> 31) & 1:
        print(f"cold: VERIFY FAIL — CMD=0x{cmd:08x} бит31=1 (C1: захват "
              f"успел/провоцирован RMW-фазой)")
        try:
            cur_b, _ = cr_read(u, addr, GW_LOCK_EN, 4,
                               note="cold-fail: R@0xf0420 (какой бит "
                                    "стоит сейчас)")
            cur = int.from_bytes(cur_b, "big")
            print(f"cold-fail: 0xf0420 сейчас 0x{cur:08x} (наш disable "
                  f"{'стоит' if not (cur & 1) else 'отсутствует/стёрт'})")
            cr_write(u, addr, GW_LOCK_EN, basis,
                     note=f"cold-fail: W restore basis (0x{basis:08x})")
        except OSError as e:
            print(f"cold-fail: restore FAIL: {e}")
        return False, basis, cmd
    print(f"cold: VERIFY OK — CMD=0x{cmd:08x} бит31=0 при disable — "
          f"LOCK HELD (C2: сессия проверит выживание disable)")
    return True, basis, cmd


# --- T6 FNP-окно: полный дамп §8.2 + bounded H-ROM-скан (O7) ---

def gw_read_block_cycle(u, addr, flash_addr, pace, poll_ms=20,
                        timeout_s=2.0, force=False):
    """Один §8.2-цикл чтения 16Б flash-блока: полный GW-цикл
    lock (poll CMD + RMW disable, quiet) → ADDR → CMD READ 0xC003041D
    (Go) → DATA 16Б сразу после Go, без пере-чтения CMD (busy-poll skip
    §7.4) → unlock в finally (RMW restore + CMD=0, quiet). Возвращает
    16Б flash-контента."""
    gw_lock(u, addr, pace, poll_ms=poll_ms, timeout_s=timeout_s,
            quiet=True, force=force)
    try:
        pace()
        cr_write(u, addr, GW_ADDR, flash_addr)
        pace()
        cr_write(u, addr, GW_CMD, CMD_READ16)
        data, _ms = cr_read(u, addr, GW_DATA, 16)
        return data
    finally:
        pace()
        gw_unlock(u, addr, pace, quiet=True)


def gw_read_block_packed_frames(addr, flash_addr):
    """T6-opt L2: три i2c-транзакции блокочного цикла §8.2 (ADDR-write,
    CMD-write Go, DATA-combined-read) ОДНИМ AA-стримом — один USB
    round-trip на блок вместо трёх; статусы/данные накапливаются в
    буфере движка и читаются одним bulk IN. DATA-чтение следует за Go
    вплотную (смежные транзакции стрима — busy-poll skip §7.4 сохранён).
    Возвращает (кадр, ackbits=24; ожидаемый IN = 24 статус + 16Б)."""
    toks = [CMD_STREAM]
    toks += ([STM_STA, STM_OUT | 9, (addr << 1) & 0xFE]
             + list(GW_ADDR.to_bytes(4, "big"))
             + list(flash_addr.to_bytes(4, "big")) + [STM_STO])
    toks += ([STM_STA, STM_OUT | 9, (addr << 1) & 0xFE]
             + list(GW_CMD.to_bytes(4, "big"))
             + list(CMD_READ16.to_bytes(4, "big")) + [STM_STO])
    toks += ([STM_STA, STM_OUT | 5, (addr << 1) & 0xFE]
             + list(GW_DATA.to_bytes(4, "big"))
             + [STM_STA, STM_OUT | 1, (addr << 1) | 1, STM_IN | 15,
                STM_IN, STM_STO])
    toks += [STM_END]
    return bytes(toks), 24


def gw_read_block_packed(u, addr, flash_addr):
    """Пакетный блокочный цикл (L2): отправка packed-кадра + валидация
    24 статус-байт + возврат 16Б данных."""
    fr, ackbits = gw_read_block_packed_frames(addr, flash_addr)
    buf = u.bulk(EP_OUT, fr, ackbits + 16)
    for k in range(ackbits):
        if buf[k] != 0x01:
            raise OSError(f"gw_read_block_packed@0x{flash_addr:x}: NAK "
                          f"статус-байт {k}: 0x{buf[k]:02x} "
                          f"(raw={buf.hex()})")
    return buf[ackbits:]


def wedge_recover(u, speed, tries=3):
    """Восстановление адаптера после wedge (rc=-7 и т.п.; урок T5 r3:
    USBDEVFS_RESET оживлял молчащий IN-эндпоинт): release →
    libusb_reset_device → detach kernel → claim → set speed; при неудаче
    — полный пере-открытый цикл USB. Мутирует u (подменяет lib/handle
    при переоткрытии). Возвращает True при успехе."""
    import time
    for _attempt in range(tries):
        try:
            u.lib.libusb_release_interface(u.handle, IFACE)
        except Exception:
            pass
        u.lib.libusb_reset_device.argtypes = [ctypes.c_void_p]
        rc = u.lib.libusb_reset_device(u.handle)
        claimed = -1
        if rc == 0:
            if u.lib.libusb_kernel_driver_active(u.handle, IFACE):
                u.lib.libusb_detach_kernel_driver(u.handle, IFACE)
            claimed = u.lib.libusb_claim_interface(u.handle, IFACE)
        if rc == 0 and claimed == 0:
            set_speed_legacy(u, speed)
            return True
        try:
            u.close()
        except Exception:
            pass
        try:
            nu = Usb().open_dev()
            u.lib, u.handle = nu.lib, nu.handle
            set_speed_legacy(u, speed)
            return True
        except OSError:
            time.sleep(2.0)
    return False


def gwdump_run(u, addr, out, flash_size=0x1000000, speed=1,
               intra_ms=2.0, inter_ms=10.0, poll_ms=20,
               # NB: 240 мин меньше полного 16 MiB-дампа на дефолтном пейсинге (~10.8 ч) — переопределяйте для полных дампов
               lock_timeout_s=2.0, max_blocks=None, deadline_min=240.0,
               resume=False, marker_every=1024, force=False, opt=0,
               batch=64):
    """Полный дамп flash через I2C (T6/FNP, канон §8.2): на каждый 16Б-блок
    — gw_read_block_cycle (lock → ADDR → CMD READ → DATA 16Б → unlock).
    Механика длительной операции (unix-process-ops / 850-howto/100 §1.2):
    kill недопустим → bounded self-stop (deadline_min / max_blocks /
    block-retry-cap), маркеры каждые marker_every блоков (rate/eta/
    errors), sidecar `<out>.progress` (next_block, каждые 64 блока + при
    выходе) для --resume, восстановление адаптера после wedge
    (wedge_recover). Ретрай-семантика: на блок ≤3 попыток (каждая
    следующая — после успешного wedge_recover); 3 подряд неудачных
    попытки ОДНОГО блока → STOP (stop_reason "block-retry-cap", rc=3) —
    защиты от error-spin до deadline при персистентной protocol-ошибке
    (wedge_recover на живом USB «успешен» всегда). Успешный блок
    сбрасывает счётчик. md5 в конце — только при полном объёме.
    Возвращает сводку-dict (done/blocks/next_block/stop_reason/errors/
    resets/forced_locks/elapsed_min/md5/size)."""
    import hashlib
    import json
    import os
    import time

    def say(msg):
        print(msg, flush=True)

    block_size = 16
    total_blocks = flash_size // block_size
    prog_path = out + ".progress"
    start_block = 0
    if resume:
        try:
            with open(prog_path) as pf:
                start_block = json.load(pf)["next_block"]
        except (OSError, ValueError, KeyError):
            say(f"gwdump: --resume без валидного {prog_path} — старт с 0")
            start_block = 0
    if start_block >= total_blocks:
        say(f"gwdump: уже готов (next_block={start_block})")
        with open(out, "rb") as hf:
            md5 = hashlib.md5(hf.read()).hexdigest()
        return {"done": True, "blocks": 0, "bytes": 0,
                "next_block": start_block, "stop_reason": "already-done",
                "errors": 0, "resets": 0, "elapsed_min": 0.0, "md5": md5,
                "size": os.path.getsize(out)}
    stop_block = total_blocks if max_blocks is None else \
        min(total_blocks, start_block + max_blocks)
    mode = "r+b" if (resume and start_block) else "wb"
    f = open(out, mode)
    f.seek(start_block * block_size)
    f.truncate(start_block * block_size)
    deadline = time.time() + deadline_min * 60
    pace = (lambda: time.sleep(intra_ms / 1000)) if intra_ms else \
        (lambda: None)
    inter = (lambda: time.sleep(inter_ms / 1000)) if inter_ms else \
        (lambda: None)
    t0 = time.time()
    i, blocks, errors, resets = start_block, 0, 0, 0
    consec = 0
    forced0 = GW_FORCED_LOCKS
    stop_reason = None

    def note_progress(cur):
        if cur % 64 == 0:
            f.flush()
            os.fsync(f.fileno())
            with open(prog_path, "w") as pf:
                json.dump({"next_block": cur}, pf)
        if cur % marker_every == 0:
            dt = time.time() - t0
            rate = blocks / dt if dt else 0.0
            eta = (stop_block - cur) / rate if rate else 0.0
            say(f"gwdump: MARKER block {cur}/{stop_block} "
                f"({cur * block_size}/{stop_block * block_size} B) "
                f"rate={rate:.2f} blk/s eta={eta / 60:.1f} min "
                f"errors={errors} resets={resets}")

    while i < stop_block:
        if time.time() >= deadline:
            stop_reason = "deadline"
            break
        try:
            if opt == 0:
                data = gw_read_block_cycle(u, addr, i * block_size, pace,
                                           poll_ms=poll_ms,
                                           timeout_s=lock_timeout_s,
                                           force=force)
                f.write(data)
                i += 1
                blocks += 1
                consec = 0
                note_progress(i)
                inter()
            else:
                gw_lock(u, addr, pace, poll_ms=poll_ms,
                        timeout_s=lock_timeout_s, quiet=True, force=force)
                try:
                    end = min(stop_block, i + batch)
                    while i < end:
                        if time.time() >= deadline:
                            stop_reason = "deadline"
                            break
                        if opt == 2:
                            data = gw_read_block_packed(
                                u, addr, i * block_size)
                        else:
                            pace()
                            cr_write(u, addr, GW_ADDR, i * block_size)
                            pace()
                            cr_write(u, addr, GW_CMD, CMD_READ16)
                            data, _ms = cr_read(u, addr, GW_DATA, 16)
                        f.write(data)
                        i += 1
                        blocks += 1
                        consec = 0
                        note_progress(i)
                        inter()
                finally:
                    pace()
                    gw_unlock(u, addr, pace, quiet=True)
        except OSError as e:
            errors += 1
            consec += 1
            say(f"gwdump: block {i} (@0x{i * block_size:x}) FAIL "
                f"(попытка {consec}/3): {e}")
            if consec >= 3:
                stop_reason = (f"block-retry-cap (block {i}: 3 подряд "
                               f"неудачных попыток): {e}")
                break
            if not wedge_recover(u, speed):
                stop_reason = f"wedge-norecover: {e}"
                break
            resets += 1
        if stop_reason:
            break
    if stop_reason is None and i < total_blocks:
        stop_reason = "max-blocks (частичный прогон)"
    f.flush()
    os.fsync(f.fileno())
    with open(prog_path, "w") as pf:
        json.dump({"next_block": i}, pf)
    f.close()
    dt = time.time() - t0
    done = (i >= total_blocks) and (stop_reason is None or
                                    stop_reason.startswith("max-blocks"))
    md5 = size = None
    if done:
        size = os.path.getsize(out)
        if size == flash_size:
            with open(out, "rb") as hf:
                md5 = hashlib.md5(hf.read()).hexdigest()
        else:
            stop_reason = f"size-mismatch: {size}"
            done = False
    say(f"gwdump: {'DONE' if done else 'STOPPED'}"
        + ("" if stop_reason is None else f" ({stop_reason})")
        + f" blocks={blocks} next_block={i}/{total_blocks} "
        f"elapsed={dt / 60:.1f} min errors={errors} resets={resets} "
        f"forced_locks={GW_FORCED_LOCKS - forced0}"
        + (f" md5={md5} size={size}" if md5 else ""))
    return {"done": done, "blocks": blocks, "bytes": blocks * block_size,
            "next_block": i, "stop_block": stop_block,
            "total_blocks": total_blocks, "stop_reason": stop_reason,
            "errors": errors, "resets": resets,
            "forced_locks": GW_FORCED_LOCKS - forced0,
            "elapsed_min": round(dt / 60, 2), "md5": md5, "size": size}


HROM_CANDIDATES = [
    ("ctrl-devid", 0x000F0014,
     "контроль декодирования: HW_ID (ожидаем dev_id 0x020d)"),
    ("ctrl-gw", 0x000F0400,
     "контроль декодирования: GW CMD-блок (ожидаем регистровые значения)"),
    ("vec0", 0x00000000,
     "вектор-окно — boot-кандидат №1 (в NORMAL здесь ICMD hcr, канон §7.5)"),
    ("vec0+1000", 0x00001000,
     "сосед вектор-окна; boot2-указатель 0x1000 (030-root-of-trust:46)"),
    ("zoneA-head", 0x00B97E00,
     "голова зоны A — уникальный runtime-код пре-MAIN-происхождения"),
    ("zoneA+1000", 0x00B98E00, "сосед зоны A (head+0x1000; окно+соседи)"),
    ("zoneB1-head", 0x01001000, "зона B ч.1 — loader-класс"),
    ("zoneB2-head", 0x01040000,
     "зона B ч.2 — flash-зеркало MAIN_CODE (контраст: ждём flash-байты)"),
    ("aperture", 0xFFFF8000,
     "апертура — на boot читается без stall, значение 0"),
    ("aperture-1", 0xFFFF7F00, "сосед апертуры снизу (окно+соседи)"),
    ("ctrl-dead", 0x02000000,
     "контроль недекодированной зоны (ожидание NAK/FF/00)"),
]


def hrom_entropy(data):
    """(число различных байт, доля топ-байта) — критерий структуры окна."""
    from collections import Counter
    c = Counter(data)
    return len(c), c.most_common(1)[0][1] / len(data)


def hrom_scan(u, addr, pause, repeat_gap_s=1.0):
    """Bounded H-ROM скан (T6/O7): по каждому кандидату HROM_CANDIDATES —
    CR-чтение 16Б ×2 (повторяемость, зазор repeat_gap_s) + probe_alive
    между кандидатами (hang-контракт: ACK loss → STOP, скан прерван).
    Критерии «данные» vs «мусор/NAK»: доставлено (нет NAK) + повторяемо
    (r1==r2) + не дегенерат (data_sane) + структура (≥4 различных байт,
    топ-байт ≤75%); контроли дают базу «декодируется/не декодируется».
    Возвращает (results, completed)."""
    import json
    import time

    def say(msg):
        print(msg, flush=True)

    results = []
    completed = True
    for tag, cr_a, _src in HROM_CANDIDATES:
        rec = {"tag": tag, "addr": f"0x{cr_a:08x}", "err": None,
               "r1": None, "r2": None, "repeatable": None, "sane": None,
               "distinct": None, "top_share": None}
        try:
            d1, ms1 = cr_read(u, addr, cr_a, 16)
            time.sleep(repeat_gap_s)
            d2, _ms2 = cr_read(u, addr, cr_a, 16)
            distinct, top = hrom_entropy(d1)
            rec["err"] = None
            rec["r1"] = d1.hex()
            rec["r2"] = d2.hex()
            rec["repeatable"] = d1 == d2
            rec["sane"] = data_sane(d1)
            rec["distinct"] = distinct
            rec["top_share"] = round(top, 3)
            say(f"hrom/{tag} @0x{cr_a:08x}: r1={d1.hex()} [{ms1:.2f} ms] "
                f"repeat={'Y' if d1 == d2 else 'N'} sane={rec['sane']} "
                f"distinct={distinct} top={top:.2f}")
        except OSError as e:
            rec["err"] = str(e)
            say(f"hrom/{tag} @0x{cr_a:08x}: NAK/ошибка: {e}")
        results.append(rec)
        alive, pr = probe_alive(u, addr, pause)
        say(f"hrom/{tag}: probe x{len(pr)} -> "
            + ("alive" if alive else "DEAD (hang-индикация)") + f" {pr}")
        if not alive:
            completed = False
            say("hrom: hang-контракт — STOP, скан прерван (BLOCKED)")
            break
        pause()
    say("hrom: SUMMARY")
    for r in results:
        say("  " + json.dumps(r))
    if completed:
        say(f"hrom: скан завершён по полному списку кандидатов "
            f"({len(HROM_CANDIDATES)})")
    return results, completed


def w1_session(u, addr, pause, lock_timeout_s=600.0, lock_poll_s=10.0,
               cold=False, variants=(1, 3, 4, 5), force=False):
    """W1-сессия T5/T6 (спека §3.3): lock (bounded wait; cold=True —
    cold-start RMW-first последовательность gw_cold_lock, без
    предварительных чтений CMD; force=True — FNP force-lock в poll-пути,
    не совместим с cold) → step1 фоновое чтение DATA-окна →
    выбранные варианты 1–5 (write → read-back → совпадение = доставка)
    → unlock в finally. variants — подмножество {1..5}; v2 (ZLP) по
    умолчанию исключён (на fw 5.44 валит адаптер — T5 r3; CLI гейтит
    его за --allow-zlp). Записи ТОЛЬКО в GW DATA 0xf0410..0xf041f (+
    lock-RMW 0xf0420 обёрткой), CMD/ADDR не трогаем, Go нет.
    Hang-индикация (probe dead) → стоп без продолжения вариантов."""
    results = {}
    if cold:
        ok, basis, cmd_v = gw_cold_lock(u, addr, pause)
        if not ok:
            print("cold-lock не взят — сессия НЕ стартует, unlock не "
                  "нужен (disable восстановлен в gw_cold_lock)")
            return results
    else:
        gw_lock(u, addr, pause, poll_ms=int(lock_poll_s * 1000),
                timeout_s=lock_timeout_s, force=force)
    try:
        step1_ok = False
        try:
            bg, ms = cr_read(u, addr, GW_DATA, 16,
                             note="w1/step1: R DATA@0xf0410 16Б (фон, без Go)")
            step1_ok = True
            print(f"w1/step1: bg={bg.hex()} [{ms:.2f} ms] "
                  f"data_sane={data_sane(bg)}")
            print("O10-read: DATA-окно читается без Go: ДА (16Б, фон)")
        except OSError as e:
            print(f"w1/step1: READ FAIL: {e}")
            print("O10-read: DATA-окно без Go НЕ читается")

        def variant(tag, sender, pattern):
            print(f"w1/{tag}: pattern={pattern.hex()}")
            send_ok = True
            try:
                sender()
            except OSError as e:
                send_ok = False
                print(f"w1/{tag}: SEND FAIL: {e}")
            rb = None
            delivered = False
            if send_ok:
                try:
                    pause()
                    rb, ms = cr_read(u, addr, GW_DATA, 16)
                    delivered = rb == pattern
                    print(f"w1/{tag}: readback={rb.hex()} [{ms:.2f} ms] -> "
                          + ("DELIVERED" if delivered else "NOT delivered"))
                except OSError as e:
                    print(f"w1/{tag}: READBACK FAIL: {e}")
            alive, pr = probe_alive(u, addr, pause)
            print(f"w1/{tag}: probe x{len(pr)} -> "
                  + ("alive" if alive else "DEAD (hang-индикация)")
                  + f" {pr}")
            results[tag] = {"send_ok": send_ok,
                            "readback": rb.hex() if rb is not None else None,
                            "delivered": delivered, "alive": alive}
            pause()
            return alive

        p1, p2, p3, p4 = (bytes(range(0x10, 0x20)), bytes(range(0x30, 0x40)),
                          bytes(range(0x50, 0x60)), bytes(range(0x70, 0x80)))
        if 1 in variants and not variant(
                "v1-frame26",
                lambda: cr_write_block(u, addr, GW_DATA, p1,
                                       note="w1/v1"), p1):
            return results
        if 2 in variants and not variant(
                "v2-zlp",
                lambda: cr_write_block(u, addr, GW_DATA, p2, zlp=True,
                                       note="w1/v2"), p2):
            return results
        if 3 in variants and not variant(
                "v3-multi-out",
                lambda: cr_write_block(u, addr, GW_DATA, p3,
                                       split_out=True,
                                       note="w1/v3"), p3):
            return results
        if 4 in variants and not variant(
                "v4-cont",
                lambda: cr_write_block_cont(u, addr, GW_DATA, p4,
                                            note="w1/v4"), p4):
            return results

        if 5 in variants:
            print("w1/v5-readdr: mwrite4 по 0xf0410/0xf0416/0xf041c")
            v5_vals = {0xF0410: 0x55AA0410, 0xF0416: 0x55AA0416,
                       0xF041C: 0x55AA041C}
            send_ok = True
            for cr_a, val in v5_vals.items():
                try:
                    cr_write(u, addr, cr_a, val,
                             note=f"w1/v5: mwrite4@0x{cr_a:08x}=0x{val:08x}")
                    pause()
                except OSError as e:
                    send_ok = False
                    print(f"w1/v5: SEND FAIL @0x{cr_a:08x}: {e}")
                    break
            rb = None
            delivered = False
            if send_ok:
                try:
                    rb, ms = cr_read(u, addr, GW_DATA, 16)
                    checks = {}
                    delivered = True
                    for cr_a, val in v5_vals.items():
                        off = cr_a - GW_DATA
                        got = rb[off:off + 4]
                        ok = got == val.to_bytes(4, "big")
                        delivered = delivered and ok
                        checks[f"0x{cr_a:08x}"] = (
                            f"0x{int.from_bytes(got, 'big'):08x}"
                            + ("=ok" if ok else "!=exp"))
                    print(f"w1/v5: readback={rb.hex()} [{ms:.2f} ms] {checks} -> "
                          + ("DELIVERED" if delivered else "NOT delivered"))
                except OSError as e:
                    print(f"w1/v5: READBACK FAIL: {e}")
                    delivered = False
            alive, pr = probe_alive(u, addr, pause)
            results["v5-readdr"] = {"send_ok": send_ok,
                                    "readback": rb.hex() if rb is not None else None,
                                    "delivered": delivered, "alive": alive}
            print(f"w1/v5: probe x{len(pr)} -> "
                  + ("alive" if alive else "DEAD (hang-индикация)") + f" {pr}")

        print("w1: SUMMARY")
        for tag, r in results.items():
            print(f"  {tag}: send={r['send_ok']} delivered={r['delivered']} "
                  f"alive={r['alive']} readback={r['readback']}")
        any_del = any(r["delivered"] for r in results.values())
        print(f"O10-write (v5): {'подтверждена' if results.get('v5-readdr', {}).get('delivered') else 'нет'}")
        if not any_del:
            print("вердикт: W1 не разрешим без Go (варианты 1–5 не "
                  "доставляют)" + ("" if step1_ok else " + DATA не читается"))
    finally:
        gw_unlock(u, addr, pause)
        if cold:
            try:
                pause()
                c_b, _ = cr_read(u, addr, GW_CMD, 4,
                                 note="cold-post: R CMD@0xf0400 (одно, "
                                      "после unlock — механизм-наблюдение)")
                print(f"cold-post: CMD=0x{int.from_bytes(c_b, 'big'):08x} "
                      f"бит31={(int.from_bytes(c_b, 'big') >> 31) & 1}")
            except OSError as e:
                print(f"cold-post: CMD read FAIL: {e}")
    return results


def jedec_decode(data):
    vendor = data[0]
    cap = data[2]
    return (f"vendor=0x{vendor:02x} ({JEDEC_VENDORS.get(vendor, '?')}) "
            f"type=0x{data[1]:02x} cap=0x{cap:02x}"
            + (f" (= {1 << cap} Б)" if cap else ""))


def data_sane(data):
    """False для дегенератов: all-FF/all-00 (нет слейва/шины) и
    vendor=0-паттерн 00 00 02 09 (T3 review #1: проходит старый all-00/
    all-FF-гейт, но валидным jedec-ответом быть не может — vendor 0x00
    вне JEDEC-таблицы)."""
    if data in (b"\xff" * len(data), b"\x00" * len(data)):
        return False
    return not data.startswith(b"\x00\x00\x02\x09")


# --- mphsi D9-семья (0xD9/~0xD9 + ack-счётчик) ---

def mphsi_init(u, hz):
    """0xDB INIT (ch34x_mphsi_master_i2c.c:657-676, форма CH9341C)."""
    pkt = bytes([M9_INIT, (~M9_INIT) & 0xFF, 10, 0, 0,
                 hz & 0xFF, (hz >> 8) & 0xFF, (hz >> 16) & 0xFF,
                 (hz >> 24) & 0xFF, 0x20, 0, 0, 0, 0])
    st = u.bulk(EP_OUT, pkt, 5)
    return st[0] == M9_INIT and st[4] == 0x00, st


def mphsi_transact(u, addr, wdata=b"", rlen=0):
    """Транзакция S [addrW wdata] [Sr addrR rlen] P.

    Возвращает (ok, ack_value, ack_expected, data, raw): ok = ack-счётчик
    совпал с ожиданием (все фазы ACK).
    """
    tx = bytes([(addr << 1) & 0xFE]) + bytes(wdata)
    toks = bytes([0x00, M9_START << 3])
    toks += bytes([0x00, M9_ADDR << 3, tx[0]])
    t = len(tx) - 1
    toks += bytes([t & 0xFF, (M9_OUT << 3) | (t >> 8)]) + tx[1:]
    ack_exp = len(tx)
    if rlen:
        toks += bytes([0x00, M9_START << 3])
        toks += bytes([0x00, M9_ADDR << 3, tx[0] | 1])
        ack_exp += 1
        toks += bytes([rlen & 0xFF, (M9_IN_N << 3) | (rlen >> 8)])
    toks += bytes([0x00, M9_STOP << 3])
    body = bytes([M9_STREAM, (~M9_STREAM) & 0xFF,
                  (len(toks)) & 0xFF, (len(toks)) >> 8]) + toks
    olen = (rlen + 6) if rlen else 6
    r = u.bulk(EP_OUT, body, olen)
    ack_val = r[4] | (r[5] << 8)
    data = r[6:6 + rlen] if rlen else b""
    return ack_val == ack_exp, ack_val, ack_exp, data, r


def probe_mphsi(u, addr):
    ok, val, exp, _, raw = mphsi_transact(u, addr)
    return ok, (raw[4], raw[5])


def read_mphsi(u, addr, n):
    out = b""
    off = 0
    while off < n:
        take = min(n - off, MAX_XFER)
        ok, val, exp, data, _ = mphsi_transact(u, addr, rlen=take)
        if not ok:
            raise OSError(f"mphsi read: ack {val} != {exp} @off {off}")
        out += data
        off += take
    return out


def write_mphsi(u, addr, data):
    ok, val, exp, _, _ = mphsi_transact(u, addr, wdata=data)
    if not ok:
        raise OSError(f"mphsi write: ack {val} != {exp}")
    return True


def chipinfo(u):
    st = u.bulk(EP_OUT, bytes([0xCA, 0x01, 0x00, 0x00]), 7)
    if st[0] != 0xCA:
        raise OSError(f"chipinfo: нет эха 0xCA (получено 0x{st[0]:02x})")
    return (st[4] << 8) | st[3], st


def hexdump(data, base=0):
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        print(f"{base + off:04x}: {hexs}")


def main():
    ap = argparse.ArgumentParser(description="CH347T mode1 userspace I2C (1a86:55db)")
    ap.add_argument("--addr", type=lambda x: int(x, 0), required=True,
                    help="7-bit I2C адрес (CX-5 non-secured: 0x48)")
    ap.add_argument("--speed", type=int, default=0, choices=[0, 1, 2, 3],
                    help="0=20k 1=100k 2=400k 3=750k (default 0 — первый контакт)")
    ap.add_argument("--family", choices=["mphsi", "legacy"], default="legacy",
                    help="семья транзакций: legacy (AA, дефолт — единственная "
                         "рабочая на fw 5.44) | mphsi (0xD9 — игнорируется fw)")
    ap.add_argument("--pause-ms", type=int, default=500,
                    help="пауза между транзакциями GW-циклов, мс (default 500 — "
                         "fw 5.44 валится молотением, уроки T1/T2; между "
                         "CMD-write Go и DATA-read паузы НЕТ — честный O9)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("chipinfo", help="firmware-версия чипа (живость IF2)")
    pp = sub.add_parser("probe", help="адресная проба (ACK/NAK)")
    pp.add_argument("--read-direction", action="store_true",
                    help="(legacy) проба в направлении чтения")
    pp.add_argument("--count", type=int, default=1, help="повторов (латентности)")
    sp = sub.add_parser("scan", help="скан 0x08-0x77 по адресной пробе")
    sp.add_argument("--repeat", type=int, default=1, help="повторов пробы на адрес")
    cp = sub.add_parser("clock", help="(legacy) непрерывные пробы для DMM")
    cp.add_argument("--count", type=int, default=100000, help="число проб")
    cp.add_argument("--delay-ms", type=int, default=0, help="пауза между пробами, мс")
    rp = sub.add_parser("read", help="прочитать N байт")
    rp.add_argument("n", type=lambda x: int(x, 0))
    dv = sub.add_parser("devid", help="CR dev-id: cr_read32(0xf0014) канона "
                       "§2.5 + разбор dev_id/rev (только legacy)")
    crp = sub.add_parser("crread", help="combined CR-read (канон §2.1/§2.3, "
                          "только legacy): BE32-адрес + repeated start + N байт")
    crp.add_argument("cr_addr", type=lambda x: int(x, 0), help="CR-адрес, напр. 0xf0014")
    crp.add_argument("n", type=lambda x: int(x, 0), nargs="?", default=4,
                     help="байт (default 4 = dword; >4 = блок)")
    wp = sub.add_parser("write", help="записать hex-байты (политика: НЕ против карты)")
    wp.add_argument("hexdata", help="hex-строка, напр. 001f0039")
    gsp = sub.add_parser("gwsmoke", help="GW-цикл: lock → CR-write-smoke "
                         "(ADDR@0xf0404=0 → read-back) + RDID (CMD "
                         "0xC09F0215, DATA 4Б) → unlock (канон §7.3, "
                         "приёмка §8.3)")
    grp2 = sub.add_parser("gwres", help="GW-цикл: lock → RES 0xab (CMD "
                          "0xC0AB0215, DATA 4Б) → unlock")
    gr = sub.add_parser("gwread", help="GW-цикл чтения 16Б flash: lock → ADDR "
                        "→ CMD READ 0xC003041D → DATA 16Б → unlock (§8.2)")
    gr.add_argument("flash_addr", type=lambda x: int(x, 0),
                    help="flash-адрес, напр. 0x0")
    for _p in (gsp, grp2, gr):
        _p.add_argument("--force-lock", action="store_true",
                        help="FNP/livefish: при занятом семафоре — release "
                             "stale (W CMD=0) + proceed с warning "
                             "(T15-прецедент)")
    w1p = sub.add_parser("w1", help="W1 T5 (спека §3.3): lock → фоновое "
                          "чтение DATA-окна → варианты 1–5 write→read-back → "
                          "unlock. Записи только в GW DATA 0xf0410..0xf041f, "
                          "без Go")
    w1p.add_argument("--lock-timeout", type=float, default=600.0,
                     help="bounded wait семафора, с (default 600 = 10 мин)")
    w1p.add_argument("--lock-poll-s", type=float, default=10.0,
                     help="каденс опроса семафора при занятом, с (default 10)")
    w1p.add_argument("--cold", action="store_true",
                     help="cold-start lock (round-3): первое GW-прикосновение "
                          "бута = R@0xf0420 → W disable → одиночный verify "
                          "CMD; без предварительных чтений CMD")
    w1p.add_argument("--variants", default="1,3,4,5",
                     help="подмножество вариантов §3.3 через запятую "
                          "(default 1,3,4,5 — v2/ZLP исключён: на fw 5.44 "
                          "валит адаптер, вердикт T5 r3)")
    w1p.add_argument("--allow-zlp", action="store_true",
                     help="разблокировать вариант 2 (ZLP) — ВРЕДЕН на "
                          "fw 5.44 (wedge IN-эндпоинта, T5 r3)")
    w1p.add_argument("--force-lock", action="store_true",
                     help="FNP/livefish: force-lock в poll-пути (не "
                          "совместим с --cold)")
    gdp = sub.add_parser("gwdump", help="полный дамп flash циклами §8.2 "
                         "(T6/FNP): per-block lock → ADDR → CMD READ → "
                         "DATA 16Б → unlock; nohup+PID, self-stop, resume")
    gdp.add_argument("out", help="выходной .bin (sidecar .progress рядом)")
    gdp.add_argument("--flash-size", type=lambda x: int(x, 0),
                     default=0x1000000,
                     help="объём дампа, Б (default 0x1000000 = 16 MiB; "
                          "уточнить по jedec из gwsmoke)")
    gdp.add_argument("--intra-ms", type=float, default=2.0,
                     help="пауза между транзакциями внутри блока, мс "
                          "(default 2)")
    gdp.add_argument("--inter-ms", type=float, default=10.0,
                     help="пауза между блоками, мс (default 10)")
    gdp.add_argument("--poll-ms", type=int, default=20,
                     help="каденс poll семафора в lock, мс (default 20)")
    gdp.add_argument("--lock-timeout-s", type=float, default=2.0,
                     help="таймаут lock на блок, с (default 2; FNP: семафор "
                          "свободен)")
    gdp.add_argument("--max-blocks", type=int, default=None,
                     help="лимит блоков в этом прогоне (замер скорости / "
                          "частичный дамп)")
    # NB: 240 мин меньше полного 16 MiB-дампа на дефолтном пейсинге (~10.8 ч) — переопределяйте для полных дампов
    gdp.add_argument("--deadline-min", type=float, default=240.0,
                     help="bounded self-stop, мин (default 240; kill "
                          "недопустим — 850-howto/100 §1.2)")
    gdp.add_argument("--resume", action="store_true",
                     help="продолжить с next_block из sidecar .progress")
    gdp.add_argument("--force-lock", action="store_true",
                     help="FNP/livefish: при занятом семафоре — release "
                          "stale + proceed (T15-прецедент; счётчик в "
                          "сводке forced_locks)")
    gdp.add_argument("--opt", type=int, default=0, choices=[0, 1, 2],
                     help="T6-opt: 0 = канон (lock+unlock на каждый блок, "
                          "9 транзакций; default) | 1 = batch-lock (lock "
                          "на --batch блоков, 3 транзакции/блок) | "
                          "2 = batch-lock + frame-packing (3 i2c-"
                          "транзакции одним AA-стримом, 1 USB round-trip "
                          "на блок)")
    gdp.add_argument("--batch", type=int, default=64,
                     help="блоков на один batch-lock при --opt 1/2 "
                          "(default 64)")
    gdp.add_argument("--marker-every", type=int, default=1024,
                     help="маркер прогресса каждые N блоков (default 1024)")
    hp = sub.add_parser("hrom", help="bounded H-ROM скан (T6/O7): boot-"
                        "кандидаты phase-XIII (030/130-доки) + контроли "
                        "декодирования; критерии данные/мусор/NAK; "
                        "hang-контракт")
    hp.add_argument("--repeat-gap-s", type=float, default=1.0,
                    help="зазор между повторными чтениями кандидата, с "
                         "(default 1; повторяемость)")
    args = ap.parse_args()

    import time

    def probe(u, a):
        if args.family == "mphsi":
            return probe_mphsi(u, a)
        return probe_legacy(u, a)

    u = Usb().open_dev()
    try:
        set_speed_legacy(u, args.speed)
        print(f"family={args.family} speed={SPEED_NAMES[args.speed]} "
              f"iface {IFACE} EP 0x{EP_OUT:02x}/0x{EP_IN:02x}", file=sys.stderr)
        if args.family == "mphsi":
            try:
                ok, st = mphsi_init(u, SPEEDS[args.speed])
                print(f"mphsi_init(0xDB, {SPEEDS[args.speed]}Hz): "
                      f"{'OK' if ok else 'no-ack'} raw={st.hex()}", file=sys.stderr)
            except OSError as e:
                print(f"mphsi_init: {e} — продолжаем без INIT", file=sys.stderr)
        if args.cmd == "chipinfo":
            ver, st = chipinfo(u)
            print(f"chipinfo: raw={st.hex()} -> firmware 0x{ver:04x}")
        if args.cmd == "probe":
            ack = False
            any_ack = False
            for i in range(args.count):
                t0 = time.time()
                ack, st = probe(u, args.addr)
                any_ack = any_ack or ack
                ms = (time.time() - t0) * 1000
                stx = " ".join(f"{b:02x}" for b in st)
                print(f"0x{args.addr:02x}: ack-info={stx} -> "
                      f"{'ACK' if ack else 'NAK'}  [{ms:.2f} ms]")
            sys.exit(0 if any_ack else 1)
        if args.cmd == "scan":
            acks = []
            t0 = time.time()
            for a in range(0x08, 0x78):
                ack, st = probe(u, a)
                if ack:
                    acks.append(a)
                    print(f"0x{a:02x}: ack-info={' '.join(f'{b:02x}' for b in st)} -> ACK")
            dt = (time.time() - t0) * 1000
            print(f"scan 0x08-0x77 @{SPEED_NAMES[args.speed]} {args.family}: "
                  + (", ".join(f"0x{a:02x}" for a in acks) if acks else "нет ACK")
                  + f"  [{dt:.0f} ms, {dt/112:.2f} ms/probe]")
            if acks and args.repeat > 1:
                for a in acks:
                    res = [probe(u, a)[0] for _ in range(args.repeat - 1)]
                    print(f"stability 0x{a:02x} x{args.repeat}: "
                          + " ".join("ACK" if r else "NAK" for r in res))
            sys.exit(0 if acks else 1)
        if args.cmd == "clock":
            for i in range(args.count):
                probe_legacy(u, args.addr)
                if args.delay_ms:
                    time.sleep(args.delay_ms / 1000)
                if (i + 1) % 10000 == 0:
                    print(f"{i + 1} probes done", file=sys.stderr)
            print(f"clock: {args.count} probes @0x{args.addr:02x} done", file=sys.stderr)
        if args.cmd == "read":
            ack, st = probe(u, args.addr)
            if not ack:
                sys.exit(f"0x{args.addr:02x}: NAK ({' '.join(f'{b:02x}' for b in st)})")
            data = (read_mphsi if args.family == "mphsi" else read_legacy)(u, args.addr, args.n)
            hexdump(data)
        if args.cmd in ("devid", "crread"):
            if args.family != "legacy":
                sys.exit("cr-read только в legacy-семье (mphsi мёртв на fw 5.44)")
            if args.cmd == "devid":
                dword, raw, ms = cr_read32(u, args.addr, 0xF0014)
                dev_id = dword & 0xFFFF
                rev = (dword >> 16) & 0xF
                fr, _ = cr_read_frames(args.addr, 0xF0014, 4)
                print(f"frame: {fr.hex()} ({len(fr)} B)")
                print(f"0xf0014: raw={raw.hex()} -> dword=0x{dword:08x}  [{ms:.2f} ms]")
                print(f"dev_id=0x{dev_id:04x} rev_id=0x{rev:x} (канон §2.5: "
                      f"dev_id=dword&0xffff, rev=биты[16:20))")
            else:
                chunks = []
                off = 0
                while off < args.n:
                    take = min(args.n - off, 64)
                    data, ms = cr_read(u, args.addr, args.cr_addr + off, take)
                    chunks.append(data)
                    off += take
                data = b"".join(chunks)
                fr, _ = cr_read_frames(args.addr, args.cr_addr, min(args.n, 64))
                print(f"frame[0]: {fr.hex()} ({len(fr)} B)")
                hexdump(data, base=args.cr_addr)
                for i in range(0, len(data) - len(data) % 4, 4):
                    print(f"  0x{args.cr_addr + i:08x}: 0x{int.from_bytes(data[i:i+4], 'big'):08x}")
        if args.cmd == "write":
            data = bytes.fromhex(args.hexdata)
            (write_mphsi if args.family == "mphsi"
             else lambda *_: sys.exit("legacy write не реализован (политика)"))(u, args.addr, data)
            print(f"written {len(data)} B -> 0x{args.addr:02x} ({args.family})")
        if args.cmd in ("gwdump", "hrom"):
            if args.family != "legacy":
                sys.exit("gwdump/hrom только в legacy-семье")
            if args.cmd == "gwdump":
                summary = gwdump_run(u, args.addr, args.out,
                                     flash_size=args.flash_size,
                                     speed=args.speed,
                                     intra_ms=args.intra_ms,
                                     inter_ms=args.inter_ms,
                                     poll_ms=args.poll_ms,
                                     lock_timeout_s=args.lock_timeout_s,
                                     max_blocks=args.max_blocks,
                                     deadline_min=args.deadline_min,
                                     resume=args.resume,
                                     marker_every=args.marker_every,
                                     force=args.force_lock,
                                     opt=args.opt, batch=args.batch)
                sys.exit(0 if summary["done"] else 3)
            pause = lambda: time.sleep(args.pause_ms / 1000)  # noqa: E731
            _results, completed = hrom_scan(u, args.addr, pause,
                                            repeat_gap_s=args.repeat_gap_s)
            sys.exit(0 if completed else 4)
        if args.cmd in ("gwsmoke", "gwres", "gwread", "w1"):
            if args.family != "legacy":
                sys.exit("GW только в legacy-семье")
            pause = lambda: time.sleep(args.pause_ms / 1000)  # noqa: E731
            try:
                if args.cmd == "w1":
                    try:
                        vs = {int(x) for x in args.variants.split(",")
                              if x.strip()}
                    except ValueError:
                        sys.exit("--variants: числа через запятую, напр. 1,5")
                    unknown = vs - {1, 2, 3, 4, 5}
                    if unknown:
                        sys.exit(f"--variants: неизвестные {sorted(unknown)}")
                    if 2 in vs and not args.allow_zlp:
                        sys.exit("--variants 2 (ZLP): обязателен --allow-zlp "
                                 "(wedge адаптера, вердикт T5 r3)")
                    if args.cold and args.force_lock:
                        sys.exit("--cold несовместим с --force-lock "
                                 "(cold = RMW-first verify; force = release-"
                                 "stale poll-путь)")
                    w1_session(u, args.addr, pause,
                               lock_timeout_s=args.lock_timeout,
                               lock_poll_s=args.lock_poll_s,
                               cold=args.cold, variants=vs,
                               force=args.force_lock)
                elif args.cmd == "gwsmoke":
                    orig, cmd0, polls = gw_lock(u, args.addr, pause,
                                                force=args.force_lock)
                    try:
                        pause()
                        cr_write(u, args.addr, GW_ADDR, 0x0,
                                 note="smoke: W ADDR@0xf0404=0x0 (без Go)")
                        pause()
                        rb_b, _ = cr_read(u, args.addr, GW_ADDR, 4,
                                          note="smoke: R ADDR read-back")
                        rb = int.from_bytes(rb_b, "big")
                        print(f"smoke: read-back 0x{rb:08x} -> "
                              + ("OK (двусторонний smoke)" if rb == 0 else "FAIL"))
                        pause()
                        cr_write(u, args.addr, GW_CMD, CMD_RDID,
                                 note="rdid: W CMD@0xf0400=0xC09F0215 (Go, без ADDR — §12.3-2)")
                        data, ms = cr_read(u, args.addr, GW_DATA, 4,
                                           note="rdid: R DATA@0xf0410 (сразу после Go, без пере-чтения CMD — O9)")
                        print(f"rdid: jedec = {data.hex()} [{ms:.2f} ms] — "
                              + jedec_decode(data))
                        print(f"O9: sanity DATA после Go без CMD re-read: "
                              + ("OK (данные не мусор)" if data_sane(data)
                                 else "FAIL (ff/00 — busy-poll skip недостаточен)"))
                    finally:
                        gw_unlock(u, args.addr, pause)
                elif args.cmd == "gwres":
                    orig, cmd0, polls = gw_lock(u, args.addr, pause,
                                                force=args.force_lock)
                    try:
                        pause()
                        cr_write(u, args.addr, GW_CMD, CMD_RES,
                                 note="res: W CMD@0xf0400=0xC0AB0215 (Go, без ADDR)")
                        data, ms = cr_read(u, args.addr, GW_DATA, 4,
                                           note="res: R DATA@0xf0410 (без пере-чтения CMD)")
                        print(f"res: data = {data.hex()} [{ms:.2f} ms] — "
                              + ("санити OK" if data_sane(data) else "мусор"))
                    finally:
                        gw_unlock(u, args.addr, pause)
                elif args.cmd == "gwread":
                    orig, cmd0, polls = gw_lock(u, args.addr, pause,
                                                force=args.force_lock)
                    try:
                        pause()
                        cr_write(u, args.addr, GW_ADDR, args.flash_addr,
                                 note=f"read: W ADDR@0xf0404=0x{args.flash_addr:08x}")
                        pause()
                        cr_write(u, args.addr, GW_CMD, CMD_READ16,
                                 note="read: W CMD@0xf0400=0xC003041D (Go)")
                        data, ms = cr_read(u, args.addr, GW_DATA, 16,
                                           note="read: R DATA@0xf0410 16Б (без пере-чтения CMD)")
                        hexdump(data, base=args.flash_addr)
                        for i in range(0, 16, 4):
                            print(f"  dword[{i // 4}]: "
                                  f"0x{int.from_bytes(data[i:i+4], 'big'):08x}")
                        print(f"sanity: {'OK' if data_sane(data) else 'мусор (ff/00)'}")
                    finally:
                        gw_unlock(u, args.addr, pause)
            except GwSemaphoreHeld as e:
                print(f"R2-факт: {e}")
                print("ничего не отпускаем (семафор не брали); записи не было")
                sys.exit(2)
    finally:
        u.close()


if __name__ == "__main__":
    main()
