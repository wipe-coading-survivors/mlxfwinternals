#!/usr/bin/env python3
"""Диагностика: ACK/NAK-статус полной транзакции записи.

Статус-байт CH341-стрима: биты = NAK-позиции (addr/mem/data);
0x00 = все байты ACK'нуты (запись принята на шине; если read-back при
этом не меняется — модуль ACK-and-drop'ает, см. гл. 2 спеки трансиверов).
По умолчанию — прежняя проба гл. 2 (pw-01a @0x50:119).
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def parse_data(text):
    """Hex-байты через пробел/запятую или слитно -> bytes."""
    return bytes.fromhex(text.replace(" ", "").replace(",", ""))


def main():
    ap = argparse.ArgumentParser(description="write-ACK диагностика CH341")
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=0x50)
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=119)
    ap.add_argument("--data", default="00 00 10 11 00 00 00 00",
                    help="байты записи: hex через пробел или слитно")
    args = ap.parse_args()

    import ch341i2c as c

    data = parse_data(args.data)
    dev = c.open_dev()
    c.set_speed(dev, 1)
    ack, st = c.probe_ack(dev, args.addr)
    print(f"probe 0x{args.addr:02x}: ack={ack} status=0x{st:02x}", file=sys.stderr)
    if not ack:
        sys.exit(1)

    frame = bytes([c.CMD_STREAM, c.STM_STA, c.STM_OUT | (len(data) + 2),
                   (args.addr << 1) & 0xFE, args.offset & 0xFF]) + data + \
        bytes([c.STM_STO, c.STM_END])
    dev.write(c.EP_OUT, frame, c.TIMEOUT)
    st = bytes(dev.read(c.EP_IN, 8, c.TIMEOUT))
    print(f"write status: 0x{st[0]:02x} (биты=NAK-позиции; 0x00 = полный ACK)",
          file=sys.stderr)

    time.sleep(0.01)
    back = c.do_read(dev, args.addr, args.offset, len(data))
    print(f"read-back {args.offset}..{args.offset + len(data) - 1}: "
          f"{back.hex(' ')}", file=sys.stderr)


if __name__ == "__main__":
    main()
