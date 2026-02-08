#!/usr/bin/env python3
import sys
import struct
import binascii
import time
import os
import fcntl
import argparse

# -----------------------------
# Defaults
# -----------------------------
DEFAULT_PAGE_SIZE = 16

# ioctl code for FS_IOC_SETFLAGS
FS_IOC_SETFLAGS = 0x40086602

# EFI variable configuration
EFI_VAR_NAME = "ConfigCodeTemporary"
EFI_VAR_GUID = "20D7915C-5ED8-4455-A55A-315B328A633A"
EFI_ATTRS = 0x1 | 0x2 | 0x4  # NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS

# ANSI color codes
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
RESET   = "\033[0m"

# Mapping from key names to TLV type codes
KEYS = {
    # Common Types
    "TLV_CODE_FAMILY": 0x20,
    "TLV_CODE_PLATFORM_NAME": 0x24,
    "TLV_CODE_MANUF_NAME": 0x25,
    "TLV_CODE_VENDOR_NAME": 0x27,

    # Sys Types
    "TLV_CODE_SYS_NAME": 0x30,
    "TLV_CODE_SYS_SKU": 0x31,
    "TLV_CODE_SYS_SERIAL_NUMBER": 0x32,
    "TLV_CODE_SYS_VERSION": 0x33,
    "TLV_CODE_SYS_UUID": 0x34,

    # NIO Types
    "TLV_CODE_NIO_NAME": 0x40,
    "TLV_CODE_NIO_SERIAL_NUMBER": 0x41,
    "TLV_CODE_NIO_VERSION": 0x42,

    # Chassis Types
    "TLV_CODE_CHS_SERIAL_NUMBER": 0x50,
    "TLV_CODE_CHS_VERSION": 0x51,
    "TLV_CODE_CHS_TYPE": 0x52,

    # Configuration types
    "TLV_CODE_CONFIG_CODE": 0x60,
}

REVERSE_KEYS = {v: k for k, v in KEYS.items()}
CRC_CODE = 0xFE

max_lengths = {
    "TLV_CODE_FAMILY": 20,
    "TLV_CODE_PLATFORM_NAME": 24,
    "TLV_CODE_MANUF_NAME": 20,
    "TLV_CODE_VENDOR_NAME": 20,
    "TLV_CODE_CONFIG_CODE": 200,

    "TLV_CODE_SYS_NAME": 20,
    "TLV_CODE_SYS_SKU": 20,
    "TLV_CODE_SYS_SERIAL_NUMBER": 24,
    "TLV_CODE_SYS_VERSION": 5,
    "TLV_CODE_SYS_UUID": 36,

    "TLV_CODE_CHS_SERIAL_NUMBER": 24,
    "TLV_CODE_CHS_VERSION": 5,
    "TLV_CODE_CHS_TYPE": 1,

    "TLV_CODE_NIO_NAME": 20,
    "TLV_CODE_NIO_SERIAL_NUMBER": 24,
    "TLV_CODE_NIO_VERSION": 5,
}

# -----------------------------
# Logging helpers
# -----------------------------
def error(message, code=1):
    print(f"{RED}Error: {message}{RESET}", file=sys.stderr)
    sys.exit(code)

def warning(message):
    print(f"{YELLOW}Warning: {message}{RESET}", file=sys.stderr)

def info(message):
    print(f"{CYAN}{message}{RESET}")

def success(message):
    print(f"{GREEN}{message}{RESET}")

def addr_space_max_bytes(addr_width: int) -> int:
    if addr_width == 8:
        return 256
    if addr_width == 16:
        return 65536
    error(f"Unsupported addr_width: {addr_width}")

# -----------------------------
# EEPROM I/O (smbus for 8-bit, smbus2 for 16-bit)
# -----------------------------
class EepromIO:
    """
    EEPROM IO abstraction:
      - addr_width=8  -> uses smbus (block read/write with command byte)
      - addr_width=16 -> uses smbus2 + i2c_msg (combined write addr_hi/lo then read)
    Enforces max address space statically based on addr_width.
    """

    def __init__(self, i2c_bus: int, dev_addr: int, addr_width: int, page_size: int):
        self.i2c_bus = i2c_bus
        self.dev_addr = dev_addr
        self.addr_width = addr_width
        self.page_size = page_size
        self.max_bytes = addr_space_max_bytes(addr_width)

        self._bus = None
        self._mode = None  # "smbus" or "smbus2"
        self._i2c_msg = None

        if addr_width == 8:
            try:
                import smbus
            except Exception as e:
                error(f"Python smbus is required for 8-bit addressing mode but import failed: {e}")
            self._bus = smbus.SMBus(i2c_bus)
            self._mode = "smbus"
        else:
            try:
                from smbus2 import SMBus, i2c_msg
            except Exception as e:
                error(f"16-bit EEPROM addressing requires smbus2, but import failed: {e}")

            self._bus = SMBus(i2c_bus)
            self._mode = "smbus2"
            self._i2c_msg = i2c_msg

    def close(self):
        if self._bus is not None:
            try:
                self._bus.close()
            except Exception:
                pass
            self._bus = None

    def _bounds_check(self, offset: int, length: int):
        if offset < 0 or length < 0:
            error("Negative offset/length not allowed")
        if offset + length > self.max_bytes:
            error(f"Access out of range: offset {offset} + len {length} exceeds max {self.max_bytes} for addr_width={self.addr_width}")

    def read(self, offset: int, length: int):
        self._bounds_check(offset, length)

        if self.addr_width == 8:
            # SMBus block read: command byte is the offset
            return self._bus.read_i2c_block_data(self.dev_addr, offset & 0xFF, length)

        # 16-bit: combined write(address_hi,address_lo) then read(length)
        hi = (offset >> 8) & 0xFF
        lo = offset & 0xFF
        w = self._i2c_msg.write(self.dev_addr, [hi, lo])
        r = self._i2c_msg.read(self.dev_addr, length)
        self._bus.i2c_rdwr(w, r)
        return list(r)

    def write(self, offset: int, data_bytes: bytes):
        self._bounds_check(offset, len(data_bytes))

        if self.addr_width == 8:
            # SMBus block write: command byte is the offset
            self._bus.write_i2c_block_data(self.dev_addr, offset & 0xFF, list(data_bytes))
            return

        # 16-bit: single write with [hi, lo, data...]
        hi = (offset >> 8) & 0xFF
        lo = offset & 0xFF
        msg = self._i2c_msg.write(self.dev_addr, [hi, lo] + list(data_bytes))
        self._bus.i2c_rdwr(msg)

    def eeprom_write_cycle_poll(self, offset: int, timeout_s: float = 1.0):
        """
        Optional ACK polling after a write cycle.
        This is best-effort; not all adapters behave identically.
        """
        end = time.time() + timeout_s

        if self.addr_width == 8:
            while time.time() < end:
                try:
                    _ = self._bus.read_byte_data(self.dev_addr, offset & 0xFF)
                    return
                except Exception:
                    time.sleep(0.005)
            return

        # 16-bit: attempt a small "address pointer set" write; retry until it works
        hi = (offset >> 8) & 0xFF
        lo = offset & 0xFF
        while time.time() < end:
            try:
                msg = self._i2c_msg.write(self.dev_addr, [hi, lo])
                self._bus.i2c_rdwr(msg)
                return
            except Exception:
                time.sleep(0.005)

# -----------------------------
# TLV parsing / building
# -----------------------------
def parse_and_display(raw: bytes):
    if len(raw) < 11:
        print("Data too short to contain TLV header.")
        return

    sig = raw[:8].rstrip(b'\x00')
    version = raw[8]
    payload_len = struct.unpack('<H', raw[9:11])[0]
    payload = raw[11:11+payload_len]

    print(f"Signature: {sig.decode(errors='ignore')}, Version: {version}, Payload length: {payload_len}")

    idx = 0
    while idx < len(payload):
        if idx + 2 > len(payload):
            print("Incomplete TLV entry at end of payload.")
            break

        t = payload[idx]
        l = payload[idx+1]
        v = payload[idx+2:idx+2+l]

        if t == CRC_CODE:
            if len(v) >= 4:
                crc_val = struct.unpack('<I', v[:4])[0]
                print(f"CRC: 0x{crc_val:08X}")
            else:
                print("CRC entry malformed.")
            break

        name = REVERSE_KEYS.get(t, f"Unknown(0x{t:02X})")
        try:
            val_str = v.decode('ascii')
        except Exception:
            val_str = binascii.hexlify(v).decode()
        print(f"{name} (0x{t:02X}), Length: {l}, Value: {val_str}")

        idx += 2 + l

def clear_immutable(path):
    fd = os.open(path, os.O_RDONLY)
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('I', 0))
    os.close(fd)

def write_efi_variable(value_str: str):
    data = value_str.encode('utf-8')
    var_path = f"/sys/firmware/efi/efivars/{EFI_VAR_NAME}-{EFI_VAR_GUID}"
    payload = struct.pack('<I', EFI_ATTRS) + data

    if os.path.exists(var_path):
        clear_immutable(var_path)
    else:
        info(f"EFI variable {EFI_VAR_NAME}-{EFI_VAR_GUID} not found; creating new.")

    try:
        with open(var_path, 'wb') as f:
            f.write(payload)
    except Exception as e:
        error(f"Unable to write EFI variable: {e}")

    success(f"Config code EFI variable {EFI_VAR_NAME} set successfully\n")

def build_tlv(pairs) -> bytes:
    if len(pairs) == 0 or len(pairs) % 2 != 0:
        error("Key/value pairs must be provided in <key> <value> format.")

    payload = bytearray()

    for i in range(0, len(pairs), 2):
        key = pairs[i]
        value = pairs[i + 1]

        if key not in KEYS:
            error(f"Unknown key: {key}")
        code = KEYS[key]

        if key == "TLV_CODE_CHS_TYPE":
            try:
                num = int(value, 16)
                if not 0 <= num <= 0xFF:
                    raise ValueError
                val_bytes = struct.pack("B", num)
            except ValueError:
                error("CHS_TYPE must be a valid hex uint8 (e.g. 0x23)")

        elif key == "TLV_CODE_CONFIG_CODE":
            write_efi_variable(value)
            continue

        else:
            try:
                val_bytes = value.encode("ascii")
            except Exception as e:
                error(f"Value for {key} must be ASCII: {e}")

        if key in max_lengths and len(val_bytes) > max_lengths[key]:
            error(f"Value for key '{key}' is too long (max {max_lengths[key]} bytes).")

        payload.extend(struct.pack("BB", code, len(val_bytes)))
        payload.extend(val_bytes)

    # CRC placeholder entry
    payload.extend(struct.pack("BB", CRC_CODE, 4))
    payload.extend(b'\x00\x00\x00\x00')

    header = bytearray()
    sig = b"TlvInfo" + b"\0" * (8 - len("TlvInfo"))
    header.extend(sig)
    header.append(1)  # version
    header.extend(struct.pack("<H", len(payload)))

    tlv_data = header + payload

    # Fill CRC
    crc = binascii.crc32(tlv_data[:-4]) & 0xFFFFFFFF
    tlv_data = tlv_data[:-4] + struct.pack("<I", crc)

    return bytes(tlv_data)

# -----------------------------
# EEPROM ops (only TLV-length bytes)
# -----------------------------
def clear_region(eio: EepromIO, length: int, page_size: int, poll_write: bool):
    offset = 0
    while offset < length:
        chunk_len = min(page_size, length - offset)
        blank = bytes([0x00] * chunk_len)
        eio.write(offset, blank)
        if poll_write:
            eio.eeprom_write_cycle_poll(offset)
        offset += chunk_len
        time.sleep(0.01)

def write_region(eio: EepromIO, blob: bytes, page_size: int, poll_write: bool):
    offset = 0
    total = len(blob)
    while offset < total:
        chunk = blob[offset:offset + page_size]
        eio.write(offset, chunk)
        if poll_write:
            eio.eeprom_write_cycle_poll(offset)
        offset += len(chunk)
        time.sleep(0.01)

def read_tlv_auto(eio: EepromIO, page_size: int) -> bytes:
    """
    Read just enough bytes to parse the TLV:
      - read 11 bytes header
      - parse payload_len
      - read (11 + payload_len) bytes total
    """
    hdr = bytes(eio.read(0, 11))
    if len(hdr) < 11:
        return hdr

    payload_len = struct.unpack('<H', hdr[9:11])[0]
    total = 11 + payload_len

    if total > eio.max_bytes:
        error(f"TLV claims total length {total}, exceeds max address space {eio.max_bytes}")

    out = bytearray(hdr)
    offset = 11
    while offset < total:
        n = min(page_size, total - offset)
        out.extend(eio.read(offset, n))
        offset += n
    return bytes(out)

# -----------------------------
# CLI
# -----------------------------
class CustomArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        base = super().format_help()
        extra = "BIOS supported keys with max lengths:\n"
        for key in KEYS:
            max_len = max_lengths.get(key)
            extra += f"  {key:<32} max length: {max_len} bytes\n"
        return f"{base}\n{extra}"

def main():
    if os.geteuid() != 0:
        error("Root privileges are required to modify EFI variables and access /dev/i2c-*.")

    parser = CustomArgumentParser(
        description="TLVwriter: Write TLV to EEPROM and CONFIG_CODE EFI variable (clears only TLV length bytes)."
    )
    parser.add_argument('i2c_bus',     type=int, help='I2C bus number (e.g. 7)')
    parser.add_argument('eeprom_addr', type=lambda x: int(x, 0), help='EEPROM I2C address (e.g. 0x51)')

    parser.add_argument('-r', '--read',   action='store_true', help='Read and display EEPROM TLV data (auto-length)')
    parser.add_argument('-y', '--yes',    action='store_true', help='Skip confirmation prompt')
    parser.add_argument('-b', '--binary', action='store_true', help='Save TLV binary to file only')

    parser.add_argument('--addr-width',   type=int, choices=[8, 16], default=8,
                        help='EEPROM internal address width in bits (8 or 16)')
    parser.add_argument('--page-size', dest='page_size', type=int, default=DEFAULT_PAGE_SIZE,
                        help='Max bytes per page write (device dependent)')
    parser.add_argument('--poll-write', action='store_true',
                        help='ACK-poll after each write page (more reliable for EEPROMs)')
    parser.add_argument('pairs', nargs='*', help='<key> <value> pairs for TLV fields')

    if hasattr(parser, "parse_intermixed_args"):
        args = parser.parse_intermixed_args()
    else:
        args = parser.parse_args()

    eio = EepromIO(
        i2c_bus=args.i2c_bus,
        dev_addr=args.eeprom_addr,
        addr_width=args.addr_width,
        page_size=args.page_size
    )

    try:
        if args.read:
            raw = read_tlv_auto(eio, args.page_size)
            parse_and_display(raw)
            return

        if not args.pairs or (len(args.pairs) % 2) != 0:
            parser.error("Key/value pairs must be provided in <key> <value> format.")

        if not args.yes:
            warning("This operation will overwrite TLV region in EEPROM (only TLV length bytes will be cleared/written).")
            if input("Proceed? [y/N]: ").lower() != 'y':
                sys.exit("Operation cancelled.")

        tlv_data = build_tlv(args.pairs)

        if len(tlv_data) > eio.max_bytes:
            error(f"TLV blob length {len(tlv_data)} exceeds max {eio.max_bytes} for addr_width={args.addr_width}")

        if args.binary:
            path = "/tmp/eeprom_tlv.bin"
            with open(path, "wb") as f:
                f.write(tlv_data)
            info(f"TLV binary saved to {path}")
            return

        clear_region(eio, len(tlv_data), args.page_size, args.poll_write)
        write_region(eio, tlv_data, args.page_size, args.poll_write)

        success(f"TLV data written successfully ({len(tlv_data)} bytes). Max space for addr-width={args.addr_width} is {eio.max_bytes} bytes.\n")

    finally:
        eio.close()

if __name__ == "__main__":
    main()
