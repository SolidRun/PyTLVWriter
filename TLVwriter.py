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
    "TLV_CODE_SYS_SKU": 30,
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
def clear_region(eio: EepromIO, length: int, page_size: int, poll_write: bool,
                 base_offset: int = 0):
    written = 0
    while written < length:
        offset = base_offset + written
        page_remaining = page_size - (offset % page_size)
        chunk_len = min(page_remaining, length - written)
        blank = bytes([0x00] * chunk_len)
        eio.write(offset, blank)
        if poll_write:
            eio.eeprom_write_cycle_poll(offset)
        written += chunk_len
        time.sleep(0.01)

def write_region(eio: EepromIO, blob: bytes, page_size: int, poll_write: bool,
                 base_offset: int = 0):
    written = 0
    while written < len(blob):
        offset = base_offset + written
        page_remaining = page_size - (offset % page_size)
        chunk = blob[written:written + page_remaining]
        eio.write(offset, chunk)
        if poll_write:
            eio.eeprom_write_cycle_poll(offset)
        written += len(chunk)
        time.sleep(0.01)

SPD_MEMORY_TYPES = {
    0x01: "FPM DRAM",
    0x02: "EDO DRAM",
    0x03: "Pipelined Nibble DRAM",
    0x04: "SDR SDRAM",
    0x05: "ROM",
    0x06: "DDR SGRAM",
    0x07: "DDR SDRAM",
    0x08: "DDR2 SDRAM",
    0x0B: "DDR3 SDRAM",
    0x0C: "DDR4 SDRAM",
    0x0F: "LPDDR3 SDRAM",
    0x10: "LPDDR4 SDRAM",
    0x11: "LPDDR4X SDRAM",
    0x12: "DDR5 SDRAM",
    0x13: "LPDDR5 SDRAM",
    0x14: "LPDDR5X SDRAM",
}

def spd_crc16(data: bytes) -> int:
    """JEDEC SPD CRC-16 (polynomial 0x1021, initial value 0)."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def detect_spd(eio: EepromIO) -> str:
    """Return an SPD description when the target strongly resembles DIMM SPD."""
    raw = bytearray()
    try:
        # SMBus block transactions are commonly limited to 32 bytes. Reading
        # 128 bytes covers the base identification and checksum/CRC fields.
        for offset in range(0, 128, 16):
            raw.extend(eio.read(offset, 16))
    except Exception:
        return ""

    if len(raw) < 128 or all(b == 0x00 for b in raw) or all(b == 0xFF for b in raw):
        return ""

    memory_type = raw[2]
    description = SPD_MEMORY_TYPES.get(memory_type)
    if description is None:
        return ""

    at_spd_address = 0x50 <= eio.dev_addr <= 0x57
    revision_valid = raw[1] not in (0x00, 0xFF) and (raw[1] >> 4) <= 2
    module_type_valid = raw[3] not in (0x00, 0xFF)

    if memory_type <= 0x08:
        # Legacy SPD formats use an 8-bit checksum at byte 63.
        integrity_valid = (sum(raw[:64]) & 0xFF) == 0
        header_valid = raw[0] not in (0x00, 0xFF)
    else:
        stored_crc = raw[126] | (raw[127] << 8)
        # DDR3 may cover 117 or 126 bytes depending on byte 0 bit 7. Accepting
        # either also tolerates readers/dumps that normalize that flag.
        crc_lengths = (117, 126) if memory_type in (0x0B, 0x0F) else (126,)
        integrity_valid = stored_crc not in (0x0000, 0xFFFF) and any(
            spd_crc16(raw[:length]) == stored_crc for length in crc_lengths
        )

        if memory_type in (0x12, 0x13, 0x14):
            header_valid = (raw[0] & 0x70) == 0x30
        else:
            bytes_used = raw[0] & 0x0F
            total_bytes = (raw[0] >> 4) & 0x07
            header_valid = 1 <= bytes_used <= 4 and 1 <= total_bytes <= 4

    # A valid checksum/CRC plus a JEDEC memory type is a strong match even if
    # the device is mapped unusually. With a damaged CRC, require all metadata
    # signals and the standard 0x50-0x57 SPD address range.
    if integrity_valid or (at_spd_address and revision_valid and module_type_valid and header_valid):
        integrity = "valid checksum/CRC" if integrity_valid else "SPD header (checksum/CRC invalid)"
        return f"{description}, {integrity}"
    return ""

def verify_region(eio: EepromIO, expected: bytes, page_size: int,
                  base_offset: int = 0):
    """Read back the programmed region and compare it byte-for-byte."""
    actual = bytearray()
    offset = 0
    while offset < len(expected):
        n = min(page_size, len(expected) - offset)
        actual.extend(eio.read(base_offset + offset, n))
        offset += n

    actual = bytes(actual)
    if actual != expected:
        mismatch = next((
            i for i, (expected_byte, actual_byte) in enumerate(zip(expected, actual))
            if expected_byte != actual_byte
        ), min(len(expected), len(actual)))
        if mismatch >= len(actual):
            error(
                f"EEPROM verification failed: read only {len(actual)} of "
                f"{len(expected)} expected bytes"
            )
        absolute_offset = base_offset + mismatch
        error(f"EEPROM verification failed at offset 0x{absolute_offset:04X}: "
              f"expected 0x{expected[mismatch]:02X}, read 0x{actual[mismatch]:02X}")

    success(f"EEPROM verification successful ({len(expected)} bytes matched).")

def read_tlv_auto(eio: EepromIO, page_size: int, base_offset: int = 0) -> bytes:
    """
    Read just enough bytes to parse the TLV:
      - read 11 bytes header
      - parse payload_len
      - read (11 + payload_len) bytes total
    """
    hdr = bytes(eio.read(base_offset, 11))
    if len(hdr) < 11:
        return hdr

    payload_len = struct.unpack('<H', hdr[9:11])[0]
    total = 11 + payload_len

    if base_offset + total > eio.max_bytes:
        error(
            f"TLV at offset 0x{base_offset:X} claims total length {total}, "
            f"exceeding max address space {eio.max_bytes}"
        )

    out = bytearray(hdr)
    offset = 11
    while offset < total:
        n = min(page_size, total - offset)
        out.extend(eio.read(base_offset + offset, n))
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

    parser = CustomArgumentParser(
        description="TLVwriter: Write TLV to EEPROM and CONFIG_CODE EFI variable (clears only TLV length bytes)."
    )
    parser.add_argument('i2c_bus',     type=int, help='I2C bus number (e.g. 7)')
    parser.add_argument('eeprom_addr', type=lambda x: int(x, 0), help='EEPROM I2C address (e.g. 0x51)')

    parser.add_argument('-r', '--read',   action='store_true', help='Read and display EEPROM TLV data (auto-length)')
    parser.add_argument('-y', '--yes',    action='store_true', help='Skip confirmation prompt')
    parser.add_argument('-b', '--binary', action='store_true', help='Save TLV binary to file only')
    parser.add_argument('-v', '--verify', action='store_true',
                        help='Read back and verify EEPROM contents after writing')

    parser.add_argument('--addr-width',   type=int, choices=[8, 16], default=8,
                        help='EEPROM internal address width in bits (8 or 16)')
    parser.add_argument('--page-size', dest='page_size', type=int, default=DEFAULT_PAGE_SIZE,
                        help='Max bytes per page write (device dependent)')
    parser.add_argument('-o', '--offset', type=lambda x: int(x, 0), default=0,
                        help='EEPROM offset for TLV read/write (default: 0)')
    parser.add_argument('--poll-write', action='store_true',
                        help='ACK-poll after each write page (more reliable for EEPROMs)')
    parser.add_argument('--force-spd', action='store_true',
                        help='Allow writing to an SPD-like EEPROM (DANGEROUS)')
    parser.add_argument('pairs', nargs='*', help='<key> <value> pairs for TLV fields')

    if hasattr(parser, "parse_intermixed_args"):
        args = parser.parse_intermixed_args()
    else:
        args = parser.parse_args()

    if args.offset < 0:
        parser.error("--offset must be non-negative")
    if args.page_size <= 0:
        parser.error("--page-size must be greater than zero")

    if os.geteuid() != 0:
        error("Root privileges are required to modify EFI variables and access /dev/i2c-*.")

    eio = EepromIO(
        i2c_bus=args.i2c_bus,
        dev_addr=args.eeprom_addr,
        addr_width=args.addr_width,
        page_size=args.page_size
    )

    try:
        if args.read:
            raw = read_tlv_auto(eio, args.page_size, args.offset)
            parse_and_display(raw)
            return

        if not args.pairs or (len(args.pairs) % 2) != 0:
            parser.error("Key/value pairs must be provided in <key> <value> format.")

        if not args.binary and not args.force_spd:
            spd_description = detect_spd(eio)
            if spd_description:
                error(
                    f"Refusing to write: device 0x{args.eeprom_addr:02X} on I2C bus "
                    f"{args.i2c_bus} looks like SPD ({spd_description}). Writing would "
                    "damage the DIMM's SPD data. Use --force-spd only if this is intentional."
                )

        if not args.yes:
            warning("This operation will overwrite TLV region in EEPROM (only TLV length bytes will be cleared/written).")
            if input("Proceed? [y/N]: ").lower() != 'y':
                sys.exit("Operation cancelled.")

        tlv_data = build_tlv(args.pairs)

        if len(tlv_data) > eio.max_bytes:
            error(f"TLV blob length {len(tlv_data)} exceeds max {eio.max_bytes} for addr_width={args.addr_width}")

        if not args.binary and args.offset + len(tlv_data) > eio.max_bytes:
            error(
                f"TLV at offset 0x{args.offset:X} ends at 0x{args.offset + len(tlv_data):X}, "
                f"exceeding max {eio.max_bytes} for addr_width={args.addr_width}"
            )

        if args.binary:
            path = "/tmp/eeprom_tlv.bin"
            with open(path, "wb") as f:
                f.write(tlv_data)
            info(f"TLV binary saved to {path}")
            return

        clear_region(eio, len(tlv_data), args.page_size, args.poll_write, args.offset)
        write_region(eio, tlv_data, args.page_size, args.poll_write, args.offset)

        success(
            f"TLV data written successfully at offset 0x{args.offset:X} "
            f"({len(tlv_data)} bytes). Max space for addr-width={args.addr_width} "
            f"is {eio.max_bytes} bytes.\n"
        )

        if args.verify:
            verify_region(eio, tlv_data, args.page_size, args.offset)

    finally:
        eio.close()

if __name__ == "__main__":
    main()
