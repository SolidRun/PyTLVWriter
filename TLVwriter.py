#!/usr/bin/env python3
import sys
import struct
import binascii
import smbus
import time
import os
import fcntl
import argparse

# PAGE_SIZE is the maximum number of bytes per write (smbus block limit)
PAGE_SIZE = 16

# EEPROM total capacity (in bytes)
EEPROM_SIZE = 256

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
CYAN    = '\033[96m'
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
    "TLV_CODE_CHS_TYPE" : 0x52,

    # Configuration types
    "TLV_CODE_CONFIG_CODE": 0x60,
}

REVERSE_KEYS = {v: k for k, v in KEYS.items()}
CRC_CODE = 0xFE

# Custom maximum lengths for specific keys.
max_lengths = {
    # Common Types
    "TLV_CODE_FAMILY": 20,
    "TLV_CODE_MAC_NUM": 2,
    "TLV_CODE_MAC_BASE": 6,
    "TLV_CODE_MANUF_DATE": 10,
    "TLV_CODE_PLATFORM_NAME": 20,
    "TLV_CODE_MANUF_NAME": 20,
    "TLV_CODE_MANUF_COUNTRY": 2,
    "TLV_CODE_VENDOR_NAME": 20,
    "TLV_CODE_CONFIG_CODE": 200,
    "TLV_CODE_NIO_TYPE": 8,


    # Sys Types
    "TLV_CODE_SYS_NAME": 20,
    "TLV_CODE_SYS_SKU": 20,
    "TLV_CODE_SYS_SERIAL_NUMBER": 24,
    "TLV_CODE_SYS_VERSION": 5,
    "TLV_CODE_SYS_UUID": 36,

    # Chassis Types
    "TLV_CODE_CHS_SERIAL_NUMBER": 24,
    "TLV_CODE_CHS_VERSION": 5,

    # NIO Types
    "TLV_CODE_NIO_NAME": 20,
    "TLV_CODE_NIO_SERIAL_NUMBER": 24,
    "TLV_CODE_NIO_VERSION": 5
}

def error(message, code=1):
    """Print an error message in red and exit."""
    print(f"{RED}Error: {message}{RESET}", file=sys.stderr)
    sys.exit(code)


def warning(message):
    """Print a warning message in yellow."""
    print(f"{YELLOW}Warning: {message}{RESET}", file=sys.stderr)


def info(message):
    """Print an informational message in cyan."""
    print(f"{CYAN}{message}{RESET}")

def success(message):
    """Print an success message in green."""
    print(f"{GREEN}{message}{RESET}")

def read_eeprom(I2C_BUS, EEPROM_ADDR):
    """
    Read the entire EEPROM content and return it as bytes.
    """
    bus = smbus.SMBus(I2C_BUS)
    data = []
    for offset in range(0, EEPROM_SIZE, PAGE_SIZE):
        chunk_len = min(PAGE_SIZE, EEPROM_SIZE - offset)
        try:
            block = bus.read_i2c_block_data(EEPROM_ADDR, offset, chunk_len)
        except Exception as e:
            sys.exit(f"I2C read error at offset {offset}: {e}")
        data.extend(block)
        time.sleep(0.05)
    return bytes(data)

def parse_and_display(raw):
    """
    Parse raw TLV data and print each entry in human-readable form.
    """
    # Minimum header length: 8 sig bytes +1 version +2 length =11 bytes
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
            crc_val = struct.unpack('<I', v)[0]
            print(f"CRC: 0x{crc_val:08X}")
            break

        name = REVERSE_KEYS.get(t, f"Unknown(0x{t:02X})")
        try:
            val_str = v.decode('ascii')
        except Exception:
            val_str = binascii.hexlify(v).decode()
        print(f"{name} (0x{t:02X}), Length: {l}, Value: {val_str}")

        idx += 2 + l

def parse_mac(mac_str):
    """
    Parse a MAC address provided either in the format xx:xx:xx:xx:xx:xx or
    as a 12-character hexadecimal string (e.g., aabbccddeeff) and return the 6-byte binary representation.
    """
    if ':' in mac_str:
        parts = mac_str.split(':')
        if len(parts) != 6:
            sys.exit("Error: MAC address must have 6 colon-separated parts.")
        try:
            return bytes(int(x, 16) for x in parts)
        except Exception as e:
            sys.exit("Error: Invalid MAC address format: " + str(e))
    else:
        if len(mac_str) != 12:
            sys.exit("Error: MAC address must be 12 hexadecimal characters when not using ':' separators.")
        try:
            return bytes(int(mac_str[i:i + 2], 16) for i in range(0, 12, 2))
        except Exception as e:
            sys.exit("Error: Invalid MAC address format: " + str(e))



def build_tlv(args):
    if len(args) == 0 or len(args) % 2 != 0:
        sys.exit("Usage: TLV_write.py <i2c_bus> <eeprom_address> [--yes] <key> <value> ...")

    payload = bytearray()

    for i in range(0, len(args), 2):
        # key = args[i].lower()
        key = args[i]
        value = args[i + 1]
        if key not in KEYS:
            sys.exit(f"Error: Unknown key: {key}")
        code = KEYS[key]

        if key == "mac_base":
            val_bytes = parse_mac(value)
        elif key == "mac_size":
            try:
                num = int(value)
                if num > 99:
                    sys.exit("Error: mac_size must be less than 99")
            except ValueError:
                sys.exit("Error: mac_size must be an integer")
            val_bytes = struct.pack(">H", num)
        # elif key == "TLV_CODE_NIO_TYPE":
        #     try:
        #         val_bytes = bytes.fromhex(value)
        #         print(val_bytes.hex())
        #     except ValueError:
        #         sys.exit("Error: NIO Type must be a valid hex number")
        elif key == "TLV_CODE_CHS_TYPE":
            # parse as hex uint8
            try:
                num = int(value, 16)
                if not 0 <= num <= 0xFF:
                    raise ValueError
                val_bytes = struct.pack("B", num)
            except ValueError:
                sys.exit("Error: CHS_TYPE must be a valid hex uint8 (e.g. 0x23)")

        elif key == "TLV_CODE_CONFIG_CODE":
            try:
                write_efi_variable(value)
                continue
            except ValueError:
                sys.exit("Error: Error writing efi variable")
        else:
            # Default: treat as ASCII string
            val_bytes = value.encode("ascii")

        # Enforce custom maximum length if defined for the key.
        if key in max_lengths and len(val_bytes) > max_lengths[key]:
            sys.exit(f"Error: Value for key '{key}' is too long (max {max_lengths[key]} bytes).")

        # Append field: type, length, value.
        payload.extend(struct.pack("BB", code, len(val_bytes)))
        payload.extend(val_bytes)

    # Append CRC placeholder and header construction
    payload.extend(struct.pack("BB", CRC_CODE, 4))
    payload.extend(b'\x00\x00\x00\x00')

    header = bytearray()
    sig = b"TlvInfo" + b"\0" * (8 - len("TlvInfo"))
    header.extend(sig)
    header.append(1)  # version
    payload_length = len(payload)
    header.extend(struct.pack("<H", payload_length))

    tlv_data = header + payload
    crc_input = tlv_data[:-4]
    crc = binascii.crc32(crc_input) & 0xffffffff
    crc_bytes = struct.pack("<I", crc)
    tlv_data = tlv_data[:-4] + crc_bytes

    return tlv_data

def clear_immutable(path):
    # open read-only, clear all flags
    fd = os.open(path, os.O_RDONLY)
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('I', 0))
    os.close(fd)


def write_efi_variable(value_str):
    """
    Write or update the CONFIG_CODE EFI variable with the provided string.
    Automatically creates the variable if it does not exist.
    """
    data = value_str.encode('utf-8')
    var_path = f"/sys/firmware/efi/efivars/{EFI_VAR_NAME}-{EFI_VAR_GUID}"
    payload = struct.pack('<I', EFI_ATTRS) + data

    if os.path.exists(var_path):
        clear_immutable(var_path)
    else:
        info(f"EFI variable {EFI_VAR_NAME}-{EFI_VAR_GUID} not found; creating new.")

    try:
        # 'wb' will create the file under efivarfs
        with open(var_path, 'wb') as f:
            f.write(payload)
    except Exception as e:
        error(f"Unable to write EFI variable: {e}")

    success(f"Config code EFI variable {EFI_VAR_NAME} set successfully\n")




def clear_eeprom(I2C_BUS, EEPROM_ADDR):
    """
    Clear the EEPROM by validate_tlv_data_from_eeproming zeros to every byte.
    """
    bus = smbus.SMBus(I2C_BUS)
    total_length = EEPROM_SIZE
    offset = 0
    while offset < total_length:
        chunk_length = min(PAGE_SIZE, total_length - offset)
        blank = [0x00] * chunk_length
        try:
            bus.write_i2c_block_data(EEPROM_ADDR, offset, blank)
        except Exception as e:
            sys.exit("I2C write error during clear at offset {}: {}".format(offset, e))
        offset += PAGE_SIZE
        time.sleep(0.05)
    info("EEPROM cleared successfully.\n")



def write_to_eeprom(data, bin_only=False):
    if bin_only:
        padded = data + bytes([0x00] * (EEPROM_SIZE - len(data)))
        bin_path=f"/tmp/eeprom_tlv.bin"
        with open(bin_path, "wb") as f:
            f.write(padded)
        print(f"saved TLV binary to {bin_path}")
        return

    bus = smbus.SMBus(I2C_BUS)
    total_length = len(data)
    offset = 0

    # Write data in PAGE_SIZE chunks.
    while offset < total_length:
        chunk = list(data[offset:offset + PAGE_SIZE])
        try:
            bus.write_i2c_block_data(EEPROM_ADDR, offset, chunk)
        except Exception as e:
            sys.exit("I2C write error at offset {}: {}".format(offset, e))
        offset += PAGE_SIZE
        time.sleep(0.05)
    print("TLV data written successfully to EEPROM.")

class CustomArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that appends BIOS key-length info to help."""
    def format_help(self):
        base = super().format_help()
        extra = "BIOS supported keys with max lengths:\n"
        for key in KEYS:
            max_len = max_lengths.get(key)
            extra += f"  {key:<32} max length: {max_len}\n"
        return f"{base}\n{extra}"

def main():
    if os.geteuid() != 0:
        error("Root privileges are required to modify EFI variables.")

    # Check for the minimum number of arguments.
    # if len(sys.argv) < 4:
    #     print("Usage: TLV_write.py <i2c_bus> <eeprom_address> [--yes] [-b] <key> <value> <key> <value> ...")
    #     print("\nBIOS supported keys with lenghts: \n")
    #     for key in KEYS.keys():
    #         code = KEYS[key]
    #         max_len = max_lengths.get(key)
    #         print(f"\t{key:<32} max length: {max_len}")
    #     sys.exit()


    parser = CustomArgumentParser(
        description='TLVwriter: Manage EEPROM TLV data and CONFIG_CODE EFI variable.'
    )
    parser.add_argument('i2c_bus', type=int, help='I2C bus number')
    parser.add_argument('eeprom_addr', type=lambda x: int(x, 0), help='EEPROM I2C address')
    parser.add_argument('-r', '--read', action='store_true', help='Read and display EEPROM TLV data')
    parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation prompt')
    parser.add_argument('-b', '--binary', action='store_true', help='Save TLV binary to file only')
    parser.add_argument('pairs', nargs='*', help='<key> <value> pairs for TLV fields')

    args = parser.parse_args()

    if args.read:
        raw = read_eeprom(args.i2c_bus, args.eeprom_addr)
        parse_and_display(raw)
        return

    if not args.pairs or len(args.pairs) % 2 != 0:
        parser.error('Key/value pairs must be provided in <key> <value> format.')

    if not args.yes:
        warning('This operation will overwrite EEPROM contents. Current data will be lost.')
        if input('Proceed? [y/N]: ').lower() != 'y':
            sys.exit('Operation cancelled.')

    tlv_data = build_tlv(args.pairs)
    if len(tlv_data) > EEPROM_SIZE:
        error(f'TLV data exceeds EEPROM capacity ({len(tlv_data)} > {EEPROM_SIZE} bytes).')

    clear_eeprom(args.i2c_bus, args.eeprom_addr)

    if args.binary:
        path = '/tmp/eeprom_tlv.bin'
        with open(path, 'wb') as f:
            f.write(tlv_data)
        info(f'TLV binary saved to {path}')
    else:
        bus = smbus.SMBus(args.i2c_bus)
        offset = 0
        while offset < len(tlv_data):
            chunk = list(tlv_data[offset:offset + PAGE_SIZE])
            try:
                bus.write_i2c_block_data(args.eeprom_addr, offset, chunk)
            except Exception as e:
                error(f'I2C write error at offset {offset}: {e}')
            offset += PAGE_SIZE
            time.sleep(0.05)
        success('TLV data written to EEPROM successfully.\n')
if __name__ == "__main__":
    main()
