#!/usr/bin/env python3
import sys
import struct
import binascii
import smbus
import time

# PAGE_SIZE is the maximum number of bytes per write (smbus block limit)
PAGE_SIZE = 16

# EEPROM total capacity (in bytes)
EEPROM_SIZE = 256
I2C_BUS = None
EEPROM_ADDR = None

# Mapping from key names to TLV type codes
KEYS = {
    # Common Types
    "TLV_CODE_FAMILY": 0x20,
    # "TLV_CODE_MAC_NUM":         0x21, # Unused by BIOS
    # "TLV_CODE_MAC_BASE":        0x22, # Unused by BIOS
    "TLV_CODE_MANUF_DATE": 0x23,
    "TLV_CODE_PLATFORM_NAME": 0x24,
    "TLV_CODE_MANUF_NAME": 0x25,
    # "TLV_CODE_MANUF_COUNTRY":   0x26, # Unused by BIOS
    "TLV_CODE_VENDOR_NAME": 0x27,
    "TLV_CODE_NIO_TYPE": 0x28,

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

    # Configuration types
    "TLV_CODE_CONFIG_CODE": 0x60,
}

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

def read_eeprom_data():
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
        elif key == "TLV_CODE_NIO_TYPE":
            try:
                val_bytes = bytes.fromhex(value)
                print(val_bytes.hex())
            except ValueError:
                sys.exit("Error: NIO Type must be a valid hex number")
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


def clear_eeprom():
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
    print("EEPROM cleared successfully.")



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


def main():
    # Check for the minimum number of arguments.
    if len(sys.argv) < 4:
        print("Usage: TLV_write.py <i2c_bus> <eeprom_address> [--yes] [-b] <key> <value> <key> <value> ...")
        print("\nBIOS supported keys with lenghts: \n")
        for key in KEYS.keys():
            code = KEYS[key]
            max_len = max_lengths.get(key)
            print(f"\t{key:<32} max length: {max_len}")
        sys.exit()

    global I2C_BUS, EEPROM_ADDR

    try:
        I2C_BUS = int(sys.argv[1])
    except ValueError:
        sys.exit("Error: i2c_bus must be an integer")

    try:
        # The address can be provided in hex (e.g., '0x50') or decimal.
        EEPROM_ADDR = int(sys.argv[2], 0)
    except ValueError:
        sys.exit("Error: eeprom_address must be an integer")

    if any(arg.lower() in ("--read", "-r") for arg in sys.argv[3:]):
        print("Reading EEPROM contents...")
        raw = read_eeprom_data()
        parse_and_display(raw)
        return

    # Determine if an auto-confirmation flag is provided.
    confirm_flag = False
    bin_only = False
    kv_offset = 3

    if sys.argv[3].lower() in ("--yes", "-y", "--force"):
        confirm_flag = True
        kv_offset = 4
        if sys.argv[4].lower() == "-b":
            bin_only=True
            kv_offset = 5
    elif sys.argv[3].lower() == "-b":
        bin_only = True
        kv_offset = 4

    # Ensure we have at least one key/value pair.
    if len(sys.argv) - kv_offset < 2 or ((len(sys.argv) - kv_offset) % 2 != 0):

        sys.exit("Usage: TLV_write.py <i2c_bus> <eeprom_address> [--yes] <key> <value> <key> <value> ...")

    yellow = "\033[93m"     # ANSI code for yellow
    reset = "\033[0m"       # ANSI code to reset to default

    if not confirm_flag:
        answer = input(
            f"{yellow}Warning: This operation will overwrite the EEPROM contents, current data will be "
            f"lost.\nContinue? [y/N]: {reset}")

        if answer.lower() != 'y':
            sys.exit("Operation cancelled by user.")

    # Build TLV data using key/value pairs from the arguments.
    tlv_data = build_tlv(sys.argv[kv_offset:])

    # Ensure TLV data does not exceed the EEPROM capacity.
    if len(tlv_data) > EEPROM_SIZE:
        sys.exit("Error: Total TLV data length ({0} bytes) exceeds EEPROM capacity ({1} bytes).".format(len(tlv_data),
                                                                                                        EEPROM_SIZE))

    # Clear EEPROM before writing new data.
    clear_eeprom()
    write_to_eeprom(tlv_data, bin_only )


if __name__ == "__main__":
    main()
