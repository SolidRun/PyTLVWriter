# TLVwriter

A command-line Python tool to read and write TLV (Type-Length-Value) data to an I²C EEPROM and manage a `CONFIG_CODE` EFI variable via efivarfs.

---

## Overview

`TLVwriter.py` facilitates:

* **Reading** existing TLV data from an EEPROM and displaying it in human-readable form.
* **Building** a TLV binary blob from `<key> <value>` pairs.
* **Writing** the TLV blob into EEPROM in page-sized chunks (default 16 B pages).
* **Clearing** EEPROM contents before writing new data.
* **Creating or updating** a `CONFIG_CODE` EFI variable under `/sys/firmware/efi/efivars`.
* **Colored output** for errors (red), warnings (yellow), info(cyan) and success (green).

This is useful for BIOS/hardware inventory, factory programming, and secure-boot configurations.

---

## Requirements

* **Python 3.6+**
* **Root privileges** (required for I²C access and EFI variable operations)
* Linux with **UEFI** and **efivarfs** mounted at `/sys/firmware/efi/efivars`
* **`smbus`** (typically provided by `python3-smbus` or `python3-smbus2`)
* An I²C EEPROM of at least **256 bytes** capacity on a known bus/address

---

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/youruser/TLVwriter.git
   cd TLVwriter
   ```

2. Install dependencies:

   ```bash
   sudo apt-get install python3-smbus
   # or via pip if using smbus2:
   pip install smbus2
   ```

3. Ensure efivarfs is mounted:

   ```bash
   sudo mountpoint -q /sys/firmware/efi/efivars || \
     sudo mount -t efivarfs efivarfs /sys/firmware/efi/efivars
   ```

---

## TLV Format

### Header (11 bytes total)

| Offset | Size | Description                                    |
| :----: | :--: | :--------------------------------------------- |
|    0   |   8  | ASCII signature: `'TlvInfo'` padded to 8 bytes |
|    8   |   1  | Version (currently `0x01`)                     |
|  9–10  |   2  | Payload length (little-endian 16-bit integer)  |

### Payload (variable length)

A sequence of entries, each:

1. **Type** (1 byte): TLV code
2. **Length** (1 byte): number of bytes in Value
3. **Value** (N bytes)

After all entries, a CRC entry is appended:

* **Type** `0xFE` (CRC code)
* **Length** `0x04`
* **Value**: 4 bytes of little-endian CRC32 computed over **all prior bytes** (header + payload before CRC field)

---

## Supported TLV Keys

Below are the BIOS/hardware keys you can specify, along with their TLV codes and maximum lengths:

```text
KEY                          | Code | Max Length (bytes)
-----------------------------|------|------------------
TLV_CODE_FAMILY              | 0x20 | 20
TLV_CODE_MANUF_DATE          | 0x23 | 10
TLV_CODE_PLATFORM_NAME       | 0x24 | 20
TLV_CODE_MANUF_NAME          | 0x25 | 20
TLV_CODE_VENDOR_NAME         | 0x27 | 20
TLV_CODE_NIO_TYPE            | 0x28 | 8
TLV_CODE_SYS_NAME            | 0x30 | 20
TLV_CODE_SYS_SKU             | 0x31 | 20
TLV_CODE_SYS_SERIAL_NUMBER   | 0x32 | 24
TLV_CODE_SYS_VERSION         | 0x33 | 5
TLV_CODE_SYS_UUID            | 0x34 | 36
TLV_CODE_NIO_NAME            | 0x40 | 20
TLV_CODE_NIO_SERIAL_NUMBER   | 0x41 | 24
TLV_CODE_NIO_VERSION         | 0x42 | 5
TLV_CODE_CHS_SERIAL_NUMBER   | 0x50 | 24
TLV_CODE_CHS_VERSION         | 0x51 | 5
TLV_CODE_CONFIG_CODE         | 0x60 | 200  ← only writes EFI variable since EEPROM is too small
```

Entries exceeding their maximum length will be rejected.

---

## Usage

```bash
sudo python3 TLVwriter.py <i2c_bus> <eeprom_addr> [options] <key1> <val1> [<key2> <val2> ...]
```

**Arguments**:

* `<i2c_bus>`: integer bus number (e.g. `1` for `/dev/i2c-1`).
* `<eeprom_addr>`: I²C address in hex or decimal (e.g. `0x50`).
* `<key> <value>`: one or more TLV field specifiers.

**Options**:

* `-r`, `--read`    : Read and display existing TLV data from EEPROM.
* `-y`, `--yes`     : Skip confirmation prompt before overwrite.
* `-b`, `--binary`  : Write TLV blob to `/tmp/eeprom_tlv.bin` instead of EEPROM.

**Examples**:

1. **Read** current TLV from EEPROM:

   ```bash
   sudo python3 TLVwriter.py 1 0x50 -r
   ```

2. **Write** system metadata:

   ```bash
   sudo python3 TLVwriter.py 1 0x50 \
     TLV_CODE_SYS_NAME "MyBoard" \
     TLV_CODE_SYS_UUID "123e4567-e89b-12d3-a456-426655440000" \
     -y
   ```

3. **Generate** binary only (no EEPROM write):

   ```bash
   sudo python3 TLVwriter.py 1 0x50 -b TLV_CODE_PLATFORM_NAME "ProtoSys" -y
   ```