# DESFire EV3 Card Provisioning Toolkit

Internal company script suite for provisioning and managing NXP DESFire EV3 contactless cards. Supports both DES and AES encryption for PICC (PICC Integrity Crypto Key) master keys.

## Overview

This toolkit provides three main utilities for complete card lifecycle management:

- **`provision.py`** — Create and encrypt application data on cards
- **`change_picc_key.py`** — Rotate PICC master key (DES ↔ AES)
- **`factory_reset.py`** — Wipe all applications and reset to defaults
- **`desfsh`** — Low-level command-line interface (binary)

## Prerequisites

### Hardware
- NXP DESFire EV3 contactless card reader (ACR122U or compatible or ISO14443)
- NXP DESFire EV3 cards

### Software
```bash
pip install pycryptodome smartcard
```

Ensure `desfsh` binary is in the working directory or specify with `--desfsh` flag.

## Quick Start

### 1. Factory Fresh Card (Default Keys)

Start with a brand-new card or one reset to factory defaults:

```bash
python3 provision.py \
    --picc-key 00:00:00:00:00:00:00:00 \
    --app-id A1:B2:C3 \
    --app-key 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF \
    --data-key AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99 \
    --data "EMP000123"
```

### 2. Card with Custom Keys

If the PICC key has been changed to AES:

```bash
python3 provision.py \
    --picc-key 01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10 \
    --app-id A1:B2:C3 \
    --app-key 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF \
    --data-key AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99 \
    --data "EMP000123"
```

### 3. Rotate PICC Key

Change PICC master key from DES to AES (auto-detects current key):

```bash
python3 change_picc_key.py \
    --new-key 0102030405060708090A0B0C0D0E0F10
```

Or specify old key explicitly:

```bash
python3 change_picc_key.py \
    --old-key 0000000000000000 \
    --new-key 0102030405060708090A0B0C0D0E0F10 \
    -y
```

### 4. Factory Reset a Card

Wipe all applications and reset PICC key to default DES zeros:

```bash
python3 factory_reset.py
```

## Detailed Usage

### `provision.py` — Application Provisioning

Creates an AES-secured application on the card with encrypted data.

**Arguments:**
- `--picc-key` (required) — Current PICC master key in `XX:XX:...` format
  - DES format: 8 bytes (e.g., `00:00:00:00:00:00:00:00`)
  - AES format: 16 bytes (e.g., `01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10`)
- `--app-id` (required) — 3-byte application ID (e.g., `A1:B2:C3`)
- `--app-key` (required) — AES-128 authentication key for the application (16 bytes)
- `--data-key` (required) — AES-128 encryption key for data (16 bytes)
- `--data` (required) — Plain text string to store (max 240 bytes)

**Output:**
```
[1] Detects card presence
[2] Authenticates with PICC key
[3] Creates AES application
[4] Sets application authentication key
[5] Creates encrypted data file
[6] Writes encrypted payload
[7] Verifies read-back
```

**Example with Employee ID:**
```bash
python3 provision.py \
    --picc-key 00:00:00:00:00:00:00:00 \
    --app-id FF:01:02 \
    --app-key 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00 \
    --data-key AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00 \
    --data "EMP000456"
```

---

### `change_picc_key.py` — PICC Key Rotation

Safely rotate the PICC master key. Supports auto-detection of current key or explicit specification.

**Arguments:**
- `--new-key` (required) — Target PICC key (16 chars DES / 32 chars AES)
- `--old-key` (optional) — Current PICC key. If omitted, tries defaults then prompts
- `--desfsh` (optional) — Path to `desfsh` binary (default: `./desfsh`)
- `--device` (optional) — Device index (default: `1`)
- `--tag` (optional) — Tag index (default: `0`)
- `-y, --yes` (optional) — Skip confirmation prompt

**Key Format (hex string, no colons):**
- DES: `0000000000000000` (16 hex characters)
- AES: `0102030405060708090A0B0C0D0E0F10` (32 hex characters)

**Workflow:**
```
[1] Detects card
[2] Auto-detects or validates current key
[3] Confirms change with user
[4] Changes key securely
[5] Verifies new key works
```

**Examples:**

Auto-detect old key, change to AES:
```bash
python3 change_picc_key.py --new-key 0102030405060708090A0B0C0D0E0F10
```

Explicit DES → AES, skip confirmation:
```bash
python3 change_picc_key.py \
    --old-key 0000000000000000 \
    --new-key 0102030405060708090A0B0C0D0E0F10 \
    -y
```

AES → DES (factory reset):
```bash
python3 change_picc_key.py \
    --old-key 0102030405060708090A0B0C0D0E0F10 \
    --new-key 0000000000000000
```

With custom device:
```bash
python3 change_picc_key.py \
    --new-key 0102030405060708090A0B0C0D0E0F10 \
    --device 2 \
    --tag 0
```

---

### `factory_reset.py` — Card Wipe

Completely resets a card by deleting all applications and resetting PICC key to default DES.

**Requirements:**
- Card must have default or known PICC key
- Uses DES default (`00:00:00:00:00:00:00:00`)
- Apps with unknown keys will be skipped with warning

**Workflow:**
```
[1] Detects card
[2] Authenticates with default DES key
[3] Enumerates all applications
[4] Deletes each application (authenticating if needed)
[5] Verifies card is clean
```

**Usage:**
```bash
python3 factory_reset.py
```

**Output example:**
```
=== Step 1: Select PICC ===
  ✓ Card detected
  ✓ DES auth OK

=== Step 2: List Applications ===
  Found 2 app(s): FF:01:02, FF:03:04

=== Deleting app FF:01:02 ===
  ✓ Deleted FF:01:02

=== Deleting app FF:03:04 ===
  ✓ Deleted FF:03:04

=== Step 4: Verify ===
  ✓ Card is factory fresh — no applications
```

**Troubleshooting:**

If you see `SW: 91 AE` (authentication failed):
```
The card's PICC master key is not default DES zeros.
First reset it to default using change_picc_key.py:

  python3 change_picc_key.py \
      --old-key <YOUR_CURRENT_KEY> \
      --new-key 0000000000000000
```

---

## Key Management

### Default Keys

| Type | Value | Use Case |
|------|-------|----------|
| DES (PICC) | `00:00:00:00:00:00:00:00` | Factory default |
| DES (PICC, hex) | `0000000000000000` | `change_picc_key.py` format |
| AES (PICC) | `00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00` | After AES migration |
| AES (app/data) | `00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF` | Default AES example |

### Supported Formats

```
Hex with colons (provision.py, factory_reset.py):
  00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF

Hex without separators (change_picc_key.py):
  0011223344556677889900AABBCCDDEEFF
```

### Key Encryption

- **PICC key:** Authenticates to PICC (card root)
- **Application key:** Authenticates to application
- **Data key:** Encrypts/decrypts file contents using AES-128-CBC

Data files are encrypted **client-side** before transmission to the card, ensuring data security in transit.

---

## Workflow Examples

### Scenario 1: New Card Issuance

```bash
# 1. Factory reset to ensure clean state
python3 factory_reset.py

# 2. Upgrade PICC key for security
python3 change_picc_key.py \
    --old-key 0000000000000000 \
    --new-key AABBCCDDEEFF00112233445566778899 \
    -y

# 3. Provision with employee data
python3 provision.py \
    --picc-key AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99 \
    --app-id FF:01:02 \
    --app-key 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00 \
    --data-key AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00 \
    --data "EMP001234"
```

### Scenario 2: Key Rotation on Existing Cards

```bash
# Check current key and rotate
python3 change_picc_key.py \
    --new-key 1122334455667788990011223344556677

# Confirm when prompted
```

### Scenario 3: Repurposing Card

```bash
# Wipe existing provisioning
python3 factory_reset.py

# Re-provision with new data
python3 provision.py \
    --picc-key 00:00:00:00:00:00:00:00 \
    --app-id FF:02:03 \
    --app-key FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00 \
    --data-key 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF \
    --data "EMP001235"
```

---

## Troubleshooting

### "No contactless reader found"
- Ensure ACR122U or compatible reader is connected
- Check `lsusb` (Linux) or Device Manager (Windows)
- Install reader drivers if needed

### "No card detected"
- Place card on reader surface
- Try different reader positions
- Check card is not damaged

### "AUTH_FAILED" / "SW: 91 AE"
- Incorrect PICC key provided
- Card may have non-default key — use `change_picc_key.py` with `--old-key` to specify
- Try defaults with auto-detection (omit `--old-key`)

### "desfsh not found"
- Ensure `desfsh` binary is in current directory, or
- Specify explicit path: `--desfsh /path/to/desfsh`

### File path issues
- Use absolute paths for `--desfsh` when not in working directory
- Verify binary has execute permissions: `chmod +x desfsh`

---

## Security Notes

⚠️ **Important:**
- **Store keys securely.** Do not commit keys to version control.
- **Data encryption:** Files are encrypted on card using AES-128-CBC with no free read access.
- **Key derivation:** Use cryptographically secure random or KMS for production keys.
- **Audit access:** Log all provisioning operations with timestamps and operator ID.
- **Key rotation:** Rotate PICC keys periodically; update records accordingly.

---

## Technical Details

### Authentication Methods
- **DES:** Single DES (PICC) or 3DES (legacy)
- **AES:** EV2 enhanced authentication with session key derivation
- **Session keys:** Derived using AES-CMAC per DESFire spec

### Data Encryption
- **Algorithm:** AES-128-CBC
- **Padding:** ISO/IEC 7816-4 (0x80 followed by 0x00s)
- **IV:** All zeros (client-side pre-encryption)

### File Structure
- **File ID:** 0x01 (data file)
- **Access:** Key 0 required for all read/write operations
- **Max size:** 240 bytes per file

---

## Support

For issues or questions:
1. Check troubleshooting section above
2. Verify card and reader are functioning
3. Test with factory defaults first
4. Check `desfsh` binary version compatibility

---

## Version History

- **v1.0** — Initial release
  - DES and AES PICC key support
  - Application provisioning with encrypted data
  - Secure key rotation
  - Factory reset utility
