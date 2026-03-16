# DESFire EV3 Provisioning Toolkit

Scripts for provisioning, managing, and resetting MIFARE DESFire EV3 cards with EV2 secure channel support.

## Security features

- **AuthenticateEV2First** (`0x71`) — full EV2 secure channel with session keys
- **Full communication mode** — file data encrypted with per-session AES-CBC + CMAC verified
- **Hardened application settings** — no free directory listing, no free file creation
- **AID enumeration disabled** — `GetApplicationIDs` requires PICC auth
- **PICC key rotation** — change master key to AES after provisioning
- **Secrets-safe logging** — keys masked by default, `--show-secrets` to reveal

## Files

### `provision.py`

Complete one-shot provisioner. All 11 steps in one card tap:

1. PICC authentication (DES or AES)
2. Check AID availability
3. Create AES application (hardened key settings)
4. EV2 auth with default key
5. Change app key via EV2 secure channel
6. Re-auth with new key
7. Create data file (Full/MAC/Plain comm mode)
8. Write data (encrypted in transit for Full mode)
9. Verify read-back with CMAC verification
10. Disable anonymous AID enumeration (via `desfsh`)
11. Optionally change PICC master key (via `desfsh`)

### `factory_reset.py`

Resets a card to factory state. Works even when AID enumeration is disabled:

1. Authenticate to PICC (tries provided key, then defaults)
2. List and delete applications (with fallback app-level auth)
3. Format PICC (resets key to factory default)
4. Verify factory state with default keys

### `change_picc_key.py`

Standalone PICC master key changer using `desfsh`. Supports DES/AES auto-detection, default key probing, and interactive key entry.

### `desfsh`

External binary for PICC-level operations: authentication, key settings, key changes, and authenticated AID listing.

## Requirements

```bash
pip install pyscard pycryptodome
```

You also need:
- Python 3.8+
- A working PC/SC stack
- A contactless smart card reader
- `desfsh` binary (for steps 10-11 of provisioning)

## Quick start

### Provision a card (max security)

```bash
python3 provision.py \
  --picc-key 0000000000000000 \
  --app-id DE:B1:70 \
  --app-key bf8248ede7a8efef3ded9e9619f51959 \
  --data "EMP001" \
  --new-picc-key 9e73dd321048bcf2de0a693b4d53bf9b \
  --desfsh ./desfsh
```

This provisions with Full comm mode (default), disables AID enumeration, and rotates the PICC key.

### Provision from config file

Create `card.json`:

```json
{
  "picc_key": "9e73dd321048bcf2de0a693b4d53bf9b",
  "new_picc_key": "9e73dd321048bcf2de0a693b4d53bf9b",
  "app_id": "DE:B1:70",
  "app_key": "bf8248ede7a8efef3ded9e9619f51959",
  "desfsh": "./desfsh",
  "device": 1,
  "tag": 0
}
```

```bash
python3 provision.py --config card.json --data "EMP001"
```

Keys stay out of shell history. Only `--data` changes per card.

### Legacy plain mode (backward compatible)

```bash
python3 provision.py \
  --picc-key 0000000000000000 \
  --app-id DE:B1:70 \
  --app-key bf8248ede7a8efef3ded9e9619f51959 \
  --data-key 50ddc80e3b5190e21727208c4b4f4203 \
  --data "EMP001"
```

Providing `--data-key` automatically forces `--comm-mode plain`.

### Factory reset

```bash
# Default DES key (fresh card):
python3 factory_reset.py

# Custom PICC key:
python3 factory_reset.py --picc-key 9e73dd321048bcf2de0a693b4d53bf9b
```

### Change PICC key separately

```bash
python3 change_picc_key.py \
  --old-key 0000000000000000 \
  --new-key 9e73dd321048bcf2de0a693b4d53bf9b \
  --desfsh ./desfsh -y
```

## ESPHome configuration

After provisioning with Full mode:

```yaml
desfire_reader:
  app_id: "DE:B1:70"
  app_key: "BF:82:48:ED:E7:A8:EF:EF:3D:ED:9E:96:19:F5:19:59"
  comm_mode: full
```

After provisioning with Plain mode (legacy):

```yaml
desfire_reader:
  app_id: "DE:B1:70"
  app_key: "BF:82:48:ED:E7:A8:EF:EF:3D:ED:9E:96:19:F5:19:59"
  data_key: "50:DD:C8:0E:3B:51:90:E2:17:27:20:8C:4B:4F:42:03"
  comm_mode: plain
```

## Comm modes

| Mode | File on card | RF transfer | Reader decryption |
|------|-------------|-------------|-------------------|
| **full** | Plaintext | AES-CBC encrypted + CMAC (per-session key) | Session key |
| **mac** | Plaintext | Cleartext + CMAC integrity | None needed |
| **plain** | Pre-encrypted with `data_key` | Raw ciphertext | Static `data_key` |

Full mode is recommended. Plain mode is backward-compatible with cards provisioned by the original script.

## Provision script options

| Flag | Description | Default |
|------|-------------|---------|
| `--config FILE` | Load config from JSON file | — |
| `--picc-key HEX` | Current PICC master key | required |
| `--new-picc-key HEX` | Rotate PICC key after provisioning | — |
| `--app-id HEX` | Application ID (3 bytes) | required |
| `--app-key HEX` | AES-128 application key | required |
| `--data STRING` | Payload to write | required |
| `--data-key HEX` | Legacy data encryption key (forces plain mode) | — |
| `--comm-mode` | `full`, `mac`, or `plain` | `full` |
| `--desfsh PATH` | Path to desfsh binary | `./desfsh` |
| `--device N` | desfsh device index | `1` |
| `--tag N` | desfsh tag index | `0` |
| `--show-secrets` | Print full key values | masked |
| `--skip-aid-enum` | Skip AID enumeration disable | — |
| `--skip-picc-key-change` | Skip PICC key rotation | — |

## Troubleshooting

### `AUTHENTICATION_ERROR` on `GetApplicationIDs`

AID enumeration is disabled. Authenticate to PICC first, or use `factory_reset.py` with `--picc-key`.

### `AUTHENTICATION_ERROR` on PICC auth

Wrong key, wrong type (DES vs AES), or key was already changed. Try the correct current key.

### `desfsh` steps fail but card operations succeed

The PC/SC connection from Python may hold the card. Place the card back on the reader and run `change_picc_key.py` or `desfsh` commands separately.

### `No card detected`

Reader or PC/SC stack issue. Verify with `pcsc_scan` or direct `desfsh` commands.

## Security notes

- **Never commit keys** to version control or shell history. Use `--config` with a gitignored JSON file.
- **Keys are masked** in output by default. Use `--show-secrets` only when debugging.
- **FormatPICC** resets the PICC key to factory default (DES all-zeros on most EV3 cards).
- The provisioner uses **EV2 secure channel** for all key changes and file operations during provisioning.

## License

See `LICENSE`.