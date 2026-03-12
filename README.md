
# DESFire EV3 Provisioning Utilities

This repository contains a small set of scripts for provisioning and resetting MIFARE DESFire EV3 cards.

The workflow implemented here is:

1. Provision the card with an application, file, and encrypted payload.
2. Disable anonymous AID enumeration at the PICC level.
3. Optionally rotate the PICC master key.
4. Reset the card back to a factory-like state later, even if AID enumeration has been disabled.

The tooling is split between direct PC/SC APDU handling in Python and `desfsh` for PICC-level operations that were verified on the target card.

## Files

### `provision.py`

Provisions a card with an application and writes encrypted data.

Its workflow is:

- authenticate to the PICC
- create an application
- select the application
- authenticate to the application
- create/write the target file
- disable anonymous AID enumeration on the PICC
- optionally change the PICC master key

This script uses the existing Python smartcard flow for provisioning, then uses `desfsh` for the PICC post-steps.

### `factory_reset.py`

Resets a DESFire card to a factory-like state.

It is designed to work even when anonymous AID enumeration has been disabled. Instead of relying on unauthenticated `GetApplicationIDs`, it authenticates to the PICC first and then enumerates applications through an authenticated session.

Its workflow is:

- select PICC
- authenticate with the current PICC key
- list installed applications
- delete applications
- verify that no applications remain

Depending on the exact version in your working tree, you may also have a variant that restores the PICC key and re-enables anonymous AID enumeration.

### `change_picc_key.py`

Changes the PICC master key using `desfsh`.

It supports:

- DES and AES PICC keys
- auto-detection of key type by key length
- trying default keys if the old key is not provided
- optional confirmation skipping with `-y`

### `desfsh`

Used for PICC-level operations such as:

- PICC authentication
- reading key settings
- changing key settings
- changing the PICC master key
- authenticated `GetApplicationIDs`

## Requirements

You need:

- Python 3
- `pyscard`
- `pycryptodome`
- a working PC/SC stack
- a contactless smartcard reader
- `desfsh`

Install Python dependencies:

```bash
pip install pyscard pycryptodome
````

## Reader assumptions

The scripts expect a working PC/SC contactless reader. In the current Python-based scripts, the reader selection typically looks for a reader with `"Contactless"` in its name.

## PICC key handling

The scripts support both common PICC master-key forms:

* DES: 8 bytes, passed as 16 hex characters
* AES: 16 bytes, passed as 32 hex characters

Examples:

* DES default zero key: `0000000000000000`
* AES default zero key: `00000000000000000000000000000000`

## Typical workflow

### 1. Provision a card

Example:

```bash
python3 provision.py \
  --picc-key 0000000000000000 \
  --app-id A1B2C3 \
  --app-key 00112233445566778899AABBCCDDEEFF \
  --data-key AABBCCDDEEFF00112233445566778899 \
  --data "EMP000123" \
  --desfsh ./desfsh \
  --device 1 \
  --tag 0
```

This provisions the card, disables anonymous AID enumeration, and leaves the PICC key unchanged.

### 2. Provision and rotate PICC key

Example:

```bash
python3 provision.py \
  --picc-key 0000000000000000 \
  --new-picc-key 0102030405060708090A0B0C0D0E0F10 \
  --app-id A1B2C3 \
  --app-key 00112233445566778899AABBCCDDEEFF \
  --data-key AABBCCDDEEFF00112233445566778899 \
  --data "EMP000123" \
  --desfsh ./desfsh \
  --device 1 \
  --tag 0
```

This provisions the card, disables anonymous AID enumeration, and then changes the PICC master key.

### 3. Change PICC key separately

Example:

```bash
python3 change_picc_key.py \
  --old-key 0000000000000000 \
  --new-key 0102030405060708090A0B0C0D0E0F10 \
  --desfsh ./desfsh \
  --device 1 \
  --tag 0
```

### 4. Factory-reset a card

If the card still uses the default DES PICC key:

```bash
python3 factory_reset.py --picc-key 0000000000000000
```

If the PICC key was rotated:

```bash
python3 factory_reset.py --picc-key 0102030405060708090A0B0C0D0E0F10
```

This works even when unauthenticated `GetApplicationIDs` is blocked.

## Verified behavior

The workflow was validated against a card where:

* unauthenticated `GetApplicationIDs` returned `AUTHENTICATION_ERROR`
* PICC authentication with default DES key succeeded
* authenticated `GetApplicationIDs` returned the installed AIDs

That confirms anonymous AID enumeration was disabled while authenticated enumeration still worked.

## Notes on AID enumeration

Disabling AID enumeration means `GetApplicationIDs` is no longer available anonymously. The PICC must first be authenticated with the PICC master key.

In `desfsh`, this is done with:

* `cmd.auth(0, DES("..."))` or `cmd.auth(0, AES("..."))`
* then `cmd.appids()`

The key-settings bit controlling open listing is the LIST bit. Clearing it disables anonymous AID enumeration.

## Notes on initialization vectors

The working authentication flows in this repository use:

* zero IV for legacy DES / AES authentication handshakes
* derived IVs for EV2 secure messaging where applicable

The zero IV is not itself a problem in the tested legacy authentication flow. Problems would arise if a stateful secure-messaging session were extended incorrectly while reusing the wrong IV behavior.

## Troubleshooting

### `AUTHENTICATION_ERROR` on unauthenticated `GetApplicationIDs`

This usually means anonymous AID enumeration has been disabled. This is expected after provisioning if the PICC LIST bit was cleared.

### `AUTHENTICATION_ERROR` on PICC auth

Common causes:

* wrong PICC key
* wrong PICC key type (DES vs AES)
* PICC key was already changed earlier

Try the correct current PICC key explicitly.

### `No card detected`

This is usually a reader / PCSC issue or a card-presence check that does not match the reader behavior. If direct `desfsh` commands work but a Python wrapper reports no card, the problem is likely the reader-detection logic rather than the card.

### `attempt to call a nil value`

This means your `desfsh` build does not expose the Lua helper name the script expected. On the verified build used here, the correct application-list command is:

* `cmd.appids()`

## Security note

These scripts handle real card master keys. Treat all keys as sensitive material. Do not commit production keys into the repository or shell history.

## License

See `LICENSE`.

```
```
