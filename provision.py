#!/usr/bin/env python3
'''
DESFire EV3 Card Provisioner - Supports DES and AES PICC keys

Examples:
  # Factory fresh card (default DES key = 8 zeros)
  python3 provision.py \
      --picc-key 00:00:00:00:00:00:00:00 \
      --app-id A1:B2:C3 \
      --app-key 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF \
      --data-key AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99 \
      --data "EMP000123"

  # Card with AES PICC key (16 bytes)
  python3 provision.py \
      --picc-key 01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10 \
      --app-id A1:B2:C3 \
      --app-key 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF \
      --data-key AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99 \
      --data "EMP000123"
'''

import argparse
import struct
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC

# ── Argument parsing ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="DESFire EV3 card provisioner (DES or AES PICC)")
parser.add_argument("--picc-key",  required=True, 
                    help="Current PICC master key. DES=8 bytes, AES=16 bytes. e.g. 00:00:00:00:00:00:00:00")
parser.add_argument("--app-id",    required=True, help="Application ID e.g. A1:B2:C3")
parser.add_argument("--app-key",   required=True, help="AES-128 app authentication key e.g. 00:11:...:FF")
parser.add_argument("--data-key",  required=True, help="AES-128 key for encrypting/decrypting the data file")
parser.add_argument("--data",      required=True, help="Plain string to write e.g. EMP000123")
args = parser.parse_args()

# ── Parse arguments ──────────────────────────────────────────────
def parse_hex(s, label):
    try:
        return bytes(int(x, 16) for x in s.split(":"))
    except Exception:
        raise ValueError(f"Invalid hex format for {label}: '{s}' — use XX:XX:XX style")

picc_key_raw = parse_hex(args.picc_key,  "--picc-key")
app_key      = parse_hex(args.app_key,   "--app-key")
data_key     = parse_hex(args.data_key,  "--data-key")
aid          = list(parse_hex(args.app_id, "--app-id"))
data_bytes   = args.data.encode("utf-8")
data_len     = len(data_bytes)

# Detect PICC key type
if len(picc_key_raw) == 8:
    picc_key_type = "DES"
elif len(picc_key_raw) == 16:
    picc_key_type = "AES"
else:
    raise ValueError("--picc-key must be 8 bytes (DES) or 16 bytes (AES)")

if len(aid) != 3:
    raise ValueError("--app-id must be exactly 3 bytes e.g. A1:B2:C3")
if len(app_key) != 16:
    raise ValueError("--app-key must be exactly 16 bytes (AES-128)")
if len(data_key) != 16:
    raise ValueError("--data-key must be exactly 16 bytes (AES-128)")
if data_len > 240:
    raise ValueError("--data too long (max 240 bytes)")

# ── AES-encrypt payload data upfront ─────────────────────────────
pad_len = (16 - (data_len % 16)) % 16
padded = data_bytes + bytes(pad_len)
encrypted_data = list(AES.new(data_key, AES.MODE_CBC, bytes(16)).encrypt(padded))
enc_len = len(encrypted_data)

print(f"  AID            : {toHexString(aid)}")
print(f"  PICC key type  : {picc_key_type}")
print(f"  PICC key       : {toHexString(list(picc_key_raw))}")
print(f"  App key        : {toHexString(list(app_key))}")
print(f"  Data key       : {toHexString(list(data_key))}")
print(f"  Plaintext      : '{args.data}' ({data_len} bytes)")
print(f"  Encrypted      : {bytes(encrypted_data).hex()} ({enc_len} bytes)")

# ── Connect ──────────────────────────────────────────────────────
r = readers()
contactless = next((x for x in r if "Contactless" in str(x)), None)
if not contactless:
    raise Exception("No contactless reader found")
print(f"\nUsing: {contactless}")
conn = contactless.createConnection()
conn.connect()

def raw(cmd):
    data, sw1, sw2 = conn.transmit(cmd)
    return data, sw1, sw2

def apdu(cmd, label, allow_fail=False):
    data, sw1, sw2 = raw(cmd)
    status = f"{sw1:02X} {sw2:02X}"
    result = toHexString(data) if data else "(empty)"
    print(f"  [{label}] SW: {status} {result}")
    if not allow_fail and not (sw1 == 0x91 and sw2 in (0x00, 0xAF)):
        raise Exception(f"FAILED [{label}]: SW {status}")
    return data, sw1, sw2

# ── CRC32 (DESFire variant, no final XOR) ────────────────────────
def crc32_desfire(data: bytes) -> bytes:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return struct.pack('<I', crc)

# ── AES-CMAC ─────────────────────────────────────────────────────
def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()

# ── EV2 session key derivation ────────────────────────────────────
def derive_session_keys_ev2(key: bytes, rnd_a: bytes, rnd_b: bytes):
    xor_part = bytes([rnd_a[2+i] ^ rnd_b[i] for i in range(6)])
    sv_suffix = rnd_a[0:2] + xor_part + rnd_b[6:16] + rnd_a[8:16]
    sv1 = bytes([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + sv_suffix
    sv2 = bytes([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + sv_suffix
    return aes_cmac(key, sv1), aes_cmac(key, sv2)

# ── Auth: EV2 (for ChangeKey) ────────────────────────────────────
def auth_ev2_first(key: bytes, key_no: int = 0):
    """AuthenticateEV2First (0x71). Returns (k_enc, k_mac, ti, cmd_ctr=0)."""
    IV_ZERO = bytes(16)
    data, sw1, sw2 = raw([0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"EV2 auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b_enc = bytes(data)
    rnd_b = AES.new(key, AES.MODE_CBC, IV_ZERO).decrypt(rnd_b_enc)
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    part2_enc = AES.new(key, AES.MODE_CBC, IV_ZERO).encrypt(rnd_a + rnd_b_rot)
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(part2_enc)]
                         + list(part2_enc) + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"EV2 auth step 2 failed: {sw1:02X} {sw2:02X}")
    resp_dec = AES.new(key, AES.MODE_CBC, IV_ZERO).decrypt(bytes(data))
    ti = resp_dec[0:4]
    rnd_a_prime = resp_dec[4:20]
    if rnd_a_prime != rnd_a[1:] + rnd_a[:1]:
        raise Exception("EV2: RndA verification failed")
    k_enc, k_mac = derive_session_keys_ev2(key, rnd_a, rnd_b)
    print(f"    TI: {ti.hex()}  KSesENC: {k_enc.hex()}")
    return k_enc, k_mac, ti, 0

# ── Auth: legacy AES (for file operations) ───────────────────────
def auth_legacy_aes(key: bytes):
    """AuthenticateAES (0xAA). Plain session — no CMAC required on file ops."""
    IV = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"Legacy AES auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key, AES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key, AES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"Legacy AES auth step 2 failed: {sw1:02X} {sw2:02X}")

# ── Auth: DES ────────────────────────────────────────────────────
def auth_des(key: bytes):
    IV = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"DES auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = DES.new(key, DES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key, DES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"DES auth step 2 failed: {sw1:02X} {sw2:02X}")

# ── Auth: DES/3DES native (INS 0x0A) — single DES for default PICC ──
def auth_des_legacy(key8: bytes):
    """
    Authenticate using legacy single-DES auth (0x0A).
    Returns (rnd_a, rnd_b).
    """
    IV = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"DES auth step 1 failed: {sw1:02X} {sw2:02X}")
    enc_rnd_b = bytes(data)
    rnd_b = DES.new(key8, DES.MODE_CBC, IV).decrypt(enc_rnd_b)
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key8, DES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"DES auth step 2 failed: {sw1:02X} {sw2:02X}")
    return rnd_a, rnd_b

# ── Auth: AES PICC (0xAA) — returns session info for app creation ──
def auth_aes_picc(key16: bytes):
    """
    Authenticate PICC using AES auth (0xAA).
    Used when PICC master key is AES.
    """
    IV = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"AES PICC auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key16, AES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key16, AES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"AES PICC auth step 2 failed: {sw1:02X} {sw2:02X}")
    return rnd_a, rnd_b

def calc_mac_ev2(k_mac: bytes, cmd: int, cmd_ctr: int, ti: bytes, data: bytes) -> bytes:
    cmd_ctr_bytes = struct.pack('<H', cmd_ctr)
    mac_input = bytes([cmd]) + cmd_ctr_bytes + ti + data
    full_mac = aes_cmac(k_mac, mac_input)
    return bytes([full_mac[i] for i in range(1, 16, 2)])

# ── ChangeKey via EV2 secure messaging ───────────────────────────
def change_key_ev2(k_enc: bytes, k_mac: bytes, ti: bytes, cmd_ctr: int,
                   key_no: int, new_key: bytes, new_key_version: int = 0x01) -> int:
    key_data = new_key + bytes([new_key_version])
    pad_len = 16 - (len(key_data) % 16)
    key_data_padded = key_data + bytes([0x80]) + bytes(pad_len - 1)
    cmd_ctr_bytes = struct.pack('<H', cmd_ctr)
    iv_input = bytes([0xA5, 0x5A]) + ti + cmd_ctr_bytes + bytes(8)
    iv = AES.new(k_enc, AES.MODE_ECB).encrypt(iv_input)
    ciphertext = AES.new(k_enc, AES.MODE_CBC, iv).encrypt(key_data_padded)
    cmd_data = bytes([key_no]) + ciphertext
    mac = calc_mac_ev2(k_mac, 0xC4, cmd_ctr, ti, cmd_data)
    full_data = list(cmd_data) + list(mac)
    data, sw1, sw2 = raw([0x90, 0xC4, 0x00, 0x00, len(full_data)] + full_data + [0x00])
    print(f"  [ChangeKey] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"ChangeKey failed: {sw1:02X} {sw2:02X}")
    return cmd_ctr + 1

# ════════════════════════════════════════════════════════════════
#  MAIN FLOW
# ════════════════════════════════════════════════════════════════

# ── Step 1: Select + Auth PICC ───────────────────────────────────
print("\n=== Step 1: Select + Auth PICC ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00], "SelectPICC")

if picc_key_type == "DES":
    auth_des_legacy(picc_key_raw)
    print("  ✓ PICC DES auth OK")
else:  # AES
    auth_aes_picc(picc_key_raw)
    print("  ✓ PICC AES auth OK")

# ── Step 2: Check AID is free ────────────────────────────────────
print("\n=== Step 2: Check AID is free ===")
data, sw1, sw2 = raw([0x90, 0x6A, 0x00, 0x00, 0x00])
existing = [data[i:i+3] for i in range(0, len(data), 3) if len(data[i:i+3]) == 3]
if bytes(aid) in [bytes(a) for a in existing]:
    raise Exception(f"App {toHexString(aid)} already exists — run factory_reset.py first.")
print(f"  ✓ AID {toHexString(aid)} is free")

# ── Step 3: Create AES application ──────────────────────────────
print("\n=== Step 3: Create AES Application ===")
data, sw1, sw2 = raw([0x90, 0xCA, 0x00, 0x00, 0x05] + aid + [0x0F, 0x81, 0x00])
print(f"  [CreateApp] SW: {sw1:02X} {sw2:02X}")
if sw1 == 0x91 and sw2 == 0x00:
    print("  ✓ Created with AES keys")
    app_is_aes = True
elif sw1 == 0x91 and sw2 == 0x7E:
    print("  Card rejected AES flag — falling back to DES app key")
    apdu([0x90, 0xCA, 0x00, 0x00, 0x05] + aid + [0x0F, 0x01, 0x00], "CreateApp-DES")
    app_is_aes = False
else:
    raise Exception(f"CreateApp failed: {sw1:02X} {sw2:02X}")

# ── Step 4: Select app ───────────────────────────────────────────
print("\n=== Step 4: Select Application ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")

# ── Step 5: Auth with default app key (EV2) ──────────────────────
print("\n=== Step 5: Auth with default app key ===")
if app_is_aes:
    k_enc, k_mac, ti, cmd_ctr = auth_ev2_first(bytes(16), 0)
    print("  ✓ Default AES EV2 auth OK (key = 16x00)")
else:
    auth_des(bytes(8))
    k_enc = k_mac = ti = None
    cmd_ctr = 0
    print("  ✓ Default DES auth OK")

# ── Step 6: Change app key ───────────────────────────────────────
if app_is_aes:
    print("\n=== Step 6: Change app AES key ===")
    cmd_ctr = change_key_ev2(k_enc, k_mac, ti, cmd_ctr, 0x00, app_key, 0x01)
    print("  ✓ App AES key changed")

    print("\n=== Step 6b: Verify new app key + switch to legacy auth ===")
    apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
    k_enc, k_mac, ti, cmd_ctr = auth_ev2_first(app_key, 0)
    print("  ✓ New app key verified!")

    # Switch to legacy auth — CreateFile/WriteData/ReadData don't need CMAC
    apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
    auth_legacy_aes(app_key)
    print("  ✓ Legacy AES auth OK — ready for file operations")
else:
    print("\n=== Step 6: SKIPPED (DES app) ===")

# ── Step 7: Create data file ─────────────────────────────────────
print("\n=== Step 7: Create Data File ===")
size_bytes = [enc_len & 0xFF, (enc_len >> 8) & 0xFF, (enc_len >> 16) & 0xFF]
apdu([0x90, 0xCD, 0x00, 0x00, 0x07,
      0x01,         # file id
      0x00,         # plain comms (data pre-encrypted client-side)
      0x00, 0x00,   # key 0 required for all access — no free read
      ] + size_bytes + [0x00], "CreateFile")

# ── Step 8: Write encrypted data ─────────────────────────────────
print("\n=== Step 8: Write Encrypted Data ===")
length_bytes = [enc_len & 0xFF, (enc_len >> 8) & 0xFF, (enc_len >> 16) & 0xFF]
lc = 1 + 3 + 3 + enc_len
apdu([0x90, 0x3D, 0x00, 0x00, lc,
      0x01,
      0x00, 0x00, 0x00,
      ] + length_bytes + encrypted_data + [0x00], "WriteData")

# ── Step 9: Read back and verify ─────────────────────────────────
print("\n=== Step 9: Verify ===")
read_length = [enc_len & 0xFF, (enc_len >> 8) & 0xFF, (enc_len >> 16) & 0xFF]
data, sw1, sw2 = apdu(
    [0x90, 0xBD, 0x00, 0x00, 0x07,
     0x01, 0x00, 0x00, 0x00] + read_length + [0x00], "ReadData")

raw_back = bytes(data[:enc_len])  # strip trailing MAC if present
decrypted = AES.new(data_key, AES.MODE_CBC, bytes(16)).decrypt(raw_back).rstrip(b'\x00').decode('utf-8', errors='replace')

print(f"\n  Written    : '{args.data}'")
print(f"  On card    : {raw_back.hex()} (ciphertext)")
print(f"  Decrypted  : '{decrypted}'")

if decrypted == args.data:
    print(f"\n  ✓ Card provisioned successfully!")
    print(f"  ✓ PICC key     : {picc_key_type} (unchanged)")
    print(f"  ✓ App key      : AES-128 (changed)")
    print(f"  ✓ File access  : key 0 required (no free read)")
    print(f"  ✓ Data         : AES-128-CBC encrypted on card")
else:
    print(f"\n  ✗ Decrypt mismatch — check AES key")