#!/usr/bin/env python3
"""
DESFire EV3 Card Provisioner

Workflow:
  1. Provision application + encrypted data using PC/SC APDUs
  2. Disable anonymous AID enumeration using desfsh
  3. Optionally change the PICC master key using desfsh
"""

import argparse
import struct
import subprocess
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC


# ── Argument parsing ─────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="DESFire EV3 card provisioner (DES or AES PICC)"
)
parser.add_argument(
    "--picc-key", required=True,
    help="Current PICC master key. DES=8 bytes, AES=16 bytes. Accepts XX:XX or plain hex."
)
parser.add_argument(
    "--new-picc-key",
    help="Optional new PICC master key to set after provisioning. DES=8 bytes, AES=16 bytes."
)
parser.add_argument(
    "--desfsh", default="./desfsh",
    help="Path to desfsh binary for PICC post-steps (default: ./desfsh)"
)
parser.add_argument(
    "--device", type=int, default=1,
    help="desfsh device index (default: 1)"
)
parser.add_argument(
    "--tag", type=int, default=0,
    help="desfsh tag index (default: 0)"
)
parser.add_argument(
    "--app-id", required=True,
    help="Application ID e.g. A1:B2:C3 or A1B2C3"
)
parser.add_argument(
    "--app-key", required=True,
    help="AES-128 app authentication key"
)
parser.add_argument(
    "--data-key", required=True,
    help="AES-128 key for encrypting/decrypting the data file"
)
parser.add_argument(
    "--data", required=True,
    help="Plain string to write e.g. EMP000123"
)
args = parser.parse_args()


# ── Helpers ──────────────────────────────────────────────────────
def parse_hex(s: str, label: str) -> bytes:
    try:
        cleaned = s.replace(":", "").replace(" ", "").strip()
        return bytes.fromhex(cleaned)
    except Exception as exc:
        raise ValueError(f"Invalid hex format for {label}: '{s}'") from exc


def hex_compact(b: bytes) -> str:
    return b.hex().upper()


picc_key_raw = parse_hex(args.picc_key, "--picc-key")
new_picc_key_raw = parse_hex(args.new_picc_key, "--new-picc-key") if args.new_picc_key else None
app_key = parse_hex(args.app_key, "--app-key")
data_key = parse_hex(args.data_key, "--data-key")
aid = list(parse_hex(args.app_id, "--app-id"))
data_bytes = args.data.encode("utf-8")
data_len = len(data_bytes)

if len(picc_key_raw) == 8:
    picc_key_type = "DES"
elif len(picc_key_raw) == 16:
    picc_key_type = "AES"
else:
    raise ValueError("--picc-key must be 8 bytes (DES) or 16 bytes (AES)")

if new_picc_key_raw is not None:
    if len(new_picc_key_raw) == 8:
        new_picc_key_type = "DES"
    elif len(new_picc_key_raw) == 16:
        new_picc_key_type = "AES"
    else:
        raise ValueError("--new-picc-key must be 8 bytes (DES) or 16 bytes (AES)")
else:
    new_picc_key_type = None

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
if new_picc_key_raw is not None:
    print(f"  New PICC type  : {new_picc_key_type}")
    print(f"  New PICC key   : {toHexString(list(new_picc_key_raw))}")
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


# ── AES-CMAC ─────────────────────────────────────────────────────
def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


# ── EV2 session key derivation ───────────────────────────────────
def derive_session_keys_ev2(key: bytes, rnd_a: bytes, rnd_b: bytes):
    xor_part = bytes([rnd_a[2 + i] ^ rnd_b[i] for i in range(6)])
    sv_suffix = rnd_a[0:2] + xor_part + rnd_b[6:16] + rnd_a[8:16]
    sv1 = bytes([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + sv_suffix
    sv2 = bytes([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + sv_suffix
    return aes_cmac(key, sv1), aes_cmac(key, sv2)


# ── Auth: EV2 (for ChangeKey) ────────────────────────────────────
def auth_ev2_first(key: bytes, key_no: int = 0):
    iv_zero = bytes(16)
    data, sw1, sw2 = raw([0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"EV2 auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b_enc = bytes(data)
    rnd_b = AES.new(key, AES.MODE_CBC, iv_zero).decrypt(rnd_b_enc)
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    part2_enc = AES.new(key, AES.MODE_CBC, iv_zero).encrypt(rnd_a + rnd_b_rot)
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(part2_enc)] + list(part2_enc) + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"EV2 auth step 2 failed: {sw1:02X} {sw2:02X}")
    resp_dec = AES.new(key, AES.MODE_CBC, iv_zero).decrypt(bytes(data))
    ti = resp_dec[0:4]
    rnd_a_prime = resp_dec[4:20]
    if rnd_a_prime != rnd_a[1:] + rnd_a[:1]:
        raise Exception("EV2: RndA verification failed")
    k_enc, k_mac = derive_session_keys_ev2(key, rnd_a, rnd_b)
    print(f"    TI: {ti.hex()}  KSesENC: {k_enc.hex()}")
    return k_enc, k_mac, ti, 0


# ── Auth: legacy AES (for file operations) ───────────────────────
def auth_legacy_aes(key: bytes):
    iv = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"Legacy AES auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key, AES.MODE_CBC, iv).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"Legacy AES auth step 2 failed: {sw1:02X} {sw2:02X}")


# ── Auth: DES ────────────────────────────────────────────────────
def auth_des(key: bytes):
    iv = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"DES auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = DES.new(key, DES.MODE_CBC, iv).decrypt(bytes(data))
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key, DES.MODE_CBC, iv).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"DES auth step 2 failed: {sw1:02X} {sw2:02X}")


# ── Auth: DES native for PICC ────────────────────────────────────
def auth_des_legacy(key8: bytes):
    iv = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"DES auth step 1 failed: {sw1:02X} {sw2:02X}")
    enc_rnd_b = bytes(data)
    rnd_b = DES.new(key8, DES.MODE_CBC, iv).decrypt(enc_rnd_b)
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key8, DES.MODE_CBC, iv).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"DES auth step 2 failed: {sw1:02X} {sw2:02X}")
    return rnd_a, rnd_b


# ── Auth: AES PICC ───────────────────────────────────────────────
def auth_aes_picc(key16: bytes):
    iv = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"AES PICC auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key16, AES.MODE_CBC, iv).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key16, AES.MODE_CBC, iv).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"AES PICC auth step 2 failed: {sw1:02X} {sw2:02X}")
    return rnd_a, rnd_b


# ── EV2 MAC / ChangeKey ──────────────────────────────────────────
def calc_mac_ev2(k_mac: bytes, cmd: int, cmd_ctr: int, ti: bytes, data: bytes) -> bytes:
    cmd_ctr_bytes = struct.pack('<H', cmd_ctr)
    mac_input = bytes([cmd]) + cmd_ctr_bytes + ti + data
    full_mac = aes_cmac(k_mac, mac_input)
    return bytes([full_mac[i] for i in range(1, 16, 2)])


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


# ── desfsh helpers for PICC post-steps ───────────────────────────
def run_desfsh(lua_script, silent=False):
    cmd = [args.desfsh, "-d", str(args.device), "-t", str(args.tag), "-c", lua_script]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exc:
        raise Exception(f"desfsh not found at: {args.desfsh}") from exc
    except subprocess.TimeoutExpired as exc:
        raise Exception("desfsh timed out") from exc

    success = result.returncode == 0 and "LUA_ERROR" not in result.stdout
    if not silent or not success:
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
    return success, result.stdout


def disable_aid_enumeration_via_desfsh(current_type: str, current_key: bytes):
    key_hex = hex_compact(current_key)
    lua = f'''
local ok, err = pcall(function()
    cmd.select(0)
    local code, errmsg = cmd.auth(0, {current_type}("{key_hex}"))
    if code ~= 0 then
        error("Auth failed: " .. tostring(errmsg))
    end

    local code2, errmsg2, keyset, maxkeys = cmd.gks()
    if code2 ~= 0 then
        error("GetKeySettings failed: " .. tostring(errmsg2))
    end

    print(string.format("KEYSET=0x%02X", keyset))

    -- Clear LIST bit (bit 1) without using bit32.
    local list_enabled = math.floor(keyset / 2) % 2
    local new_keyset = keyset
    if list_enabled == 1 then
        new_keyset = keyset - 2
    end

    if new_keyset == keyset then
        print("AID_ENUM_ALREADY_DISABLED")
        return
    end

    local code3, errmsg3 = cmd.cks(new_keyset)
    if code3 ~= 0 then
        error("ChangeKeySettings failed: " .. tostring(errmsg3))
    end

    local code4, errmsg4, verify_keyset, maxkeys2 = cmd.gks()
    if code4 ~= 0 then
        error("Verify GetKeySettings failed: " .. tostring(errmsg4))
    end

    print(string.format("NEW_KEYSET=0x%02X", verify_keyset))

    local verify_list_enabled = math.floor(verify_keyset / 2) % 2
    if verify_list_enabled == 0 then
        print("AID_ENUM_DISABLED")
    else
        error("LIST bit still enabled")
    end
end)
if not ok then
    print("AID_ENUM_CHANGE_FAILED: " .. tostring(err))
end
'''
    _, stdout = run_desfsh(lua)
    if "AID_ENUM_DISABLED" in stdout or "AID_ENUM_ALREADY_DISABLED" in stdout:
        return
    raise Exception("Failed to disable AID enumeration")

def change_picc_key_via_desfsh(old_type: str, old_key: bytes, new_type: str, new_key: bytes):
    old_hex = hex_compact(old_key)
    new_hex = hex_compact(new_key)
    lua = f'''
local ok, err = pcall(function()
    cmd.select(0)
    local code, errmsg = cmd.auth(0, {old_type}("{old_hex}"))
    if code ~= 0 then
        error("Auth failed: " .. tostring(errmsg))
    end

    local code2, errmsg2 = cmd.ck(0, {new_type}("{new_hex}"))
    if code2 ~= 0 then
        error("ChangeKey failed: " .. tostring(errmsg2))
    end

    cmd.select(0)
    local code3, errmsg3 = cmd.auth(0, {new_type}("{new_hex}"))
    if code3 ~= 0 then
        error("Verification auth failed: " .. tostring(errmsg3))
    end

    print("PICC_KEY_CHANGED")
end)
if not ok then
    print("PICC_KEY_CHANGE_FAILED: " .. tostring(err))
end
'''
    _, stdout = run_desfsh(lua)
    if "PICC_KEY_CHANGED" in stdout:
        return
    raise Exception("Failed to change PICC master key")


# ════════════════════════════════════════════════════════════════
# MAIN FLOW
# ════════════════════════════════════════════════════════════════
print("\n=== Step 1: Select + Auth PICC ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00], "SelectPICC")

if picc_key_type == "DES":
    auth_des_legacy(picc_key_raw)
    print("  ✓ PICC DES auth OK")
else:
    auth_aes_picc(picc_key_raw)
    print("  ✓ PICC AES auth OK")

print("\n=== Step 2: Check AID is free ===")
data, sw1, sw2 = raw([0x90, 0x6A, 0x00, 0x00, 0x00])
existing = [data[i:i + 3] for i in range(0, len(data), 3) if len(data[i:i + 3]) == 3]
if bytes(aid) in [bytes(a) for a in existing]:
    raise Exception(f"App {toHexString(aid)} already exists — run factory_reset.py first.")
print(f"  ✓ AID {toHexString(aid)} is free")

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

print("\n=== Step 4: Select Application ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")

print("\n=== Step 5: Auth with default app key ===")
if app_is_aes:
    k_enc, k_mac, ti, cmd_ctr = auth_ev2_first(bytes(16), 0)
    print("  ✓ Default AES EV2 auth OK (key = 16x00)")
else:
    auth_des(bytes(8))
    k_enc = k_mac = ti = None
    cmd_ctr = 0
    print("  ✓ Default DES auth OK")

if app_is_aes:
    print("\n=== Step 6: Change app AES key ===")
    cmd_ctr = change_key_ev2(k_enc, k_mac, ti, cmd_ctr, 0x00, app_key, 0x01)
    print("  ✓ App AES key changed")

    print("\n=== Step 6b: Verify new app key + switch to legacy auth ===")
    apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
    k_enc, k_mac, ti, cmd_ctr = auth_ev2_first(app_key, 0)
    print("  ✓ New app key verified!")

    apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
    auth_legacy_aes(app_key)
    print("  ✓ Legacy AES auth OK — ready for file operations")
else:
    print("\n=== Step 6: SKIPPED (DES app) ===")

print("\n=== Step 7: Create Data File ===")
size_bytes = [enc_len & 0xFF, (enc_len >> 8) & 0xFF, (enc_len >> 16) & 0xFF]
apdu([0x90, 0xCD, 0x00, 0x00, 0x07,
      0x01,
      0x00,
      0x00, 0x00,
      ] + size_bytes + [0x00], "CreateFile")

print("\n=== Step 8: Write Encrypted Data ===")
length_bytes = [enc_len & 0xFF, (enc_len >> 8) & 0xFF, (enc_len >> 16) & 0xFF]
lc = 1 + 3 + 3 + enc_len
apdu([0x90, 0x3D, 0x00, 0x00, lc,
      0x01,
      0x00, 0x00, 0x00,
      ] + length_bytes + encrypted_data + [0x00], "WriteData")

print("\n=== Step 9: Verify ===")
read_length = [enc_len & 0xFF, (enc_len >> 8) & 0xFF, (enc_len >> 16) & 0xFF]
data, sw1, sw2 = apdu(
    [0x90, 0xBD, 0x00, 0x00, 0x07,
     0x01, 0x00, 0x00, 0x00] + read_length + [0x00], "ReadData")

raw_back = bytes(data[:enc_len])
decrypted = AES.new(data_key, AES.MODE_CBC, bytes(16)).decrypt(raw_back).rstrip(b'\x00').decode('utf-8', errors='replace')

print(f"\n  Written    : '{args.data}'")
print(f"  On card    : {raw_back.hex()} (ciphertext)")
print(f"  Decrypted  : '{decrypted}'")

if decrypted != args.data:
    print("\n  ✗ Decrypt mismatch — check AES key")
    raise SystemExit(1)

print("\n=== Step 10: Disable anonymous AID enumeration ===")
disable_aid_enumeration_via_desfsh(picc_key_type, picc_key_raw)
print("  ✓ Anonymous GetApplicationIDs disabled")

final_picc_key_type = picc_key_type
final_picc_key_raw = picc_key_raw
if new_picc_key_raw is not None:
    print("\n=== Step 11: Change PICC master key ===")
    change_picc_key_via_desfsh(picc_key_type, picc_key_raw, new_picc_key_type, new_picc_key_raw)
    final_picc_key_type = new_picc_key_type
    final_picc_key_raw = new_picc_key_raw
    print("  ✓ PICC master key changed")
else:
    print("\n=== Step 11: Change PICC master key ===")
    print("  - Skipped (--new-picc-key not provided)")

print("\n  ✓ Card provisioned successfully!")
print(f"  ✓ PICC key     : {final_picc_key_type} {toHexString(list(final_picc_key_raw))}")
print("  ✓ AID enum     : disabled for anonymous access")
print(f"  ✓ App key      : {'AES-128 (changed)' if app_is_aes else 'DES (unchanged fallback)'}")
print("  ✓ File access  : key 0 required (no free read)")
print("  ✓ Data         : AES-128-CBC encrypted on card")
