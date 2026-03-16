#!/usr/bin/env python3
"""
DESFire EV3 Factory Reset

Resets a card to factory state, even if AID enumeration is disabled.
Workflow:
  1. Auth to PICC (tries provided key, then defaults)
  2. List and delete applications
  3. Change PICC key back to DES all-zeros via desfsh (if non-default)
  4. Format PICC
  5. Verify factory state
"""

from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
import argparse
import os
import subprocess
import sys

parser = argparse.ArgumentParser(
    description="Factory-reset a DESFire EV3 card"
)
parser.add_argument(
    "--picc-key",
    help="Current PICC master key (hex). DES=16 chars, AES=32 chars. "
         "If omitted, tries default DES then default AES."
)
parser.add_argument(
    "--app-key",
    default="00000000000000000000000000000000",
    help="Fallback app key for deletion (AES, default: 16 zero bytes)"
)
parser.add_argument("--desfsh", default="./desfsh", help="Path to desfsh binary")
parser.add_argument("--device", type=int, default=1, help="desfsh device index")
parser.add_argument("--tag", type=int, default=0, help="desfsh tag index")
parser.add_argument("--show-secrets", action="store_true", help="Print key values")
args = parser.parse_args()

FACTORY_DES_KEY = bytes(8)
FACTORY_AES_KEY = bytes(16)


def parse_key(key_str):
    if not key_str:
        return None, None
    key_hex = key_str.strip().replace(":", "").replace(" ", "").upper()
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        return None, None
    if len(key_bytes) == 8:
        return "DES", key_bytes
    if len(key_bytes) == 16:
        return "AES", key_bytes
    return None, None


def mask_key(b):
    if len(b) <= 4:
        return b.hex().upper()
    return f"{b[:2].hex().upper()}...{b[-2:].hex().upper()}"


def show_key(b):
    return toHexString(list(b)) if args.show_secrets else mask_key(b)


def hex_compact(b):
    return b.hex().upper()


APP_KEY_TYPE, APP_KEY = parse_key(args.app_key)
if APP_KEY_TYPE != "AES":
    raise SystemExit("--app-key must be a 32-hex-character AES key")

# ── PC/SC Connect ────────────────────────────────────────────────
r = readers()
contactless = next((x for x in r if "Contactless" in str(x)), None)
if not contactless:
    raise Exception("No contactless reader found")
print(f"Using: {contactless}")
conn = contactless.createConnection()
conn.connect()


def raw(cmd):
    data, sw1, sw2 = conn.transmit(cmd)
    return data, sw1, sw2


def apdu(cmd, label, allow_fail=False):
    data, sw1, sw2 = raw(cmd)
    status = f"{sw1:02X} {sw2:02X}"
    print(f"  [{label}] SW: {status}")
    if not allow_fail and not (sw1 == 0x91 and sw2 in (0x00, 0xAF)):
        raise Exception(f"FAILED [{label}]: SW {status}")
    return data, sw1, sw2


def authenticate_des(key_bytes):
    IV = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw1 != 0x91 or sw2 != 0xAF:
        return False
    rnd_b = DES.new(key_bytes, DES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key_bytes, DES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    return sw1 == 0x91 and sw2 == 0x00


def authenticate_aes(key_bytes):
    IV = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw1 != 0x91 or sw2 != 0xAF:
        return False
    rnd_b = AES.new(key_bytes, AES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key_bytes, AES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    return sw1 == 0x91 and sw2 == 0x00


def authenticate_picc(key_type, key_bytes):
    if key_type == "DES":
        return authenticate_des(key_bytes)
    if key_type == "AES":
        return authenticate_aes(key_bytes)
    return False


def select_picc():
    apdu([0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00], "SelectPICC")


def get_app_ids():
    data, sw1, sw2 = raw([0x90, 0x6A, 0x00, 0x00, 0x00])
    if sw1 == 0x91 and sw2 == 0x00:
        return [data[i:i+3] for i in range(0, len(data), 3) if len(data[i:i+3]) == 3]
    return []


# ── desfsh helper ────────────────────────────────────────────────
def run_desfsh(lua_script, silent=False):
    cmd = [args.desfsh, "-d", str(args.device), "-t", str(args.tag), "-c", lua_script]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return False, "desfsh not found"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    success = result.returncode == 0 and "LUA_ERROR" not in result.stdout
    if not silent or not success:
        for line in (result.stdout.strip() + "\n" + result.stderr.strip()).strip().split("\n"):
            if line.strip():
                print(f"    {line.strip()}")
    return success, result.stdout


def desfsh_change_picc_key(old_type, old_key_bytes, new_type, new_key_bytes):
    old_hex = hex_compact(old_key_bytes)
    new_hex = hex_compact(new_key_bytes)
    lua = f'''
local ok, err = pcall(function()
    cmd.select(0)
    local code, errmsg = cmd.auth(0, {old_type}("{old_hex}"))
    if code ~= 0 then error("Auth failed: " .. tostring(errmsg)) end
    local code2, errmsg2 = cmd.ck(0, {new_type}("{new_hex}"))
    if code2 ~= 0 then error("ChangeKey failed: " .. tostring(errmsg2)) end
    cmd.select(0)
    local code3, errmsg3 = cmd.auth(0, {new_type}("{new_hex}"))
    if code3 ~= 0 then error("Verify auth failed: " .. tostring(errmsg3)) end
    print("PICC_KEY_CHANGED")
end)
if not ok then print("PICC_KEY_CHANGE_FAILED: " .. tostring(err)) end
'''
    _, stdout = run_desfsh(lua)
    return "PICC_KEY_CHANGED" in stdout


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

print(f"\n{'=' * 60}")
print(f"  DESFire EV3 Factory Reset")
print(f"{'=' * 60}")

# ── Step 1: Auth ─────────────────────────────────────────────────
print("\n=== Step 1: Authenticate to PICC ===")

PICC_KEY_TYPE = None
PICC_KEY = None

if args.picc_key:
    key_type, key_bytes = parse_key(args.picc_key)
    if key_type is None:
        raise SystemExit("--picc-key must be 16 hex (DES) or 32 hex (AES)")
    print(f"  Trying provided {key_type} key...")
    select_picc()
    if authenticate_picc(key_type, key_bytes):
        print(f"  ✓ {key_type} auth OK")
        PICC_KEY_TYPE, PICC_KEY = key_type, key_bytes
    else:
        raise SystemExit("  ✗ Provided PICC key failed")
else:
    candidates = [
        ("DES", FACTORY_DES_KEY, "default DES zeros"),
        ("AES", FACTORY_AES_KEY, "default AES zeros"),
    ]
    print("  Trying default keys...")
    for key_type, key_bytes, label in candidates:
        print(f"    {label}...", end=" ")
        select_picc()
        if authenticate_picc(key_type, key_bytes):
            print("✓")
            PICC_KEY_TYPE, PICC_KEY = key_type, key_bytes
            break
        else:
            print("✗")

    if PICC_KEY is None:
        print("\n  ✗ Could not auth with default keys")
        print("  Supply --picc-key explicitly")
        sys.exit(1)

print(f"  PICC key: {PICC_KEY_TYPE} {show_key(PICC_KEY)}")

# ── Step 2: Reset PICC key to DES zeros via desfsh ───────────────
print("\n=== Step 2: Reset PICC key to DES all-zeros ===")

is_factory_des = (PICC_KEY_TYPE == "DES" and PICC_KEY == FACTORY_DES_KEY)

if is_factory_des:
    print("  Already DES all-zeros — no change needed")
else:
    if not os.path.exists(args.desfsh):
        print(f"  ✗ desfsh not found at {args.desfsh}")
        print(f"    Run manually: python3 change_picc_key.py \\")
        print(f"      --old-key {hex_compact(PICC_KEY)} --new-key 0000000000000000")
        print(f"    Then re-run: python3 factory_reset.py")
        sys.exit(1)

    print(f"  Changing {PICC_KEY_TYPE} key → DES all-zeros via desfsh...")

    # Release PC/SC so desfsh can access the reader
    try:
        conn.disconnect()
    except Exception:
        pass

    if desfsh_change_picc_key(PICC_KEY_TYPE, PICC_KEY, "DES", FACTORY_DES_KEY):
        print("  ✓ PICC key reset to DES all-zeros")
        PICC_KEY_TYPE = "DES"
        PICC_KEY = FACTORY_DES_KEY
    else:
        print("  ✗ PICC key change failed")
        print(f"    Run manually: python3 change_picc_key.py \\")
        print(f"      --old-key {hex_compact(PICC_KEY)} --new-key 0000000000000000")
        sys.exit(1)

    # Reconnect PC/SC for format
    conn.connect()

# ── Step 3: Format PICC (wipes all apps + data) ─────────────────
print("\n=== Step 3: Format PICC ===")
print("  Re-authenticating...")
select_picc()
if not authenticate_picc(PICC_KEY_TYPE, PICC_KEY):
    raise SystemExit("  ✗ Re-auth failed before format")

data, sw1, sw2 = raw([0x90, 0xFC, 0x00, 0x00, 0x00])
print(f"  [FormatPICC] SW: {sw1:02X} {sw2:02X}")
if sw1 == 0x91 and sw2 == 0x00:
    print("  ✓ Card formatted (all apps wiped)")
else:
    print(f"  ✗ FormatPICC failed")
    sys.exit(1)

# ── Step 4: Verify ───────────────────────────────────────────────
print("\n=== Step 4: Verify factory state ===")

verify_candidates = [
    ("DES", FACTORY_DES_KEY, "DES all-zeros"),
    ("AES", FACTORY_AES_KEY, "AES all-zeros"),
]

verified = False
verified_type = None
for v_type, v_key, v_label in verify_candidates:
    print(f"  Trying {v_label}...", end=" ")
    select_picc()
    if authenticate_picc(v_type, v_key):
        print("✓")
        verified = True
        verified_type = v_type
        aids = get_app_ids()
        if aids:
            print(f"  ⚠ Remaining apps: {[toHexString(list(a)) for a in aids]}")
        break
    else:
        print("✗")

if not verified:
    print("\n  ✗ Could not verify factory state")
    sys.exit(1)

print(f"\n{'=' * 60}")
print(f"  ✓ Card is factory fresh")
print(f"{'=' * 60}")
print(f"  PICC key : {verified_type} all-zeros")
print(f"  Apps     : none")
print(f"  Ready for provisioning")