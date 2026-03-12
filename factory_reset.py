#!/usr/bin/env python3
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
import argparse
import sys

parser = argparse.ArgumentParser(
    description="Factory-reset a DESFire card, including cards with disabled AID enumeration"
)
parser.add_argument(
    "--picc-key",
    help="Current PICC master key in hex. DES=16 chars, AES=32 chars. If omitted, tries default DES then default AES."
)
parser.add_argument(
    "--app-key",
    default="00000000000000000000000000000000",
    help="Default application master key used for fallback app deletion (AES, default: 16 zero bytes)"
)
args = parser.parse_args()


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


APP_KEY_TYPE, APP_KEY = parse_key(args.app_key)
if APP_KEY_TYPE != "AES":
    raise SystemExit("--app-key must be a 32-hex-character AES key")

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
    result = toHexString(data) if data else "(empty)"
    print(f"  [{label}] SW: {status} {result}")
    if not allow_fail and not (sw1 == 0x91 and sw2 in (0x00, 0xAF)):
        raise Exception(f"FAILED [{label}]: SW {status}")
    return data, sw1, sw2


def authenticate_des(key_bytes):
    IV = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw1 != 0x91 or sw2 != 0xAF:
        return False, f"Auth step 1 failed: {sw1:02X} {sw2:02X}"
    rnd_b = DES.new(key_bytes, DES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key_bytes, DES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if sw1 == 0x91 and sw2 == 0x00:
        print("  ✓ DES auth OK")
        return True, "OK"
    return False, f"Auth step 2 failed: {sw1:02X} {sw2:02X}"


def authenticate_aes(key_bytes):
    IV = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw1 != 0x91 or sw2 != 0xAF:
        return False, f"Auth step 1 failed: {sw1:02X} {sw2:02X}"
    rnd_b = AES.new(key_bytes, AES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key_bytes, AES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if sw1 == 0x91 and sw2 == 0x00:
        print("  ✓ AES auth OK")
        return True, "OK"
    return False, f"Auth step 2 failed: {sw1:02X} {sw2:02X}"


def authenticate_picc(key_type, key_bytes):
    if key_type == "DES":
        return authenticate_des(key_bytes)
    if key_type == "AES":
        return authenticate_aes(key_bytes)
    return False, f"Unsupported PICC key type: {key_type}"


def select_picc():
    apdu([0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00], "SelectPICC")


def get_app_ids():
    data, sw1, sw2 = apdu([0x90, 0x6A, 0x00, 0x00, 0x00], "GetAppIDs")
    return [data[i:i+3] for i in range(0, len(data), 3) if len(data[i:i+3]) == 3]


def determine_picc_key():
    if args.picc_key:
        key_type, key_bytes = parse_key(args.picc_key)
        if key_type is None:
            raise SystemExit("--picc-key must be 16 hex chars (DES) or 32 hex chars (AES)")
        print(f"\nTrying provided PICC key as {key_type}...")
        select_picc()
        ok, msg = authenticate_picc(key_type, key_bytes)
        if not ok:
            raise SystemExit(f"Provided PICC key failed: {msg}")
        return key_type, key_bytes

    candidates = [
        ("DES", bytes(8), "default DES zeros"),
        ("AES", bytes(16), "default AES zeros"),
    ]

    print("\nTrying default PICC keys...")
    for key_type, key_bytes, label in candidates:
        print(f"  Trying {label}...")
        select_picc()
        ok, _ = authenticate_picc(key_type, key_bytes)
        if ok:
            return key_type, key_bytes

    print("\n" + "=" * 60)
    print("  ✗ Could not authenticate to PICC with default keys")
    print("=" * 60)
    print("\n  Supply the current PICC key explicitly, for example:")
    print("    python3 factory_reset.py --picc-key 0000000000000000")
    print("    python3 factory_reset.py --picc-key 0102030405060708090A0B0C0D0E0F10")
    raise SystemExit(1)


print("\n=== Step 1: Select PICC and authenticate ===")
PICC_KEY_TYPE, PICC_KEY = determine_picc_key()
print(f"  Using PICC key type: {PICC_KEY_TYPE}")

print("\n=== Step 2: List Applications ===")
aids = get_app_ids()

if not aids:
    print("  No applications found — card already clean")
else:
    print(f"  Found {len(aids)} app(s): {[toHexString(list(a)) for a in aids]}")

for aid in aids:
    aid_list = list(aid)
    aid_str = toHexString(aid_list)
    print(f"\n=== Deleting app {aid_str} ===")

    data, sw1, sw2 = raw([0x90, 0xDA, 0x00, 0x00, 0x03] + aid_list + [0x00])
    print(f"  [DeleteApp] SW: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00:
        print(f"  ✓ Deleted {aid_str}")

    elif sw1 == 0x91 and sw2 == 0xAE:
        print(f"  Needs app-level auth first, trying AES app key...")
        try:
            apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid_list + [0x00], "SelectApp")
            ok, msg = authenticate_aes(APP_KEY)
            if not ok:
                raise Exception(msg)
            select_picc()
            ok, msg = authenticate_picc(PICC_KEY_TYPE, PICC_KEY)
            if not ok:
                raise Exception(f"PICC re-auth failed: {msg}")
            apdu([0x90, 0xDA, 0x00, 0x00, 0x03] + aid_list + [0x00], "DeleteApp")
            print(f"  ✓ Deleted {aid_str}")
        except Exception as e:
            print(f"  ✗ Could not delete {aid_str}: {e}")
            print(f"    (non-default app key — skipping)")
    else:
        print(f"  ✗ Unexpected SW: {sw1:02X} {sw2:02X} — skipping")

print("\n=== Step 4: Verify ===")
select_picc()
ok, msg = authenticate_picc(PICC_KEY_TYPE, PICC_KEY)
if not ok:
    raise SystemExit(f"Could not re-authenticate to PICC for verify step: {msg}")

aids = get_app_ids()

if not aids:
    print("\n  ✓ Card is factory fresh — no applications")
else:
    remaining = [toHexString(list(a)) for a in aids]
    print(f"\n  ⚠ Apps with unknown keys remain: {remaining}")
