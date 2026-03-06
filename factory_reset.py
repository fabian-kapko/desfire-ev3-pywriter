# factory_reset.py
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes

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

def authenticate_des(key_bytes=bytes(8)):
    """DES authenticate with key 0x00"""
    IV = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        if sw2 == 0xAE:
            print("\n" + "="*60)
            print("  ✗ DES auth failed — card has non-default PICC key!")
            print("="*60)
            print("\n  The card's PICC master key is not the default DES zeros.")
            print("  First reset it to default using change_picc_key.py:\n")
            print("    python3 change_picc_key.py \\")
            print("        --old-key <YOUR_CURRENT_KEY> \\")
            print("        --new-key 0000000000000000\n")
            print("  Example if your current key is AES:")
            print("    python3 change_picc_key.py \\")
            print("        --old-key 0102030405060708090A0B0C0D0E0F10 \\")
            print("        --new-key 0000000000000000\n")
            raise SystemExit(1)
        raise Exception(f"Auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = DES.new(key_bytes, DES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key_bytes, DES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"Auth step 2 failed: {sw1:02X} {sw2:02X}")
    print("  ✓ DES auth OK")

def authenticate_aes(key_bytes=bytes(16)):
    """AES authenticate with key 0x00 (for apps created with AES)"""
    IV = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"Auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key_bytes, AES.MODE_CBC, IV).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key_bytes, AES.MODE_CBC, IV).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"Auth step 2 failed: {sw1:02X} {sw2:02X}")
    print("  ✓ AES auth OK")

def select_picc():
    apdu([0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00], "SelectPICC")

PICC_KEY = bytes(8)   # DES all zeros
APP_KEY  = bytes(16)  # AES all zeros (apps were created with AES)

# ── 1. Select + auth PICC ────────────────────────────────────────
print("\n=== Step 1: Select PICC ===")
select_picc()
authenticate_des(PICC_KEY)

# ── 2. Get all AIDs ──────────────────────────────────────────────
print("\n=== Step 2: List Applications ===")
data, sw1, sw2 = apdu([0x90, 0x6A, 0x00, 0x00, 0x00], "GetAppIDs")
aids = [data[i:i+3] for i in range(0, len(data), 3) if len(data[i:i+3]) == 3]

if not aids:
    print("  No applications found — card already clean")
else:
    print(f"  Found {len(aids)} app(s): {[toHexString(list(a)) for a in aids]}")

# ── 3. Delete each app ───────────────────────────────────────────
for aid in aids:
    aid_list = list(aid)
    aid_str = toHexString(aid_list)
    print(f"\n=== Deleting app {aid_str} ===")

    data, sw1, sw2 = raw([0x90, 0xDA, 0x00, 0x00, 0x03] + aid_list + [0x00])
    print(f"  [DeleteApp] SW: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00:
        print(f"  ✓ Deleted {aid_str}")

    elif sw1 == 0x91 and sw2 == 0xAE:
        print(f"  Needs app-level auth first, trying AES zeros...")
        try:
            apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid_list + [0x00], "SelectApp")
            authenticate_aes(APP_KEY)
            select_picc()
            authenticate_des(PICC_KEY)
            apdu([0x90, 0xDA, 0x00, 0x00, 0x03] + aid_list + [0x00], "DeleteApp")
            print(f"  ✓ Deleted {aid_str}")
        except Exception as e:
            print(f"  ✗ Could not delete {aid_str}: {e}")
            print(f"    (non-default app key — skipping)")
    else:
        print(f"  ✗ Unexpected SW: {sw1:02X} {sw2:02X} — skipping")

# ── 4. Verify clean ──────────────────────────────────────────────
print("\n=== Step 4: Verify ===")
select_picc()
authenticate_des(PICC_KEY)
data, sw1, sw2 = apdu([0x90, 0x6A, 0x00, 0x00, 0x00], "GetAppIDs")

if not data:
    print("\n  ✓ Card is factory fresh — no applications")
else:
    remaining = [toHexString(list(data[i:i+3])) for i in range(0, len(data), 3)]
    print(f"\n  ⚠ Apps with unknown keys remain: {remaining}")
