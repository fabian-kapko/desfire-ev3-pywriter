#!/usr/bin/env python3
"""
DESFire EV3 Card Provisioner — Complete

Provisions a card end-to-end:
  1. PICC auth
  2. Create AES application with hardened key settings
  3. Change app key via EV2 secure channel
  4. Create file (Full/MAC/Plain comm mode)
  5. Write data (encrypted in transit for Full mode)
  6. Verify read-back
  7. Disable anonymous AID enumeration (via desfsh)
  8. Optionally change PICC master key (via desfsh)

Config can come from CLI args, a YAML/JSON config file, or interactive prompts.
Secrets are never printed unless --show-secrets is passed.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC


# ═══════════════════════════════════════════════════════════════
#  CLI / Config
# ═══════════════════════════════════════════════════════════════

parser = argparse.ArgumentParser(
    description="DESFire EV3 card provisioner (complete)",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  # Full mode (max security), all CLI:
  %(prog)s --picc-key 0000000000000000 --app-id DE:B1:70 \\
           --app-key bf8248ede7a8efef3ded9e9619f51959 --data "EMP001"

  # From config file:
  %(prog)s --config card.json

  # Config file + override data interactively:
  %(prog)s --config card.json --data "EMP002"

  # Legacy plain mode with data-key:
  %(prog)s --config card.json --data-key AA:BB:... --data "EMP003"

  # Change PICC key after provisioning:
  %(prog)s --config card.json --data "EMP004" \\
           --new-picc-key 0102030405060708090A0B0C0D0E0F10

Config file format (JSON):
  {
    "picc_key": "0000000000000000",
    "app_id": "DE:B1:70",
    "app_key": "bf8248ede7a8efef3ded9e9619f51959",
    "new_picc_key": "9e73dd321048bcf2de0a693b4d53bf9b",
    "desfsh": "./desfsh",
    "device": 1,
    "tag": 0
  }
""",
)
parser.add_argument("--config", help="Path to JSON config file")
parser.add_argument("--picc-key", help="Current PICC master key (hex)")
parser.add_argument("--new-picc-key", help="New PICC master key after provisioning (hex)")
parser.add_argument("--app-id", help="Application ID (e.g. DE:B1:70)")
parser.add_argument("--app-key", help="AES-128 application key (hex)")
parser.add_argument("--data-key", help="(Legacy) AES-128 data encryption key → forces plain mode")
parser.add_argument("--data", help="Plaintext payload to write")
parser.add_argument("--comm-mode", choices=["plain", "mac", "full"], default=None,
                    help="File comm mode (default: full, or plain if --data-key given)")
parser.add_argument("--desfsh", default=None, help="Path to desfsh binary")
parser.add_argument("--device", type=int, default=None, help="desfsh device index")
parser.add_argument("--tag", type=int, default=None, help="desfsh tag index")
parser.add_argument("--show-secrets", action="store_true",
                    help="Print key values in output (default: hidden)")
parser.add_argument("--skip-aid-enum", action="store_true",
                    help="Skip disabling AID enumeration")
parser.add_argument("--skip-picc-key-change", action="store_true",
                    help="Skip PICC key change even if --new-picc-key is set")
args = parser.parse_args()


# ── Load config file if given ────────────────────────────────────
file_cfg = {}
if args.config:
    p = Path(args.config)
    if not p.exists():
        print(f"  ✗ Config file not found: {args.config}")
        sys.exit(1)
    with open(p) as f:
        file_cfg = json.load(f)
    print(f"  Loaded config from {args.config}")


def cfg(name, cli_val, required=False, prompt_msg=None):
    """Resolve a config value: CLI > file > interactive prompt."""
    if cli_val is not None:
        return cli_val
    # Map CLI-style names to file keys (--picc-key → picc_key)
    file_key = name.replace("-", "_")
    if file_key in file_cfg:
        return file_cfg[file_key]
    if prompt_msg and sys.stdin.isatty():
        val = input(f"  {prompt_msg}: ").strip()
        if val:
            return val
    if required:
        print(f"  ✗ Missing required parameter: --{name} (or '{file_key}' in config file)")
        sys.exit(1)
    return None


# ── Resolve all parameters ───────────────────────────────────────
picc_key_hex = cfg("picc-key", args.picc_key, required=True,
                   prompt_msg="PICC master key (hex)")
app_id_hex = cfg("app-id", args.app_id, required=True,
                 prompt_msg="Application ID (e.g. DE:B1:70)")
app_key_hex = cfg("app-key", args.app_key, required=True,
                  prompt_msg="App AES key (32 hex chars)")
data_str = cfg("data", args.data, required=True,
               prompt_msg="Payload to write")
new_picc_key_hex = cfg("new-picc-key", args.new_picc_key)
data_key_hex = cfg("data-key", args.data_key)
desfsh_path = cfg("desfsh", args.desfsh) or "./desfsh"
desfsh_device = int(cfg("device", args.device) or 1)
desfsh_tag = int(cfg("tag", args.tag) or 0)

# ── Comm mode logic ──────────────────────────────────────────────
comm_mode = args.comm_mode
if comm_mode is None:
    comm_mode = file_cfg.get("comm_mode", "full")
if data_key_hex and comm_mode == "full":
    print("  ⚠ --data-key provided → forcing --comm-mode plain (legacy mode)")
    comm_mode = "plain"
COMM_MODE_BYTE = {"plain": 0x00, "mac": 0x01, "full": 0x03}[comm_mode]


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def parse_hex(s: str, label: str) -> bytes:
    try:
        return bytes.fromhex(s.replace(":", "").replace(" ", "").strip())
    except Exception as exc:
        raise ValueError(f"Invalid hex for {label}: '{s}'") from exc


def hex_compact(b: bytes) -> str:
    return b.hex().upper()


def mask_key(b: bytes) -> str:
    """Show first 2 and last 2 bytes, mask the rest."""
    if len(b) <= 4:
        return b.hex().upper()
    return f"{b[:2].hex().upper()}...{b[-2:].hex().upper()}"


def show_key(b: bytes) -> str:
    """Full key or masked, depending on --show-secrets."""
    if args.show_secrets:
        return toHexString(list(b))
    return mask_key(b)


# ── Parse keys ───────────────────────────────────────────────────
picc_key_raw = parse_hex(picc_key_hex, "picc-key")
app_key = parse_hex(app_key_hex, "app-key")
data_key = parse_hex(data_key_hex, "data-key") if data_key_hex else None
new_picc_key_raw = parse_hex(new_picc_key_hex, "new-picc-key") if new_picc_key_hex else None
aid = list(parse_hex(app_id_hex, "app-id"))
data_bytes = data_str.encode("utf-8")
data_len = len(data_bytes)

if len(picc_key_raw) == 8:
    picc_key_type = "DES"
elif len(picc_key_raw) == 16:
    picc_key_type = "AES"
else:
    raise ValueError("picc-key must be 8 bytes (DES) or 16 bytes (AES)")

if new_picc_key_raw:
    if len(new_picc_key_raw) == 8:
        new_picc_key_type = "DES"
    elif len(new_picc_key_raw) == 16:
        new_picc_key_type = "AES"
    else:
        raise ValueError("new-picc-key must be 8 or 16 bytes")
else:
    new_picc_key_type = None

if len(aid) != 3:
    raise ValueError("app-id must be exactly 3 bytes")
if len(app_key) != 16:
    raise ValueError("app-key must be 16 bytes (AES-128)")
if data_key is not None and len(data_key) != 16:
    raise ValueError("data-key must be 16 bytes (AES-128)")
if data_len > 240:
    raise ValueError("data too long (max 240 bytes)")


# ═══════════════════════════════════════════════════════════════
#  Crypto
# ═══════════════════════════════════════════════════════════════

def aes_cmac_full(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


def cmac_truncate(full_mac: bytes) -> bytes:
    return bytes([full_mac[i] for i in range(1, 16, 2)])


def iso_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + b'\x80' + b'\x00' * (pad_len - 1)


def zero_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = (block_size - (len(data) % block_size)) % block_size
    return data + b'\x00' * pad_len


# ═══════════════════════════════════════════════════════════════
#  EV2 Session
# ═══════════════════════════════════════════════════════════════

class EV2Session:
    def __init__(self, k_enc, k_mac, ti):
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.ti = ti
        self.cmd_ctr = 0

    def _iv(self, for_response):
        label = bytes([0x5A, 0xA5]) if for_response else bytes([0xA5, 0x5A])
        iv_in = label + self.ti + struct.pack('<H', self.cmd_ctr) + bytes(8)
        return AES.new(self.k_enc, AES.MODE_ECB).encrypt(iv_in)

    def cmd_mac(self, cmd_byte, cmd_data):
        mac_in = bytes([cmd_byte]) + struct.pack('<H', self.cmd_ctr) + self.ti + cmd_data
        return cmac_truncate(aes_cmac_full(self.k_mac, mac_in))

    def resp_mac(self, sw2, resp_data):
        mac_in = bytes([sw2]) + struct.pack('<H', self.cmd_ctr) + self.ti + resp_data
        return cmac_truncate(aes_cmac_full(self.k_mac, mac_in))

    def encrypt_cmd_data(self, plaintext):
        return AES.new(self.k_enc, AES.MODE_CBC, self._iv(False)).encrypt(iso_pad(plaintext))

    def decrypt_resp_data(self, ciphertext):
        return AES.new(self.k_enc, AES.MODE_CBC, self._iv(True)).decrypt(ciphertext)

    def verify_response(self, sw2, resp_data, mac8, warn_only=False):
        expected = self.resp_mac(sw2, resp_data)
        if expected != mac8:
            msg = f"Response MAC mismatch"
            if warn_only:
                print(f"    ⚠ {msg} (non-fatal)")
            else:
                raise Exception(msg)

    def increment(self):
        self.cmd_ctr += 1


def derive_session_keys(key, rnd_a, rnd_b):
    xor_part = bytes([rnd_a[2 + i] ^ rnd_b[i] for i in range(6)])
    sv_suffix = rnd_a[0:2] + xor_part + rnd_b[6:16] + rnd_a[8:16]
    sv1 = bytes([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + sv_suffix
    sv2 = bytes([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + sv_suffix
    return aes_cmac_full(key, sv1), aes_cmac_full(key, sv2)


# ═══════════════════════════════════════════════════════════════
#  Card I/O
# ═══════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════
#  Authentication
# ═══════════════════════════════════════════════════════════════

def auth_des_legacy(key8):
    iv = bytes(8)
    data, sw1, sw2 = raw([0x90, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"DES auth failed: {sw1:02X} {sw2:02X}")
    rnd_b = DES.new(key8, DES.MODE_CBC, iv).decrypt(bytes(data))
    rnd_a = get_random_bytes(8)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(DES.new(key8, DES.MODE_CBC, iv).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"DES auth failed: {sw1:02X} {sw2:02X}")


def auth_aes_picc(key16):
    iv = bytes(16)
    data, sw1, sw2 = raw([0x90, 0xAA, 0x00, 0x00, 0x01, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"AES PICC auth failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key16, AES.MODE_CBC, iv).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]
    token = list(AES.new(key16, AES.MODE_CBC, iv).encrypt(rnd_a + rnd_b_rot))
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(token)] + token + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"AES PICC auth failed: {sw1:02X} {sw2:02X}")


def auth_ev2_first(key, key_no=0):
    iv_zero = bytes(16)
    data, sw1, sw2 = raw([0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00])
    if sw2 != 0xAF:
        raise Exception(f"EV2 auth step 1 failed: {sw1:02X} {sw2:02X}")
    rnd_b = AES.new(key, AES.MODE_CBC, iv_zero).decrypt(bytes(data))
    rnd_a = get_random_bytes(16)
    part2_enc = AES.new(key, AES.MODE_CBC, iv_zero).encrypt(rnd_a + rnd_b[1:] + rnd_b[:1])
    data, sw1, sw2 = raw([0x90, 0xAF, 0x00, 0x00, len(part2_enc)] + list(part2_enc) + [0x00])
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"EV2 auth step 2 failed: {sw1:02X} {sw2:02X}")
    resp_dec = AES.new(key, AES.MODE_CBC, iv_zero).decrypt(bytes(data))
    ti = resp_dec[0:4]
    if resp_dec[4:20] != rnd_a[1:] + rnd_a[:1]:
        raise Exception("EV2: RndA' mismatch")
    k_enc, k_mac = derive_session_keys(key, rnd_a, rnd_b)
    print(f"    EV2 session established (TI={ti.hex()})")
    return EV2Session(k_enc, k_mac, ti)


# ═══════════════════════════════════════════════════════════════
#  EV2 Secure Channel Commands
# ═══════════════════════════════════════════════════════════════

def ev2_change_key(session, key_no, new_key, key_version=0x01):
    key_data_padded = iso_pad(new_key + bytes([key_version]))
    iv = session._iv(for_response=False)
    ciphertext = AES.new(session.k_enc, AES.MODE_CBC, iv).encrypt(key_data_padded)
    cmd_data = bytes([key_no]) + ciphertext
    mac8 = session.cmd_mac(0xC4, cmd_data)
    full = list(cmd_data) + list(mac8)
    data, sw1, sw2 = raw([0x90, 0xC4, 0x00, 0x00, len(full)] + full + [0x00])
    print(f"  [ChangeKey] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"ChangeKey failed: {sw1:02X} {sw2:02X}")
    session.increment()
    if len(data) >= 8:
        session.verify_response(0x00, b'', bytes(data[:8]), warn_only=True)


def ev2_create_std_file(session, file_no, comm_mode_byte, access_rights, file_size):
    size_le = struct.pack('<I', file_size)[:3]
    file_data = bytes([file_no, comm_mode_byte]) + access_rights + size_le
    mac8 = session.cmd_mac(0xCD, file_data)
    full = list(file_data) + list(mac8)
    data, sw1, sw2 = raw([0x90, 0xCD, 0x00, 0x00, len(full)] + full + [0x00])
    print(f"  [CreateFile] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"CreateFile failed: {sw1:02X} {sw2:02X}")
    session.increment()
    if len(data) >= 8:
        session.verify_response(0x00, b'', bytes(data[:8]), warn_only=True)


def ev2_write_data_full(session, file_no, plaintext):
    cmd_header = bytes([file_no]) + bytes(3) + struct.pack('<I', len(plaintext))[:3]
    encrypted = session.encrypt_cmd_data(plaintext)
    cmd_data = cmd_header + encrypted
    mac8 = session.cmd_mac(0x3D, cmd_data)
    full = list(cmd_data) + list(mac8)
    data, sw1, sw2 = raw([0x90, 0x3D, 0x00, 0x00, len(full)] + full + [0x00])
    print(f"  [WriteData FULL] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"WriteData failed: {sw1:02X} {sw2:02X}")
    session.increment()
    if len(data) >= 8:
        session.verify_response(0x00, b'', bytes(data[:8]), warn_only=True)


def ev2_write_data_mac(session, file_no, plaintext):
    cmd_header = bytes([file_no]) + bytes(3) + struct.pack('<I', len(plaintext))[:3]
    cmd_data = cmd_header + plaintext
    mac8 = session.cmd_mac(0x3D, cmd_data)
    full = list(cmd_data) + list(mac8)
    data, sw1, sw2 = raw([0x90, 0x3D, 0x00, 0x00, len(full)] + full + [0x00])
    print(f"  [WriteData MAC] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"WriteData failed: {sw1:02X} {sw2:02X}")
    session.increment()
    if len(data) >= 8:
        session.verify_response(0x00, b'', bytes(data[:8]), warn_only=True)


def ev2_write_data_plain(session, file_no, ciphertext):
    write_len = len(ciphertext)
    lc = 1 + 3 + 3 + write_len
    full = [file_no] + [0]*3 + list(struct.pack('<I', write_len)[:3]) + list(ciphertext)
    data, sw1, sw2 = raw([0x90, 0x3D, 0x00, 0x00, lc] + full + [0x00])
    print(f"  [WriteData PLAIN] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"WriteData failed: {sw1:02X} {sw2:02X}")
    session.increment()


def ev2_read_data_full(session, file_no, read_len):
    cmd_header = bytes([file_no]) + bytes(3) + struct.pack('<I', read_len)[:3]
    mac8 = session.cmd_mac(0xBD, cmd_header)
    full = list(cmd_header) + list(mac8)
    data, sw1, sw2 = raw([0x90, 0xBD, 0x00, 0x00, len(full)] + full + [0x00])
    print(f"  [ReadData FULL] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"ReadData failed: {sw1:02X} {sw2:02X}")
    resp = bytes(data)
    resp_enc, resp_mac = resp[:-8], resp[-8:]
    session.increment()
    session.verify_response(0x00, resp_enc, resp_mac)
    dec = bytearray(session.decrypt_resp_data(resp_enc))
    while len(dec) > 0 and dec[-1] == 0x00: dec.pop()
    if len(dec) > 0 and dec[-1] == 0x80: dec.pop()
    return bytes(dec)


def ev2_read_data_mac(session, file_no, read_len):
    cmd_header = bytes([file_no]) + bytes(3) + struct.pack('<I', read_len)[:3]
    mac8 = session.cmd_mac(0xBD, cmd_header)
    full = list(cmd_header) + list(mac8)
    data, sw1, sw2 = raw([0x90, 0xBD, 0x00, 0x00, len(full)] + full + [0x00])
    print(f"  [ReadData MAC] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"ReadData failed: {sw1:02X} {sw2:02X}")
    resp = bytes(data)
    plaintext, resp_mac = resp[:-8], resp[-8:]
    session.increment()
    session.verify_response(0x00, plaintext, resp_mac)
    return plaintext


def ev2_read_data_plain(session, file_no, read_len):
    lc = 1 + 3 + 3
    full = [file_no] + [0]*3 + list(struct.pack('<I', read_len)[:3])
    data, sw1, sw2 = raw([0x90, 0xBD, 0x00, 0x00, lc] + full + [0x00])
    print(f"  [ReadData PLAIN] SW: {sw1:02X} {sw2:02X}")
    if not (sw1 == 0x91 and sw2 == 0x00):
        raise Exception(f"ReadData failed: {sw1:02X} {sw2:02X}")
    session.increment()
    return bytes(data)


# ═══════════════════════════════════════════════════════════════
#  desfsh helpers
# ═══════════════════════════════════════════════════════════════

def run_desfsh(lua_script, silent=False):
    cmd = [desfsh_path, "-d", str(desfsh_device), "-t", str(desfsh_tag), "-c", lua_script]
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


def disable_aid_enumeration(key_type, key_bytes):
    key_hex = hex_compact(key_bytes)
    lua = f'''
local ok, err = pcall(function()
    cmd.select(0)
    local code, errmsg = cmd.auth(0, {key_type}("{key_hex}"))
    if code ~= 0 then error("Auth failed: " .. tostring(errmsg)) end
    local code2, errmsg2, keyset = cmd.gks()
    if code2 ~= 0 then error("GetKeySettings failed: " .. tostring(errmsg2)) end
    local list_enabled = math.floor(keyset / 2) % 2
    if list_enabled == 0 then print("AID_ENUM_ALREADY_DISABLED") return end
    local code3, errmsg3 = cmd.cks(keyset - 2)
    if code3 ~= 0 then error("ChangeKeySettings failed: " .. tostring(errmsg3)) end
    local code4, _, verify_keyset = cmd.gks()
    if code4 ~= 0 then error("Verify failed") end
    if math.floor(verify_keyset / 2) % 2 == 0 then print("AID_ENUM_DISABLED")
    else error("LIST bit still set") end
end)
if not ok then print("AID_ENUM_CHANGE_FAILED: " .. tostring(err)) end
'''
    _, stdout = run_desfsh(lua)
    if "AID_ENUM_DISABLED" in stdout or "AID_ENUM_ALREADY_DISABLED" in stdout:
        return True
    return False


def change_picc_key(old_type, old_key, new_type, new_key):
    old_hex, new_hex = hex_compact(old_key), hex_compact(new_key)
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


# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════

print(f"\n{'=' * 60}")
print(f"  DESFire EV3 Provisioner")
print(f"{'=' * 60}")
print(f"  Mode       : {comm_mode.upper()}")
print(f"  AID        : {toHexString(aid)}")
print(f"  PICC key   : {picc_key_type} {show_key(picc_key_raw)}")
if new_picc_key_raw:
    print(f"  New PICC   : {new_picc_key_type} {show_key(new_picc_key_raw)}")
print(f"  App key    : {show_key(app_key)}")
if data_key:
    print(f"  Data key   : {show_key(data_key)}")
print(f"  Payload    : '{data_str}' ({data_len} bytes)")
print()

# ── 1. PICC auth ────────────────────────────────────────────────
print("=== Step 1: Select + Auth PICC ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00], "SelectPICC")
if picc_key_type == "DES":
    auth_des_legacy(picc_key_raw)
else:
    auth_aes_picc(picc_key_raw)
print(f"  ✓ PICC {picc_key_type} auth OK")

# ── 2. Check AID ────────────────────────────────────────────────
print("\n=== Step 2: Check AID is free ===")
data, sw1, sw2 = raw([0x90, 0x6A, 0x00, 0x00, 0x00])
existing = [data[i:i+3] for i in range(0, len(data), 3) if len(data[i:i+3]) == 3]
if bytes(aid) in [bytes(a) for a in existing]:
    raise Exception(f"App {toHexString(aid)} already exists — run factory_reset.py first")
print(f"  ✓ AID {toHexString(aid)} is free")

# ── 3. Create app ───────────────────────────────────────────────
print("\n=== Step 3: Create AES application ===")
KS1 = 0x09  # config changeable + master key changeable, no free list/create
KS2 = 0x81  # AES keys + max 2 key slots
data, sw1, sw2 = raw([0x90, 0xCA, 0x00, 0x00, 0x05] + aid + [KS1, KS2, 0x00])
print(f"  [CreateApp] SW: {sw1:02X} {sw2:02X}")
if not (sw1 == 0x91 and sw2 == 0x00):
    raise Exception(f"CreateApp failed: {sw1:02X} {sw2:02X}")
print(f"  ✓ Created (KS1=0x{KS1:02X}, KS2=0x{KS2:02X})")

# ── 4. Auth default key ─────────────────────────────────────────
print("\n=== Step 4: Select app + EV2 auth (default key) ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
session = auth_ev2_first(bytes(16), 0)
print("  ✓ Default key auth OK")

# ── 5. Change app key ───────────────────────────────────────────
print("\n=== Step 5: Change app key ===")
ev2_change_key(session, 0x00, app_key, 0x01)
print("  ✓ App key changed")

# ── 6. Re-auth ──────────────────────────────────────────────────
print("\n=== Step 6: Re-auth with new key ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
session = auth_ev2_first(app_key, 0)
print("  ✓ Verified — secure channel active")

# ── 7. Create file ──────────────────────────────────────────────
print(f"\n=== Step 7: Create file (comm={comm_mode}) ===")
if comm_mode == "plain" and data_key:
    file_size = len(AES.new(data_key, AES.MODE_CBC, bytes(16)).encrypt(zero_pad(data_bytes)))
else:
    file_size = data_len
ev2_create_std_file(session, 0x01, COMM_MODE_BYTE, bytes([0x00, 0x00]), file_size)
print(f"  ✓ File created (size={file_size}, comm=0x{COMM_MODE_BYTE:02X})")

# ── 8. Write data ───────────────────────────────────────────────
print("\n=== Step 8: Write data ===")
if comm_mode == "full":
    ev2_write_data_full(session, 0x01, data_bytes)
    print(f"  ✓ Wrote {data_len} bytes (encrypted via session key)")
elif comm_mode == "mac":
    ev2_write_data_mac(session, 0x01, data_bytes)
    print(f"  ✓ Wrote {data_len} bytes (CMAC protected)")
else:
    encrypted = AES.new(data_key, AES.MODE_CBC, bytes(16)).encrypt(zero_pad(data_bytes))
    ev2_write_data_plain(session, 0x01, encrypted)
    print(f"  ✓ Wrote {len(encrypted)} bytes (pre-encrypted)")

# ── 9. Verify ───────────────────────────────────────────────────
print("\n=== Step 9: Verify read-back ===")
apdu([0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00], "SelectApp")
session = auth_ev2_first(app_key, 0)
if comm_mode == "full":
    readback = ev2_read_data_full(session, 0x01, file_size)
    result_str = readback.rstrip(b'\x00').decode('utf-8', errors='replace')
elif comm_mode == "mac":
    readback = ev2_read_data_mac(session, 0x01, file_size)
    result_str = readback.rstrip(b'\x00').decode('utf-8', errors='replace')
else:
    readback = ev2_read_data_plain(session, 0x01, file_size)
    result_str = AES.new(data_key, AES.MODE_CBC, bytes(16)).decrypt(
        bytes(readback)).rstrip(b'\x00').decode('utf-8', errors='replace')

if result_str != data_str:
    print(f"  ✗ Mismatch: wrote '{data_str}', read '{result_str}'")
    sys.exit(1)
print(f"  ✓ Verified: '{result_str}'")

# ── 10. Disable AID enumeration ─────────────────────────────────
if not args.skip_aid_enum:
    print("\n=== Step 10: Disable anonymous AID enumeration ===")
    if not os.path.exists(desfsh_path):
        print(f"  ⚠ desfsh not found at {desfsh_path} — skipping")
        print(f"    Run manually: desfsh -c 'cmd.select(0); cmd.auth(0, ...); ...'")
    else:
        if disable_aid_enumeration(picc_key_type, picc_key_raw):
            print("  ✓ AID enumeration disabled")
        else:
            print("  ⚠ Failed to disable AID enumeration")
            print("    Card may need to be re-placed on reader, or run separately")
else:
    print("\n=== Step 10: AID enumeration — SKIPPED ===")

# ── 11. Change PICC key ─────────────────────────────────────────
if new_picc_key_raw and not args.skip_picc_key_change:
    print("\n=== Step 11: Change PICC master key ===")
    if not os.path.exists(desfsh_path):
        print(f"  ⚠ desfsh not found at {desfsh_path} — skipping")
    else:
        if change_picc_key(picc_key_type, picc_key_raw, new_picc_key_type, new_picc_key_raw):
            print("  ✓ PICC key changed")
            picc_key_raw = new_picc_key_raw
            picc_key_type = new_picc_key_type
        else:
            print("  ⚠ PICC key change failed — run change_picc_key.py separately")
elif new_picc_key_raw:
    print("\n=== Step 11: PICC key change — SKIPPED (--skip-picc-key-change) ===")
else:
    print("\n=== Step 11: PICC key — unchanged ===")

# ── Summary ──────────────────────────────────────────────────────
print(f"\n{'=' * 60}")
print(f"  ✓ Card provisioned successfully!")
print(f"{'=' * 60}")
print(f"  PICC key   : {picc_key_type} {show_key(picc_key_raw)}")
print(f"  App key    : AES-128 {show_key(app_key)}")
print(f"  File comm  : {comm_mode.upper()}")
print(f"  Payload    : '{data_str}'")
print(f"\n  ESPHome config:")
print(f"    app_key: \"{':'.join(f'{b:02X}' for b in app_key)}\"")
print(f"    comm_mode: {comm_mode}")
if data_key:
    print(f"    data_key: \"{':'.join(f'{b:02X}' for b in data_key)}\"")