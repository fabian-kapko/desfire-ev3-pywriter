'''# Auto-detect old key (tries defaults, then asks)
python3 change_picc_key.py --new-key 0102030405060708090A0B0C0D0E0F10

# Specify old key explicitly
python3 change_picc_key.py \
    --old-key 0000000000000000 \
    --new-key 0102030405060708090A0B0C0D0E0F10 --device 0

# Skip confirmation
python3 change_picc_key.py \
    --old-key 0000000000000000 \
    --new-key 0102030405060708090A0B0C0D0E0F10 \
    -y

# Change from AES back to DES (factory reset)
python3 change_picc_key.py \
    --old-key 0102030405060708090A0B0C0D0E0F10 \
    --new-key 0000000000000000

# With custom device/tag
python3 change_picc_key.py \
    --new-key 0102030405060708090A0B0C0D0E0F10 \
    --device 1 \
    --tag 0

# Full help
python3 change_picc_key.py --help

usage: change_picc_key.py [-h] [--old-key OLD_KEY] --new-key NEW_KEY
                          [--desfsh DESFSH] [--device DEVICE] [--tag TAG] [-y]

Change DESFire EV3 PICC master key

optional arguments:
  -h, --help         show this help message and exit
  --old-key OLD_KEY  Current PICC key (hex). Auto-detects DES(16)/AES(32).
                     If omitted, tries defaults then asks.
  --new-key NEW_KEY  New PICC key (hex). DES=16 chars, AES=32 chars.
  --desfsh DESFSH    Path to desfsh binary (default: ./desfsh)
  --device DEVICE    Device index (default: 1)
  --tag TAG          Tag index (default: 0)
  -y, --yes          Skip confirmation prompt
#!/usr/bin/env python3
# change_picc_key.py - Change DESFire EV3 PICC master key using desfsh
'''
import argparse
import subprocess
import sys

# ── Argument parsing ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Change DESFire EV3 PICC master key")
parser.add_argument("--old-key", 
                    help="Current PICC key (hex). Auto-detects DES(16)/AES(32). If omitted, tries defaults then asks.")
parser.add_argument("--new-key", required=True,
                    help="New PICC key (hex). DES=16 chars, AES=32 chars.")
parser.add_argument("--desfsh", default="./desfsh",
                    help="Path to desfsh binary (default: ./desfsh)")
parser.add_argument("--device", type=int, default=1,
                    help="Device index (default: 1)")
parser.add_argument("--tag", type=int, default=0,
                    help="Tag index (default: 0)")
parser.add_argument("-y", "--yes", action="store_true",
                    help="Skip confirmation prompt")
args = parser.parse_args()

DESFSH_PATH = args.desfsh
DEVICE = args.device
TAG = args.tag

# ── Helpers ──────────────────────────────────────────────────────
def run_desfsh(lua_script, silent=False):
    """Run desfsh with a Lua script, return (success, stdout)"""
    cmd = [DESFSH_PATH, "-d", str(DEVICE), "-t", str(TAG), "-c", lua_script]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0 and "LUA_ERROR" not in result.stdout
        if not silent and not success:
            print(f"    stdout: {result.stdout.strip()}")
        return success, result.stdout
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError:
        print(f"  ✗ desfsh not found at: {DESFSH_PATH}")
        sys.exit(1)

def try_auth(key_type, key_hex):
    """Try to authenticate with given key. Returns True if success."""
    lua = f'''
local ok, err = pcall(function()
    cmd.select(0)
    local code, err = cmd.auth(0, {key_type}("{key_hex}"))
    if code ~= 0 then
        error("AUTH_FAILED")
    end
end)
if ok then
    print("AUTH_OK")
else
    print("AUTH_FAILED")
end
'''
    success, stdout = run_desfsh(lua, silent=True)
    return "AUTH_OK" in stdout

def change_key(old_type, old_key, new_type, new_key):
    """Change PICC master key. Returns True if success."""
    lua = f'''
local ok, err = pcall(function()
    cmd.select(0)
    local code, err = cmd.auth(0, {old_type}("{old_key}"))
    if code ~= 0 then
        error("Auth failed: " .. tostring(err))
    end
    code, err = cmd.ck(0, {new_type}("{new_key}"))
    if code ~= 0 then
        error("ChangeKey failed: " .. tostring(err))
    end
end)
if ok then
    print("CHANGE_OK")
else
    print("CHANGE_FAILED: " .. tostring(err))
end
'''
    success, stdout = run_desfsh(lua)
    return "CHANGE_OK" in stdout

def get_card_info():
    """Get card version info."""
    lua = '''
local ok, err = pcall(function()
    cmd.getver()
end)
if ok then
    print("CARD_OK")
end
'''
    success, stdout = run_desfsh(lua, silent=True)
    return success

def parse_key(key_str):
    """Parse key string, return (type, hex) or None if invalid."""
    key_hex = key_str.strip().replace(":", "").replace(" ", "").upper()
    try:
        bytes.fromhex(key_hex)
    except ValueError:
        return None, None
    
    if len(key_hex) == 16:
        return "DES", key_hex
    elif len(key_hex) == 32:
        return "AES", key_hex
    else:
        return None, None

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

print("=" * 60)
print("DESFire EV3 PICC Master Key Changer")
print("=" * 60)

# Parse new key
new_type, new_key = parse_key(args.new_key)
if new_type is None:
    print(f"  ✗ Invalid --new-key: must be 16 (DES) or 32 (AES) hex chars")
    sys.exit(1)

# Check card is present
print("\n[1] Checking card...")
if not get_card_info():
    print("  ✗ No card detected. Place card on reader and try again.")
    sys.exit(1)
print("  ✓ Card detected")

# Determine current key
current_type = None
current_key = None

if args.old_key:
    # User provided old key
    print(f"\n[2] Using provided old key...")
    old_type, old_key = parse_key(args.old_key)
    if old_type is None:
        print(f"  ✗ Invalid --old-key: must be 16 (DES) or 32 (AES) hex chars")
        sys.exit(1)
    
    print(f"  Trying {old_type} {old_key}...", end=" ")
    if try_auth(old_type, old_key):
        print("✓")
        current_type = old_type
        current_key = old_key
    else:
        print("✗")
        print("  ✗ Authentication failed with provided key")
        sys.exit(1)
else:
    # Try default keys
    print("\n[2] Trying default keys...")
    
    DEFAULT_DES = "0000000000000000"
    DEFAULT_AES = "00000000000000000000000000000000"
    
    print("  Trying default DES (8x 00)...", end=" ")
    if try_auth("DES", DEFAULT_DES):
        print("✓")
        current_type = "DES"
        current_key = DEFAULT_DES
    else:
        print("✗")
        print("  Trying default AES (16x 00)...", end=" ")
        if try_auth("AES", DEFAULT_AES):
            print("✓")
            current_type = "AES"
            current_key = DEFAULT_AES
        else:
            print("✗")
    
    # If no default key worked, ask user
    if current_type is None:
        print("\n  Default keys failed. Please enter current PICC key.")
        print("  Format: hex string without spaces or colons")
        print("  Examples:")
        print("    DES (8 bytes):  0102030405060708")
        print("    AES (16 bytes): 0102030405060708090A0B0C0D0E0F10")
        
        while True:
            user_key = input("\n  Enter current PICC key: ").strip().replace(":", "").replace(" ", "").upper()
            
            if len(user_key) == 16:
                print("  Trying as DES...", end=" ")
                if try_auth("DES", user_key):
                    print("✓")
                    current_type = "DES"
                    current_key = user_key
                    break
                else:
                    print("✗")
            elif len(user_key) == 32:
                print("  Trying as AES...", end=" ")
                if try_auth("AES", user_key):
                    print("✓")
                    current_type = "AES"
                    current_key = user_key
                    break
                else:
                    print("✗")
            else:
                print("  ✗ Invalid length. Must be 16 (DES) or 32 (AES) hex chars.")
                continue
            
            print("  ✗ Authentication failed. Try again.")

print(f"\n  Current key: {current_type} {current_key}")
print(f"  New key:     {new_type} {new_key}")

# Confirm
if not args.yes:
    print(f"\n[3] Confirm key change")
    print(f"  FROM: {current_type} {current_key}")
    print(f"  TO:   {new_type} {new_key}")
    confirm = input("\n  Type 'yes' to confirm: ").strip().lower()
    
    if confirm != "yes":
        print("  Cancelled.")
        sys.exit(0)
else:
    print(f"\n[3] Skipping confirmation (-y flag)")

# Change key
print("\n[4] Changing PICC master key...")
if change_key(current_type, current_key, new_type, new_key):
    print("  ✓ Key changed successfully!")
    
    # Verify new key
    print("\n[5] Verifying new key...")
    if try_auth(new_type, new_key):
        print("  ✓ New key verified!")
        print("\n" + "=" * 60)
        print("  SUCCESS! PICC master key changed to:")
        print(f"  {new_type} {new_key}")
        print("=" * 60)
        print("\n  ⚠️  SAVE THIS KEY! You need it to access the card.")
    else:
        print("  ✗ Verification failed! Card may be in unknown state.")
        sys.exit(1)
else:
    print("  ✗ Key change failed!")
    sys.exit(1)