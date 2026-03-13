#!/usr/bin/env bash
# encrypt_multi.sh — Encrypt an HTML file with multiple passwords (one per reviewer).
#
# Usage:  ./encrypt_multi.sh <input.html> <passwords.txt> [output_dir]
#
# passwords.txt format (one per line):
#   password:Reviewer Name
#
# Produces content.js containing a REVIEWERS[] array, each entry with
# { name, salt, iv, data } — compatible with the multi-blob decryption
# flow in index.html.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <html_file> <passwords.txt> [output_dir]" >&2
  exit 1
fi

INPUT_FILE="$1"
PASSWORDS_FILE="$2"
OUTPUT_DIR="${3:-.}"

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: File not found: $INPUT_FILE" >&2
  exit 1
fi

if [[ ! -f "$PASSWORDS_FILE" ]]; then
  echo "Error: Passwords file not found: $PASSWORDS_FILE" >&2
  exit 1
fi

python3 - "$INPUT_FILE" "$PASSWORDS_FILE" "$OUTPUT_DIR" << 'PYEOF'
import sys, base64, hashlib, json, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

input_file     = sys.argv[1]
passwords_file = sys.argv[2]
output_dir     = sys.argv[3]

with open(input_file, 'rb') as f:
    plaintext = f.read()

with open(passwords_file, 'r') as f:
    lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

reviewers = []
for line in lines:
    password, name = line.split(':', 1)
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    encrypted_b64 = base64.b64encode(ciphertext).decode('ascii')

    reviewers.append({
        'name': name,
        'salt': salt.hex(),
        'iv':   iv.hex(),
        'data': encrypted_b64
    })
    print(f"  Encrypted for: {name} (salt={salt.hex()[:12]}...)")

# Write content.js with REVIEWERS array
out_path = os.path.join(output_dir, 'content.js')
with open(out_path, 'w') as out:
    out.write('const REVIEWERS = [\n')
    for i, r in enumerate(reviewers):
        comma = ',' if i < len(reviewers) - 1 else ''
        out.write(f'  {{\n')
        out.write(f'    name: "{r["name"]}",\n')
        out.write(f'    salt: "{r["salt"]}",\n')
        out.write(f'    iv:   "{r["iv"]}",\n')
        out.write(f'    data: "{r["data"]}"\n')
        out.write(f'  }}{comma}\n')
    out.write('];\n')

size = os.path.getsize(out_path)
print(f"\nEncrypted {input_file} → {out_path}")
print(f"  Reviewers: {len(reviewers)}")
print(f"  Size: {size:,} bytes")
PYEOF
