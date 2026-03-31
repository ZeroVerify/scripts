#!/bin/bash
set -euo pipefail

S3_PATH="${1:-s3://zeroverify-artifacts/bitstring/v1/bitstring.gz}"

tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

aws s3 cp "$S3_PATH" - | gunzip | base64 -d > "$tmpfile"

byte_count=$(wc -c < "$tmpfile")
echo "Bitstring: $byte_count byte(s), $((byte_count * 8)) slot(s)"
echo ""

python3 - "$tmpfile" <<'EOF'
import sys

with open(sys.argv[1], 'rb') as f:
    data = f.read()

print("hex  binary")
for byte_idx, byte in enumerate(data):
    bits = f"{byte:08b}"
    print(f"  {byte:02x}   {bits}   (indices {byte_idx*8}–{byte_idx*8+7})")

print()
print("Revoked indices:")
revoked = [
    byte_idx * 8 + bit
    for byte_idx, byte in enumerate(data)
    for bit in range(8)
    if (byte >> (7 - bit)) & 1
]

if revoked:
    for idx in revoked:
        print(f"  {idx}")
else:
    print("  (none)")
EOF
