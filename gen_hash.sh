#!/usr/bin/env bash
# Print a file's SHA-256 as a C byte-array ready to paste into hashguard.bpf.c
#   usage: ./gen_hash.sh /usr/bin/xxd
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <binary>" >&2; exit 1; }
[ -f "$1" ]  || { echo "not a file: $1" >&2; exit 1; }

sum=$(sha256sum "$1" | cut -d' ' -f1)

echo "    /* $1"
echo "       $sum */"
echo -n "    {"
for ((i = 0; i < 64; i += 2)); do
    (( i % 16 == 0 )) && printf "\n      "
    printf " 0x%s," "${sum:$i:2}"
done
echo ""
echo "    },"