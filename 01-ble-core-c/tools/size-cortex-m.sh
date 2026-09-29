#!/usr/bin/env bash
# Cross-compile the library for Cortex-M and report flash, RAM and stack.
#
# Runs arm-none-eabi-gcc inside a throwaway Debian container, so nothing is
# installed on the host and no sudo is needed. newlib is deliberately not
# installed: the library is freestanding, and this proves it — if any source
# pulled in <string.h> or called malloc, this build would fail.
#
# Usage: tools/size-cortex-m.sh            (from 01-ble-core-c/)
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm -v "$PWD":/src -w /src debian:bookworm-slim bash -c '
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends gcc-arm-none-eabi binutils-arm-none-eabi >/dev/null
arm-none-eabi-gcc --version | head -1
for cpu in cortex-m0plus cortex-m4; do
  out=/tmp/$cpu; mkdir -p $out
  for f in src/*.c; do
    arm-none-eabi-gcc -mcpu=$cpu -mthumb -Os -std=c99 -ffreestanding -fno-builtin \
      -ffunction-sections -fdata-sections -fstack-usage \
      -Wall -Wextra -Werror -Iinclude -Isrc -c "$f" -o "$out/$(basename "${f%.c}").o"
  done
  echo
  echo "== $cpu (-Os, thumb) =="
  arm-none-eabi-size -t "$out"/*.o | sed "s#$out/##"
  echo "-- worst-case stack per function (bytes) --"
  cat "$out"/*.su | awk -F"\t" "{print \$2\"\t\"\$1}" | sort -rn | head -5 | sed "s#src/##"
done
'
