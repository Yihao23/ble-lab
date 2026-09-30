#!/usr/bin/env bash
# Cross-compile the library for Cortex-M and report flash, RAM and stack.
#
# Runs arm-none-eabi-gcc inside a throwaway Debian container, so nothing is
# installed on the host and no sudo is needed. newlib is deliberately not
# installed, so a source that includes <string.h> fails to compile.
#
# Compiling is not enough to prove the library needs no libc: GCC may emit
# calls to memcpy, memmove, memset and memcmp on its own, even with
# -ffreestanding -fno-builtin, and a missing one only shows at link time. So
# every symbol the objects leave undefined must be defined by another object
# of the library; anything else fails the run. (It once caught a memset GCC
# generated for `uint8_t block[16] = {0}` on Cortex-M0+ but not on M4.)
#
# The per-function stack usage (.su) and the call graph the compiler
# actually emitted (.ci, from -fcallgraph-info=su) are kept in
# build/cortex-m/<cpu>/ for tools that add stack frames along call chains.
#
# Usage: tools/size-cortex-m.sh            (from 01-ble-core-c/)
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm -v "$PWD":/src -w /src debian:bookworm-slim bash -c '
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends gcc-arm-none-eabi binutils-arm-none-eabi >/dev/null
arm-none-eabi-gcc --version | head -1
fail=0
for cpu in cortex-m0plus cortex-m4; do
  out=/tmp/$cpu; keep=/src/build/cortex-m/$cpu
  mkdir -p $out; rm -rf $keep; mkdir -p $keep
  for f in src/*.c; do
    arm-none-eabi-gcc -mcpu=$cpu -mthumb -Os -std=c99 -ffreestanding -fno-builtin \
      -ffunction-sections -fdata-sections -fstack-usage -fcallgraph-info=su \
      -Wall -Wextra -Werror -Iinclude -Isrc -c "$f" -o "$out/$(basename "${f%.c}").o"
  done
  echo
  echo "== $cpu (-Os, thumb) =="
  arm-none-eabi-size -t "$out"/*.o | sed "s#$out/##"
  echo "-- worst-case stack per function (bytes) --"
  cat "$out"/*.su | awk -F"\t" "{print \$2\"\t\"\$1}" | sort -rn | head -5 | sed "s#src/##"
  cp "$out"/*.su "$out"/*.ci "$keep"/
  echo "-- symbols needed from outside the library (must be none) --"
  missing=$(arm-none-eabi-nm "$out"/*.o | awk "
    \$1 == \"U\"                              { need[\$2] = 1 }
    NF == 3 && \$2 ~ /^[A-Z]\$/ && \$2 != \"U\" { have[\$3] = 1 }
    END { for (s in need) if (!(s in have)) print s }" | sort)
  if [ -n "$missing" ]; then
    echo "$missing" | sed "s/^/  MISSING: /"
    fail=1
  else
    echo "  none"
  fi
done
chown -R "$(stat -c %u:%g /src)" /src/build/cortex-m
exit $fail
'
