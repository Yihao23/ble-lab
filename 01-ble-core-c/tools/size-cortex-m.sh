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
# The one exception is the ARM EABI compiler runtime, __aeabi_*: Cortex-M0+
# has no divide instruction, so `x % 1000000u` becomes a call to
# __aeabi_uidivmod in libgcc, which ships with the compiler rather than libc.
# Those are listed with the object that needs them, and allowed.
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
  echo "-- symbols needed from outside the library --"
  # One line per symbol: "<object> <symbol>". __aeabi_* are the ARM EABI
  # compiler-runtime helpers (software division on cores without a divide
  # instruction, for one): they come with the compiler in libgcc, not libc,
  # and a bare-metal link has them. Listed, but allowed. Anything else fails.
  outside=$(arm-none-eabi-nm "$out"/*.o | awk "
    /:\$/                                     { obj = \$1; sub(/.*\\//, \"\", obj); sub(/:\$/, \"\", obj) }
    \$1 == \"U\"                              { need[\$2] = need[\$2] \" \" obj }
    NF == 3 && \$2 ~ /^[A-Z]\$/ && \$2 != \"U\" { have[\$3] = 1 }
    END { for (s in need) if (!(s in have)) print s need[s] }" | sort)
  if [ -z "$outside" ]; then
    echo "  none"
  fi
  while read -r sym objs; do
    [ -n "$sym" ] || continue
    case "$sym" in
      __aeabi_*) echo "  compiler runtime (libgcc): $sym  <- $objs" ;;
      *)         echo "  MISSING: $sym  <- $objs"; fail=1 ;;
    esac
  done <<< "$outside"
done
chown -R "$(stat -c %u:%g /src)" /src/build/cortex-m
exit $fail
'
