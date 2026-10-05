# 01 · BLE core in C
# 01 · C 语言 BLE 核心库

**Goal / 目标** — The parts of a BLE host that sit on the hot path of every
advertisement and every GATT read, write and notification, written the way
firmware is written: C99, no heap, no libc, every length checked, and proven
against Wireshark on real traffic.
BLE host 里每一条广播、每一次 GATT 读写和通知都要经过的那几段代码，按固件的写法来写：
C99、不用堆、不依赖 libc、每个长度都检查，并在真实流量上和 Wireshark 逐字段对拍。

| Module | What it does | 做什么 |
|---|---|---|
| `ble_aes` | AES-128 encrypt, one block — all `ah()` needs | AES-128 单块加密，`ah()` 只需要这个 |
| `ble_rpa` | Address kind from the top two bits, `ah()`, make and resolve a Resolvable Private Address | 地址类型判定、`ah()`、生成/解析 RPA |
| `ble_ad` | Iterate Advertising Data structures without ever reading past the buffer; read Flags, the device name and 16-bit service data | 安全遍历 AD 结构；读取 Flags、设备名、16 位服务数据 |
| `ble_hci` | Iterate the reports inside an HCI LE Advertising Report event, legacy (0x02) and extended (0x0D); tell complete, fragmented and truncated data apart | 解析 HCI 广播报告事件；区分完整、分段、截断的数据 |
| `ble_cmac` | AES-CMAC (RFC 4493), the MAC every LE Secure Connections function is built on | AES-CMAC，LE 安全连接所有函数的基础 |
| `ble_sc` | `g2`: the six digits both screens show during numeric-comparison pairing | `g2`：数字比较配对时两边屏幕显示的 6 位数 |
| `ble_l2cap` | Split an HCI ACL data packet (connection handle, packet boundary flag) and the L2CAP header (channel, length); tell a whole PDU from a first and a continuing fragment | 拆 HCI ACL 数据包（连接句柄、分段标志）和 L2CAP 头部（通道、长度）；区分完整 PDU、首段和后续分段 |
| `ble_att` | Decode an ATT PDU's opcode and fixed parameters — handle, range, MTU, error, offset — after checking its length against the opcode's format | 先按 opcode 的格式检查长度，再解析 ATT PDU 的固定参数：handle、范围、MTU、错误码、偏移 |

**The cryptography here is for understanding, not for products.** `ble_aes`,
`ble_cmac` and `ble_sc` are checked against FIPS-197, RFC 4493 and the Core
spec's Appendix D, but a product should use the chip's hardware AES and a
qualified Bluetooth stack (Zephyr, the vendor's SDK), not hand-written crypto.
Writing them is how the pairing protocol, its byte orders and its test
vectors became familiar enough to debug a failing pairing.
**这里的密码学代码用于学习，不用于产品。** 它们通过了 FIPS-197、RFC 4493 和规范附录 D
的官方向量，但产品应使用芯片的硬件 AES 和经过认证的蓝牙协议栈，而不是手写的加密代码。

---

## Quick start / 快速开始

```bash
cd 01-ble-core-c
cmake -S . -B build -G Ninja && cmake --build build
./build/ble_tests                                   # 620 checks + 300k fuzz inputs

cmake -S . -B build-asan -G Ninja -DBLE_SANITIZE=ON && cmake --build build-asan
./build-asan/ble_tests                              # same, under ASan + UBSan

# differential test: this library vs Wireshark, every report in a capture
python3 tools/diff_vs_tshark.py ../03-hci-capture/captures/scan-*.pcapng

# the same for a connection: every ACL packet, down to ATT, vs Wireshark
python3 tools/diff_acl_vs_tshark.py ../02-gatt-peripheral/captures/phone-fixed-*.pcapng

# what it costs on a microcontroller (needs Docker; no newlib is installed),
# and fail if the objects need any symbol from outside the library
./tools/size-cortex-m.sh

# worst-case stack along the deepest call chain, from GCC's own call graph
./tools/stack-depth.py

# API documentation (Doxygen; any warning fails the run)
doxygen Doxyfile && xdg-open build/docs/html/index.html
```

## What you should see / 你应该看到

```
  200000 inputs, 215848 AD structures, 43915 reports parsed, all in bounds

620 checks, 0 failed
```
```
59437 reports compared on 6 fields each (356622 values)
mismatches: 0
reports whose AD payload is malformed: 0
```
```
307 ACL packets compared, 3349 values
mismatches: 0
```
```
== cortex-m0plus (-Os, thumb) ==
   text    data     bss     dec     hex filename
   3511       0       0    3511     db7 (TOTALS)
-- symbols needed from outside the library --
  compiler runtime (libgcc): __aeabi_uidivmod  <- ble_sc.o
  compiler runtime (libgcc): __gnu_thumb1_case_uqi  <- ble_att.o
```
```
== cortex-m0plus: worst-case stack of each public function ==
      496  ble_sc_g2 (112) -> ble_aes_cmac (104) -> ble_cmac_subkeys (32) -> ble_aes128_encrypt (240) -> add_round_key (8)
      384  ble_aes_cmac (104) -> ble_cmac_subkeys (32) -> ble_aes128_encrypt (240) -> add_round_key (8)
      352  ble_rpa_resolve_any (32) -> ble_rpa_resolve (24) -> ble_ah (48) -> ble_aes128_encrypt (240) -> add_round_key (8)
       72  ble_ad_name (56) -> ble_ad_next (16)
```

**3.5 KB of flash, zero RAM, no libc — checked at the symbol level. 496 bytes
of stack in the worst case**, computing `g2`: its 80-byte message, CMAC's
state and subkeys, and the AES frame, whose key schedule is 176 of its 240
bytes — expanded on the stack and wiped before return, never kept in a
static. Resolving an address needs 352; the AD and HCI parsers 72 at most,
the ACL, L2CAP and ATT parsers 32. The two outside symbols are compiler
helpers: M0+ has no divide instruction and no table-branch instruction.
**3.5 KB flash、0 字节 RAM、不依赖 libc（在符号层面检查过）。最坏情况 496 字节栈**，
发生在计算 `g2` 时：80 字节消息、CMAC 的状态和子密钥，再加上 AES 的栈帧。解析地址需要
352 字节，AD 和 HCI 解析最多 72 字节，ACL/L2CAP/ATT 解析最多 32 字节。两个外部符号都是
libgcc 的编译器辅助函数：M0+ 没有除法指令，也没有查表跳转指令。

---

## Layout / 目录

| Path | What |
|---|---|
| `Doxyfile` | Doxygen config: `WARN_AS_ERROR`, `WARN_NO_PARAMDOC`, output to `build/docs`. Every public function documents each parameter's direction and byte order |
| `include/ble/*.h` | The public API. Addresses are 6 bytes **LSB-first, as on air**; keys and hashes are **MSB-first, as in the spec's test vectors**. Every header says which. |
| `src/ble_util.h` | `ble_copy`, `ble_wipe` (through a `volatile` pointer so the compiler cannot drop it), `ble_le16`. Replaces `string.h`. |
| `tests/fixtures.h` | 7 real HCI events from the capture in project 03, expected values decoded by tshark, **addresses and payloads scrubbed**. Generated by `tools/extract_fixtures.py`. |
| `tests/acl_fixtures.h` | 16 real ACL packets from a phone session against project 02 — MTU exchange, discovery, reads, writes, notifications, errors — expected values decoded by tshark; no SMP packet, name or address. Generated by `tools/extract_acl_fixtures.py`. |
| `tests/test_l2cap_att.c` | Hand-made edge cases for every length rule, the 16 real packets, and 100 000 random ACL inputs taken through all three parsers |
| `tests/test_fuzz.c` | 200 000 random and mutated inputs, each in an exactly-sized `malloc` so ASan catches a one-byte over-read. |
| `docs/multi-report.md` | How several reports share one legacy event: the spec, Linux and this parser compared, and why a `Data_Length` above 31 is accepted |
| `tools/bleg2.c` | `g2` from the command line, arguments as SMP carries them (LSB first); a ctest runs it on the spec's vector |
| `tools/pairing_from_capture.py` | Every pairing in an HCI capture: keys and nonces off the air, Cb re-derived with f4 to prove they were read right, then `bleg2` |
| `tools/bleparse.c` | Hex HCI events on stdin, one TSV line per report on stdout. What `diff_vs_tshark.py` drives. |
| `tools/aclparse.c` | Hex HCI ACL packets on stdin, one TSV line per packet down to ATT. What `diff_acl_vs_tshark.py` drives. |
| `tools/diff_acl_vs_tshark.py` | Every ACL packet in a capture, decoded by this library and by tshark, field by field |
| `tools/size-cortex-m.sh` | Cross-compiles with `arm-none-eabi-gcc -Os -ffreestanding` in a throwaway container, prints size, fails if any object needs a symbol the library does not define, and keeps the `.su` and `.ci` files in `build/cortex-m/` |
| `tools/stack-depth.py` | Adds stack frames along GCC's call graph (after inlining) and prints each public function's worst case and the chain behind it |

---

## Design decisions to defend / 要能辩护的设计决策

**Iterators, not arrays.** `ble_ad_next()` hands back a pointer into the
caller's buffer, one structure at a time. No copy, no maximum count, no
allocation — the caller decides what to keep. It returns `BLE_AD_ERR_TRUNCATED`
the moment a length byte points past the end, and every call after that
returns `BLE_AD_END`: no path reads another byte.
**用迭代器而不是数组。** 每次返回一个指向调用者缓冲区的指针，不拷贝、不设上限、
不分配。长度字节一旦越界就返回错误，之后每次调用都返回 END，不会再读任何字节。

**Resolve without an early exit.** `ble_rpa_resolve()` compares the 24-bit
hash with an OR-accumulator, not `memcmp`, and `ble_rpa_resolve_any()` runs
one AES per key in the list even after a match. A timing difference would tell a nearby
attacker which bonded device a phone just recognised.
**解析不提前退出。** 哈希比较用 OR 累加而不是 `memcmp`；`resolve_any` 在命中后仍然
把所有 IRK 试完。否则时间差会泄露手机刚认出了哪个已绑定设备。

**Reject what the spec forbids when *making*, accept what the air sends when
*parsing*.** `ble_rpa_make()` refuses a `prand` whose random part is all zeros
or all ones (Vol 6 Part B 1.3.2.2). The parser, on the other hand, classifies
the reserved `10` top bits as `BLE_ADDR_RESERVED` instead of failing: a sniffer
that crashes on a bad packet is useless to the person debugging it.
**生成时严格，解析时宽容。** 生成 RPA 时拒绝全 0/全 1 的随机部分；解析时遇到
保留位 `10` 只标记为 RESERVED，不报错——一个见到坏包就崩溃的抓包工具对调试者毫无用处。

**Check the whole PDU, then write.** `ble_att_parse()` first looks up the
opcode's shape and allowed length, refuses the PDU if it does not fit, and
only then touches `*out`. A caller that ignores the return value still never
sees half a decode, and the length rule for each opcode sits in one table in
the header, where it can be checked against the spec.
**先整体检查，再写结果。** 先按 opcode 查出格式和允许的长度，不合格直接拒绝，之后才写
`*out`。即使调用者忽略返回值，也不会拿到解析了一半的结果；每种 opcode 的长度规则集中在
头文件的一张表里，可以直接对照规范。

**Two implementations, one truth.** Project 04 has a Python mirror of
`ble_hci.c`. Both are tested against the same fixtures, and those fixtures were
decoded by Wireshark — so three independent parsers agree.
**两个实现，一个事实。** 项目 04 有 `ble_hci.c` 的 Python 镜像，两者用同一组
fixture 测试，fixture 由 Wireshark 解码——三个独立解析器互相印证。

---

## Gotchas / 踩过的坑

| Symptom | Cause | Fix |
|---|---|---|
| Address prints backwards vs. `bluetoothctl` | HCI carries addresses LSB-first | Store as on air, reverse only when printing |
| `ah()` fails the spec vector | Spec vectors are MSB-first, the address field is LSB-first | Headers state the byte order of every argument |
| Extended report header size | The fixed part is **24** bytes; the 2-byte periodic interval and the 7-byte direct address are easy to miscount | Offsets checked against tshark on 59 437 reports |
| Every report has the legacy bit set | BlueZ scans with extended commands, but nearly everything around still advertises with legacy PDUs; the controller reports them as `0x0D` with bit 4 set | Map legacy `0x02` events onto the extended bit layout, one format downstream |
| `tx_power` always 127 | 127 means "not available"; legacy PDUs never carry it | Treat 127 as absent, not as +127 dBm |
| `-Wconversion` errors on `uint8_t` arithmetic | Integer promotion: `a + b` is `int` | Explicit casts at every narrowing, compiled with `-Werror` |
| `uint8_t block[16] = {0}` needed libc on Cortex-M0+ | GCC emitted a call to `memset` for the initialiser on M0+ (not on M4), which `-ffreestanding -fno-builtin` does not prevent. The build only compiled, never linked, so nothing noticed | Zero it with `ble_wipe()`, whose volatile stores cannot become a call; `size-cortex-m.sh` now fails on any symbol the library does not define itself |
| `__aeabi_uidivmod` appeared on M0+ only | Cortex-M0+ has no divide instruction, so `g2 % 1000000u` calls libgcc's software division. Division by 16 in the CMAC is a shift and needs nothing | libgcc ships with the compiler, not libc, so `__aeabi_*` is allowed and listed with the object that needs it; the check still fails on `memset` (tested by putting the old `= {0}` back) |
| Wireshark shows a handle on READ_RSP and WRITE_RSP; the parser said none | Those PDUs carry no handle on the wire — Wireshark copies it from the request it matched. Likewise the "starting handle" it shows inside a READ_BY_TYPE_RSP is decoded from the attribute data | The diff compares a handle only for opcodes with a handle field, a range only for the four range requests |
| `__gnu_thumb1_case_uqi` on M0+ only, from `ble_att.o` | A dense `switch` becomes a jump table; Thumb-2 has `tbb` for it, Thumb-1 calls a libgcc helper | Allowed like `__aeabi_*`: libgcc, not libc |
| The ASan build had stopped linking | `bleg2` was added without being added to the list of targets built with the sanitizer flags, so it linked ASan-instrumented objects without the runtime | Every executable is in the list; the ASan build is run before every commit |
| Tests crashed or differed between builds after a failed parse | They read the output of a parse that had failed — garbage pointers, and a `bool` holding `0xAA`, which UBSan rightly calls undefined | Outputs zero-initialised; nothing is read unless the parse succeeded |
| Per-function stack looked like the answer | `.su` gives each function's own frame; callers stack them. Inlining also hides functions the source calls | `stack-depth.py` adds frames along the call graph GCC emitted |

**Not claimed:** the AES here uses a lookup-table S-box, so it is not
constant-time against a cache-timing attacker on the same core. On a
Cortex-M0+ without cache that does not arise; on anything bigger, use the
controller's AES (`HCI_LE_Encrypt`) or a hardware block.
**不声称：** 这里的 AES 用查表 S-box，对同核缓存计时攻击不是常数时间。
无 cache 的 M0+ 上不存在这个问题；更大的芯片应使用控制器的 `HCI_LE_Encrypt` 或硬件 AES。

---

## Interview talking points / 面试要点

- *"Why no `malloc`?"* — An advertising parser runs thousands of times a
  second for the life of the device. Fragmentation on a 32 KB heap is a field
  failure months later; a stack frame is released on return, every time.
- *"How do you know the parser is right?"* — Three ways that do not share
  assumptions: spec test vectors, 200 000 fuzz inputs under ASan, and a
  differential run against Wireshark over 59 437 real reports.
- *"How does a phone recognise its paired headphones if the address keeps
  changing?"* — The headphones' address is `prand ‖ ah(IRK, prand)`. The phone
  got the IRK at pairing; it recomputes `ah` over the first 3 bytes and
  compares with the last 3. Nobody without the IRK can do that.
- *"Would you write your own crypto in a product?"* — No: the chip's
  hardware AES and a qualified stack. Writing CMAC and `g2` against the
  RFC's and the spec's vectors is how I learned what a pairing computes and
  where byte orders flip, which is what debugging a failed pairing needs.
- *"Did your g2 ever meet a real device?"* — Yes: a phone and a laptop
  paired with numeric comparison and both showed 985572. Taking the public
  keys and nonces off an HCI capture of that pairing, this library computes
  985572. The script first recomputes the commitment the laptop sent, so a
  misread byte would have been caught before g2 ran.
- *"How do you parse a GATT request from an untrusted radio?"* — Three
  layers, each with a length that must agree with the one around it: ACL's
  Data Total Length with the packet, L2CAP's PDU Length with the ACL
  payload, and the ATT opcode's format with the PDU. A READ_REQ is exactly
  3 bytes; one byte short is refused before a byte is read. Checked on
  100 000 random packets under ASan, and against Wireshark on 1 410 real ones.
- *"How much stack does it need?"* — 496 bytes on an M0+, found by adding
  frames along the call graph GCC emitted, not by reading the source: the
  compiler inlines half of the AES into one frame. Plus whatever an interrupt
  stacks on top at the worst moment. It is also why the key schedule is not
  static: a static would hold the expanded key forever, the stack frame is wiped.
- *"How do you know it needs no libc?"* — Compiling proves nothing: GCC may
  call `memset` on its own. It did, on M0+ only. The build now checks every
  undefined symbol in the objects.

---

## Step by step / 分步推进

### Day 1–2 · Read the spec, then the code / 先读规范，再读代码
- [x] Core Vol 6 Part B 1.3 (address types) and Vol 3 Part H 2.2.2 (`ah`).
- [x] Reproduce the `ah` test vector by hand in Python before touching C.
- [ ] TODO(you): explain out loud why the all-zeros / all-ones check in
  `ble_rpa_make` masks off the top two bits first.

### Day 3–4 · Parsers and fixtures / 解析器与 fixture
- [x] `ble_ad.c` and `ble_hci.c` with every bound written as "bytes left < n"
  (never `p + n > end`: forming a pointer past the end is already undefined).
- [x] Extract fixtures from a real capture, scrub them, commit them.
- [x] Multi-report legacy events: the Core spec (Vol 4 Part E §5.2), Linux
  and `ble_hci.c` all lay the reports out one after another. Written up,
  with the one place they differ, in [`docs/multi-report.md`](docs/multi-report.md).

### Day 5 · Pairing cryptography / 配对密码学
- [x] AES-CMAC from RFC 4493: subkeys by doubling in GF(2^128), constant
  time in the secret bit; every official vector plus lengths 1–48 around
  each block boundary, checked against pyca/cryptography.
- [x] `g2` from Core Vol 3 Part H §2.2.9, Appendix D.5: 0x2f9ed5ba → 938554.
- [x] `g2` on a real pairing: an Android phone and this laptop both showed
  985572; `tools/pairing_from_capture.py` recomputed 985572 with this
  library from the keys and nonces in the capture (project 02).
- [ ] TODO(you): `f4` (the confirm value that stops an attacker choosing a
  nonce after seeing the other side's) — one more CMAC call, vector in
  Appendix D.2.

### Day 7 · Connection traffic: ACL, L2CAP, ATT / 连接数据
- [x] Core Vol 4 Part E §5.4.2 (ACL), Vol 3 Part A §3.1 (L2CAP), Vol 3
  Part F §3.3–3.4 (ATT PDUs and their formats).
- [x] `ble_acl_parse` and `ble_l2cap_parse`: Data Total Length must match
  the packet exactly; fragments reported, not reassembled.
- [x] `ble_att_parse`: one length rule per opcode, from the spec's tables.
- [x] 16 real packets as fixtures; every ACL packet of three phone sessions
  compared with tshark, 0 mismatches.
- [ ] TODO(you): reassemble a PDU that arrives in fragments (PB `0b01`).
  None of the captures has one: BlueZ and this phone fit every PDU in
  one ACL packet. A test with a hand-split packet would show it works.

### Day 6 · Prove it / 证明它
- [x] Fuzz under ASan + UBSan, exactly-sized buffers.
- [x] Differential test against tshark on the full 40-minute capture.
- [x] Cross-compile for Cortex-M0+ and M4 with no libc.
- [x] Worst-case stack along the call chain, not per function:
  `tools/stack-depth.py` — 496 bytes on M0+ (`g2`), 504 on M4.
- [x] Prove "no libc" at the symbol level. It was not true: `memset` on M0+.

- **Caught by cross-checking with tshark:** a fixture labelled as an
  advertisement that was really a scan response, and two "different" fixtures
  that were the same frame picked twice.

---

## What was actually run / 实际跑过的

Last run on 2026-10-05 (the scan capture is from 2026-09-27, the phone sessions from 2026-09-30), Ubuntu 24.04, kernel 7.0, gcc 13 on the host, arm-none-eabi-gcc 12.2 for Cortex-M, Intel AX201, BlueZ 5.72:

| Command | Result |
|---|---|
| `./build/ble_tests` | 620 checks, 0 failed; 200 000 advertising and 100 000 ACL fuzz inputs, all in bounds |
| `./build-asan/ble_tests` | same, no ASan/UBSan report |
| `python3 tools/diff_vs_tshark.py …40min.pcapng` | 59 437 reports × 6 fields, 0 mismatches |
| `python3 tools/diff_acl_vs_tshark.py` on the three phone captures in 02 | 865 + 307 + 238 ACL packets (9431 + 3349 + 2436 values), 0 mismatches; the last one includes the SMP pairing |
| `doxygen Doxyfile` | 0 warnings with warnings as errors; 114 HTML pages |
| `./tools/size-cortex-m.sh` | M0+: 3511 B text, 0 data, 0 bss · M4: 3581 B; no libc symbol on either, two libgcc helpers (`__aeabi_uidivmod`, `__gnu_thumb1_case_uqi`) on M0+ |
| `./tools/stack-depth.py` | Worst case 496 B on M0+ and 504 B on M4, both through `ble_sc_g2` |
| `ctest` in `build/` | 2 tests: the unit suite and `bleg2` on the Appendix D.5 vector |
| `python3 tools/pairing_from_capture.py …pairing-*.pcapng` | Cb matches f4 on air; 985572, the number both screens showed |

Not run: on real Cortex-M hardware. The size and stack numbers come from the
cross-compiler, not from a board.
没有跑过：真实 Cortex-M 硬件。尺寸和栈数据来自交叉编译器，不是开发板。
