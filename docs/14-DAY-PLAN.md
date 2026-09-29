# 14-Day Plan / 两周计划

One rule: **every day ends with something that ran.** A day of reading only
produces nothing you can show.
一条规则：**每天结束时都要有真正跑过的东西。** 只有阅读的一天等于没有产出。

`[x]` done and recorded in a README · `[ ]` open — most need a phone, a dev
board, or a second device.

---

## Week 1 — Build / 第一周 · 造

### Day 1 · Concepts / 概念
- [x] Read [`GLOSSARY.md`](GLOSSARY.md). Close it; draw the stack from the
  radio to GATT from memory. Mark where HCI is.
- [x] Lecture 10 again: identifiers, rotation, CrossLink. Write down what
  would make a rotation fail.

### Day 2 · `ah()` / 地址哈希
- [x] Core Vol 3 Part H 2.2.2 and Appendix D; reproduce the test vector by
  hand in Python.
- [x] `ble_aes.c` + `ble_rpa.c`, checked against the spec vector and FIPS-197.

### Day 3 · Parsers / 解析器
- [x] `ble_ad.c`, `ble_hci.c`. Every bound as "bytes left < n".
- [x] First capture; extract and scrub fixtures; tshark as the oracle.

### Day 4 · Prove the C / 证明 C 代码
- [x] Fuzz under ASan + UBSan with exactly sized buffers.
- [x] Differential test against tshark over a whole capture.
- [x] Cross-compile for Cortex-M0+ / M4 without libc; record size and stack.
- [ ] Sum the stack along the deepest call chain.

### Day 5 · GATT model / GATT 模型
- [x] Battery Level, Temperature formats; validation; ATT error choice.
- [x] `NotifyPolicy`; 24 tests, red first for the 21.005 °C rounding.

### Day 6 · GATT on air / GATT 上线
- [x] BlueZ D-Bus objects; register; advertise.
- [x] Capture HCI while registering; fix the missing Flags AD.
- [ ] Phone: connect, read, subscribe, screenshot the notifications.
- [ ] Phone: bad writes — which ATT codes does bluetoothd really send?
- [ ] Pair with passkey; authenticated write to Identify.

### Day 7 · Buffer / 缓冲
- [ ] `Privacy = device` in bluetoothd; confirm the own address type changes.
- [ ] Port `model.py` to a Zephyr sample on an nRF52 board, if one is at hand.

---

## Week 2 — Read and analyse / 第二周 · 读与分析

### Day 8 · Capture / 抓包
- [x] `capture.sh`; 40 minutes, 0 drops.

### Day 9 · Read HCI / 读 HCI
- [x] `layers.py`; decode one report by hand; `REPORT-01.md`.
- [ ] The kernel's 10 240 ms LE discovery timeout, in the source.
- [ ] The 86 advertisements with no Device Found.
- [ ] Same capture with `DuplicateData=false`: what changes?

### Day 10 · Python parsers / Python 解析器
- [x] pcapng, monitor, HCI, AD, `ah()` in pure Python, tested against the C
  fixtures and tshark.

### Day 11 · Privacy analysis / 隐私分析
- [x] Tracks, handoffs, concurrent links, rules; run on the capture.
- [x] Fix the false positive the real data exposed; regression test.
- [ ] Own device + its IRK: every RPA resolves with `--irk`.
- [ ] Ground truth for P005 with a device you control.

### Day 12 · Report / 报告
- [x] Pseudonymised text / Markdown / JSON; no-leak tests; samples.
- [ ] Payload-clock rule: how often the payload changes vs. the address.

### Day 13 · Write it down / 写下来
- [x] Every project README: what it proves, what was run, what is open.
- [x] Top-level README, both languages.

### Day 14 · Explain it / 讲出来
- [ ] Each project's interview talking points, out loud, without notes.
- [ ] Explain every line of `ble_hci.c` and `analyze.py` to someone else.
