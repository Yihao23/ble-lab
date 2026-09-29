# 04 · Advertising privacy audit
# 04 · 广播隐私审计

**Goal / 目标** — Take an HCI capture of everything in range and answer the
question from Lecture 10: *address rotation is supposed to make a device
untraceable — does it?* Rotation fails if anything else in the packet stays
the same across the change, or if the old address stops and a new one of the
same shape starts at the same signal strength a second later.
拿一份周围所有设备的 HCI 抓包，回答第 10 讲的问题：*地址轮换本应让设备无法被追踪——
真的做到了吗？* 如果包里其他东西在换地址前后保持不变，或者旧地址一停、同样"形状"的新地址
一秒后以相同信号强度出现，轮换就失败了。

Standard library only (the `cryptography` package is used by one test, if
installed, to cross-check AES). The parsers mirror the C library in project 01
and are tested against the same fixtures.
只用标准库。解析器是项目 01 C 库的镜像，用同一组 fixture 测试。

---

## Quick start / 快速开始

```bash
cd 04-adv-privacy
python3 -m unittest discover -s tests -t .                  # 41 tests

python3 -m bleprivacy ../03-hci-capture/captures/scan-*.pcapng
python3 -m bleprivacy CAPTURE --format md   -o report.md
python3 -m bleprivacy CAPTURE --format json -o report.json

# which RPAs in the capture belong to a device whose IRK you have
python3 -m bleprivacy CAPTURE --irk 0123456789abcdef0123456789abcdef
```

Addresses are replaced by keyed hashes (`nrpa#447079`) and names by their
length, so the report can be shared. `--salt S` makes labels stable across
runs; `--show-addresses` / `--show-names` reveal them — do not publish that.
地址被替换成带密钥的哈希，名字只显示长度，所以报告可以分享。
`--show-addresses` / `--show-names` 会显示真实值——那样的输出不要公开。

## What you should see / 你应该看到

On the 40-minute capture from project 03 ([full report](samples/report-40min.md)):

```
96513 packets, 60333 HCI events, 59437 advertising reports over 40.0 min
addresses: 18 nrpa, 2 public, 12 rpa, 3 static

P004  error    nrpa#447079     rotation defeated: new address appeared 0.2 s later carrying identical service_data bytes
P001  warning  public#97c4e4   public address, heard for 40.0 of 40.0 min: trackable wherever it goes, it never changes
P003  warning  public#97c4e4   advertised name (18 chars) contains the last two bytes of the device's own address
P007  warning  nrpa#8f471b     on air at the same time as nrpa#c6e5ab, carrying the same service_data bytes: two advertising sets, one device
S001  warning  public#97c4e4   advertised LE Limited Discoverable for 40.0 min; the spec caps it at 180 s (TGAP(lim_adv_timeout))

 40.0 min  nrpa#fb4c64 -=-> nrpa#58871a -=-> nrpa#80bb2c -=-> nrpa#805c4d -?-> nrpa#c6e5ab -=-> nrpa#981485 -?-> nrpa#bbf5be
```

---

## Rules / 规则

| Rule | Severity | Detects | 检测 |
|---|---|---|---|
| **P001** | warning | Public address heard ≥ 1 min — it never changes | public 地址，永不改变 |
| **P002** | info | Random static address unchanged ≥ 10 min | 随机静态地址长时间不变 |
| **P003** | warning | Advertised name contains the last two bytes of the device's own address | 名字里含自己地址的后两字节 |
| **P004** | error | A random address replaced by a new one carrying **identical** payload bytes | 换地址后 payload 字节完全相同 |
| **P005** | warning | Replaced by one of the same shape, seconds later, RSSI within 8 dB | 同形状、数秒内、RSSI 相近的接替 |
| **P006** | info | RPA lived longer than 20 min (Lecture 10: 7–20 min on phones) | RPA 超过 20 分钟未轮换 |
| **P007** | warning | Two addresses on air **at the same time** sharing payload bytes | 两个地址同时在线且共享 payload |
| **S001** | warning | LE Limited Discoverable held longer than TGAP(lim_adv_timeout) = 180 s | 有限可发现模式超过 180 秒 |
| **S002** | error | Random address with the reserved top bits `10` | 随机地址使用保留位 `10` |
| **S003** | warning | Malformed AD structures | AD 结构格式错误 |

**What counts as an identifier.** A name, or a manufacturer / service data
payload of at least 6 bytes with at least 4 distinct byte values — so a status
bitmap like `01 00 00 … 80 00` does not link two devices just because they run
the same app. Low-entropy payloads go into the device's *shape* instead,
together with its address kind, company IDs, UUIDs, payload lengths and PDU
types. A handoff needs the same shape; P004 additionally needs a shared
identifier.
**什么算标识符：** 名字，或至少 6 字节且至少 4 种不同字节值的 payload。
低熵 payload 归入设备的*形状*。接替需要形状相同；P004 还需要共享标识符。

---

## What the capture showed / 抓包显示了什么

**Rotation defeated by the payload.** Devices advertising Google service data
(`0xFEF3`, `0xFCF1`, both assigned to Google LLC) changed their non-resolvable
address every few minutes (bounded lifetimes up to 8.8 min, median 7.6), but
kept the same 20+ byte service-data payload for 10–20 minutes. Each address change carried the payload over unchanged,
0.1–3.1 s later: 9 of 13 NRPA handoffs link on identical bytes. The payload
rotates too — just on a different clock from the address, so an observer
bridges one with the other.
**payload 让轮换失效。** 广播 Google service data 的设备每几分钟换一次 NRPA（中位 7.6 分钟），
但 20 多字节的 payload 10–20 分钟才换一次。每次换地址，payload 原样带过去。
payload 也会轮换——只是和地址用了不同的时钟，观察者就可以用一个桥接另一个。

**Two advertising sets, one device.** The same devices ran a legacy set and an
extended set at the same time under **different** addresses; the 92-byte
extended payload begins with the full 27-byte legacy payload. Two addresses,
trivially one device (P007).
**两个广播集，一个设备。** 同时用两个不同地址发 legacy 和 extended 广播；92 字节的
extended payload 开头就是完整的 27 字节 legacy payload。

**One trace, forty minutes.** Chaining handoffs, identical bytes link 4
addresses over the first 20 minutes. Adding the weaker links (same shape, same
RSSI, under a second apart) joins 7 addresses into one trace covering the whole
capture.
**一条 40 分钟的轨迹。** 仅靠相同字节，4 个地址串成前 20 分钟；再加上较弱的时间/RSSI
关联，7 个地址串成覆盖整个抓包的一条轨迹。

**Two bulbs that are trackable three ways.** Two smart bulbs of the same model
advertise a public address (P001), a name ending in the last two bytes of that
address (P003), and the LE **Limited** Discoverable flag for the full 40
minutes, where the spec allows 180 s (S001). Their company ID `0x8802` is not
in the Bluetooth SIG's assigned numbers — Wireshark decodes it as "Unknown".
**两个可以三种方式追踪的灯泡。** public 地址、名字里带地址后两字节、Limited
Discoverable 持续 40 分钟（规范上限 180 秒）。company ID `0x8802` 未在 SIG 注册。

**Address lifetimes**, where both birth and death were observed:

| kind | n | min | median | max |
|---|---|---|---|---|
| NRPA | 12 | 1.4 | 7.6 | 8.8 min |
| RPA | 5 | 2.3 | 17.4 | 27.4 min |
| static | 2 | 12.4 | 14.9 | 14.9 min |

The long-lived RPAs sit in the 7–20 minute range Lecture 10 reports for
phones, with one at 27.4 min (P006).

The static addresses are the odd ones. Core Vol 6 Part B 1.3.2.1 says a
static address, once initialised, **shall not change until the device is
power cycled** — yet three Apple static addresses followed one another, each
lasting 11–15 minutes, all with a 4-byte manufacturer payload of type `0x12`.
That type matches what public research on Apple's offline-finding network
describes (Heinrich et al., *Who Can Find My Devices?*, PETS 2021): the address
is derived from a rotating key. Whether it is one device re-keying cannot be
proven from this capture — the 4-byte payload changes with the address, so
nothing links them.
静态地址按规范上电后不得改变，但这里三个 Apple static 地址前后相接，各持续 11–15 分钟，
payload 类型 `0x12`，与公开研究描述的 Apple 离线查找广播一致。能否证明是同一设备？
这份抓包不能——4 字节 payload 随地址一起变。

**A false positive, found on real data and now a test.** The first version
linked three Apple RPAs because they shared a 17-byte payload. It was
`01 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00` — a bitmap every device
in the same state sends. `test_low_entropy_payload_is_not_an_identifier` fails
without the distinct-byte-values rule.
**真实数据发现的误报，现在是一个测试。** 第一版因为三个 Apple RPA 共享一个 17 字节
payload 把它们连在一起，而那是几乎全零的 bitmap。

---

## Layout / 目录

| Path | What |
|---|---|
| `bleprivacy/pcapng.py` | pcapng reader: both byte orders, `if_tsresol`, stops cleanly at a cut block and says so |
| `bleprivacy/monitor.py` | Linux monitor header (link type 254) |
| `bleprivacy/hci.py` | LE advertising reports, legacy and extended — mirror of `01/src/ble_hci.c` |
| `bleprivacy/ad.py` | AD structures and the fields that identify a device |
| `bleprivacy/addr.py` | Address kinds; `Pseudonymizer` (HMAC-SHA256, random key per run by default) |
| `bleprivacy/rpa.py` | AES-128 and `ah()` in pure Python, for `--irk` |
| `bleprivacy/analyze.py` | Tracks, handoffs, concurrent links, chains, rules, lifetimes |
| `bleprivacy/report.py` | text / Markdown / JSON, pseudonymised |
| `samples/` | The report from the 40-minute capture, Markdown and JSON |
| `tests/` | 41 tests: C fixtures, spec + FIPS vectors, pcapng edge cases, every rule, no-leak checks, and a count check against tshark when a capture is present |

---

## Gotchas / 踩过的坑

| Symptom | Cause | Fix |
|---|---|---|
| Three Apple RPAs linked as one device | A near-all-zero bitmap counted as an identifier | Distinct-byte-value threshold; regression test |
| 0.0-minute "rotations" in the lifetime table | 13-report bursts of an RPA are not a rotation period | Lifetimes below 60 s are left out |
| Handoff window vs. slow advertisers | Several devices here advertise every 6–9 s; one lost packet and a fixed 10 s window misses the handoff | Window is max(10 s, 2.5 × advertising interval); `test_gap_scales_with_advertising_interval` |
| The same P007 printed twice for one address | The finding did not say which other address | Findings carry the related address |

---

## Interview talking points / 面试要点

- *"You rotate the address. Are you private now?"* — Only if nothing else in
  the packet is stable across the rotation, and the rotation is not
  observable as a handoff. This capture has a device whose address changes
  every 8 minutes and whose payload changes every 20: the address rotation
  bought nothing.
- *"How would you make a device pass this audit?"* — Rotate every identifier
  in the payload **in the same instant** as the address (on Zephyr, regenerate
  the payload in the RPA-rotation callback), advertise the name only in the
  scan response or not at all, use one advertising set, and do not start the
  new address at the exact moment the old one stops if the application allows
  a random delay.
- *"Why pseudonymise the report?"* — A capture of the air is a list of the
  neighbours' devices. The analysis only needs to know that two sightings are
  the same address, not which address — so a keyed hash is enough.
- *"How is this related to CrossLink (Lecture 10)?"* — CrossLink links a
  device's identities across protocols by time and space. P005 is the same
  reasoning inside one protocol: a disappearance and an appearance, the same
  shape, the same RSSI, milliseconds apart.

---

## Step by step / 分步推进

### Day 10 · Parse / 解析
- [x] pcapng + monitor + HCI + AD in pure Python; tested against the C fixtures.
- [x] `ah()` in Python against the spec vector and FIPS-197.

### Day 11 · Analyse / 分析
- [x] Tracks, handoffs, rules; run on the 40-minute capture.
- [x] Fix what the real capture broke (the Gotchas table).
- [ ] TODO(you): turn on `Privacy = device` on a device of your own, pair it
  with your phone, get both IRKs (`/var/lib/bluetooth/<adapter>/<device>/info`
  on Linux), capture, and run with `--irk`. Every RPA of that device should
  resolve; none of anyone else's should.
- [ ] TODO(you): with an AirTag or iPhone of your own, find out whether the
  static-address changes above are one device re-keying.
- [ ] TODO(you): P005 has no ground truth. Put a device you own in the room,
  record when you toggle its Bluetooth, and measure how often P005 is right.

### Day 12 · Report / 报告
- [x] Pseudonymised text / Markdown / JSON output; no-leak tests.
- [ ] TODO(you): a rule for the payload clock — for each chain, report how
  often the payload changed compared with the address.

---

## What was actually run / 实际跑过的

On 2026-09-27, Python 3.12, `cryptography` 41.0.7, tshark 4.2:

| Command | Result |
|---|---|
| `python3 -m unittest discover -s tests -t .` | 41 tests, OK (Wireshark and `cryptography` cross-checks included, not skipped) |
| `python3 -m bleprivacy …40min.pcapng` | Report in `samples/`, 0.6 s |
| `grep -E '([0-9A-F]{2}:){5}'` on `samples/` | 0 matches — no address in the published report |
