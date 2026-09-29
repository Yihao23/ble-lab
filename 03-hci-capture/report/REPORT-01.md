# REPORT-01 · Forty minutes between bluetoothd and the controller
# REPORT-01 · bluetoothd 与控制器之间的四十分钟

One capture, read one layer at a time. Every number here is printed by
`python3 layers.py` or `python -m bleprivacy` on the same file; nothing is
estimated. The capture itself is not in the repository: it holds the addresses
of every device in range.
一份抓包，逐层读。这里的每个数字都由 `layers.py` 或 `bleprivacy` 在同一个文件上打印出来，
没有估算。抓包文件本身不入库：它包含周围所有设备的地址。

| | |
|---|---|
| Date | 2026-09-27, 10:31–11:11, indoors |
| Hardware | Intel AX201 (USB `8087:0026`), laptop not moving |
| Software | Linux 7.0, BlueZ 5.72, dumpcap on `bluetooth-monitor` |
| How | `./capture.sh 40` — `org.bluez.Adapter1.StartDiscovery` with `Transport=le`, `DuplicateData=true`, held for 2400 s |
| Result | 96 513 packets, 0 dropped, file not truncated |

---

## 1. The monitor layer: what the kernel copies out
## 1. Monitor 层：内核复制出来的是什么

`bluetooth-monitor` is not a radio. It is the Linux kernel copying every
packet that crosses the HCI boundary — and every management message between
the kernel and bluetoothd — into one stream, each with a 4-byte header:
adapter index and an opcode, **big-endian** (it is written by libpcap, not by
the Bluetooth stack, which is little-endian everywhere else).
`bluetooth-monitor` 不是射频接口，而是内核把跨越 HCI 边界的每个包、以及内核与 bluetoothd
之间的每条管理消息复制到同一个流里，每个包带 4 字节头：适配器号 + opcode，**大端**。

```
COMMAND           896     host → controller           HCI
EVENT          60 333     controller → host           HCI
CTRL_COMMAND      225     bluetoothd → kernel         mgmt
CTRL_EVENT     35 053     kernel → bluetoothd         mgmt
(6 more: NEW_INDEX, OPEN_INDEX, INDEX_INFO, SYSTEM_NOTE ×2, CTRL_OPEN)
```

So one file shows **two** interfaces: HCI below the kernel, mgmt above it.
Section 5 is about the difference between them.
所以一个文件里有**两个**接口：内核之下的 HCI，内核之上的 mgmt。第 5 节讲它们的差别。

---

## 2. What the host asks for
## 2. 主机请求了什么

Only three HCI commands in forty minutes, repeated:

```
0x2042 LE Set Extended Scan Enable        448   (224 on, 224 off)
0x2005 LE Set Random Address              224
0x2041 LE Set Extended Scan Parameters    224
```

**Scan parameters**, identical all 224 times:

```
own address type 1 (random), filter policy 0 (accept all)
   1M:    active, interval 11.25 ms, window 11.25 ms
   Coded: active, interval 33.75 ms, window 33.75 ms
```

Window equals interval on both PHYs: the radio listens **100 % of the time**,
alternating between LE 1M and LE Coded (long range). That is a laptop on mains
power. A coin-cell sensor that scanned like this would be flat in days.
两个 PHY 上 window 都等于 interval：射频 **100% 时间在听**，在 1M 和 Coded 之间交替。
这是插着电的笔记本。纽扣电池设备这么扫，几天就没电了。

**Scan enable**: `filter_duplicates = 0`, `duration = 0`, `period = 0`. The
controller is asked to report every packet — because `DuplicateData=true` was
set; the analysis in project 04 needs every sighting, not one per device.

**The scanner changes its own address every 10.75 s.** The pattern, 224 times:

```
Scan Enable (off) → Set Random Address → Set Scan Parameters → Scan Enable (on)
```

224 addresses set, **224 distinct**, all non-resolvable private (top bits
`00`), median period 10.752 s (min 10.552, max 10.834). Active scanning sends
`SCAN_REQ`, and a `SCAN_REQ` carries the scanner's address — so without this,
every device in range could log this laptop walking past. The period is close
to the kernel's LE discovery timeout of 10 240 ms plus the restart overhead.
扫描器每 10.75 秒换一次自己的地址，224 次、224 个不同的 NRPA。主动扫描要发 `SCAN_REQ`，
里面带着扫描者地址——不换的话，周围每台设备都能记下这台笔记本经过。

> TODO(you): confirm the 10 240 ms figure in the kernel source
> (`DISCOV_LE_TIMEOUT` in `include/net/bluetooth/hci_core.h`) and find where
> the new random address is chosen.

---

## 3. What the controller answers
## 3. 控制器回了什么

```
LE Meta, subevent 0x0D (Extended Advertising Report)   59 437
event 0x0E (Command Complete)                              896
advertising reports 59 437: 34 466 advertisements, 24 971 scan responses
```

- **Every** report is the extended format `0x0D`, never legacy `0x02` — the
  host used extended scan commands, so the controller answers in kind.
- **Every** report except those from extended advertising sets carries the
  *legacy* bit (`0x0010`): the devices around still advertise with 4.x PDUs;
  only the format of the report is new.
- `tx_power` is 127 ("not available") in every report: legacy PDUs have no
  field for it.
- One Command Complete per command, 896 = 896. Nothing failed.

### One report, byte by byte / 手工解一个报告

A real event from this capture, address and payload scrubbed (it is fixture
`REAL_EVT_2` in project 01):

```
3e 36 0d 01                     LE Meta, 54 parameter bytes, subevent 0x0D, 1 report
13 00                           event type 0x0013: connectable | scannable | legacy → ADV_IND
01                              address type: random
11 22 33 44 55 2a               address, LSB first → 2A:55:44:33:22:11, top bits 00 → NRPA
01 00                           primary PHY 1M, no secondary PHY
ff                              SID: none (legacy)
7f                              TX power 127: not available
d8                              RSSI 0xd8 = −40 dBm
00 00                           periodic advertising interval: none
00 00 00 00 00 00 00            direct address type + direct address: unused
1c                              data length 28
02 01 02                        AD: Flags 0x02, LE General Discoverable
18 16 f1 fc 00 … 00             AD: Service Data, UUID 0xFCF1 (Google LLC), 22 bytes zeroed
```

4 + 24 + 28 = 56 = `0x36` + 2. The 24-byte fixed part is the one to memorise.

### What HCI does not say / HCI 没有告诉你的

**Which channel.** BLE advertises on three of its 40 channels (37, 38, 39),
and the controller knows which one each packet came in on — but the HCI
advertising report has no field for it. Channel hopping (Lecture 7) happens
entirely below this interface. Seeing it takes a sniffer below the link layer
(nRF Sniffer, Ubertooth); a host stack never learns it.
**信道。** 控制器知道每个包来自 37/38/39 哪个信道，但 HCI 报告没有这个字段。
跳频（第 7 讲）完全发生在这个接口之下。要看到它需要链路层以下的 sniffer。

---

## 4. RSSI from two devices that did not move
## 4. 两个没动过的设备的 RSSI

Two smart bulbs of the same model, fixed in place, public addresses, heard for
the whole 40 minutes:

| | reports | median | 5th–95th percentile | min–max | std dev | per-minute median |
|---|---|---|---|---|---|---|
| bulb A | 18 727 | −60 dBm | −65 … −57 | −70 … −54 | 2.7 dB | −64 … −59 |
| bulb B | 9 250 | −81 dBm | −85 … −77 | −91 … −73 | 2.4 dB | −85 … −78 |

Nothing moved, yet a single packet's RSSI spans 8 dB between the 5th and 95th
percentile. Under free-space path loss (exponent 2), 8 dB is a factor of
10^(8/20) ≈ **2.5 in distance**. A per-minute median is steadier, but still
wanders 5–7 dB.
什么都没动，单包 RSSI 的 5%–95% 区间仍有 8 dB。按自由空间路径损耗，8 dB 就是
**距离 2.5 倍**的误差。

That is the benign case. Lectures 2–4 are about the malicious one: RSSI is
set by whoever transmits, so an attacker simply transmits louder. A
"is the key within 2 m?" decision built on RSSI fails honestly here, and
fails on purpose under a relay attack — which is why the course ends at
distance bounding and UWB.
这还是良性情况。第 2–4 讲讲的是恶意情况：RSSI 由发射方决定，攻击者直接加大功率即可。

---

## 5. HCI below the kernel, mgmt above it
## 5. 内核之下的 HCI，内核之上的 mgmt

```
HCI advertising reports             59 437   (34 466 ADV + 24 971 SCAN_RSP)
mgmt Device Found (0x0012)          34 380
mgmt Discovering (0x0013)              448   (on/off, 224 each)
mgmt Command Complete (0x0001)         225
```

bluetoothd never sees a scan response on its own. The kernel holds each
scannable advertisement until its scan response arrives and delivers the two
as **one** Device Found event, with the AD structures of both — which is why
Device Found (34 380) tracks the advertisements (34 466), not the total
(59 437). Anything built on the D-Bus API sees the merged view; a tool that
needs the raw packets has to read HCI.
bluetoothd 从来不单独看到 scan response：内核把可扫描广播和它的 scan response 合并成
**一个** Device Found 事件。所以 Device Found 的数量跟随广播数，而不是总数。
基于 D-Bus API 的程序看到的是合并后的视图；需要原始包就得读 HCI。

> TODO(you): 86 advertisements have no Device Found. Find out why — a
> scan response that never came before the scan restarted? Check the reports
> just before each Scan Enable (off).

---

## 6. What this capture feeds
## 6. 这份抓包喂给了谁

- **Project 01** — seven scrubbed events became C fixtures, and the whole file
  is the differential test: 59 437 reports, 6 fields each, against Wireshark,
  0 mismatches.
- **Project 04** — the privacy analysis: 35 addresses, 11 rotations defeated
  by identical payload bytes, one device followed across 7 addresses for the
  full 40 minutes.
