# 03 · Reading HCI
# 03 · 读懂 HCI

**Goal / 目标** — Capture everything between bluetoothd and the Bluetooth
controller for forty minutes and explain every layer of it: the Linux monitor
header, the HCI commands the host sends, the reports the controller returns,
and what the kernel does with them before bluetoothd ever sees one.
抓 bluetoothd 和蓝牙控制器之间 40 分钟的全部流量，把每一层讲清楚：Linux monitor 头、
主机发的 HCI 命令、控制器返回的报告、以及内核在 bluetoothd 看到之前对它们做了什么。

**Why it matters / 为什么重要** — HCI is the boundary between the part of
Bluetooth you write (host) and the part you buy (controller). When something
goes wrong in the field, the HCI log is the evidence both sides accept.
HCI 是你写的部分（host）和你买的部分（controller）之间的边界。现场出问题时，
HCI 日志是双方都认的证据。

The output of this project is [`report/REPORT-01.md`](report/REPORT-01.md).

---

## Quick start / 快速开始

```bash
cd 03-hci-capture
sudo usermod -aG wireshark $USER        # once, then log in again: dumpcap without sudo
./capture.sh 5                          # 5 minutes; writes captures/scan-*.pcapng
python3 layers.py captures/scan-*.pcapng
wireshark captures/scan-*.pcapng        # filter: bthci_evt.le_meta_subevent == 0x0d
```

## What you should see / 你应该看到

```
2. HCI commands, host -> controller
   0x2042 LE Set Extended Scan Enable                448
   0x2005 LE Set Random Address                      224
   0x2041 LE Set Extended Scan Parameters            224
   scan parameters x224: own address type 1, filter policy 0
      1M: active, interval 11.25 ms, window 11.25 ms
      Coded: active, interval 33.75 ms, window 33.75 ms
   scanner address set 224 times, 224 distinct, kinds {'nrpa': 224}; every 10.752 s
3. HCI events, controller -> host
   LE Meta, subevent 0x0D        59437
   advertising reports 59437: 34466 advertisements, 24971 scan responses
4. Management events, kernel -> bluetoothd
   0x0012 Device Found          34380
```

(Numbers from the 40-minute capture; a 5-minute one is proportionally smaller.)

---

## Layout / 目录

| Path | What |
|---|---|
| `capture.sh` | `dumpcap` on `bluetooth-monitor` + hold an LE discovery open, then run `layers.py` |
| `discovery_hold.py` | `SetDiscoveryFilter(Transport=le, DuplicateData=true)` + `StartDiscovery` over D-Bus, for N seconds |
| `layers.py` | Monitor opcodes → HCI commands (scan parameters decoded) → HCI events → mgmt events. Counts and classifies addresses, never prints one |
| `report/REPORT-01.md` | The reading, six sections |
| `captures/` | Git-ignored. A capture of the air is a list of your neighbours' devices |

---

## Findings / 发现

1. **The scanner rotates its own address every 10.75 s** — 224 NRPAs in
   40 minutes, all distinct. Active scanning broadcasts the scanner's address
   in every `SCAN_REQ`.
2. **The radio listens 100 % of the time**, alternating LE 1M and LE Coded.
3. **bluetoothd never sees a scan response alone**: the kernel merges it into
   the advertisement's Device Found event (34 380 ≈ 34 466 advertisements, not
   59 437 reports).
4. **HCI hides the advertising channel.** Hopping across 37/38/39 happens
   below this interface.
5. **RSSI of a device that never moved spans 8 dB** (5th–95th percentile) —
   a factor of 2.5 in any distance estimate.

---

## Gotchas / 踩过的坑

| Symptom | Cause | Fix |
|---|---|---|
| `tshark -c 1 -Y …` returns nothing | `-c` counts packets *read*, not packets that matched | Find frame numbers first, then `-Y frame.number==N` |
| `bthci_evt.le_meta_subevent in {0x02 0x0d}` rejected by tshark | Not valid set syntax for this field in this version | `== 0x02 \|\| == 0x0d` |
| Monitor header is big-endian | libpcap writes it; everything else in Bluetooth is little-endian | `struct.unpack(">HH")` |
| Wireshark says "Encapsulation type 159" | That is Wireshark's internal number; the pcap link type is 254 | Check `LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254` |
| Reading a capture while dumpcap is still writing it | The last block is half written | The reader in project 04 stops cleanly at a cut block and reports `truncated` |

---

## Interview talking points / 面试要点

- *"A customer says your device doesn't show up on their phone. What do you
  ask for?"* — An HCI log from the phone (Android: Bluetooth HCI snoop log in
  developer options). It shows whether the phone's controller ever reported
  the advertisement; if yes, it is the app or the OS filter, not the radio.
- *"What is the difference between HCI and mgmt?"* — HCI is the standard
  interface to the controller, defined in the Core Spec. mgmt is Linux's own
  interface between the kernel and bluetoothd. The kernel sits between them
  and changes things — like merging scan responses.
- *"Why would a scanner change its address?"* — Because active scanning is
  not passive: `SCAN_REQ` carries the scanner's address.

---

## Step by step / 分步推进

### Day 8 · Capture / 抓包
- [x] dumpcap permissions, `capture.sh`, one 40-minute capture, 0 drops.
- [x] Open it in Wireshark; find one command, one report, one mgmt event.

### Day 9 · Read / 阅读
- [x] `layers.py`: every layer counted.
- [x] Decode one extended report by hand (report §3); check with Wireshark.
- [x] Write `REPORT-01.md`.
- [ ] TODO(you): the two TODOs in the report — the kernel's 10 240 ms
  discovery timeout, and the 86 advertisements without a Device Found.
- [ ] TODO(you): take the same capture with `Transport=le` **and**
  `DuplicateData=false`. How many reports does the controller send now, and
  does the kernel still restart the scan every 10.75 s?

---

## What was actually run / 实际跑过的

On 2026-09-27, 10:31–11:11, Intel AX201, BlueZ 5.72:

| Command | Result |
|---|---|
| `dumpcap -i bluetooth-monitor -a duration:2410` + `discovery_hold.py --seconds 2400` | 96 513 packets, 0 dropped |
| `python3 layers.py captures/scan-20260927-1031-40min.pcapng` | The numbers in this README and the report |
| `tshark` on the same file | Cross-check of every decoded field (project 01) |
