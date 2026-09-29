# 02 · GATT peripheral on BlueZ
# 02 · 基于 BlueZ 的 GATT 外设

**Goal / 目标** — A real BLE sensor peripheral: standard Battery and
Environmental Sensing services with notifications, plus a custom control
service with validated writes and an encrypted, authenticated write. The laptop
is the "device"; its battery and a thermal zone are the sensors.
一个真实的 BLE 传感器外设：标准 Battery、Environmental Sensing 服务（带 notify），
外加一个自定义控制服务（写入校验 + 需要加密认证的写）。笔记本就是"设备"，
它的电池和温度区就是传感器。

**The split to defend / 要能辩护的划分** — `model.py` is everything a GATT
server *decides*: value encoding, write validation, which ATT error to return,
when a notification is worth sending. It has no radio and no D-Bus, and it is
what you would port into a Zephyr or nRF SDK callback unchanged in structure.
`gatt_bluez.py` only moves bytes between `model.py` and bluetoothd.
`model.py` 是 GATT 服务器所有的*决策*：编码、写校验、返回哪个 ATT 错误码、何时值得发
notification。它不碰射频也不碰 D-Bus，移植到 Zephyr / nRF SDK 的回调里结构不用变。
`gatt_bluez.py` 只负责在 `model.py` 和 bluetoothd 之间搬字节。

---

## The GATT table / GATT 表

| Service | Characteristic | Properties | Format / rule |
|---|---|---|---|
| Battery `0x180F` | Battery Level `0x2A19` | read, notify | uint8, 0–100 % |
| Environmental Sensing `0x181A` | Temperature `0x2A6E` | read, notify | sint16, 0.01 °C, `0x8000` = unknown |
| Control `b1e1ab01-…` | Sample Interval `b1e1ab02-…` | read, write | uint16 LE ms, 100–10000 |
| | Identify `b1e1ab03-…` | **encrypt-authenticated-write** | uint8 seconds, 1–30 |

| Bad write | ATT error returned | Why this code |
|---|---|---|
| Interval, wrong length | `0x0D` Invalid Attribute Value Length | The length is wrong, not the value |
| Interval, 50 ms | `0xFF` Out of Range | Core Spec Supplement's common profile error for exactly this |
| Identify, 0 or 31 s | `0x13` Value Not Allowed | Right length, value the device refuses |
| Identify, unencrypted | expected `0x0F`/`0x05`, from bluetoothd | The stack enforces it before `model.py` sees anything (not yet seen on air — TODO below) |

Notifications go through `NotifyPolicy`: at most one per 0.5 s per
characteristic, only when the value changed, plus a 30 s heartbeat. A
temperature that flickers 0.01 °C must not drain a coin cell.
Notification 经过 `NotifyPolicy`：每个特征最多每 0.5 秒一次、值变了才发、外加 30 秒心跳。
温度抖 0.01 °C 不应该把纽扣电池耗干。

---

## Quick start / 快速开始

```bash
cd 02-gatt-peripheral
sudo apt install python3-dbus python3-gi        # already on Ubuntu desktop
python3 -m unittest discover -s tests -t .      # 24 tests, no radio needed

python3 -m peripheral                           # advertise until Ctrl-C
python3 -m peripheral --seconds 60 --thermal-zone x86_pkg_temp
```

Then on a phone: **nRF Connect** → Scan → `BLE-Lab` → Connect.

## What you should see / 你应该看到

```
11:17:15 peripheral battery 94%, temperature 49000 mdegC, adapter /org/bluez/hci0
11:17:15 peripheral GATT application registered with bluetoothd
11:17:15 peripheral advertisement registered with bluetoothd
```

And in an HCI capture taken at the same time (`dumpcap -i bluetooth-monitor`),
what bluetoothd turned the D-Bus objects into:
同时抓的 HCI 包里，能看到 bluetoothd 把 D-Bus 对象翻译成了什么：

```
LE Set Extended Advertising Parameters  legacy PDUs, connectable + scannable,
                                        interval 1280 ms, own address: public
LE Set Extended Advertising Data        Flags 0x06 + UUID16 180F 181A   (9 bytes)
LE Set Extended Scan Response Data      Complete Local Name "BLE-Lab"   (9 bytes)
LE Set Extended Advertising Enable      → Selected TX Power 7 dBm
```

---

## What the HCI capture showed / HCI 抓包揭示了什么

The first version was written from the D-Bus documentation. The capture
disagreed with it three times:
第一版是照着 D-Bus 文档写的，抓包三次推翻了它：

1. **No Flags AD at all.** bluetoothd adds Flags only when the advertisement
   sets `Discoverable = true`. Without them the advertisement is not
   discoverable in the GAP sense. Fixed; the second capture shows `0x06`
   (LE General Discoverable, BR/EDR not supported).
   **根本没有 Flags。** 只有 `Discoverable=true` 时 bluetoothd 才加 Flags，没有 Flags
   的广播在 GAP 意义上不可发现。已修复，第二次抓包显示 `0x06`。
2. **The name is not in the advertisement.** bluetoothd puts `LocalName` in the
   scan response. A passive scanner never sees it; an active one pays a
   SCAN_REQ/SCAN_RSP round trip for it.
   **名字不在广播里。** 在 scan response 里，被动扫描器看不到。
3. **It advertises with the adapter's public address.** Anyone can follow this
   laptop by that address — finding P001 of project 04, about my own device.
   `Privacy = device` in `/etc/bluetooth/main.conf` switches to an RPA.
   **用的是网卡的 public 地址。** 任何人都能靠它追踪这台笔记本——正是项目 04 的
   P001，只不过对象是我自己。`main.conf` 里 `Privacy = device` 可切换到 RPA。

---

## Layout / 目录

| Path | What |
|---|---|
| `peripheral/model.py` | UUIDs, encoders, write validation, ATT error choice, `NotifyPolicy`, `Device` |
| `peripheral/gatt_bluez.py` | `org.bluez.GattService1` / `GattCharacteristic1` objects over `model.Device`; maps `AttError` to the D-Bus error names bluetoothd understands |
| `peripheral/advertisement.py` | `org.bluez.LEAdvertisement1`; the docstring records what bluetoothd actually sends |
| `peripheral/sensors.py` | `/sys/class/power_supply/BAT*/capacity`, `/sys/class/thermal/thermal_zone*/temp` |
| `peripheral/__main__.py` | Register, tick at the current sample interval, unregister on exit |
| `tests/test_model.py` | 24 tests on encoding, validation, error codes and notification policy |
| `captures/` | Two HCI captures, before and after the Flags fix. Git-ignored: they contain the adapter address |

---

## Gotchas / 踩过的坑

| Symptom | Cause | Fix |
|---|---|---|
| 21.005 °C encodes as 2100, not 2101 | 21.005 is 21.00499999… in binary floating point | Sensors report integer millidegrees; `encode_temperature_millideg` rounds half away from zero in integers. A test pins the float behaviour with `Decimal` |
| A custom error like `0x80` never reaches the phone | bluetoothd only maps a few D-Bus error names to ATT codes (`InvalidValueLength`, `NotPermitted`, `NotAuthorized`, `Failed`, …) | Application errors collapse to what bluetoothd knows — see TODO below |
| Advertisement has no Flags AD | bluetoothd adds Flags only for `Discoverable = true` | Set it; verified in the HCI capture |

---

## Interview talking points / 面试要点

- *"Walk me through a write from the phone."* — ATT Write Request → the
  controller → bluetoothd checks the permissions (encryption, authentication)
  → D-Bus `WriteValue` → `model.parse_*` → either the new value, or an
  `AttError` that goes back as an ATT Error Response with that code.
- *"Why is Identify `encrypt-authenticated-write`?"* — It makes the device do
  something physical. An unauthenticated attacker in range should not be able
  to blink it, so the stack refuses the write until the link is encrypted with
  an MITM-protected key.
- *"Why 0x0D and not 0x13 for a wrong length?"* — They mean different things
  to the client: 0x0D says "you sent the wrong shape", 0x13 says "the shape is
  fine, I refuse this value". A client developer debugging against your
  device reads those codes.
- *"How would this look on an nRF52?"* — `model.py` becomes the write/read
  handlers; `NotifyPolicy` becomes a timer; the GATT table becomes a static
  `BT_GATT_SERVICE_DEFINE` in Zephyr. The decisions do not change.

---

## Step by step / 分步推进

### Day 6 · The model / 模型
- [x] Encoders for Battery Level and Temperature from the GATT Specification
  Supplement; the `0x8000` unknown value.
- [x] Validation and error-code choice, tested.
- [x] `NotifyPolicy`: rate limit, change filter, heartbeat.

### Day 7 · On air / 上线
- [x] BlueZ D-Bus objects, register, advertise.
- [x] Capture the HCI traffic while registering; fix the missing Flags.
- [ ] TODO(you): connect with nRF Connect, read both values, subscribe, and
  watch notifications arrive at most every 0.5 s. Screenshot it.
- [ ] TODO(you): write `0x0032` (50 ms) to Sample Interval from nRF Connect
  and check in an HCI capture which ATT error code bluetoothd **actually**
  sends. `model.py` asks for `0xFF`; bluetoothd only knows D-Bus error names
  and may send `0x0E` (Unlikely Error) instead. Write down what you see.
- [ ] TODO(you): write Identify before pairing (expect a refusal), pair with
  passkey, write again. Which pairing method did the phone pick, and why?
- [ ] TODO(you): set `Privacy = device` in `/etc/bluetooth/main.conf`, restart
  bluetoothd, capture again, and confirm the own address type is no longer
  public.

---

## What was actually run / 实际跑过的

On 2026-09-27, Ubuntu 24.04, BlueZ 5.72, Intel AX201:

| Command | Result |
|---|---|
| `python3 -m unittest discover -s tests -t .` | 24 tests, OK |
| `python3 -m peripheral --seconds 40` + `dumpcap` | Application and advertisement registered; HCI shows no Flags AD |
| same, after `Discoverable=True` | Advertising Data = Flags `0x06` + UUID16 `180F 181A`, 9 bytes; name in scan response |

Not run yet: a phone connecting, notifications on air, pairing, and the
authenticated write. Those are the TODOs above.
还没跑过：手机连接、空中的 notification、配对、认证写。就是上面的 TODO。
