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

| Bad write | `model.py` chooses | What the phone gets (BlueZ 5.72) | Why |
|---|---|---|---|
| Interval, wrong length | `0x0D` Invalid Attribute Value Length | `0x0D` | The length is wrong, not the value |
| Interval, 50 ms | `0xFF` Out of Range | **`0x80`** — seen on air | CSS names 0xFF for exactly this, but BlueZ cannot send it (below) |
| Identify, 0 or 31 s | `0x13` Value Not Allowed | `0x80` by the same mapping; not seen on air (needs pairing first) | Same limit |
| Identify, unencrypted | — | `0x05` Insufficient Authentication — seen on air | The stack refuses before `model.py` sees anything; Android answers by starting to pair |

**What BlueZ 5.72 can send.** `dbus_error_to_att_ecode()` in
`src/gatt-database.c` maps `org.bluez.Error.Failed` to `0x80` — or to the
code in its message, but only `0x80`–`0x9F`; `"0xFF"` becomes `0x0E` with an
"Invalid error code" in the log. A handful of names map to standard codes
(`InvalidValueLength` → `0x0D`, `NotPermitted` → `0x03` on write,
`NotAuthorized`, `NotSupported`, `InvalidOffset`). Anything else — an
exception the stack does not know — becomes `0x0E` Unlikely Error. The
common profile codes `0xE0`–`0xFF` are out of reach from a D-Bus application.
**BlueZ 5.72 能发什么：** `Failed` 发 `0x80`（或消息里写的 `0x80`–`0x9F`）；
`0xE0`–`0xFF` 这段 profile 公共错误码，D-Bus 应用根本发不出去。

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
python3 -m unittest discover -s tests -t .      # 25 tests, no radio needed

python3 -m peripheral                           # advertise until Ctrl-C
python3 -m peripheral --seconds 60 --thermal-zone x86_pkg_temp
```

Then on a phone: **nRF Connect** → Scan → `BLE-Lab` → Connect → expand
Battery Service → read (↓) Battery Level; the ↓↓↓ button subscribes. Failed
writes show in the app's log, not always on screen.

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

## What a phone showed / 手机连上来之后

An Android phone running nRF Connect, 2026-09-30, with an HCI capture of
both sessions.

1. **Every read failed with ATT error `0x0E`.** The phone connected and saw
   all services, but each read came back "Unlikely Error". The program log
   said why: `TypeError: 'NoneType' object is not callable`. The
   characteristic had a helper method `_name()`, and
   `dbus.service.Object.__init__` sets `self._name` to the bus name — `None`
   here — replacing the method. Every `ReadValue` and every notification
   raised; bluetoothd, getting an exception it did not know, sent `0x0E`.
   Renamed to `_label()`. `tests/test_dbus_names.py` fails if any D-Bus class
   defines an attribute `dbus.service.Object` sets on itself (checked red on
   the old code). The 24 model tests had all passed: nothing exercised this
   layer until a real client did.
   **每次读取都返回 `0x0E`。** 辅助方法 `_name()` 被父类构造函数里的
   `self._name = None` 覆盖，读取时抛出 TypeError，BlueZ 回复 Unlikely Error。
   模型测试全部通过，因为这一层直到真实客户端连上来之前从未被调用过。
2. **After the fix:** reads correct (battery `5f` = 95 %, temperature `9411`
   and `cc10` = 45.00 and 43.00 °C, little-endian), both characteristics
   subscribed, 97 notifications in 20 minutes, 0 errors. Temperature: 68 on
   air, gaps 1.0 s to 30.1 s — the change filter and the 30 s heartbeat both
   visible. The 0.5 s rate limit was **not** exercised: the sensor is sampled
   once a second.
3. **`0xFF` arrives as `0x80`.** Writing 50 ms to the sample interval:
   `model.py` refused it with `0xFF`, the capture shows `Application Error
   0x80` on air. BlueZ's mapping, above, is why.
4. **The phone uses an RPA, and a new one per connection:** two sessions five
   minutes apart came from two addresses, both with top bits `01`. The
   address `ble_rpa.c` in project 01 classifies and the rotation project 04
   measures, on a phone in hand.
   **手机每次连接都换一个 RPA 地址。**

---

## Pairing / 配对

Same phone, same day, the laptop's agent in `bluetoothctl`, an HCI capture
running. `01-ble-core-c/tools/pairing_from_capture.py` reads the capture.

1. **Writing Identify started it.** The write came back `0x05` Insufficient
   Authentication, and Android sent Pairing Request on its own:
   `AuthReq: Bonding, MITM, SecureConnection`.
2. **Numeric comparison.** Both sides declared KeyboardDisplay, and with LE
   Secure Connections that pair selects numeric comparison — the method
   with MITM protection and a number on each screen.
3. **Both screens showed 985572, and so did the library.** The phone's
   dialog and `bluetoothctl` (`Confirm passkey 985572`) agreed. From the
   capture, `pairing_from_capture.py` took the two public keys and the two
   nonces off the air, checked it had read them right by recomputing the
   laptop's commitment Cb = f4(PKbx, PKax, Nb, 0) and matching it to the
   Pairing Confirm on air, and ran project 01's `ble_sc_g2`: **985572**.
   The g2 written against the spec's test vector, confirmed on a real
   pairing between a real phone and this laptop.
   **两块屏幕都显示 985572，01 的 `ble_sc_g2` 从抓包里算出的也是 985572。**
4. **The first attempt was not confirmed** and has no DHKey Check; its
   screens would have shown 941252. New nonces, new number.
5. **13 seconds** between the last Pairing Random and the phone's DHKey
   Check: a person reading two screens.
6. **Keys distributed after encryption:** the phone sent its IRK and its
   identity address, and `bluetoothctl` moved the device from the RPA it
   paired with to that public identity address, bonded. The laptop sent no
   IRK — it has no RPA to resolve. The phone still advertises RPAs; only
   the bonded laptop can now tell they are the same phone.
   **手机交出了 IRK 和身份地址，笔记本从此能认出它不断变化的 RPA。**
7. **Identify then accepted:** `write identify <- 05 ok`, five blinks.

The identity address and the IRK stay out of this repository: with them,
anyone could recognise that phone's every RPA.
身份地址和 IRK 不写进仓库：拿到它们就能认出这部手机的每一个 RPA。

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
| `tests/test_dbus_names.py` | No D-Bus class may shadow an attribute `dbus.service.Object` sets on itself |
| `captures/` | HCI captures: before and after the Flags fix, the two phone sessions, and the pairing. Git-ignored: they contain the adapter's and the phone's addresses, and the pairing's keys |

---

## Gotchas / 踩过的坑

| Symptom | Cause | Fix |
|---|---|---|
| 21.005 °C encodes as 2100, not 2101 | 21.005 is 21.00499999… in binary floating point | Sensors report integer millidegrees; `encode_temperature_millideg` rounds half away from zero in integers. A test pins the float behaviour with `Decimal` |
| Every read returned ATT `0x0E` Unlikely Error | A method named `_name` on a `dbus.service.Object` subclass; the base constructor overwrites it with `None` | Renamed; `test_dbus_names.py` guards every D-Bus class |
| The phone gets `0x80`, not the `0xFF` `model.py` chose | BlueZ 5.72 maps `org.bluez.Error.Failed` to `0x80` and cannot send `0xE0`–`0xFF` at all | Documented above; a client sees "application error", not "out of range" |
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
- *"All your tests passed. Why did it fail on a phone?"* — The tests covered
  the model; the D-Bus glue ran for the first time when a phone read a value.
  A method name clashed with an attribute the base class sets. The capture
  showed `0x0E` on air, the program log showed the `TypeError`, and now a
  test checks for the clash.
- *"How do you know your g2 is right?"* — The spec's vector, and then a real
  pairing: both screens showed 985572, and the library computed 985572 from
  the public keys and nonces in the capture — after recomputing the
  commitment Cb from the same values proved they had been read correctly.
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
- [x] Connect with nRF Connect, read both values, subscribe. Found and fixed
  the `_name` clash that made every read fail; 97 notifications afterwards.
- [x] Write 50 ms to Sample Interval and check the capture: `0x80` on air,
  not `0xFF`. BlueZ's source says why.
- [ ] TODO(you): screenshots of the phone for the README.
- [ ] TODO(you): lower the sample interval to 100 ms and confirm on air that
  notifications never come closer than 0.5 s.
- [x] Write Identify before pairing: refused with `0x05`; the phone paired
  with numeric comparison (both KeyboardDisplay, Secure Connections), and
  the write went through. The six digits recomputed from the capture.
- [ ] TODO(you): reconnect and show from a capture that a bonded link
  encrypts with the stored LTK — LE Long Term Key Request, no SMP at all.
- [ ] TODO(you): set `Privacy = device` in `/etc/bluetooth/main.conf`, restart
  bluetoothd, capture again, and confirm the own address type is no longer
  public.

---

## What was actually run / 实际跑过的

On 2026-09-27 and 2026-09-30, Ubuntu 24.04, BlueZ 5.72, Intel AX201, an
Android phone with nRF Connect:

| Command | Result |
|---|---|
| `python3 -m unittest discover -s tests -t .` | 25 tests, OK |
| `python3 -m peripheral --seconds 40` + `dumpcap` | Application and advertisement registered; HCI shows no Flags AD |
| same, after `Discoverable=True` | Advertising Data = Flags `0x06` + UUID16 `180F 181A`, 9 bytes; name in scan response |
| `python3 -m peripheral --seconds 1800` + phone + `dumpcap` | Connected; every read answered `0x0E` — the `_name` clash |
| same, after the fix, `--seconds 1200` | Reads correct; 97 notifications, 0 errors; bad interval write refused, `0x80` on air |
| same, `--seconds 1800`, `bluetoothctl` as agent | Numeric comparison, 985572 on both screens; Identify written after pairing |
| `01-ble-core-c/tools/pairing_from_capture.py pairing-*.pcapng` | Cb matches f4 on air; `ble_sc_g2` → 985572 (and 941252 for the unconfirmed first attempt) |

Not run yet: the 0.5 s rate limit on air, reconnection with the stored
key, and `Privacy = device`. Those are the TODOs above.
还没跑过：空中的 0.5 秒限速、用已存密钥重连、`Privacy = device`。就是上面的 TODO。
