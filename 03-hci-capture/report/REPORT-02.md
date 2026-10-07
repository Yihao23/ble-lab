# REPORT-02 · One connection, start to finish: pairing once, then reconnecting
# REPORT-02 · 一条连接从头到尾：配对一次，之后重连

Two HCI captures of the same phone and the same laptop, a week apart: the
first pairing, and a reconnection. Every line quoted here is printed by
`python3 timeline.py` on those files, which decodes HCI itself and hands
every ACL packet to project 01's C parser; the few things it does not decode
(the SMP key-distribution flags, the Service Changed ranges) were read with
`tshark` and are marked so. The captures are not in the repository: they hold
both devices' addresses, and the link's keys in clear (section 7).
同一部手机、同一台笔记本，相隔一周的两份 HCI 抓包：首次配对和一次重连。下面引用的每一行都由
`timeline.py` 打印；它自己解 HCI，把每个 ACL 包交给项目 01 的 C 解析器。它不解的少数内容
（SMP 密钥分发标志、Service Changed 的范围）用 `tshark` 读取，并单独标明。抓包不入库：
里面有两台设备的地址，还有明文的链路密钥（第 7 节）。

| | Pairing | Reconnection |
|---|---|---|
| Date | 2026-09-30, 20:07 | 2026-10-07, 19:55 |
| Peripheral | project 02 on the laptop: Intel AX201, Linux 7.0, BlueZ 5.72 | same |
| Central | an Android phone, nRF Connect | same phone, still bonded |
| What the user did | connect, write Identify, confirm 985572 on both screens | connect, read Battery Level, write Identify `05` |
| Capture | `pairing-20260930-2007.pcapng`, 2 LE connections and 1 BR/EDR | `reconnect-20261007-1955.pcapng`, 1 LE connection |

```bash
python3 timeline.py ../02-gatt-peripheral/captures/reconnect-*.pcapng
python3 timeline.py ../02-gatt-peripheral/captures/pairing-*.pcapng
```

---

## 1. A connection, step by step
## 1. 一条连接的每一步

The reconnection, from the controller's first event to the first thing the
user did. `>` is host to controller, `<` controller to host, `=` bluetoothd.
Times from the start of the capture; the right column from the connection.

```
    8.658  < HCI   LE Enhanced Connection Complete: handle 0x800, we are peripheral,     +0 ms
                   peer address random, interval 17.5 ms, latency 0, timeout 5000 ms
    8.659  < HCI   LE Channel Selection Algorithm: CSA #2                                 +1
    8.660  < HCI   LE Advertising Set Terminated: advertising stopped                     +2
    8.661  < HCI   LE Data Length Change: up to 251 octets out, 27 in                     +3
    8.663  > L2CAP LE signalling: Connection Parameter Update Request                    +5
    8.663  > SMP   Security Request                                                       +5
    8.686  < HCI   LE Long Term Key Request (Rand and EDIV 0: LE Secure Connections)     +28
    8.686  > HCI   LE Long Term Key Request Reply: LTK given (16 octets, withheld)       +28
    8.738  < HCI   Encryption Change: on (AES-CCM)                                       +80
    8.738  > ATT   EXCHANGE_MTU_REQ MTU 517                                              +80
    8.738  > ATT   HANDLE_VALUE_IND handle 0x000a          (Service Changed, section 5)  +80
    8.758  < ATT   first discovery request from the phone                               +100
    9.895  < HCI   LE PHY Update Complete: TX 2M, RX 2M                                +1237
   11.417  < ATT   last discovery request                                             +2759
   33.277  < ATT   READ_REQ handle 0x0017                  (the user: Battery Level)
  113.268  < ATT   WRITE_REQ handle 0x0021                 (the user: Identify 05)
```

In order: the controller reports the link (handle, our role, interval); says
which channel-selection algorithm it will hop with — **CSA #2**, on every
connection in both captures; reports that the advertising set ended, as a
connectable set does once it has produced a connection; and agrees a longer
data length. Then the host takes over: asks for a slower interval, asks for
security, gets it 80 ms after the link came up, and only then does any GATT
traffic flow. The phone spends the next 2.7 s rediscovering the server.
控制器先报告连接（句柄、角色、间隔）、跳频算法（两份抓包里每条连接都是 **CSA #2**），停止广播，
协商更长的数据长度；然后主机接手：请求更慢的间隔、请求加密，80 ms 后加密完成，之后才有 GATT 流量。
手机接下来用 2.7 s 重新发现服务。

---

## 2. Pairing once, reconnecting after
## 2. 配对一次，之后直接重连

| | First pairing (2026-09-30) | Reconnection (2026-10-07) |
|---|---|---|
| What started security | the phone's write to Identify was refused, `0x05` Insufficient Authentication | **the laptop asked, 5 ms after connecting**: SMP Security Request |
| SMP packets | 9 pairing + 4 key distribution | **1** (the Security Request) |
| User action | compare 985572 on two screens, confirm (13.3 s on the phone, 16.7 s on the laptop) | none |
| Connection → encrypted | 38.1 s, almost all of it waiting for a person | **80 ms** |
| LTK Request → Encryption Change | 89 ms | 52 ms |
| Keys stored by bluetoothd (mgmt events) | IRK, CSRK ×2, LTK, BR/EDR link key | **none** — nothing new to store |
| Identify `05` | refused, then accepted after pairing | accepted at once: `write identify <- 05 ok` |

The reconnection, as the summary prints it:

```
LE connection, handle 0x800, we are peripheral, interval 47.5 ms, CSA #2
  encrypted 80 ms after connecting, from a key stored at an earlier pairing — no SMP at all
```

**Why no pairing is needed.** Pairing produced a Long Term Key that both
sides kept: the phone in its bond store, bluetoothd under
`/var/lib/bluetooth`. On reconnection the central starts encryption by
naming the key — for LE Secure Connections, Rand and EDIV are zero, since
there is one LTK per bond — the peripheral's controller asks its host for
it (`LE Long Term Key Request`), the host hands it over, and the controllers
derive a session key from it and fresh nonces. An attacker replaying the old
pairing gets nothing: the session key depends on nonces chosen now.
**为什么不用再配对。** 配对产生的 LTK 两边都保存了。重连时 central 指明用哪把密钥（LE
Secure Connections 每个绑定只有一把 LTK，所以 Rand 和 EDIV 都是 0），peripheral 的控制器向主机要这把
密钥，主机交出，两边控制器用它和新的随机数派生会话密钥。重放旧的配对过程没有用：会话密钥取决于这次的随机数。

**What I expected and was wrong about.** I expected the write to Identify to
be what triggered encryption, as it triggered pairing the first time. The
capture shows it was already encrypted: BlueZ sent a Security Request to the
bonded central 5 ms after the link came up, so the protected characteristic
never had to refuse anything.
**我原先预期错了的地方：** 以为要靠写 Identify 触发加密。抓包显示链路早已加密：BlueZ 一连上就向已绑定的
central 发 Security Request。

---

## 3. The first attempt ran out of time
## 3. 第一次尝试超时了

The pairing capture holds two attempts. The first:

```
  163.363  < SMP   Pairing Request
  163.484  = mgmt  User Confirmation Request: the six digits go to the user
  163.484  > SMP   Pairing Random
  193.543  < HCI   Disconnection Complete: reason 0x13 Remote User Terminated Connection
```

**30.06 s** between the digits appearing and the link dropping. The Security
Manager has a 30-second timeout on a pairing procedure (Core Vol 3 Part H,
3.4): when it expires, the procedure fails and no further SMP traffic is
allowed on that link. The phone disconnected. The digits of that attempt,
941252, were never confirmed on the laptop; 02's README records them. The
second attempt, on a new connection 42 s later, was confirmed in 13–17 s.
数字出现后 **30.06 s** 连接断开。SMP 规定配对过程超时 30 秒（Core Vol 3 Part H 3.4），超时后这条链路上
不允许再有 SMP 流量，手机断开了连接。第二次在新连接上，13–17 s 内确认成功。

So a device with a slow confirmation path — a button behind a menu, a user
reading a manual — has 30 seconds, not more, and the failure looks like a
plain disconnection with reason 0x13, not like a pairing error.
所以确认步骤慢的设备只有 30 秒；失败时看起来只是一次普通断开（0x13），不像配对错误。

---

## 4. What pairing left behind
## 4. 配对留下了什么

**Which keys.** From the Pairing Request and Response (read with tshark):

```
phone (initiator):   AuthReq 0x2d  Secure Connections, MITM, Bonding, CT2
                     key distribution 0x0f: LTK, IRK, CSRK, Link Key
laptop (responder):  AuthReq 0x2d
                     key distribution 0x0d: LTK, CSRK, Link Key — no IRK
```

and the mgmt events bluetoothd received right after encryption (keys withheld):

```
  273.840  = mgmt  New Identity Resolving Key   ← the phone's IRK: resolves its RPAs from now on
  273.840  = mgmt  New Signature Resolving Key  ×2
  273.840  = mgmt  New Long Term Key            ← what section 2 used a week later
  273.840  = mgmt  New Link Key (BR/EDR)        ← derived from the LTK
```

- **The laptop distributes no IRK.** It does not use resolvable private
  addresses, so it has none to give: anyone can recognise it. That is the
  open `Privacy = device` item in project 02.
- **A BR/EDR link key, from an LE pairing.** Both sides set the Link Key bit,
  so the LE Secure Connections LTK was also turned into a key for classic
  Bluetooth (cross-transport key derivation). One pairing bonded both
  transports.
- **Then BlueZ tried to look at the phone over classic Bluetooth.** 1.6 s
  later the laptop sent Create Connection (BR/EDR) to the phone's identity
  address — the one it had just learnt in Identity Address Information. On
  that link it sent an L2CAP Information Request (extended features) and,
  4.0 s later, a Connection Request for PSM 0x0001: **SDP**, the classic
  service directory, to learn which classic profiles the newly bonded
  device offers. The phone answered neither — no ACL packet came back on
  that handle — and 39 s after the Connection Request the laptop
  disconnected (0x16, terminated by local host). Why the phone stayed
  silent is **open**.
- 笔记本不分发 IRK（它不用可解析私有地址，谁都能认出它）；双方都置了 Link Key 位，所以 LE 配对同时
  派生了经典蓝牙的链路密钥，一次配对绑定了两种传输方式；随后 BlueZ 用刚学到的身份地址建立经典蓝牙连接，
  请求 SDP（PSM 0x0001）想查手机的经典服务，手机始终没有回应，39 s 后笔记本断开。手机为何不回应，**待查**。

---

## 5. Why the phone rediscovered everything
## 5. 手机为什么重新发现了所有服务

Right after encryption the laptop sent an indication on handle 0x000a. In
the phone's own discovery, 0x000a is the value of **Service Changed** (UUID
0x2A05, in the Generic Attribute service). Its value, read with tshark:

```
    8.738  HANDLE_VALUE_IND  0x000a  01 00 ff ff      handles 0x0001–0xffff may have changed
  130.554  HANDLE_VALUE_IND  0x000a  0x0015–0x0018
  130.606  HANDLE_VALUE_IND  0x000a  0x0019–0x001c
  130.701  HANDLE_VALUE_IND  0x000a  0x001d–0x0021
```

- **At 8.738**, "everything may have changed"; 20 ms later the phone began a
  full discovery — 53 requests over 2.7 s. Service Changed reaches only a
  client that subscribed to it, and a subscription survives a disconnection
  only for a bonded client; the phone subscribed (wrote 0x000b) right after
  pairing on 2026-09-30.
- **Why "everything"**: project 02 registers its services each time it
  starts, so the database the phone cached a week ago may differ. That is
  my reading; the capture shows the indication and the rediscovery, not
  bluetoothd's reason.
- **At 130.5**, when project 02 was stopped and unregistered its three
  services, bluetoothd indicated exactly their three handle ranges, one per
  service, and the phone rediscovered them (14 requests).
- 加密后笔记本立即在 Service Changed 上发 indication，内容是"0x0001–0xFFFF 都可能变了"，20 ms 后
  手机开始完整的服务发现（2.7 s 内 53 个请求）。只有已绑定且订阅过的客户端才会收到它。为什么是"全部"是我的
  推断（02 每次启动都重新注册服务）。02 停止时，bluetoothd 精确通知了被删除的三个服务的范围。

---

## 6. Two clients on one link
## 6. 一条链路上两个客户端

Project 02 is the GATT server and the phone the client — but the laptop is a
client too. In both captures BlueZ discovers the phone's own GATT server as
soon as the link is up, reads two of its attributes and writes two:

```
    peer as client : 67 discovery requests, 1 reads, 1 writes; 37 error responses to it
    us as client   : 14 discovery requests, 2 reads, 2 writes; 6 error responses to it
```

The error responses are mostly `0x0a` Attribute Not Found: that is how a
discovery learns it has reached the end of a range, not a failure. GATT
roles belong to each request, not to the device; the LE roles (central,
peripheral) are a separate thing and do not change.
GATT 的客户端/服务器角色属于每个请求，不属于设备；笔记本在这条链路上同时也是客户端。错误响应大多是
`0x0a` Attribute Not Found：服务发现就是靠它知道范围已经读完，不是故障。

---

## 7. HCI is a trust boundary
## 7. HCI 是信任边界

The line the timeline prints as

```
    8.686  > HCI   LE Long Term Key Request Reply: handle 0x800, LTK given (16 octets, withheld)
```

carries, in the capture, the LTK itself in clear: the host gives the key to
the controller over USB in an ordinary HCI command. Anyone who can capture
HCI — root on the laptop, or a bus analyser on the USB cable — has the key
for every future connection with this phone, and with the BR/EDR link key,
for classic Bluetooth too. The radio side is protected by AES-CCM; the
host-controller side is protected by nothing but the operating system.
抓包里这一行带着明文 LTK：主机通过普通 HCI 命令经 USB 把密钥交给控制器。能抓 HCI 的人（笔记本的 root，
或 USB 总线分析仪）就拿到了以后每次连接的密钥。空中有 AES-CCM 保护，主机-控制器之间只有操作系统保护。

That is why `timeline.py` never prints a key, why its tests check that the
16 key octets do not appear in its output, and why these captures are not
in the repository. On a single-chip product the boundary is inside the chip
and this attack does not exist; on a two-chip design (application MCU plus a
radio over UART) it does, and the UART is the place to protect.
所以 `timeline.py` 从不打印密钥，测试检查输出里不出现密钥的任何字节，抓包也不入库。单芯片产品里这条边界在芯片内部；
双芯片设计（应用 MCU + 通过 UART 连接的射频芯片）里它真实存在，UART 就是要保护的地方。

---

## 8. The link, as the controllers tuned it
## 8. 控制器把链路调成了什么样

- **Interval**: connected at 17.5 ms; the phone then asked for 30–50 ms and
  10–20 ms by turns, and the laptop accepted every request. During the 2.7 s
  of discovery the interval moved 47.5 → 17.5 → 47.5 → 17.5 → 47.5 ms, and
  again when the services changed at 130 s: fast while there is traffic,
  slow when idle, as Android does.
- **PHY**: 2M from 1.2 s on, both directions.
- **Data length**: 251 octets each way, so an MTU of 517 needs only three
  link-layer packets.
- **Channel selection**: CSA #2 on every connection. The algorithm (task 6
  in project 01) is now known to be the one actually in use.
- 间隔在 17.5 ms 和 47.5 ms 之间来回切换（有流量时快，空闲时慢）；PHY 1.2 s 后升到 2M；
  数据长度双向 251 字节；每条连接都用 CSA #2。

---

## 9. Not verified, and open
## 9. 没有验证的和待解决的

- **One reconnection.** Timings from one sample; no disconnection was
  captured on that connection, so no reason code.
- **The BR/EDR connection after pairing**: why the phone never answered
  BlueZ's SDP request (section 4).
- **Why Service Changed said "everything"** at reconnection (section 5): the
  explanation is inferred, not read from bluetoothd.
- **Not on air.** Everything here is the host-controller view. Whether the
  phone really hopped with CSA #2, and the encrypted packets themselves,
  would need a sniffer on the radio.
- TODO(you): reconnect twice more, disconnect from the phone, and compare:
  is it always 80 ms, and is the reason always 0x13?
- 只有一次重连样本；配对后经典蓝牙连接上手机为何不回应 SDP 待查；Service Changed 为何是"全部"为推断；
  这里全是 HCI 视角，空中的情况需要射频嗅探器。
