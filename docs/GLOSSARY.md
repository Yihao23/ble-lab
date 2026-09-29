# Glossary / 术语表

Every acronym in this repo, with the one sentence that actually explains it.
本仓库出现的所有缩写，配一句真正能解释清楚的话。

---

## The stack / 协议栈

| Term | Full name | What it is | 中文 |
|---|---|---|---|
| **Controller** | — | The chip (or part of it) that runs the radio and the Link Layer; you buy it | 跑射频和链路层的芯片，是你买来的部分 |
| **Host** | — | Everything above HCI: L2CAP, ATT, GATT, SMP, GAP; on a single-chip device it is your firmware | HCI 之上的一切，单芯片设备上就是你的固件 |
| **HCI** | Host Controller Interface | Standard command/event interface between host and controller (Core Vol 4 Part E) | 主机与控制器之间的标准命令/事件接口 |
| **LL** | Link Layer | Advertising, connections, channel selection, timing — below HCI | 广播、连接、信道选择、时序，都在 HCI 之下 |
| **GAP** | Generic Access Profile | Roles, modes, discoverability, addresses | 角色、模式、可发现性、地址 |
| **ATT** | Attribute Protocol | Read/write/notify on numbered attributes; the error codes live here | 对编号属性的读写和通知，错误码定义在这里 |
| **GATT** | Generic Attribute Profile | Services and characteristics built on ATT | 建立在 ATT 之上的服务与特征 |
| **SMP** | Security Manager Protocol | Pairing and key distribution, including the IRK | 配对和密钥分发，包括 IRK |
| **mgmt** | Linux Bluetooth Management API | The kernel's own interface to bluetoothd, above HCI — not a Bluetooth standard | Linux 内核与 bluetoothd 之间的接口，不是蓝牙标准 |
| **BlueZ** | — | The Linux Bluetooth host stack; `bluetoothd` exposes it over D-Bus | Linux 蓝牙主机栈 |

---

## Advertising / 广播

| Term | Full name | What it is | 中文 |
|---|---|---|---|
| **AD** | Advertising Data | Length-type-value structures, at most 31 bytes in a legacy PDU | 长度-类型-值结构，legacy PDU 最多 31 字节 |
| **PDU** | Protocol Data Unit | One packet at a given layer | 某一层的一个数据包 |
| **ADV_IND** | — | Connectable, scannable, undirected advertisement | 可连接、可扫描的非定向广播 |
| **ADV_NONCONN_IND** | — | Neither connectable nor scannable: a beacon | 不可连接也不可扫描：信标 |
| **SCAN_REQ / SCAN_RSP** | — | Active scanning: the scanner asks, the advertiser sends up to 31 more bytes. `SCAN_REQ` carries the scanner's address | 主动扫描：扫描者请求，广播者多发 31 字节；请求里带扫描者地址 |
| **Legacy / extended advertising** | — | 4.x PDUs on channels 37–39 vs. 5.x advertising sets with up to 1650 bytes on secondary channels | 4.x 的老式广播 vs 5.x 的广播集 |
| **Advertising set** | — | One independent advertisement with its own data, interval and address; a device can run several | 一个独立的广播，有自己的数据、间隔和地址 |
| **Flags** | AD type `0x01` | Discoverable mode and BR/EDR support; limited = bit 0, general = bit 1 | 可发现模式和是否支持经典蓝牙 |
| **Limited Discoverable** | — | Discoverable for at most TGAP(lim_adv_timeout) = 180 s, e.g. after a button press | 最多 180 秒的有限可发现 |
| **RSSI** | Received Signal Strength Indicator | Received power in dBm as the controller measured it; not authenticated, not a distance | 接收功率，不经认证，也不是距离 |
| **PHY** | Physical layer | LE 1M, LE 2M, LE Coded (long range) | 物理层 |

---

## Addresses and privacy / 地址与隐私

| Term | Full name | What it is | 中文 |
|---|---|---|---|
| **Public address** | — | IEEE-assigned, fixed for life | IEEE 分配，终身不变 |
| **Static random** | — | Top bits `11`; may change at power cycle, not in between | 最高两位 `11`，只能在上电时改变 |
| **RPA** | Resolvable Private Address | Top bits `01`: `prand ‖ ah(IRK, prand)`; only holders of the IRK can recognise it | 可解析私有地址，只有持有 IRK 的一方能认出 |
| **NRPA** | Non-Resolvable Private Address | Top bits `00`: random, recognisable by nobody | 不可解析私有地址 |
| **IRK** | Identity Resolving Key | 128-bit key exchanged at pairing, used to resolve RPAs | 配对时交换的 128 位密钥 |
| **`ah()`** | Random address hash function | `AES-128(IRK, 0¹⁰⁴ ‖ prand)` truncated to 24 bits (Core Vol 3 Part H 2.2.2) | 随机地址哈希函数 |
| **Handoff** | (this repo) | An address disappears and a new one appears seconds later: the moment rotation is observable | 旧地址消失、新地址数秒后出现 |
| **CrossLink** | (Lecture 10) | Linking a device's identities across protocols by time and space | 按时间和空间跨协议关联身份 |

---

## GATT and security / GATT 与安全

| Term | What it is | 中文 |
|---|---|---|
| **Service / Characteristic** | A group of values / one value with properties (read, write, notify) | 一组值 / 一个带属性的值 |
| **CCCD** | Client Characteristic Configuration Descriptor: the client writes it to subscribe to notifications | 客户端写它来订阅通知 |
| **Notification / Indication** | Server-pushed value, unacknowledged / acknowledged | 服务器推送，无确认 / 有确认 |
| **MTU** | Largest ATT packet; 23 bytes by default | 最大 ATT 包，默认 23 字节 |
| **Encrypted / authenticated** | Link encrypted / encrypted with a key from MITM-protected pairing (passkey, numeric comparison) | 链路加密 / 用防中间人配对得到的密钥加密 |
| **CSS** | Core Specification Supplement: common data types and profile error codes like `0xFF` Out of Range | 核心规范补充 |

---

## Tools / 工具

| Term | What it is | 中文 |
|---|---|---|
| **btmon / bluetooth-monitor** | Linux's HCI + mgmt trace; `dumpcap -i bluetooth-monitor` writes it as pcapng, link type 254 | Linux 的 HCI + mgmt 跟踪 |
| **pcapng** | Wireshark's capture file format: blocks with lengths at both ends | Wireshark 的抓包文件格式 |
| **ASan / UBSan** | Address / Undefined Behaviour Sanitizer: compiler instrumentation that stops at the first bad read | 编译器插桩，第一次越界读就停下 |
| **Freestanding** | C without the hosted library: no `malloc`, no `string.h` unless you bring it | 不依赖宿主标准库的 C |
