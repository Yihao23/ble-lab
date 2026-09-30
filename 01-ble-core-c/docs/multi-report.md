# One HCI event, several advertising reports

*中文摘要在文末。*

Every answer below cites where it came from: a section of the Core
Specification, or a file and function in the Linux kernel.

## The question

An LE Advertising Report event (subevent 0x02) carries `Num_Reports`
reports. With two or more, how are their bytes laid out?

**Layout A — one report after another** (what `ble_hci.c` assumes):

    Event_Type[0] Address_Type[0] Address[0] Data_Length[0] Data[0] RSSI[0]
    Event_Type[1] Address_Type[1] Address[1] Data_Length[1] Data[1] RSSI[1]

**Layout B — one field after another:**

    Event_Type[0] Event_Type[1]
    Address_Type[0] Address_Type[1]
    Address[0] Address[1]
    Data_Length[0] Data_Length[1]
    Data[0] Data[1]
    RSSI[0] RSSI[1]

The same bytes read under the two layouts give different addresses, RSSIs
and data. A test cannot settle it: tests written from the same assumption
as the parser agree with it whether or not the assumption is right.

## 1. What the Core Specification says

Read in Core Specification **6.2**, Vol 4 Part E (Host Controller
Interface Functional Specification), from the HTML edition on
bluetooth.com. The two passages below are word for word the same in 5.4.

**§7.7.65.2 LE Advertising Report event** lists the parameters as
`Subevent_Code, Num_Reports, Event_Type[i], Address_Type[i], Address[i],
Data_Length[i], Data[i], RSSI[i]` and gives each arrayed one a size of
"Num_Reports × 1 octet" (× 6 for `Address`, `SUM(Data_Length[i])` for
`Data`). Those are total sizes. They say how many bytes each parameter
takes across all reports, not in what order the bytes come — read on their
own they fit layout B as well as A.

The order is defined once, for every command and event, in
**§5.2 Data and parameter formats**:

> Arrayed parameters are specified using the following notation:
> ParameterA[i]. If more than one set of arrayed parameters are specified
> (e.g. ParameterA[i], ParameterB[i]), then, unless noted otherwise, the
> order of the parameters are as follows: ParameterA[0], ParameterB[0],
> ParameterA[1], ParameterB[1], ParameterA[2], ParameterB[2], ...
> ParameterA[n], ParameterB[n]. The description of an arrayed parameter
> will actually describe a single element of the array.

`A[0], B[0], A[1], B[1]` is **layout A**. The rule applies "unless noted
otherwise", and §7.7.65.2 notes nothing otherwise.

Two more things §7.7.65.2 says that matter here:

- `Num_Reports` is **0x01 to 0x19**; `Data_Length[i]` is **0x00 to 0x1F**.
  Everything else is reserved.
- "This event shall only be generated if scanning was enabled using the
  HCI_LE_Set_Scan_Enable command. It only reports advertising events that
  used legacy advertising PDUs." BlueZ on the AX201 enables scanning with
  the *extended* command (0x2042, see 03's report), which is why the
  40-minute capture holds no 0x02 event at all.

## 2. What Linux does

Read at torvalds/linux master, commit `551c722f4080` (2026-09-30).

`include/net/bluetooth/hci.h` describes one report as one packed struct:

```c
struct hci_ev_le_advertising_info {
	__u8	 type;
	__u8	 bdaddr_type;
	bdaddr_t bdaddr;
	__u8	 length;
	__u8	 data[];
} __packed;

struct hci_ev_le_advertising_report {
	__u8    num;
	struct hci_ev_le_advertising_info info[];
} __packed;
```

A struct per report only describes layout A: under layout B no report's
fields sit next to each other.

`net/bluetooth/hci_event.c`, `hci_le_adv_report_evt()`, walks them:

```c
while (ev->num--) {
	info = hci_le_ev_skb_pull(hdev, skb, HCI_EV_LE_ADVERTISING_REPORT,
				  sizeof(*info));                 /* the 9 fixed bytes */
	if (!info)
		break;
	if (!hci_le_ev_skb_pull(hdev, skb, HCI_EV_LE_ADVERTISING_REPORT,
				info->length + 1))                /* data + RSSI */
		break;
	if (info->length <= max_adv_len(hdev)) {
		rssi = info->data[info->length];
		process_adv_report(...);
	} else {
		bt_dev_err(hdev, "Dropping invalid advertising data");
	}
}
```

Each pass takes the 9 fixed bytes, then `length + 1`, then the next report
starts where that one ended. Layout A. RSSI is not a field of the struct;
it is the byte after the data, `data[length]`.

`max_adv_len()` in `include/net/bluetooth/hci_core.h` is 31 for a
controller without extended advertising and **251** for one with it, so on
a modern controller Linux accepts a legacy `Data_Length` up to 251.

## 3. What `ble_hci.c` does

`ble_hci_adv_next()`, legacy branch:

```c
if (avail < LEGACY_FIXED) goto malformed;               /* 9 fixed bytes */
uint8_t dlen = p[8];
if (avail < LEGACY_FIXED + dlen + 1u) goto malformed;   /* data + RSSI */
...
out->rssi = (int8_t)p[9u + dlen];
it->p += LEGACY_FIXED + dlen + 1u;                      /* next report */
```

The last line steps over one whole report. Layout A, the same two checks
Linux makes, in the same order, with RSSI in the same place.

## 4. Conclusion

| Source | Layout | Where |
|---|---|---|
| Core 6.2 (and 5.4) | A | Vol 4 Part E §5.2; nothing contrary in §7.7.65.2 |
| Linux master | A | `hci_le_adv_report_evt()`: 9 bytes, then `length + 1` |
| `ble_hci.c` | A | `it->p += LEGACY_FIXED + dlen + 1u` |

All three agree. `ble_hci.c` keeps its layout.

They do **not** agree on the ranges §7.7.65.2 sets:

| | Spec | Linux | `ble_hci.c` |
|---|---|---|---|
| `Num_Reports` = 0 | reserved | returns at once | first `next()` returns END |
| `Num_Reports` > 25 | reserved | not checked | not checked |
| `Data_Length` > 31 | reserved | dropped above 31, or above 251 with extended advertising | **accepted** while the bytes are inside the event |

**Decision: `ble_hci.c` stays tolerant, on purpose.**

- There is no memory-safety question. Every read is checked against the
  event's own length; 200 000 fuzz inputs under ASan agree.
- The library's rule is strict when *making* (`ble_rpa_make` refuses a
  forbidden prand) and tolerant when *parsing*, the same reason a reserved
  address type is reported as `BLE_ADDR_RANDOM_RESERVED` rather than
  rejected. An iterator over the air that throws away what it does not
  like leaves the person debugging with nothing to look at.
- Linux does not enforce 31 either on the controllers people have now.
- The data a 32-byte report hands back is still bounded by `data_len`, so
  `ble_ad` walks it as safely as any other.

A caller that wants the spec's limit can check `r.data_len <= 31` for a
report with `from_legacy_event` set. The decision is pinned by case 4 of
`suite_hci_multi()`: whoever changes it changes that test with it.

## 5. The test

`tests/test_hci_multi.c`, `suite_hci_multi()`, 39 checks:

1. **Three valid reports, data lengths 0, 3 and 5.** Each has its own event
   type, address type, address and RSSI, and every one of those is checked,
   so a parser reading any field from the wrong report reads a wrong value.
   The fourth `next()` is END.
2. **The second of three claims 200 bytes, four follow.** The first report
   still comes back intact, the second is `BLE_HCI_ERR_MALFORMED`, and the
   call after that is END: after a bad length, nothing further along can be
   trusted to be where it claims.
3. **`Num_Reports` = 0.** Initialises, returns END, reads nothing.
4. **`Data_Length` = 32.** Accepted, with the right length and RSSI — the
   decision in section 4, written down as a test.

274 checks, 0 failed, also under ASan + UBSan.

---

## 中文摘要

**问题：** 一个 0x02 事件里有多条报告时，字节是"一条接一条"（布局 A）还是"一个字段接一个字段"（布局 B）？

**答案：布局 A，三方一致。**

- **规范**（Core 6.2，5.4 相同）Vol 4 Part E §5.2 规定数组参数的顺序是 `A[0], B[0], A[1], B[1] …`；§7.7.65.2 没有另作说明。§7.7.65.2 表格里的 "Num_Reports × 1 octet" 只是总大小，不是排列顺序。
- **Linux** `hci_le_adv_report_evt()` 每轮先取 9 字节固定部分，再取 `length + 1`（数据 + RSSI）。
- **`ble_hci.c`** 用 `it->p += LEGACY_FIXED + dlen + 1u` 跳过一整条报告。

**差异：** 规范规定 `Num_Reports` 为 1–25、`Data_Length` 为 0–31。`ble_hci.c` 不检查这两个上限。这是**有意的宽容**：所有读取都在事件长度之内，没有内存安全问题；解析空中数据时应描述收到的内容，而不是丢弃；Linux 在支持扩展广播的控制器上也接受最长 251 字节。测试用例 4 把这个决定固定了下来。

**顺带解释了一个现象：** 规范说 0x02 事件只在用旧命令 `HCI_LE_Set_Scan_Enable` 开启扫描时产生。BlueZ 在 AX201 上用的是扩展扫描命令，所以 40 分钟抓包里一个 0x02 都没有。
