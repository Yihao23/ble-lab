# BLE advertising privacy report

96513 packets, 60333 HCI events, 59437 advertising reports over 40.0 min
subevents: {'0x0D': 59437}; malformed events: 0
addresses: 18 nrpa, 2 public, 12 rpa, 3 static

## Findings

```
P004  error    nrpa#447079     rotation defeated: new address appeared 0.2 s later carrying identical service_data bytes
P004  error    nrpa#58871a     rotation defeated: new address appeared 3.1 s later carrying identical service_data bytes
P004  error    nrpa#8f471b     rotation defeated: new address appeared 0.6 s later carrying identical service_data bytes
P004  error    nrpa#fb4c64     rotation defeated: new address appeared 1.0 s later carrying identical service_data bytes
P004  error    nrpa#8b3ab1     rotation defeated: new address appeared 0.1 s later carrying identical service_data bytes
P004  error    nrpa#c6e5ab     rotation defeated: new address appeared 0.3 s later carrying identical service_data bytes
P004  error    nrpa#6fc941     rotation defeated: new address appeared 0.5 s later carrying identical service_data bytes
P004  error    nrpa#80bb2c     rotation defeated: new address appeared 1.0 s later carrying identical service_data bytes
P004  error    nrpa#b0fe98     rotation defeated: new address appeared 0.2 s later carrying identical service_data bytes
P001  warning  public#97c4e4   public address, heard for 40.0 of 40.0 min: trackable wherever it goes, it never changes
P001  warning  public#438227   public address, heard for 40.0 of 40.0 min: trackable wherever it goes, it never changes
P003  warning  public#97c4e4   advertised name (18 chars) contains the last two bytes of the device's own address
P003  warning  public#438227   advertised name (18 chars) contains the last two bytes of the device's own address
P005  warning  nrpa#805c4d     probable handoff: same device shape reappeared 0.7 s later at RSSI within 8 dB
P005  warning  nrpa#981485     probable handoff: same device shape reappeared 0.4 s later at RSSI within 2 dB
P005  warning  nrpa#225c18     probable handoff: same device shape reappeared 0.4 s later at RSSI within 2 dB
P005  warning  nrpa#b18350     probable handoff: same device shape reappeared 0.3 s later at RSSI within 1 dB
P005  warning  rpa#495c47      probable handoff: same device shape reappeared 7.9 s later at RSSI within 0 dB
P005  warning  rpa#21e81a      probable handoff: same device shape reappeared 2.1 s later at RSSI within 0 dB
P007  warning  nrpa#bbf5be     on air at the same time as nrpa#eec985, carrying the same service_data bytes: two advertising sets, one device
P007  warning  nrpa#eadbf0     on air at the same time as nrpa#bbf5be, carrying the same service_data bytes: two advertising sets, one device
P007  warning  nrpa#8f471b     on air at the same time as nrpa#c6e5ab, carrying the same service_data bytes: two advertising sets, one device
P007  warning  nrpa#8f471b     on air at the same time as nrpa#981485, carrying the same service_data bytes: two advertising sets, one device
P007  warning  nrpa#981485     on air at the same time as nrpa#225c18, carrying the same service_data bytes: two advertising sets, one device
S001  warning  public#97c4e4   advertised LE Limited Discoverable for 40.0 min; the spec caps it at 180 s (TGAP(lim_adv_timeout))
S001  warning  public#438227   advertised LE Limited Discoverable for 40.0 min; the spec caps it at 180 s (TGAP(lim_adv_timeout))
P002  info     static#9f8e98   random static address unchanged for 11.1 min
P002  info     static#c3dddf   random static address unchanged for 14.9 min
P002  info     static#82cca7   random static address unchanged for 12.4 min
P006  info     rpa#c57ca6      RPA did not rotate for 27.4 min (Lecture 10 measured 7-20 min on phones)
```

## Linked addresses

Addresses joined by handoffs: one device, several addresses, one trace.

```
 40.0 min  nrpa#fb4c64 -=-> nrpa#58871a -=-> nrpa#80bb2c -=-> nrpa#805c4d -?-> nrpa#c6e5ab -=-> nrpa#981485 -?-> nrpa#bbf5be
 20.2 min  nrpa#447079 -=-> nrpa#b18350 -?-> nrpa#b0fe98 -=-> nrpa#11093a
 19.8 min  nrpa#6fc941 -=-> nrpa#8b3ab1 -=-> nrpa#8a9940
 39.8 min  rpa#21e81a -?-> rpa#495c47 -?-> rpa#a061c4
 19.9 min  nrpa#8f471b -=-> nrpa#225c18 -?-> nrpa#eadbf0
```
-=-> identical payload bytes on both sides;  -?-> same shape, same RSSI, seconds apart

## Address lifetimes (birth and death both observed)

```
nrpa    n=12  min   1.4  median   7.6  max   8.8  min
rpa     n=5   min   2.3  median  17.4  max  27.4  min
static  n=2   min  12.4  median  14.9  max  14.9  min
```

## Devices

```
address          from     to reports  rssi ivl ms  ids
public#97c4e4     0.0   40.0   18727   -60    206  0x8802  name <18 chars>
nrpa#fb4c64       0.0    3.3     150   -57   1038  0xFEF3
public#438227     0.0   40.0    9250   -81    398  0x8802  name <18 chars>
nrpa#6fc941       0.0    6.7    2180   -40    288  0xFCF1
rpa#21e81a        0.2   10.6     239   -84   1942  0x004C
rpa#eb682b        0.3   10.6      23   -84   8021  0x004C
rpa#c57ca6        1.1   28.5      79   -83   9018  0x004C
static#82cca7     1.2   13.6      50   -84   6022  0x004C
nrpa#58871a       3.3   10.8     345   -56   1038  0xFEF3
nrpa#8b3ab1       6.7   15.5    2821   -40    288  0xFCF1
rpa#495c47       10.6   28.9     686   -84   1106  0x004C
nrpa#80bb2c      10.9   18.4     340   -56   1038  0xFEF3
rpa#599163       11.1   28.5      49   -84   6019  0x004C
static#c3dddf    13.8   28.8      57   -84   8016  0x004C
nrpa#8a9940      15.5   19.8    1464   -39    288  0xFCF1
nrpa#805c4d      18.4   19.9      75   -56   1036  0xFEF3
nrpa#447079      19.9   28.5    6211   -64    137  0xFCF1
rpa#6de1c5       19.9   19.9      13   -63    137  0xFEF3
nrpa#8f471b      19.9   28.7    1394   -64    288  0xFEF3
nrpa#c6e5ab      19.9   28.5    1437   -64    288  0xFEF3
rpa#dcf567       20.3   22.5       2   -96 135818  0x004C
nrpa#b18350      28.5   30.0    1103   -61    137  0xFCF1
nrpa#981485      28.5   32.6     714   -61    288  0xFEF3
nrpa#225c18      28.7   32.6     656   -61    288  0xFEF3
static#9f8e98    28.9   40.0     115   -84   4007  0x004C
rpa#eb84d2       28.9   39.9      85   -84   6006  0x004C
rpa#a061c4       29.1   40.0     905   -84    821  0x004C
rpa#43f048       29.7   39.7      32   -84   8004  0x004C
nrpa#b0fe98      30.0   38.7    6572   -60    137  0xFCF1
rpa#cedcc5       32.6   32.7      13   -69    137  0xFEF3
nrpa#eadbf0      32.6   39.8    1240   -59    287  0xFEF3
nrpa#bbf5be      32.6   40.0    1358   -59    287  0xFEF3
rpa#4753f6       32.8   35.8       2   -94 180286  0x004C
nrpa#11093a      38.7   40.0    1018   -52    137  0xFCF1
nrpa#eec985      39.8   40.0      32   -51    288  0xFEF3
```
