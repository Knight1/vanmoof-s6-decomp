# ble - DTC code -> name decode (`batt_can_od_dispatch` / `dtc list` dump)

This decodes the class/subcode jump-table in **`batt_can_od_dispatch` `0x2c314`**,
the renderer behind the `dtc list` shell command's active-DTC table.

All addresses are OEM runtime addresses. The image is the MCUboot slot: the file
is mapped at `0xC000` (the 96-byte MCUboot header occupies `0xC000..0xC200`), and
the application vector table / link base is `0xC200`, so **`runtime VMA =
fileoff + 0xC000`**. (An earlier pass of this file used `fileoff + 0xBE00`, i.e.
the vector table at `0xC000`; that was 0x200 low and mis-resolved the
suffix-merged name pool. Every address and name below has been re-derived at the
correct base and cross-checked against the decompiler.)

## How it is reached

`dtc` is a shell command with a `list` subcommand (name string `0x8589e`
`"list"`, help `0x83eb5` `"List active DTC's"`). Its static descriptor lives in
`.rodata` at `0x7d5d8` as `{name, help, subcmds=0, handler}`; the handler word at
**`0x7d5e4` = `0x2c315`** (Thumb) enters the renderer at `0x2c314`.

The renderer prints a header + rule line, then loops the active-DTC container and
formats one row per entry with the format string at `0x83d8b`:

```
%04X | %-14.14s | %-35.35s | %-7u | %2d-%02u-%02u %02u:%02u:%02u UTC | %s
code     device            DTC name        counter   last-occurrence (UTC)     state
```

- header line `0x83cb9`, rule line `0x83d22`
- `state` is `Active` (`0x83ca9`) or `Inactive` (`0x83cb0`)

## Dispatch algorithm

Each 16-bit fault code is split into a device class and a subcode and run through
a two-level switch (`0x2c36c`):

```
r2 = code & 0xffff           ; full 16-bit DTC code            (uxth)
r3 = (code >> 8) & 0xff       ; device class                    (ubfx r3,r1,#8,#8)
r1 = code & 0xff              ; subcode                         (uxtb r1,r1)

switch (class) {              ; @0x2c36c..0x2c3ea
    0x08 -> 0x2c3ec
    0x8d -> 0x2c776
    0x90 -> 0x2c730
    0xa1..0xa7 -> selector tbh @0x2c3bc   (r3-0xa1)
    0xc0..0xc4 -> selector tbh @0x2c3a8   (class-0xc0)
}
```

The row has two name columns:

- **device name** (`%-14.14s`): a per-class pointer (`puVar8`).
- **DTC name** (`%-35.35s`): for **subcode < 0x14** it comes from a *shared*
  subcode table (`0x7d574`, indexed by subcode); subcode `0x13` is forced to
  `UNKNOWN`. For **subcode >= 0x14** it comes from the per-class inner jump table.

Each inner table routes to a leaf stub `ldr r1, =<name>; b 0x2c79c` (`0x2c79c` is
the shared row formatter), or to a preset default (`mov r1, r5/r6/r7`).

## Device-name column (per class)

| class | device name   | notes |
|-------|---------------|-------|
| 0x08  | `monitor`     | watches the CAN bus for missing modules |
| 0x8d  | `motor_control` | |
| 0x90  | `ble`         | this ECU's own + modem/connectivity faults |
| 0xa1  | `motor_sensor` | |
| 0xa2  | `power_control` | CAN/SPI/CPU faults |
| 0xa3  | `power`       | battery/charger state-machine timeouts |
| 0xa4  | `battery`     | BMS/AFE protection |
| 0xa7  | `charger`     | |
| 0xc0  | `handlebar`   | |
| 0xc1  | `elock`       | |
| 0xc3  | `rearlight`   | |
| 0xc4  | `frontlight`  | |
| other | `UNKNOWN`     | pointer `0x835a7` |

## Generic subcode-name table (`0x7d574`, subcode 0x00-0x13)

For any device, subcodes below `0x14` name a reset reason / CAN state (the DTC
is `(class << 8) | subcode`, so e.g. `0xa202` prints device `power_control`,
name `SOFTWARE`):

| subcode | name | subcode | name |
|---------|------|---------|------|
| 0x00 | `NORESET`  | 0x08 | `OTHER` |
| 0x01 | `WAKEUP`   | 0x09-0x0f | `UNKNOWN` |
| 0x02 | `SOFTWARE` | 0x10 | `WARNING` |
| 0x03 | `NRSTPIN`  | 0x11 | `PASSIVE` (CAN error-passive) |
| 0x04 | `PORSUPPLY`| 0x12 | `BUS_OFF` (CAN bus-off) |
| 0x05 | `BORSUPPLY`| 0x13 | `UNKNOWN` (forced in code) |
| 0x06 | `HWFAULT`  |      | |
| 0x07 | `WATCHDOG` |      | |

## Inner jump-table catalog (reproduced)

`tbh`/`tbb` targets = `(tbX + 4) + 2 * entry`; `ldrpc` is
`adr r0, <tbl>; ldr.w pc, [r0, r1, lsl #2]` over a word table. The guard
`cmp r1, #N` just before each table gives the entry count `N+1`, and the preceding
`sub.w r1, r2, #base [; subs r1, #k]` gives the first code.

| table @ | kind  | class | first code | entries | guard @ |
|---------|-------|-------|------------|---------|---------|
| 0x2c3a8 | tbh   | selector 0xc0..0xc4 | -      | 5  | `cmp r0,#4`  @0x2c3a0 |
| 0x2c3bc | tbh   | selector 0xa1..0xa7 | -      | 7  | `cmp r3,#6`  @0x2c3b4 |
| 0x2c928 | tbb   | 0x08 monitor        | 0x0801 | 7  | `cmp r1,#6`  @0x2c91e |
| 0x2c900 | tbh   | 0x8d motor_control  | 0x8d14 | 10 | `cmp r1,#9`  @0x2c8f6 |
| 0x2c770 | tbh   | 0x90 ble            | 0x9051 | 3  | `cmp r1,#2`  @0x2c766 |
| 0x2c838 | ldrpc | 0x90 ble (ext)      | 0x90a0 | 20 | `cmp r1,#0x13` @0x2c82a |
| 0x2c6f0 | tbh   | 0xa2 power_control  | 0xa214 | 17 | `cmp r1,#0x10` @0x2c6e6 |
| 0x2c422 | tbh   | 0xa3 power          | 0xa300 | 12 | `cmp r1,#0xb` @0x2c41a |
| 0x2c580 | ldrpc | 0xa4 battery        | 0xa400 | 70 | `cmp r1,#0x45` @0x2c572 |
| 0x2c4b8 | ldrpc | 0xa7 charger        | 0xa701 | 15 | `cmp r1,#0xe` @0x2c4ac |
| 0x2c96c | ldrpc | 0xc0 handlebar      | 0xc014 | 10 | `cmp r1,#9`  @0x2c95e |
| 0x2c51e | tbh   | 0xc1 elock          | 0xc114 | 4  | `cmp r1,#3`  @0x2c514 |

Codes matched directly (not via a table): `0x9000`, `0x9050`, `0xa114`, `0xa115`,
`0xa500`-`0xa503`, `0xc314`, `0xc414`, `0xff00`.

## DTC-name catalog (code -> name, verified)

Resolved by following each leaf's literal pointer to its NUL-terminated `.rodata`
string. The `-Os` build suffix-merges these strings (e.g. `DISCHARGE_...` at
`0x83a51` and `CHARGE_...` at `0x83a54` share the tail via the dropped `DIS`
prefix), but each pointer still terminates at its own name, so the names below are
exact.

**0x08 monitor** - missing-module detector (`0x0800` = `POWER_CONTROL_MISSING`
default):
```
0x0801 HANDLEBAR_MISSING      0x0805 FRONTLIGHT_MISSING
0x0802 ELOCK_MISSING          0x0806 REARLIGHT_MISSING
0x0803 MOTOR_CONTROL_MISSING  0x0807 BATTERY_MISSING
0x0804 MOTOR_SENSOR_MISSING
```

**0x8d motor_control** (0x8d14-0x8d1d):
```
0x8d14 FOC_RATE         0x8d19 SOFTWARE_ERROR
0x8d15 OVER_VOLTAGE     0x8d1a SAMPLE_FAULT
0x8d16 UNDER_VOLTAGE    0x8d1b OVERCURRENT_SW
0x8d17 OVER_TEMPERATURE 0x8d1c DRIVER_PROTECTION
0x8d18 OVER_CURRENT     0x8d1d MESSAGE_TIMEOUT
```

**0x90 ble** - self-diagnostics + modem/connectivity:
```
0x9000 NOT_PROVISIONED   0x90a0 NOT_REGISTERED   0x90b0 RESET_LOOP
0x9050 RSOC_READ_ERROR   0x90a1 DENIED           0x90b1 BATTERY_LOW
0x9051 WATCHDOG_RESET    0x90a2 FAILED           0x90b2 OVERHEATED
0x9052 VBAT_READ_ERROR                           0x90b3 NO_IMEI
0x9053 SHIPPING_REQUEST
```
`0x9052`/`0x9053` match the `power_state_smf.c` set-sites (VBAT read-fail,
low-battery shutdown); `0x9050` matches lipo RSOC read-fail.

**0xa1 motor_sensor**: `0xa114 INIT_ERROR`, `0xa115 WRITE_ERROR`.

**0xa2 power_control** (0xa214-0xa224) - CAN/SPI/CPU faults:
```
0xa214 CAN_RX_OVERFLOW     0xa21b CAN_RESTRICTED_MODE  0xa221 HARD_FAULT
0xa215 CAN_TX_ATTEMPTS     0xa21c CAN_TXFIFO_ATTEMPTS  0xa222 NMI_HANDLER
0xa216 CAN_BUS_ERROR       0xa21d SPI_BUSY             0xa223 DEFAULT_HANDLER
0xa217 CAN_SYSTEM_ERROR    0xa21e SPI_TIMEOUT          0xa224 STUCK_IN_IRQ
0xa218 CAN_RAM_ECC_EVENT   0xa21f SPI_IN_PROGRESS
0xa219 CAN_SPI_CRC_EVENT   0xa220 TORQUE_VOLTAGE
0xa21a CAN_INVALID_MESSAGE
```

**0xa3 power** (0xa300-0xa30b) - battery/charger state-machine timeouts:
```
0xa300 BATTERY_DISCHARGE_WAKE_UP_TIMEOUT   0xa306 BATTERY_STANDBY_MONITOR_TIMEOUT
0xa301 BATTERY_DISCHARGE_MODE_TIMEOUT      0xa307 CHARGER_RAMP_UP_TIMEOUT
0xa302 BATTERY_DISCHARGE_MONITOR_TIMEOUT   0xa308 BATTERY_VOLTAGE_TOO_LOW
0xa303 BATTERY_CHARGE_WAKE_UP_TIMEOUT      0xa309 CHARGER_INVALID
0xa304 BATTERY_CHARGE_MODE_TIMEOUT         0xa30a CHARGER_FW_OUTDATED
0xa305 BATTERY_CHARGE_MONITOR_TIMEOUT      0xa30b CHARGER_IDENTIFICATION_TIMEOUT
```

**0xa4 battery** (0xa400-0xa445) - BMS/AFE protection. The switch pairs the
`0xa4(0x00..0x16)` block with `0xa4(0x20..0x36)` (same name for both), then
`0xa418`, `0xa419` and `0xa438+` are distinct:
```
0xa400/0xa420 DEEPLY_DISCHARGED              0xa411/0xa431 DISCHARGE_UNDER_TEMPERATURE
0xa401/0xa421 UNDER_VOLTAGE_THRESHOLD1       0xa412/0xa432 CHARGE_OVER_TEMPERATURE
0xa402/0xa422 UNDER_VOLTAGE_THRESHOLD2       0xa413/0xa433 CHARGE_UNDER_TEMPERATURE
0xa403/0xa423 OVER_VOLTAGE_THRESHOLD1        0xa415/0xa435 CHARGE_FET_OVER_TEMPERATURE
0xa404/0xa424 OVER_VOLTAGE_THRESHOLD2        0xa416/0xa436 DISCHARGE_FET_OVER_TEMPERATURE
0xa405/0xa425 CHARGE_VOLTAGE_WARNING         0xa418 CELL_IMBALANCE_THRESHOLD1
0xa408/0xa428 DISCHARGE_OVERCURRENT_THRESHOLD1  0xa419 CELL_IMBALANCE_THRESHOLD2
0xa409/0xa429 DISCHARGE_OVERCURRENT_THRESHOLD2  0xa438 INITIALIZING
0xa40a/0xa42a CHARGE_OVERCURRENT_THRESHOLD1  0xa439 CELL_IMBALANCE
0xa40b/0xa42b CHARGE_OVERCURRENT_THRESHOLD2  0xa43a PRE_CHARGE_TIMEOUT
0xa40d/0xa42d PRE_DISCHARGE_OVERCURRENT      0xa43b FW_SIG_FAILED
0xa40e/0xa42e CHARGE_CURRENT_WARNING         0xa43c PRE_DISCHARGE_FET_FAILURE
0xa410/0xa430 DISCHARGE_OVER_TEMPERATURE     0xa43d DISCHARGE_FET_FAILURE
0xa43e CHARGE_FET_FAILURE                    0xa440 CELL_THERMISTOR_OPEN
0xa43f PRE_DISCHARGE_OVERLOAD               0xa441 FET_THERMISTOR_OPEN
0xa444 SECONDARY_OVP_TRIGGERED              0xa445 OCP_BY_AFE
```

**0xa7 charger** (0xa701-0xa70f), with `0xa701..0xa704` aliased to
`0xa709..0xa70c`:
```
0xa701/0xa709 OVER_VOLTAGE    0xa704/0xa70c OVER_POWER   0xa70e SHORT_CIRCUIT
0xa702/0xa70a UNDER_VOLTAGE   0xa70d OVER_TEMPERATURE    0xa70f FUSE_BURN
0xa703/0xa70b OVER_CURRENT
```

**0xc0 handlebar** (0xc014-0xc01d), with `0xc014..0xc016` aliased to
`0xc017..0xc019`:
```
0xc014/0xc017 I2C_DRIVER    0xc016/0xc019 I2C_EEPROM
0xc015/0xc018 I2C_TIMEOUT   0xc01a-0xc01d STUCK
```

**0xc1 elock** (0xc114-0xc117):
```
0xc114 I2C_ERROR   0xc115 UNDER_CURRENT   0xc116 UNDER_VOLTAGE   0xc117 PREVENTION
```

**0xc3 rearlight**: `0xc314 SPI_ERROR`.
**0xc4 frontlight**: `0xc414 SPI_ERROR`.
**Direct**: `0xff00 LIST_FULL`; class `0xa5` (minor/placeholder) `0xa500/0xa502
READ_ERROR`, `0xa501/0xa503 WATCHDOG`.

## Method / reproduction

- Image: `s6_unpack/v1.8.8.4974/ble.bin` (nRF52840, MCUboot `0x96f3b83d`,
  hdr `0x200`, img `0x89ef0`, 565639 bytes). Load as raw ARM Cortex-M at base
  `0xC000` (whole file including the MCUboot header), so a program VMA equals the
  OEM runtime address.
- The two-level switch and all 12 inner jump tables were taken from the
  decompiler and the function disassembly of `batt_can_od_dispatch` `0x2c314`;
  the `tbh`/`tbb`/`ldrpc` tables and their guards are listed above.
- Each leaf's literal pointer was resolved to its NUL-terminated `.rodata` string
  at base `0xC000`; this recovers the full names despite the `-Os` suffix merge.
- Cross-checks: the row-format pointer `0x83d8b` resolves to the `%04X | ...`
  format string, and `0x9052`/`0x9053` resolve to `VBAT_READ_ERROR` /
  `SHIPPING_REQUEST`, matching the `power_state_smf.c` set-sites.

## Notes

- `dtc` codes are `(device_class << 8) | subcode`; a device prints its own class.
- Subcodes `0x00-0x12` are reset-reason / CAN-state names shared across devices;
  per-fault names start at subcode `0x14`.
- Class `0xa4` and `0xa7`/`0xc0` have aliased subcode blocks (documented inline);
  the `0xa5` class is a thin placeholder with only `READ_ERROR`/`WATCHDOG`.
