# ble - DTC code -> name decode (`batt_can_od_dispatch` / `dtc` shell dump)

This decodes the large class/subcode jump-table in **`batt_can_od_dispatch`
`0x2c314`** (the `dtc` shell command's active-DTC dump, see `progress.md`) that
was previously left un-transcribed. All addresses are OEM runtime addresses
(image base `0xC000`; the MCUboot header occupies file `0x0..0x200`, so
`runtime = fileoff + 0xBE00`).

## How it is reached

The `dtc` root shell command's static entry is in `.rodata` at `0x7d3d8`
(`{syntax, help="List active DTC's" 0x83eb5, subcmd=0, handler}`); the handler
word at **`0x7d3e4` = `0x2c315`** (Thumb) enters the renderer at `0x2c314`.
The renderer loops the active-DTC container and, per entry, formats one table row
with the format string at `0x83b8b`:

```
%04X | %-14.14s | %-35.35s | %-7u | %2d-%02u-%02u %02u:%02u:%02u UTC | %s
code     device            DTC name        counter   last-occurrence (UTC)     state
```

`state` is `Active` (`0x83aa9`) / `Inactive` (`0x83ab0`); the header line is at
`0x83ab9`.

## Dispatch algorithm

For each 16-bit fault code the renderer splits it into a device class and a
subcode and runs a two-level switch:

```
r2 = code & 0xffff          ; full 16-bit DTC code
r3 = (code >> 8) & 0xff      ; device class  (ubfx r3, code, #8, #8)
r1 = code & 0xff             ; subcode       (uxtb r1, code)
switch (r3) {                ; outer class switch @0x2c176
    0x08 -> 0x2c1ec   0x8d -> 0x2c576   0x90 -> 0x2c530
    0xa1..0xa7 -> 0x2c1b2 (tbh selector 0x2c1b8)
    0xc0..0xc4 -> 0x2c1ca (tbh selector 0x2c1a4)
    default    -> subcode logic / 0x2c208 ("_ERROR")
}
```

Each class handler range-checks `(code - class_base)` and dispatches the subcode
through an inner jump table to a 1-2 instruction leaf stub of the form
`ldr r1, =<name>; b 0x2c59c` (or `mov r1, r5/r6/r7` for a preset default), where
`0x2c59c` is the shared row formatter. The class/device map matches the CAN node
ids already recorded in `progress.md` (0x08 ble, 0x8D BMS, 0x90 power/battery
supervisor, 0xA1 motor_sensor, 0xA2 power_control, 0xA3 charger-timeouts,
0xA4 battery, 0xA7 charger, 0xC0 handlebar, 0xC1 elock, 0xC3 rear carrier,
0xC4 frontlight).

## Inner jump-table catalog (reproduced)

`tbh`/`tbb` targets = `(tbX + 4) + 2 * entry`; `ldrpc` is
`add r0, pc, #4; ldr.w pc, [r0, r1, lsl #2]` over a word table at `((J+2)&~3)+4`.
The guard `cmp r1, #N` just before each table gives the entry count `N+1`, and the
preceding `sub.w r1, r2, #B1 [; subs r1, #B2]` gives the first code `B1(+B2)`.

| table @ | kind  | class | first code | entries | guard |
|---------|-------|-------|------------|---------|-------|
| 0x2c1a4 | tbh   | selector 0xc0..0xc4 | - | 5 | `cmp r0,#4` |
| 0x2c1b8 | tbh   | selector 0xa1..0xa7 | - | 7 | `cmp r3,#6` |
| 0x2c724 | tbb   | 0x08 ble            | 0x0800 | 7  | `cmp r1,#6`  |
| 0x2c6fc | tbh   | 0x8d BMS            | 0x8d14 | 10 | `cmp r1,#9`  |
| 0x2c56c | tbh   | 0x90                | 0x9051 | 3  | `cmp r1,#2`  |
| 0x2c632 | ldrpc | 0x90 (ext)          | 0x90a0 | 20 | `cmp r1,#19` |
| 0x2c4ec | tbh   | 0xa2 power_control  | 0xa214 | 17 | `cmp r1,#16` |
| 0x2c21e | tbh   | 0xa3 charger-to     | 0xa300 | 12 | `cmp r1,#11` |
| 0x2c37a | ldrpc | 0xa4 battery        | 0xa400 | 70 | `cmp r1,#69` |
| 0x2c2b2 | ldrpc | 0xa7 charger        | 0xa701 | 15 | `cmp r1,#14` |
| 0x2c766 | ldrpc | 0xc0 handlebar      | 0xc014 | 10 | `cmp r1,#9`  |
| 0x2c31a | tbh   | 0xc1 elock          | 0xc114 | 4  | `cmp r1,#3`  |

A few codes are matched directly (not via a table), e.g. `0x9000`, `0xa114`,
`0xa115`, `0xa500`/`0xa501`, `0xc314`.

## Decoded DTC-name taxonomy

The name strings are suffix-merged by the `-Os` build, so each leaf pointer lands
*inside* a longer `.rodata` string: the row the shell prints is therefore a
*truncated* tail (e.g. code `0x0800` prints `C_EVENT`), while the full intended
name is the `.rodata` string whose byte-range contains the pointer. The full
names below are recovered by that containment; the raw printed tails are in the
scratch extraction. Several consecutive subcodes alias onto the same string at
different offsets, so treat the per-code column as the class' name *set*, not a
guaranteed 1:1 map.

**0x08 ble (0x0800-0x0806)** - the ble ECU's own CAN/SPI faults:
`CAN_SPI_CRC_EVENT`, `CAN_INVALID_MESSAGE`, `CAN_RESTRICTED_MODE`,
`CAN_TXFIFO_ATTEMPTS`, `SPI_BUSY`, `SPI_IN_PROGRESS`, `TORQUE_VOLTAGE`.
(Neighbouring strings in the same block: `CAN_RX_OVERFLOW`, `CAN_TX_ATTEMPTS`,
`CAN_BUS_ERROR`, `CAN_SYSTEM_ERROR`, `CAN_RAM_ECC_EVENT`.)

**0x8d BMS (0x8d14-0x8d1d)** - battery charge state-machine timeouts:
`BATTERY_CHARGE_WAKE_UP_TIMEOUT`, `BATTERY_CHARGE_MODE_TIMEOUT`,
`BATTERY_CHARGE_MONITOR_TIMEOUT`, `BATTERY_STANDBY_MONITOR_TIMEOUT`.

**0x90 power/battery supervisor (0x9051-0x9053)** - the dump associates
`STUCK_IN_IRQ` and `BATTERY_DISCHARGE_WAKE_UP_TIMEOUT`. NOTE: these do **not**
match the authoritative set-sites: `power_state_smf.c` sets `0x9050` on lipo RSOC
read-fail, `0x9052` on VBAT read-fail, `0x9053` on low-battery shutdown
(RSOC < 11% or VBAT < 3401 mV), and `modem_dtc.c` sets `0x9000` on a malformed
DTC-clear command. The dump's 0x90 sub-table (3 entries over 0x9051-0x9053)
appears to be a generic/placeholder string set; prefer the set-site semantics for
0x90xx meaning.

**0xa2 power_control (0xa214-0xa224)** - BMS/AFE protection + charger status:
`BATTERY_VOLTAGE_TOO_LOW`, `CHARGER_INVALID`, `CHARGER_FW_OUTDATED`,
`CHARGER_IDENTIFICATION_TIMEOUT`, `DEEPLY_DISCHARGED`,
`UNDER_VOLTAGE_THRESHOLD1`, `UNDER_VOLTAGE_THRESHOLD2`,
`OVER_VOLTAGE_THRESHOLD1`, `OVER_VOLTAGE_THRESHOLD2`, `CHARGE_VOLTAGE_WARNING`,
`DISCHARGE_OVERCURRENT_THRESHOLD1`.

**0xa3 charger-timeouts (0xa300-0xa30b)** - more BMS/AFE protection bits:
`DISCHARGE_OVERCURRENT_THRESHOLD2`, `PRE_DISCHARGE_OVERCURRENT`,
`CHARGE_CURRENT_WARNING`, `DISCHARGE_OVER_TEMPERATURE`,
`DISCHARGE_UNDER_TEMPERATURE`, `DISCHARGE_FET_OVER_TEMPERATURE`,
`CELL_IMBALANCE_THRESHOLD1`, `INITIALIZING`, `PRE_CHARGE_TIMEOUT`,
`FW_SIG_FAILED`, `PRE_DISCHARGE_FET_FAILURE`, `PRE_DISCHARGE_OVERLOAD`.

**0xc1 elock (0xc114-0xc117)** - reset-reason enum (shared with
`ble/system/reset_reason`): `SOFTWARE`, `NRSTPIN` (+ a preset default via r7).

**0x90 ext (0x90a0-0x90b3), 0xa4 battery (0xa400-0xa445), 0xa7 charger
(0xa701-0xa70f), 0xc0 handlebar (0xc014-0xc01d)** - these `ldrpc` tables route
almost every slot to the shared default (`_ERROR` at `0x2c208`) or to the row
formatter with a preset default; no per-code names are stored here in this build
(the battery/charger names live under the 0xa2/0xa3 tables above). A handful of
0xa4 slots alias onto unrelated pool words (`DTC_%04X CLEARED`, a light-mode
string) - i.e. dead table entries, not real DTC names.

### Full fault-name string block (`.rodata`, verbatim)

The complete name vocabulary the dump draws from lives at `0x8343a-0x83aa9`
(fault names) and `0x83c56-0x83ca0` (reset-reason / CAN-state enum):

```
BATTERY_MISSING NOT_PROVISIONED RSOC_READ_ERROR WATCHDOG_RESET VBAT_READ_ERROR
SHIPPING_REQUEST NOT_REGISTERED DENIED RESET_LOOP BATTERY_LOW OVERHEATED NO_IMEI
FOC_RATE OVER_VOLTAGE UNDER_VOLTAGE OVER_CURRENT SOFTWARE_ERROR SAMPLE_FAULT
OVERCURRENT_SW DRIVER_PROTECTION MESSAGE_TIMEOUT INIT_ERROR WRITE_ERROR
CAN_RX_OVERFLOW CAN_TX_ATTEMPTS CAN_BUS_ERROR CAN_SYSTEM_ERROR CAN_RAM_ECC_EVENT
CAN_SPI_CRC_EVENT CAN_INVALID_MESSAGE CAN_RESTRICTED_MODE CAN_TXFIFO_ATTEMPTS
SPI_BUSY SPI_TIMEOUT SPI_IN_PROGRESS TORQUE_VOLTAGE HARD_FAULT NMI_HANDLER
DEFAULT_HANDLER STUCK_IN_IRQ BATTERY_DISCHARGE_WAKE_UP_TIMEOUT
BATTERY_DISCHARGE_MODE_TIMEOUT BATTERY_DISCHARGE_MONITOR_TIMEOUT
BATTERY_CHARGE_WAKE_UP_TIMEOUT BATTERY_CHARGE_MODE_TIMEOUT
BATTERY_CHARGE_MONITOR_TIMEOUT BATTERY_STANDBY_MONITOR_TIMEOUT
CHARGER_RAMP_UP_TIMEOUT BATTERY_VOLTAGE_TOO_LOW CHARGER_INVALID
CHARGER_FW_OUTDATED CHARGER_IDENTIFICATION_TIMEOUT DEEPLY_DISCHARGED
UNDER_VOLTAGE_THRESHOLD1 UNDER_VOLTAGE_THRESHOLD2 OVER_VOLTAGE_THRESHOLD1
OVER_VOLTAGE_THRESHOLD2 CHARGE_VOLTAGE_WARNING DISCHARGE_OVERCURRENT_THRESHOLD1
DISCHARGE_OVERCURRENT_THRESHOLD2 PRE_DISCHARGE_OVERCURRENT CHARGE_CURRENT_WARNING
DISCHARGE_OVER_TEMPERATURE DISCHARGE_UNDER_TEMPERATURE
DISCHARGE_FET_OVER_TEMPERATURE CELL_IMBALANCE_THRESHOLD1 CELL_IMBALANCE_THRESHOLD2
INITIALIZING CELL_IMBALANCE PRE_CHARGE_TIMEOUT FW_SIG_FAILED
PRE_DISCHARGE_FET_FAILURE PRE_DISCHARGE_OVERLOAD CELL_THERMISTOR_OPEN
FET_THERMISTOR_OPEN SECONDARY_OVP_TRIGGERED OCP_BY_AFE WATCHDOG OVER_POWER
SHORT_CIRCUIT FUSE_BURN I2C_DRIVER I2C_TIMEOUT I2C_EEPROM STUCK I2C_ERROR
UNDER_CURRENT PREVENTION SPI_ERROR LIST_FULL POWER_CONTROL_MISSING
-- reset/CAN enum: NORESET WAKEUP SOFTWARE NRSTPIN PORSUPPLY BORSUPPLY HWFAULT
   OTHER PASSIVE BUS_OFF
```

## Method / reproduction

- Image: `s6_unpack/v1.8.8.4974/ble.bin` (nRF52840, MCUboot `0x96f3b83d`,
  hdr `0x200`, img `0x89ef0`). Load/disassemble with base `0xBE00`:
  `arm-none-eabi-objdump -D -b binary -m arm -M force-thumb --adjust-vma=0xBE00 ble.bin`
  (so a displayed address equals the runtime address).
- Jump tables and leaf pointers were reproduced statically (Capstone) and
  cross-checked by emulating the dispatch (Unicorn, enter at `0x2c16a` with the
  code in `[sp,#104]`) and by Ghidra 11.2 headless analysis. The full per-code
  extraction is in the analysis scratch, not committed.
- Caveat: Ghidra's decompiler fails this function with
  `Low-level Error: Case block has become detached from switch` (shared case
  tails across the nested class/subcode tables), so the switch was reconstructed
  from the raw tables rather than from decompiler output. The suffix-merged
  string pool means the shell prints truncated name tails; the full names here
  are the containing `.rodata` strings.

## Open items

- Pin the exact 1:1 subcode->name for the aliased slots (several codes share a
  base string at different offsets) - best done in the Ghidra GUI with a manual
  jump-table override per table, which also sidesteps the "detached switch"
  decompiler error.
- Reconcile the 0x90xx dump names against the `power_state_smf.c` /
  `modem_dtc.c` set-sites (the dump table looks generic/partially stale for 0x90).
- The 0xa1 (motor_sensor), 0xc3 (rear carrier) and 0xc4 (frontlight) class
  handlers are reached via the two selector `tbh` tables (`0x2c1a4`, `0x2c1b8`)
  but their sub-tables were not fully transcribed here.
