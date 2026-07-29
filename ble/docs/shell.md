# ble — debug-shell command surface

> The `ble` image carries a **Zephyr shell** (UART/RTT) exposing the whole bike
> for diagnostics. This maps the VanMoof command groups and the shell-table
> layout so the CLI handlers can be recovered. The handlers themselves are **thin
> `argc`/`argv` wrappers** over the subsystems already reconstructed in
> `ble/src/` (battery/charger, elock, power-state, FMNA, modem/DTC, audio, …), so
> they are **recovered + named in Ghidra but not individually reconstructed to C**
> (per the scope note in `CLAUDE.md`).

## Command groups (VanMoof)

Each group is a `SHELL_CMD_REGISTER` root whose help string is `"<X> commands"`:

| Group | help string | addr | subsystem it drives |
| --- | --- | --- | --- |
| `bell` | "Bell sound commands" | `0x815c9` | audio_bell |
| `lock` | "Lock commands" | `0x81ed0` | elock / backup-unlock |
| `lipo` | "Lipo Manager commands" | `0x831b5` | batt_mgmt (lipo gauge) |
| `charger` (int) | "Internal charger commands" | `0x832b8` | battery_charger |
| `dtc` | "DTC commands" | `0x83ea8` | modem_dtc / dtc_set |
| `modem` | "Modem commands" | `0x842d5` | modem_dtc |
| `rings` | "Rings commands" | `0x85272` | handlebar LED ring (CAN) |
| `update` | "Update commands" | `0x8587a` | firmware update |
| `power` | "Power commands" | `0x86212` | power_state |
| `battery` | "Battery commands" | `0x86221` | batt_mgmt |
| `charger` | "Charger commands" | `0x86232` | battery_charger |
| `can` | "CAN commands" | `0x86247` | vmtp_can |
| `updatestate` | "Update state commands" | `0x86254` | power_state (update SMF) |
| `lights` | "Lights commands" | `0x8626a` | front/rear light (CAN) |
| `motor` | "Motor controller commands" | `0x8627a` | motor_control (CAN) |
| `handlebar` | "Handlebar commands" | `0x86294` | handlebar (CAN) |
| `powerecu` | "PowerECU commands" | `0x862b0` | power_control (CAN) |
| `elock` | "Elock commands" | `0x862c2` | elock / elock_report |
| `capacity` | "Capacity sub-commands" | `0x862d6` | batt_mgmt (design cap) |
| `fmna` | "Apple FindMy commands" | `0x86b94` | fmna_glue / fmna_sound |
| `aem` | "Application Event Manager commands" | `0x887d1` | AEM bus |

(Zephyr built-ins — `kernel`, `device`, `date`, the `vt100`/wildcard helpers — are
vendor and out of scope.)

## Shell-table layout (reverse-engineered)

The Zephyr shell entry here is a **20-byte** record (not the stock 16-byte
`shell_static_entry` — this NCS build carries a trailing flags word):

```
struct entry {            // 20 bytes
    const char       *syntax;   // +0x00  command word
    const char       *help;     // +0x04  help string (== syntax for leaves)
    const void       *subcmd;   // +0x08  child set (0 for a leaf)
    shell_cmd_handler handler;  // +0x0c  Thumb fn ptr (0 for a parent group)
    uint32_t          flags;    // +0x10
};
```

- A **group's `subcmd`** points to a small union header whose first word is the
  child array: `array = *(u32*)subcmd` (equivalently `subcmd + 4`).
- The child array is a run of 20-byte `entry`s **terminated by a zero `syntax`**.
- **Leaf command** ⇒ `handler != 0` ⇒ the CLI function to recover
  (`create_function(handler & ~1)`); name it `<group>_cmd_<syntax>`.
- **Sub-group** ⇒ `handler == 0`, `subcmd != 0` ⇒ recurse.

The root entries live at `~0x7dd30`; the child arrays at `~0x7de00`–`0x7e900`.
Group entry located via `getReferencesTo(help_addr)` in the `0x7d000–0x7f800`
data window: `entry = ref − 4`, `subcmd = *(entry + 8)`.

## Recovery status — DONE

The full sweep was executed by the standalone Ghidra script
[`ghidra_scripts/RecoverBleShellCmds.java`](../../../ghidra_scripts/RecoverBleShellCmds.java)
(the MCP script runner is disabled here, so it runs from the Ghidra Script Manager).
It walks each group's `subcmd` array (deref, stride 20, leaf `handler`@`+0x0c`),
`create_function`s each undefined handler, and names it `<group>_cmd_<syntax>`.

**Result: 54 command handlers recovered + named across all 21 groups** (Ghidra
2847 → 2981 functions). Verified against the OEM decompile that they are real
`argc`/`argv` wrappers calling the reconstructed subsystems, e.g.:

- `battery_cmd_on` `0x33100` → parses `on`/`off` → `ps_power_on_request(3)` /
  `ps_power_off_request(3)`
- `dtc_cmd_clear` `0x2cf60` → clears the DTC store + shell-prints
- `fmna_cmd_pair` `0x33f00`, `fmna_cmd_enable` `0x33d60`, `fmna_cmd_state` `0x33780`
- `update_cmd_install`/`list`/`start`/`version`, `rings_cmd_play`/`soc`,
  `aem_cmd_show_events`/`show_subscribers`, `lock_cmd_lock`/`unlock`,
  `capacity_cmd_get`/`set`, `elock_cmd_power`/`reset`, …

The script is idempotent (safe to re-run) and aborts if pointed at the wrong
program/base. Re-run the `ble/ghidra/exports/ble_program.json` export to capture the
new names.
