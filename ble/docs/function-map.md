# ble — VanMoof app function map

> Inventory of the VanMoof-authored functions in the S6 `ble` image (Nordic
> nRF52840, base `0xC000`), built by log-string anchoring (workflow
> `s6-ble-app-map`, 10 agents). **94 functions** classified: 75 `app`, 17 `glue`,
> 2 `vendor`. Addresses are OEM (image base `0xC000`). Names are the
> reconstruction targets; apply them in Ghidra and keep
> `ghidra/exports/ble_program.json` in sync.

## ⚠️ Dominant finding — app code in dispatch/shell-table gaps

Much of the highest-value app code is **not auto-defined by Ghidra**: handlers are
reached only through indirect dispatch tables (the BLE record table at
`0x30800`/`0x30a90`, the Zephyr **shell command tables**, the power-state **SMF**
descriptor tables, and the OD command table). The recursive analyzer never
created functions for them — `get_function_by_address` returns "No function" and
string xrefs resolve only to `[DATA]`. This is the S5 `elock` 85→131 pattern
(CLAUDE.md → Gotchas). **Recovery:** `disassemble_bytes` + `create_function` at
the table-referenced entries, then re-anchor. Gap clusters to recover (high value):

- **CAN/OD command dispatch** (the BLE→CAN command bridge): around `0x2e186`,
  `0x30aa0`, and `0x2c000–0x31000`. Strings: "com.vanmoof.app:command" (`0x84fd1`),
  "unable to get command data", "missing command record", "command not allowed"
  (`0x84b8d`), "cannot parse message", "ipipe dispatch failed".
- **Backup-unlock (SECURITY)**: offline unlock-code path. Shell table `0x7dbf8`,
  settings key `backup_unlock/code` (`0x853c2`), `backup_unlock_verify` (`0x85424`),
  lockout strings `0x81a7a/0x81aa8`. **High-priority security target.**
- **Power-state SMF handlers** reached via rodata state tables `0x29200–0x2b600`
  (power-on/off request, "go to shipping mode in 5s", "cut power in %d s").
- **Battery/Charger/Capacity CLI** handlers: gap `0x32xxx–0x33xxx`.
- **elock** shell + sensor/report handlers: `0x32fac`, `0x32d78`, `0x2cxxx`.
- **Modem/DTC/Device shell** handlers: `0x2dbb0/0x2dc64/0x2dcfc`, tables
  `0x7d740/0x7d790/0x7e3b8`.
- **FMNA glue** (sound start/stop/timeout, enable/disable/toggle, BT-ID create):
  `0x33b00–0x34000`, shell table `0x7e174`.
- **identity/ODO/service-mode**: `0x2d508/0x2d6a0/0x2d604/0x31ff0/0x28134/0x3213c`
  (verified by disassembly; need `create_function`).

## Common anchors / infrastructure (vendor unless noted)

- **VanMoof log** (the universal anchor): `vm_logf` wrapper `0x6efea` → core
  `0x6ef6a` (also `0x6efd8`/`0x6effe`/`0x6f948` snprintf/`0x6f980` printf,
  `0x364f0` obj-publish-log). First arg = per-subsystem log-module pointer; a
  `(*module & 7)` level gate guards each call.
- **OD/CAN publish**: `0x364f0` / `0x6d586` / `0x6d5aa` (object publish by id).
- **App Event Manager** (the S6 internal bus, ≈ S5 MQTT): publish `0x79b92` /
  `0x79bb2`; event alloc `0x77cfc`; submit `0x55564`; settings store `0x38234`.
- **Vendor crypto** (skip): `ec_signature_verify_core` `0x68880` (EC verify),
  `ble_pkt_buf_alloc` `0x565d4` (net_buf pool).

## Inventory by subsystem

Legend: cls = app / glue / vendor · pri = recon priority · `*gap*` = needs
`create_function` first (verified by disassembly, not yet a Ghidra function).

### 1. auth-ble-vmtp — phone auth + BLE→CAN bridge (HIGHEST)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x56fd4 | vmtp_auth_record_handler | app | high | core BLE auth dispatcher; verifies cert + 0x40-byte challenge, sets session role byte (state+0x1e), builds auth response; wipes 0x80-byte session on fail |
| 0x5732c | vmtp_auth_cert_extract | app | high | pulls cert+sig blob from inbound record, forwards to verifier |
| 0x572b4 | vmtp_auth_signature_verify | app | high | enforces 64-byte sig length, drives EC verify (`0x68880`) + cert-chain check |
| 0x5dddc | vmtp_can_init | app | high | VMTP-over-CAN bring-up: CAN dev open, RX thread (prio 5), endpoint register |
| 0x25920 | ble_gatt_notify_send | app | med | GATT notify wrapper (status/challenge/command responses) |
| 0x5dd4c | vmtp_zephyr_can_tx_done | glue | low | CAN TX-complete/error callback; "CAN TX ERROR %d", tx-err ctr state+0xc5c |
| 0x68880 | ec_signature_verify_core | vendor | — | EC signature verify (Nordic oberon); **do not reconstruct** |
| 0x565d4 | ble_pkt_buf_alloc | vendor | — | net_buf-style response pool; **do not reconstruct** |

> Session/auth state object (param_2 of `0x56fd4`): +0x1a..0x46 = 16-byte
> challenge nonce + role/key material; +0x1e = auth result/role (0x01 ok, 0xfe
> special, 0xff fail). BLE record types = string-pointer dispatch table
> `0x30800–0x30ac0` (`com.vanmoof.app:challenge/status/certificate/command/signature`
> + pairing URL `0x84eb7`). Log modules: `auth_certificate_validator` `0x81143`,
> `vmtp_zephyr` `0x8ed75`.

### 2. can-dispatch / power-rail (HIGH)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x2ad44 | can_power_off | app | high | CAN power-rail consumer refcount; on last release schedules delayed power-off (0x60000) |

> The per-opcode VMTP-RX / OD command handlers are in the dispatch gap (see top).

### 3. power-state — Zephyr SMF lifecycle FSM (HIGH)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x29048 | ps_power_on_request | app | high | power-on for a consumer; refuses in shipping mode (-EINVAL), sets bit, publishes |
| 0x29134 | ps_power_off_request | app | high | power-off for a consumer; on last clear → power off + publish |
| 0x28f38 | ps_power_state_publish | app | high | publish power_state byte as TOPIC_POWER_STATE event |
| 0x28f98 | ps_power_state_set | app | high | set power_state (if changed), log "Change state from %s to %s", publish |
| 0x2900c | ps_power_state_get | app | low | return power_state byte |
| 0x28e14 | ps_consumer_bit_clear | app | low | atomic LDREX/STREX clear of a consumer bit |
| 0x29904 | ps_standby_entry | app | high | SMF standby entry; arm CAN-standby timer; power_state=3 |
| 0x29a9c | ps_standby_run | app | med | SMF standby run; ensure standby + reschedule work |
| 0x295f0 | ps_charge_state_entry | app | high | SMF charge entry; OD cmd 0xa300; publish payload 5 |
| 0x296dc | ps_charge_wakeup_run | app | high | OD cmd 0xa301 + reschedule |
| 0x29c98 | ps_discharge_state_entry | app | high | SMF discharge entry; OD cmd 0xa303; publish payload 2 |
| 0x29d88 | ps_discharge_wakeup_run | app | high | OD cmd 0xa304 + reschedule |
| 0x29ef4 | ps_update_state_entry | app | high | SMF fw-update entry; timer + publish 3 |
| 0x294d4 | ps_state_entry_log_only | app | low | SMF entry: log + re-arm work |
| 0x29a58 | ps_state_entry_log_only_2 | app | low | twin of `ps_state_entry_log_only` (ICF-fold suspect) |
| 0x29868 | ps_state_run_reschedule | app | low | SMF run: reschedule work (0x8000) |
| 0x29fc0 | ps_state_run_reschedule_2 | app | low | twin of `ps_state_run_reschedule` (ICF-fold suspect) |
| 0x2cec4 | ps_canbus_od_send | glue | med | send CAN/OD command by id via driver vtable |
| 0x2a88c | ps_publish_state_evt2 | glue | low | publish 2-byte power-state event |
| 0x2a400 | ps_publish_empty_evt_a | glue | low | publish parameterless event |
| 0x2a424 | ps_publish_evt_4b | glue | low | publish 4-byte event |
| 0x2a44c | ps_set_flag_publish_1b | glue | low | set status bit1, reset timers, publish |
| 0x2a484 | ps_set_charging_flag_publish | glue | med | set status bit2 (charging/active), (re)arm work, publish |

### 4. battery-charger (HIGH)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x590cc | charger_write_config_registers | app | high | encode+write charger-IC CHARGE_CONTROL0..4 / TIMER regs from config |
| 0x58b5c | charger_set_fast_charge_current | app | high | fast-charge current limit; **refuses > pack max** (safety clamp) |
| 0x2b100 | charger_update_charge_current | app | high | charge-current update tied to power-state; applies new current |
| 0x58db8 | charger_set_discharge_current_limit | app | med | discharge current limit reg with min/max clamp |
| 0x2aa54 | charger_identify | app | high | identify Liteon charger (normal 2kW vs speed 5kW) by id match |
| 0x2aaec | charger_publish_detected_event | app | med | post charger-detected AEM event (id 0x23/0x1b2) |
| 0x2ab90 | charger_publish_status_event | app | low | publish short charger status event |
| 0x5aaec | battery_gauge_init | app | high | fuel-gauge init: id check (0x220), config load, design-cap verify, BTP GPIO |
| 0x5a158 | battery_gauge_write_config | app | high | program gauge regs 0x929b..0x92d1; verify design capacity |
| 0x5aa6c | battery_set_btp_charge_threshold | app | med | program BTP charge threshold (% of design cap) into reg 0x36 |

> Device ctx: +4 = i2c handle, +0x28 = pack max current; gauge +0x2a = design
> cap, +0x24 = last BTP, +0x10 = config struct. Battery log module `0x82b54`.

### 5. elock (HIGH)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x278fc | elock_state_machine_step | app | high | core FSM: dispatch on reported/target lock-state, drive motor, stuck-retry, OD 0x164 |
| 0x27380 | elock_set_lock_state | app | high | set/request lock state under mutex; OD 0x1cc0; entry cb + transition |
| 0x272d8 | elock_fsm_transition | app | high | commit transition under mutex; OD 0x28c0; per-state cb from 0x34-stride table |
| 0x283f0 | elock_touch_unlock_request | app | high | touch-unlock: log, OD frame 0x1900, OD set 0x163, run unlock |
| 0x27b64 | elock_unlock_complete | app | high | on pending-unlock: report state 0, time unlock, post completion event |
| 0x277e4 | elock_drive_unlock_pulse | app | high | enable motor power domain, current-limited motor drive pulse |
| 0x28760 | elock_report_lock_state | app | med | publish lock-state byte: OD 0x160 + AEM |
| 0x28a9c | elock_is_present | app | med | presence/availability check; gates unlock |
| 0x2719c | elock_state_differs | app | low | reported vs requested state compare (mutex) |
| 0x27190 | elock_mutex_unlock | glue | low | release elock state mutex |
| 0x2873c | elock_request_present_init | glue | low | post presence-discovery query on AEM |
| 0x2ad9c | actuator_power_domain_enable | app | med | refcounted actuator/motor power-rail enable (shared w/ motor) |

### 6. fmna-glue — Apple Find My integration (MED)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x338c4 | app_fmna_app_state_get | app | high | central FMNA state reporter; publishes OD 0x280; called by all callbacks |
| 0x254f8 | fmna_update_owner_connections | app | high | format/publish owner BLE addr (OD 0x2500); toggle name VANMOOF↔VANMOOF-FindMy |
| 0x33ca8 | fmna_app_enable | app | high | enable FMNA; gated by stolen-mode; runs serial provisioning + stack enable |
| 0x33c38 | fmna_app_update_serial_number | app | high | provision serial = frame-id (fallback ecu-id) → key `fmna/provisioning/997` |
| 0x33e00 | fmna_app_factory_reset | app | high | FMNA factory reset/disable; stolen-mode gated |
| 0x338d8 | fmna_app_location_availability_changed | glue | med | location enabled/disabled cb; OD 0x2500 |
| 0x33948 | fmna_app_paired_state_changed | glue | med | paired-state cb; OD 0x1cc0; play findmy success/disabled cue |
| 0x339f0 | fmna_app_pairing_mode_exited | glue | med | pairing-exit cb; OD 0x1900 code 3 |
| 0x62270 | fmna_stolen_mode_get | app | low | read stolen-mode security bit ((*state&7)>>2); the FMNA-enable gate |
| 0x3197c | alarm_stolen_set | app | med | set stolen flag (alarm subsystem); source of stolen condition |
| 0x319b8 | alarm_stolen_clear | app | med | clear stolen/recovery; re-enable FMNA gate |
| 0x62288 | fmna_stack_enable | glue | med | Apple FMN stack init sequence (conn/storage/keys/state + battery) |
| 0x5e5e4 | fmna_battery_level_check_init | glue | low | guard: is FMNA battery level initialized (likely vendor — confirm) |

### 7. audio-bell (MED/LOW)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x26794 | audio_play | app | high | play-sound API (wav path, type 0xd/0xe, count); -EBUSY if already playing |
| 0x26740 | audio_enqueue_play_cmd | app | high | build 0x10-byte cmd, copy wav path, k_msgq_put to worker `DAT_00026790` |
| 0x2671c | audio_player_reset | app | med | reset player state before new playback |
| 0x27568 | audio_play_by_index | app | low | play wav N from lookup table (type 0xe) |
| 0x27c4c | audio_play_event_cue | app | med | event-driven cue (type 0xe) + follow-up timer |
| 0x27fa8 | audio_play_timed_cue | app | low | timed cue + deferred-work completion |
| 0x31944 | audio_play_on_config_event | app | low | setting-change confirmation sound (type 0xd) |
| 0x2694c | audio_play_current_bell | app | high | `*gap*` play selected bell (push/release variant) |
| 0x269c0 | audio_set_bell_index | app | med | `*gap*` set/persist bell selection (bounds ≤7) |
| 0x269e0 | audio_set_mute_level | app | med | `*gap*` store mute level (suppress low-priority files) |

### 8. modem-dtc-device (MED)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x25c20 | modem_reset_set | app | high | drive modem RESET pin (1 normal / 0 held); "Reset modem to %s" |
| 0x25f44 | modem_reset_state_handler | app | high | modem connect/disconnect → toggle reset line |
| 0x2ce30 | dtc_set | app | high | set DTC (id e.g. 0x9000): bump counter, timestamp, activate, persist |
| 0x2da50 | dtc_can_cmd_handler | app | high | CAN/OD cmd handler: set/clear DTC 0x9000 from 16-byte payload |
| 0x1f758 | dtc_pattern_match | app | low | wildcard byte matcher (0x01 = wildcard) |
| 0x2dcb8 | modem_get_info | glue | high | fetch modem SiP info/version over AEM IPC (msg 0x1101); -ETIMEDOUT on fail |
| 0x30094 | modem_parse_version_from_filename | glue | med | parse `_X.Y.Z` modem fw version from filename |
| 0x30170 | modem_firmware_update | glue | high | modem FMFU over nrf_modem bootloader: parse pak, SHA-verify, stream |
| 0x2dbb0 | shell_cmd_dtc | app | med | `*gap*` DTC shell cmd (list/save/clear) |
| 0x2dc64 | shell_cmd_modem_version | app | med | `*gap*` "modem version" shell cmd |
| 0x2dcfc | shell_cmd_modem_info | app | med | `*gap*` "modem info" shell cmd (SiP/IMEI/ICCID) |

### 9. identity-settings-odo (MED — all `*gap*`)
| addr | name | cls | pri | role |
|---|---|---|---|---|
| 0x2d6a0 | vm_identity_set_id | app | high | `*gap*` write bike/frame/ECU id; enforce ecu-id-locked |
| 0x31ff0 | vm_odo_update | app | high | `*gap*` update/rate-limit odometer; "Update Bike distance (ODO) to %u" |
| 0x28134 | vm_enter_service_mode | app | high | `*gap*` enter service mode (sub-state sequence) |
| 0x2d508 | vm_identity_format_ids | app | med | `*gap*` format Bike/Frame/ECU id triple into a buffer |
| 0x2d604 | vm_identity_load_id | app | med | `*gap*` load/validate 16-byte id from storage |
| 0x3213c | vm_state_restore_distance | app | med | `*gap*` restore ODO/ECU distance on boot |

## Gap-recovered functions — pass 1

Recovered via `disassemble_bytes` + `create_function` at dispatch/literal-pool
sites (named in Ghidra + in `ghidra/exports/ble_program.json`).

### BLE command-dispatch pipeline ("ipipe")
| addr | name | role |
|---|---|---|
| 0x2e0c8 | ipipe_ctx_init | alloc + init the ~0x460-byte command-pipeline context (`ipipe`) — the global at `DAT_0002e19c` |
| 0x2e14c | ipipe_dispatch | the dispatch entry: resets the ctx, parses the inbound message (`0x6e92c`) into `ctx+0x20`, then invokes the registered handler `ctx+0x1c → +0x18 (handler, ctx, ctx+0x20)`; logs "ipipe dispatch failed (err=%d)"; returns `-32` if no handler registered |

### BLE command map (per-command handlers) — structure + first command
The authenticated **command** channel dispatches to per-command handlers. Each
handler follows one pattern (recognizable for bulk enumeration):
```
memcmp(msg+8, "<8-byte command name>", min(msg_len@+6, 8)) == 0
  → switch (sub_opcode = msg[5]) { ... } ; else log "command not allowed"
  → reply via AEM event (alloc 0x77cfc using msg_id@+3, fill, submit 0x55564)
```
| addr | name | command | role |
|---|---|---|---|
| 0x2ff30 | vmtp_cmd_firmware | **"firmware"** | op1 = trigger update → permission-checked write of **`/fs/firmware.pak`** (else "update in progress"); op4 = firmware path query; op0 = version query; else "command not allowed". So **BLE-driven firmware update** stages the image to `/fs/firmware.pak`. |
| 0x2ff14 | vmtp_cmd_permission_check | — | precondition/permission check (0x10c-byte scratch; 0 = allowed) used by the firmware-update op |

**Dispatch tables found.** The command handlers are registered in two rodata tables:
- **OD/command-id → handler** at **`0x958e0`** — entries keyed by an OD/command id
  (`0x100`–`0x202`). Confirmed: **`0x10e` → `vmtp_cmd_firmware`** (`0x2ff30`),
  **`0x1b1` → `vmtp_cmd_version`** (`0x2f550`: reports `/fs/version` + the staged
  `/fs/firmware.pak` version), **`0x163` → `vmtp_cmd_elock`** (`0x284b8`: the BLE
  **lock/unlock** command — drives the elock motor, gated on `elock_is_present`).
- **shell-name → handler** at **`0x95980`** — the Zephyr debug-shell command table.

These handlers have no code xref (table-only), so `create_function` at each entry
recovers them. Recovered this pass (named where decoded, else `*_cmd_h_<addr>` pending
decode): `vmtp_cmd_version` `0x2f550`, `vmtp_cmd_elock` `0x284b8`, + `vmtp_cmd_h_2f120/
2f6b4/28574/282a8/282cc` and shell handlers `0x261d0/26890/30e24/32944/2d040/2d050`.

> **Next pass:** walk the `0x958e0` table to read every (id, handler) pair, decode the
> remaining `vmtp_cmd_*` handlers (the full BLE command set the phone can issue), and
> reconstruct them to C. Good **workflow** target (one agent per handler).

### Backup-unlock — offline unlock-code security path (`0x31600`–`0x317c0`)
| addr | name | role |
|---|---|---|
| 0x316e4 | backup_unlock_verify | **the verifier**: decode input, then an **8-byte code compare** via a callback `(*cb)(stored, ref@0x31744, 8)`; returns `0` ok / `-2` decode-fail / `-22` mismatch |
| 0x31620 | backup_unlock_get_lockout_count | remaining attempts: **5** when state off, **64** (`0x40`) when active, clamped by the lockout counter; publishes it over AEM/OD |
| 0x3178c | backup_unlock_store_code | store the code + active flag, persist via settings (`0x38334`) |
| 0x31650 | backup_unlock_set_active | set the active flag from an event byte |
| 0x31668 | backup_unlock_reset_lockout | zero the lockout attempt counter |
| 0x31780 | backup_unlock_is_active | return the active flag |
| 0x316a4 | backup_unlock_publish_event | alloc+submit the AEM event with the code/len |
| 0x31688 | backup_unlock_log_code | format "Backup unlock code: %d, len: %d" |
| 0x31750 | backup_unlock_verify_fail | log "backup_unlock_verify failed", return `-22` |

> Security notes: the unlock secret is an **8-byte code** compared via a callback
> (the constant-time compare lives in the callback). A lockout counter gates
> attempts (max 5 inactive / 64 active). Settings key `backup_unlock/code`
> (`0x853c2`). The 8-byte reference at `DAT_00031744`/`0x31748` and the decode
> (`0x6f4d8`) are the next things to pin for a full security write-up.

## Reconstruction order (from synthesis)

§1 auth-ble-vmtp → §3 power-state → §4 battery-charger → §5 elock → §2 can-rail
(folds into §1/§3) → §6 modem-dtc → §7 fmna-glue → §8 audio-bell → §9 identity.
Within a subsystem: callees/helpers first, then the public entry points. Keep
vendor calls (crypto/net_buf/Zephyr/nrf_modem) external. Reconstruct one of each
ICF-twin pair, verify the other is byte-identical before writing a second body.
