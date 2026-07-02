# ble — architecture

> What the S6 `ble` firmware actually does, and the reconstruction scope.
> Evidence below is from host-level string/disassembly triage of the
> v1.8.8.4974 `ble.bin`; behaviour marked *(confirm in Ghidra)* is not yet
> decompiled.

## Headline: the nRF52840 `ble` ECU is the S6 central controller

On the S5, the bike's brain was the i.MX8 Linux board (the `power`/`ride`/`ux`/
`tracking` services over MQTT). **The S6 OTA bundle has no i.MX8 / Linux board**,
and the `ble` image is far more than a BLE peripheral — it carries the
orchestration that lived in the i.MX8 on S5. Evidence (strings in this one image):

- A **debug shell** with command groups for the whole bike:
  `CAN commands`, `Battery commands`, `Charger commands`, `Capacity sub-commands`,
  `DTC commands`, `Audio commands`, `Bell sound commands`, `Device commands`,
  `Date commands`, `Apple FindMy commands`, `Application Event Manager commands`.
- Direct **battery/charger control over CAN**: "Battery set charge/discharge
  mode", "Timed out setting battery to charge mode", "Design capacity not equal
  to settings", "test battery capacity <enable> <rsoc> <rem_cap_mah> <avg_curr>".
- **elock orchestration**: "new reported elock state: %s", "touch unlock
  request/deactivate", "lock state: %d", "Lock was not properly locked".
- **Power-state machine**: "Publishing on TOPIC_POWER_STATE", "Request power off
  due to shipping mode", charge/discharge state transitions.
- **Modem control**: "Reset modem to %s".
- **Audio/UX**: a large `/audio/*.wav` catalog (boot, lock/unlock, alarm, power
  levels, update, and ~8 selectable bell sounds).
- **Internal message bus**: Zephyr **Application Event Manager** (the S6 analogue
  of the S5 MQTT bus); topic-style strings (`TOPIC_POWER_STATE`, `fmna/en`,
  `fmna/pairing/%02d`, `fmna/provisioning/99x`).

So `ble` = **phone interface + bike orchestrator**. (The dir is named `ble` to
match the OEM image/manifest; functionally it is closer to the S5 `user_ecu` +
the i.MX8 service suite combined. Confirm the exact CAN-master role in Ghidra.)

## Subsystems

| Subsystem | What it does | Surface (strings) |
| --- | --- | --- |
| **BLE host + vmtp** | Zephyr BT host + SoftDevice Controller; VanMoof transport (`vmtp_zephyr`) and the `com.vanmoof.app` GATT auth/command service (see `protocol.md`) | `bt_gatt`, `vmtp_zephyr`, `com.vanmoof.app:*` |
| **Auth / security** | challenge–response with certificate + signature; ECDH/ECDSA via SDC crypto | `com.vanmoof.app:{certificate,challenge,command,signature,status}`, `bt_sdc_ecdh`, "SW Authentication Token" |
| **Apple Find My (FMNA)** | full Find My Network Accessory: pairing, key rotation, owner key, separated/nearby advertising, serial-number query, stolen-mode gating | `FMNA_STORAGE_*`, `fmna_adv_*`, `fmna_keys`, "FMNA disabled due to stolen mode" |
| **CAN master** | command/telemetry to the sub-ECUs (battery, charger, elock, lights, motor, modem) | `CAN commands`, per-device command groups |
| **Battery / charger** | charge/discharge mode, capacity/SoC, design-capacity checks | `Battery commands`, `Charger commands`, `Capacity sub-commands` |
| **elock** | lock/unlock state, touch-unlock, lock fault reporting | "reported elock state", "touch unlock request" |
| **Power state** | power-mode/shipping/power-off state machine | `TOPIC_POWER_STATE`, "shipping mode" |
| **Audio / bell** | plays UX cues + selectable bell sounds; volume/mute settings | `/audio/*.wav`, `master_volume_set`, `mute_level_set` |
| **DTC** | diagnostic trouble codes | `DTC commands` |
| **Settings / storage** | Zephyr settings + NVS (`/fs/settings`); bt CCC store; FMNA key storage | `/fs/settings`, `bt_settings`, `NVS` |
| **Bike identity** | bike ID / ECU ID, ODO distance, service mode | "Set bike ID to %s", "Update Bike distance (ODO)", `app.vanmoof.com/connect?ecu_id=…&bike_id=…` |

## Reconstruction scope (VanMoof vs vendor)

Per the project rule (`CLAUDE.md` → Decomp scope), reconstruct **only
VanMoof-authored application code**. In this image that means the orchestration /
auth / glue layer; the following are **vendor (deferred, not reconstructed)**:

- **Zephyr RTOS** (kernel, BT host stack, settings/NVS, logging, shell, App Event
  Manager) — `WEST_TOPDIR/zephyr/...`.
- **Nordic SoftDevice Controller** + crypto/ECDH (`bt_sdc_*`, `bt_hci_sdc`).
- **MCUboot** (bootloader is a separate image at `0x0`; the header here is its
  metadata).
- **Apple FMNA library** — the Find My protocol implementation follows Apple's
  spec (like the ~116 deferred Find My functions in the S5 ble). The VanMoof
  **integration glue** (enable/disable, stolen-mode gating, storage wiring, the
  audio cues) IS in scope; the FMNA crypto/state machine itself is vendor/spec.
- **libc / libgcc** runtime.

Flag borderline cases (e.g. `dragoon/libs/*` — VanMoof's own framework vs a
third-party lib) in `progress.md` rather than guessing.

## Open questions

- Exact **CAN** controller + on-wire mapping: is the nRF52840 the CAN master, and
  does it speak the S5 `vm` 29-bit OD protocol? Ground-truth via `../canbus`.
- The internal **Application Event Manager** topic catalog (the S6 "MQTT
  equivalent") — enumerate publishers/subscribers as services are decoded.
- Where the `com.vanmoof.app` auth keys / certificates live (UICR? settings? a
  provisioned MFi token — "MFi Token UUID not found: please provision a token").
