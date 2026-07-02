# vanmoof-s6-decomp

Clean-room rebuild of the **VanMoof S6** firmware from decompilations, producing
buildable source trees that re-emit binary-equivalent (or behaviour-equivalent)
images.

Sibling to [`vanmoof-s5-decomp`](../vanmoof-s5-decomp) (S5/A5) and
[`vanmoof-s3-decomp`](../vanmoof-s3-decomp) (S3/X3). The S6 reuses the **S5-generation
CAN-bus architecture**: a fleet of **Cortex-M sub-ECUs** on a CAN bus, a **BLE
SoC** (Nordic nRF5x), and a **cellular modem** (Nordic nRF91x1). This repo
decomposes that stack target by target, following the same conventions as the
S5/S3 projects.

> **Status: bootstrap.** This repo is freshly scaffolded from the S5 project
> structure. The firmware layout and per-target container/MCU are being mapped;
> no target is reconstructed yet. Each target subdirectory is created as work on
> it begins.

> **Architecture note:** the S6 OTA bundle is **ECU-only** — unlike the S5 there
> is **no i.MX8 Linux `main` board / Go gateway / C++ MQTT service suite**.
> Triage of `ble.bin` shows the **nRF52840 `ble` ECU is the bike's central
> controller** (CAN master + battery/charger/elock/power/audio orchestration over
> a Zephyr Application-Event-Manager bus, plus the phone BLE auth + Apple Find My)
> — it takes the brain role the i.MX8 held on S5. See
> [`ble/docs/architecture.md`](ble/docs/architecture.md). (CAN-master role to be
> confirmed in Ghidra.)

## Targets

### Confirmed platform map (host triage of v1.8.8.4974 — see each target's `docs/hardware.md`)

S6 is a **heterogeneous multi-vendor fleet** (not the S5's uniform NXP LPC546xx). MCUboot
images need a nonzero Ghidra slot **base**; raw images load at `0x0`.

| ECU | Container | Ghidra base | MCU | Framework / role |
| --- | --- | --- | --- | --- |
| [`ble`](ble/) | MCUboot | `0xC000` | Nordic **nRF52840** (M4F) | NCS/Zephyr + SDC — **central controller** (reconstructed) |
| [`modem`](modem/) | MCUboot | `0x10000` | Nordic **nRF91x1** (M33+TrustZone) | NCS + **TF-M** + **AWS-IoT** cloud gateway (cert/telemetry/FOTA/A-GNSS) |
| [`elock`](elock/) | MCUboot | `0x1900` | **TI MSPM0G** (M0+) | **takahe-fw** — solenoid lock + TMAG hall + CAN |
| [`handlebar`](handlebar/) | MCUboot | `0x1900` | **TI MSPM0G** (M0+) | takahe-fw — buttons + LED ring + CAN (S6 user-ECU) |
| [`power_control`](power_control/) | MCUboot | `0x1900` | **TI MSPM0G** (M0+) | takahe-fw + ext **MCP251XFD** CAN-FD (SPI) |
| [`motor_control`](motor_control/) | MCUboot | `0x08004000` | **STM32G4** (M4F) | bare-metal FOC/BLDC + SEGGER RTT — **not** the S5 TI C2000 |
| [`frontlight`](frontlight/) | raw | `0x0` | **NXP LPC546xx** (M4F), VMFW@`0x134` | updater/bootstrap partition |
| [`rearlight`](rearlight/) | raw | `0x0` | NXP LPC546xx-class (M3/M4), VMFW@`0x134` | updater partition |
| [`motor_sensor`](motor_sensor/) | raw | `0xC00` | ARM Cortex-M4 (small), VMFW@`0x134` | updater + string-silent sensor/CAN |
| [`charger`](charger/) | raw | `0x0` | **Renesas RA** (M33) | LiteON supplier fw (no VanMoof strings; OD layer only if any) |

> `takahe-fw` is VanMoof's in-house monorepo backing the TI MSPM0 CAN nodes; the modem
> absorbed the S5 i.MX8 Go-gateway cloud role. The tables below are the *initial
> S5-inferred* guesses, now superseded by the map above.

### Wireless SoCs (MCUboot header `0x96f3b83d` expected)

| Component | Image | MCU *(tbc)* | Size | Status |
| --- | --- | --- | --- | --- |
| [`ble`](ble/) | `ble.bin` | Nordic **nRF52840** (NCS 2.9.1 / Zephyr 3.7.99 + SDC) | ~552 KB | **triaged** — MCUboot slot base `0xC000`; the bike's central controller (see [`ble/docs`](ble/docs/)) |
| [`modem`](modem/) | `modem.bin` + `mfw_nrf91x1-v2.0.2.cbor` | Nordic **nRF91x1** (LTE-M/NB-IoT + GNSS), Zephyr | ~417 KB | pending — `mfw_nrf91x1` (~2.0 MB) is the **vendor** Nordic modem firmware |

### Sub-ECUs (ARM Cortex-M, raw vector table; `VMFW` header at `0x134` expected)

| Component | Image | Role | Size | Status |
| --- | --- | --- | --- | --- |
| [`handlebar`](handlebar/) | `handlebar.bin` | handlebar / user-interface controller (the S6 analogue of the S5 `user_ecu` + `eshifter`) | ~26 KB | pending |
| [`elock`](elock/) | `elock.bin` | electronic frame / kick lock | ~28 KB | pending |
| [`power_control`](power_control/) | `power-control.bin` | power management — rail sequencing, power-mode state machine, CAN comms | ~35 KB | pending |
| [`motor_sensor`](motor_sensor/) | `motor-sensor.bin` | motor position / current / temperature sensing | ~18 KB | pending |
| [`frontlight`](frontlight/) | `frontlight.bin` (+ `animations.pak`) | front light controller; `animations.pak` (~18 KB) is a data asset (LED-matrix animations) | ~15 KB | pending |
| [`rearlight`](rearlight/) | `rearlight.bin` | rear light controller | ~14 KB | pending |

### Motor controller (TI C2000 — not ARM, no `VMFW` header)

| Component | Image | MCU *(tbc)* | Size | Status |
| --- | --- | --- | --- | --- |
| [`motor_control`](motor_control/) | `motor-control.bin` | expected **TI C2000** (C28x) DSP (per S5; *not* an arm-none-eabi target, no `VMFW` header) | ~44 KB | pending |

### Peripheral / vendor firmware

| Component | Image | Vendor | Size | Status |
| --- | --- | --- | --- | --- |
| [`charger`](charger/) | `charger-liteon-normal-v1.8.0.bin`, `charger-liteon-speed-v1.2.0.bin` | LiteON charger HW; only the **VanMoof CAN/OD protocol layer** inside is in scope | ~23 KB each | pending |
| — | `mfw_nrf91x1-v2.0.2.cbor` | Nordic modem firmware (CBOR) | ~2.0 MB | vendor — not reconstructed (analysed under `modem/`) |
| — | `animations.pak` | LED animation data | ~18 KB | data asset — not code |

> The on-wire CAN ID/node mapping is expected to follow the S5 `vm` protocol
> (29-bit IDs + Object-Dictionary addressing); ground-truth it against the
> sibling [`../canbus`](../canbus) analyzer + an S6 capture before relying on any
> specific ID.

Each target subdirectory follows the S3/S5 convention: `src/`, `include/`,
`docs/` (`progress.md`, `hardware.md`, `protocol.md`), `ghidra/exports/`, and a
linker script + `Makefile`.

## Legal

This is a clean-room interoperability project. OEM firmware images are **not**
redistributed in this repository — extract them from a FOTA bundle or flash
dump of a bike you own.

Reverse engineering for interoperability is permitted under EU Software
Directive 2009/24/EC Art. 6 and US DMCA §1201(f). The reconstructed source in
this repository is original work derived from analysis of the OEM image and
publicly available documentation.

No warranty. Flashing reconstructed firmware to a bike will **brick or damage
hardware** if it is wrong. Do not flash to a bike you depend on. Use a spare
PCB or hardware-in-the-loop simulator.
