# handlebar — architecture

> S6 **handlebar / user-interface ECU** (the S6 analogue of the S5 user_ecu +
> eshifter): **TI MSPM0G (Cortex-M0+)** on VanMoof's bare-metal **takahe-fw**.
> Image base `0x1800` (vectors `0x1900`); 175 fns. App reconstructed to C
> (`src/handlebar_ui.c`, `src/handlebar_node.c`, compile clean Cortex-M0+).

## What it does
- **Buttons** (`handlebar_ui.c`, `button_fsm_tick` 0x313c): periodic debounce
  sampling + single/multi-press counting + long-press detection (500 ms multi,
  1000 ms long), publishing the 3-byte `{id,event,counter}` state over the OD/CAN.
- **LED ring** (`handlebar_ui.c`): dual Right/Left RGB rings (`NUM_LEDS`=10),
  enable/disable, per-pixel colour, "set led new data" CAN command → SPI flush.
- **CAN/OD node** (`handlebar_node.c`): the takahe-fw node layer — MCAN; CAN
  error handling (Bus-Off/Error-Passive/Warning → DTC); OD endpoints + multi-frame
  reassembly + heartbeat; DTC set/clear; serial/provisioning.
- **OTA self-update** (`handlebar_node.c`): `sys_image_*` image validate/erase/
  program with CRC ("Image CRC failed %u vs %u"), MCUboot-staged.

## Scope
App = buttons + LED ring + node/CAN/OD/DTC/heartbeat + image-update orchestration.
Vendor (`extern`): TI MSPM0 DriverLib, MCAN driver, MCUboot/sys_image core,
libc, the takahe printf logger. Platform shared with `elock`/`power_control`.
