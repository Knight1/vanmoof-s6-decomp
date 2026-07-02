# power_control — architecture

> S6 **power-management ECU**: **TI MSPM0G (Cortex-M0+)** on VanMoof's bare-metal
> **takahe-fw**, with an **external Microchip MCP251XFD CAN-FD** controller over
> SPI (the MCU's on-chip MCAN is unused). Image base `0x1800` (vectors `0x1900`);
> 238 fns. App reconstructed to C (`src/power_node.c`, compiles clean Cortex-M0+).

## What it does
- **Power orchestration / IRQ dispatch** (`power/src/irq_dispatcher.c`): the power
  node's event/IRQ routing.
- **ADC torque** ("D>ADC Torque") + **battery wake** ("D>Battery wake pulse %d ms")
  — pedal-torque sensing and battery wake-pulse control.
- **CAN/OD node over MCP251XFD**: `Init_MCP251XFD` / `MCP251XFD_StartCAN20`, bus-off
  recovery; the takahe-fw node/OD/heartbeat/DTC layer on top.
- Serial/provisioning, reset/reboot, and `sys_image_*` OTA self-update.

## Scope
App = power/ADC/battery orchestration + node/CAN-OD/DTC/heartbeat. Vendor
(`extern`): the **MCP251XFD driver** (third-party), TI MSPM0 DriverLib, MCUboot/
sys_image, libc, the takahe logger. Platform shared with `elock`/`handlebar`.
