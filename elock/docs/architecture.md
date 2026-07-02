# elock — architecture

> S6 e-lock ECU: **TI MSPM0G (Cortex-M0+)** running VanMoof's in-house bare-metal
> **takahe-fw** (NoRTOS; `common/mspm0` + `common/node`). Image base `0x1800`
> (MCUboot slot; vector table `0x1900`). 196 fns; ~32 named, app reconstructed to C.

## What it does
The e-lock physically locks/unlocks the bike frame via a **solenoid latch** and
senses lock position with a **TI TMAG5x70 3D hall sensor**, as a CAN node.

- **Solenoid FSM** (`solenoid_state_handler` 0x19c0): states check_unlock /
  enable_power / locking / retry_unlock (budget 8) / check_locking / disable_power.
  Drives an H-bridge PWM, monitors solenoid current/supply/MCU voltage (integer
  mV/mA), raises DTCs on open-circuit / under-voltage. Public entry
  `solenoid_request_unlock` (0x6c7c); settle timer `solenoid_timer_tick`.
- **TMAG hall sensor** (`tmag_sensor_handler` 0x28bc): handshake FSM
  (DEVICE_RESET→STATUS_READ→ID_CHECK→…), z-axis threshold config/detect
  (`tmag_threshold_handler` 0x43f0) → lock-detect class (near/unlock vs far/lock),
  published over the OD; fault counter re-inits the bus.
- **CAN / Object-Dictionary node** (`node_*`, `can_status_handler`,
  `od_endpoint_register`, `heartbeat_*`): MCAN CAN-FD; bus-off/error-passive/
  warning handling; OD publish; 8-byte heartbeat; serial-number + reset-reason.
- **DTC** system (`dtc_set`/`dtc_clear`, ids 0x14..0x4b); reboot/device-reset.

## Reconstruction scope
App = solenoid FSM + TMAG sensor + node/CAN/OD/DTC/heartbeat logic. Vendor
(deferred, `extern`): TI MSPM0 DriverLib register I/O, the MCAN driver, MCUboot,
the log/printf core, libc/udivmod. See `ble/docs/architecture.md` for the bus
peer (the nRF52840 ble central controller).
