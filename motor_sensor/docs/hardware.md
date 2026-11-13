# motor_sensor — hardware / image layout

> S6 `motor_sensor` ECU, host-level triage of the `v1.8.8.4974` image (no Ghidra yet).
> Confirmed from the image; MCU/base cross-checked (string-xref vote + disasm).

> **Ghidra base (2026-11-09): `0xC00`** (link = file offset + 0xC00; the app sits above a 3 KB
> bootloader reserve). Offsets in this host-triage note are **file offsets** unless stated.

## Container
RAW Cortex-M image (NOT MCUboot). File offset 0 holds the vector table: initial SP = 0x20008000 @0x0, reset = 0x00000d81 (Thumb, +1) @0x4. No 0x96f3b83d MCUboot magic. The first 0xC00 (3 KB) of flash is reserved for a small bootloader (see image base), so the app vector table is linked at 0xC00, not 0x0.

## Image base (Ghidra)
0x00000C00 (NONZERO despite being a raw image). String-xref MODE vote: base 0xC00 = 7 string-pointer hits, base 0x0 = 0 hits, no other base scored. Concrete proof (literal-pool pointer words, file-offset = link-0xC00): word@file0x1d20 = 0x00004f84 -> "E>failed to erase page" @file0x4384 (0xC00+0x4384=0x4f84); word@0x1e28=0x4fa8->validate; 0x1e2c=0x4fcc->size; 0x1e30=0x4fec->crc; 0x1e34=0x5009->allow_update; 0x1704=0x4f74->"Terminal"; 0x1cac=0x4f7d->"(NULL)". Cross-check: vec[1] reset 0xd81 maps to file 0x180 (=0xd80-0xC00), and disassembly there at link 0xd80 is a clean Cortex-M reset prologue: cpsid i / ldr r3,[pc,#0x5c] / ldr r2,[pc,#0x5c] / ldr r0,[pc,#0x70] / str r3,[r0] (VTOR/data-init). Margin: 7 vs 0, decisive.

## MCUboot header
n/a (raw image, no MCUboot header)

## VMFW header
PRESENT at 0x134. magic "VMFW" @0x134; version u32 @0x138 = 0x00080801 (bytes 01 08 08 00 => 1.8.8.0); CRC32 @0x13C = 0xe0b9399a; image length u32 @0x140 = 0x4658 (18008) == exact file size; @0x144 u32 = 0x0000136e (build/date marker, raw not ascii) then version string "v1.8.8.4974\0" @0x148. Header sits right after the vector table as expected for an in-house VanMoof Cortex-M image.

## MCU
**NXP LPC55S0x/S1x, ARM Cortex-M33** (corrected 2026-11-13; the M4 / LPC546xx reading below was
wrong). Evidence from the image: the reset handler (link 0xd90) executes `msr MSPLIM, r2`, an
ARMv8-M-only instruction (no Cortex-M4 has stack-limit registers); flash operations call the LPC55
ROM API at 0x1300xxxx (e.g. 0x1300413b with the "kefl" erase key), not the LPC546xx IAP entry
0x03000205; and the CAN controller is the CAN-FD block at 0x4009D000, which in the LPC55 line only
the S0x/S1x parts have. The exact part (S16 / S14 / S06 / S04) is not distinguishable from the
image. No FPU instructions occur in the image, so the build gate uses `-mcpu=cortex-m33
-mfloat-abi=soft`. The same markers are present in all three LPC-trio images.

Original host-triage note (superseded):
ARM Cortex-M4 (Thumb-2 confirmed: cpsid i, strd, movw/ldr-literal in reset handler). RAM = 32 KB (SP=0x20008000 over 0x20000000 base). Very small: 18 KB image at flash base 0xC00 (3 KB bootloader reserve). Profile (32 KB SRAM + tiny flash + SEGGER RTT + Cortex-M4) is consistent with a small Nordic nRF52 sensor-class part (e.g. nRF52810/nRF52811, Cortex-M4) or an equivalent small Cortex-M4 — exact silicon to be confirmed in Ghidra from peripheral base addresses (no reliable MMIO literals survived host triage; the 0x4xxxxxxx words observed are mostly bx-lr/opcode coincidences). Definitely ARM Cortex-M, NOT a TI C2000.

## SDK / framework fingerprint
SEGGER RTT logging present: "Terminal", "(NULL)", "0123456789ABCDEF", and the RTT up-buffer control magic stored word-reversed in flash ("TTR REGGES" = "SEGGER RTT", and "%VMKYS"/"VMKYS" fragments). Up-buffer/down-buffer descriptor table visible around file 0x4360-0x4460. No Zephyr/NCS banner, no FreeRTOS marker, no Nordic SoftDevice string -> likely bare-metal / minimal RTOS (unlike the ble ECU which is NCS 2.9.1/Zephyr 3.7.99). Toolchain: GCC/Thumb-2.

## VanMoof vs vendor
Mostly VanMoof app + a small vendor logging shim. Vendor: SEGGER RTT (the printf transport) and toolchain runtime. VanMoof: the firmware-update / image-validation routine (the only real string literals besides RTT names) — "sys_image_validate", "sys_image_size", "sys_image_allow_update", per-page erase, and "Image CRC failed %u vs %u" implement VanMoof's per-page-CRC OTA flashing that keys off the VMFW header (matches the methodology note). With ~16.8 KB of code vs ~760 bytes of data/strings and almost no vendor SDK footprint, the bulk is VanMoof-authored sensor + updater application code; estimate ~85-90% VanMoof app, the rest RTT/runtime. Sensor/CAN logic exists in code but emits no strings (no log messages), so it must be read from disassembly in Ghidra.

### Sample VanMoof app strings
- `E>failed to erase page %d (err=%d)`
- `E>sys_image_validate failed ret=%d`
- `E>sys_image_size failed ret=%d`
- `E>Image CRC failed %u vs %u`
- `E>sys_image_allow_update failed ret=%d`
- `v1.8.8.4974`

## Ghidra import recipe
1. Import /mnt/c/Users/Tobias/dev/vanmoof/s6_unpack/v1.8.8.4974/motor-sensor.bin into the S6 folder of the 'vanmoof' project (mirror ble: e.g. S6-v1.8.8). 2. Language: ARM Cortex little-endian Thumb -> 'ARM:LE:32:Cortex' (Cortex-M4). 3. Set image base = 0x00000C00 (set_image_base BEFORE analysis) — NOT 0x0. 4. Vector table is at address 0xC00 (file offset 0): mark 0xC00 as the VTOR/vector table; initial SP=0x20008000, reset handler entry = 0xD80 (Thumb). Create function at 0xD80. 5. Create a RAM block at 0x20000000 size 0x8000 (32 KB) RW. 6. reanalyze (full pass) to follow the literal-pool string xrefs (they resolve at base 0xC00). 7. Anchor naming from the OTA strings: name the function referencing word@0x1d20/0x1e28.. as the sys_image_* updater (erase/validate/size/crc/allow_update) and walk its callers for the VMFW-driven flash routine. 8. ISR/gap audit: the sensor + CAN logic emits no strings and may sit behind an indirect dispatch table — do the orphaned-caller + disassemble_bytes gap-recovery pass after the initial auto-analysis. Export to motor_sensor/ghidra/exports/motor_sensor_program.json.

## Notes
Task's "reset 0x0d80" is a file offset; the true linked reset address is 0xD80 at base 0xC00 (so vec[1]=0xd81 IS the link address, no rebase needed — Ghidra handles it once base=0xC00 is set). The 0xC00 base is unusual (the ble slot was 0xC000, ten-fold larger) and reflects a tiny 3 KB bootloader reserve ahead of an 18 KB app — consistent with a memory-constrained sensor MCU. VMFW length field exactly equals file size, so the whole 18008-byte file is one signed/CRC'd image (CRC32 0xe0b9399a over the body, verifiable later). No CAN/sensor log strings exist, so subsystem mapping is disassembly-only in Ghidra. Treat SEGGER RTT as vendor (deferred); the sys_image_*/VMFW updater and the (string-silent) sensor/CAN code are the VanMoof reconstruction targets.

OEM image (not committed): `../../../s6_unpack/v1.8.8.4974/` (from the v1.8.8.4974 OTA zip).
