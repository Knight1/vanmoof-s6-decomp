# rearlight — hardware / image layout

> S6 `rearlight` ECU, host-level triage of the `v1.8.8.4974` image (no Ghidra yet).
> Confirmed from the image; MCU/base cross-checked (string-xref vote + disasm).

> **Ghidra base (2026-11-09): `0xC00`** (link = file offset + 0xC00; the app sits above a 3 KB
> bootloader reserve). Offsets in this host-triage note are **file offsets** unless stated.

## Container
RAW Cortex-M vector table. Word@0 = 0x20008000 (initial SP, NOT MCUboot magic 0x96f3b83d). reset@4 = 0x00000d81 (thumb -> entry 0xd80). Vector table at file offset 0x0. NMI 0xe79, HardFault 0x3b9d; exception handlers 0xe79..0xeb1; external IRQ handlers begin at 0x38c1. All handlers odd/thumb and in-range; reserved slots (0x20/24/28/34) zero. No MCUboot header.

## Image base (Ghidra)
0x0 (raw image; vectors at file offset 0)

## MCUboot header
n/a (raw image — magic@0 is 0x20008000, not 0x96f3b83d)

## VMFW header
present @0x134. magic "VMFW"; version u32@0x138 = 0x00080801 (encodes 1.8.8); CRC32 u32@0x13C = 0x0e97deb9; image-len u32@0x140 = 14328 (== full file size); build u32@0x144 = 0x136e = 4974; build string @0x148 = "v1.8.8.4974". Len covers whole image, so CRC32 is over the image with the CRC field excluded (per-page-CRC updater scheme).

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
Cortex-M, M3/M4 class. SP 0x20008000 => single 32 KB SRAM bank at 0x20000000 (top-of-RAM init). 14 KB flash. Disasm: 0 VFP/Neon ops but 203 Thumb-2 ops (movw/movt/ldr.w/bl.w) => rules out M0/M0+; M3 or M4 with FPU unused. S5/A5 sibling rearlight is NXP LPC546xx Cortex-M4F with identical SP/base/VMFW profile => same family expected (confirm exact part + FPU in Ghidra). Peripheral-base literal histogram was noise (image too small for a stable MMIO signal).

## SDK / framework fingerprint
No Zephyr/NCS/Nordic-SDC/FreeRTOS/SoftDevice banner strings present (tiny image, almost all code). Visible strings are the VanMoof in-house bootloader/updater: "E>sys_image_validate failed ret=%d", "E>sys_image_size failed ret=%d", "E>Image CRC failed %u vs %u", "E>sys_image_allow_update failed ret=%d", "E>failed to erase page %d (err=%d)", plus "Terminal", "(NULL)", "0123456789ABCDEF". Same VMFW updater/bootloader stack as the S5 light ECUs (LPC546xx + likely FreeRTOS, tbc in Ghidra).

## VanMoof vs vendor
Predominantly VanMoof in-house code for a 14 KB image. The only readable strings are the VanMoof sys_image_* updater/CRC/page-erase messages (VanMoof app/bootloader). Vendor portion (toolchain runtime, any RTOS/HAL) is not surfaced by strings and is small. Estimate: ~70-85% VanMoof app+updater, remainder vendor toolchain/HAL. App layer is small; LED/CAN-OD handlers likely sit behind indirect-dispatch tables (recover in gap pass).

### Sample VanMoof app strings
- `E>sys_image_validate failed ret=%d`
- `E>Image CRC failed %u vs %u`
- `E>sys_image_allow_update failed ret=%d`
- `E>failed to erase page %d (err=%d)`
- `v1.8.8.4974`

## Ghidra import recipe
Import rearlight.bin into the 'vanmoof' Ghidra project under the S6 folder (S6-v1.8.8). Language: ARM:LE:32:Cortex (little-endian, 32-bit). Image base: 0x0. Vector table at 0x0 (initial SP 0x20008000, reset 0xd80). Pass program arg explicitly on every MCP call. Run reanalyze for a full pass. Then audit ISR vectors (handlers from 0x38c1) separately, and do a gap-recovery pass (disassemble_bytes + create_function) for indirect-dispatch LED/CAN handlers if the classify pass returns mostly-vendor. Export renamed state to rearlight/ghidra/exports/rearlight_program.json.

## Notes
Triage written to /mnt/c/Users/Tobias/dev/vanmoof/vanmoof-s6-decomp/rearlight/docs/hardware.md. Matches S5/A5 rearlight (NXP LPC546xx Cortex-M4F, raw base 0x0, SP 0x2000_8000, VMFW@0x134) per ../vanmoof-s5-decomp/rearlight/docs/hardware.md. VMFW version field 0x138 encodes the 1.8.8 triplet (bytes 01 08 08 00); the full build "4974" lives in u32@0x144 and the string @0x148. FPU not exercised (0 VFP ops) so confirm M3-vs-M4-no-FPU in Ghidra before fixing the -mfloat-abi/-mfpu compile flags. Function tracker rearlight/docs/progress.md left untouched (still 'pending' — no functions analysed without Ghidra).

OEM image (not committed): `../../../s6_unpack/v1.8.8.4974/` (from the v1.8.8.4974 OTA zip).
