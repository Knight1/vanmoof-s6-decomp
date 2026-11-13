# handlebar — hardware / image layout

> S6 `handlebar` ECU, host-level triage of the `v1.8.8.4974` image (no Ghidra yet).
> Confirmed from the image; MCU/base cross-checked (string-xref vote + disasm).

## Container
MCUboot. magic 0x96f3b83d @file 0; ih_load_addr@4=0x0; ih_hdr_size@8=0x100; ih_pad@0xa=0; ih_img_size@0xc=0x6780 (26496); ih_flags@0x10=0; ih_ver@0x14=1.8.8.4974 (major=1 minor=8 rev=8 build=4974). Vector table at file offset = hdr_size = 0x100. Image payload = file [0x100 .. 0x100+0x6780=0x6880); bytes [0x6880..0x69d0) are the MCUboot TLV trailer (hash/signature, high-entropy).

## Image base (Ghidra)
0x1900 (flash slot/app base, NOT 0x0). Determined by string-XREF MODE: pointer_word - rodata_string_image_offset, restricted to the readable .rodata text region. Winner 0x1900 with 37 votes vs next candidate 9 (decisive >4x margin). Cross-check: vec[1] Reset=0x7251 -> 0x7250 disassembles to a Reset trampoline 'b #0x6b74' at base 0x1900; SysTick(0x7220), IRQ1(0x591c), IRQ24(0x70b8) all decode to clean Cortex-M0+ 'push {...,lr}' prologues; and ~all readable rodata strings resolve from code LDR-literals at base 0x1900 (e.g. code@0x3234 -> 0x78d6 = "D>button %d long press timer is expired"). NOTE: in Ghidra the IMAGE BASE is the vector-table load address = 0x1900; the MCUboot header (file 0x0..0x100) is NOT part of the loaded image.

## MCUboot header
MCUboot present. hdr_size=0x100, img_size=0x6780, version=1.8.8.4974 (matches OTA bundle build 4974). Signed (TLV trailer at file 0x6880 onward).

## VMFW header
none. No "VMFW" magic at img+0x134 (bytes there are code: 72 1c 0a 23). Expected — VMFW is only on raw in-house Cortex-M images; MCUboot-wrapped images (ble/modem and this handlebar) do not carry it.

## MCU
TI MSPM0 (Arm Cortex-M0+). Definitive: build path "/__w/takahe-fw/takahe-fw/common/mspm0/src/mspm0_flash.c". Vector table is M0+ shaped (SVCall/PendSV at vec[11]/[14], ~32 IRQ slots with a shared default handler 0x454b; no fault vectors 4-6,7-10 beyond M0+ set). Initial SP@0=0x20208000 => 32KB SRAM (0x8000) at the MSPM0 SRAM bank alias 0x20200000, consistent with an MSPM0G-class part (e.g. MSPM0G350x, 32KB SRAM) which carries the integrated MCAN controller (CAN-FD) the handlebar needs. ~0x6780 (26KB) code in flash starting at app slot 0x1900 (bootloader/slot region below). MCU part exactly: MSPM0G family (CAN-FD capable), Cortex-M0+, 32KB SRAM.

## SDK / framework fingerprint
No Zephyr/NCS/FreeRTOS/SoftDevice banners (this is a bare-metal/RTOS-light MSPM0 node, unlike the nRF52 ble). Fingerprint is VanMoof's own "takahe-fw" project (GitHub Actions build path /__w/takahe-fw/takahe-fw/...) layered on the TI MSPM0 SDK/driverlib (flash driver mspm0_flash.c with FLASH_ERASE_SIZE/FLASH_WRITE_SIZE asserts). MCUboot bootloader (magic 0x96f3b83d) handles the slot/signature. Toolchain: arm-none-eabi GCC (Thumb, M0+). No explicit GCC version string emitted.

## VanMoof vs vendor
Overwhelmingly VanMoof application code. Almost every readable string is VanMoof app: button press/multi-press/long-press state machine, LED ring (led_ring.c: led_ring_enable/disable, NUM_LEDS, "R/L set led new data"), CAN node layer (Bus_Off recovery, Error Passive/Warning, "Control reg" read/write/mismatch, heartbeat.c, DTC_MAX), OTA self-update (sys_image_allow_update/validate/size, page erase, "Image CRC failed %u vs %u", RDP), provisioning/serial number. Vendor portion is small and deferred: MSPM0 SDK flash driver (mspm0_flash.c), CMSIS/Cortex-M0+ startup + default handler (0x454b), libgcc/compiler runtime, and the MCUboot loader/TLV trailer. Estimate: ~85-90% of the 26KB image is VanMoof app logic; the rest is TI SDK + runtime + MCUboot metadata.

### Sample VanMoof app strings
- `/__w/takahe-fw/takahe-fw/handlebar/src/led_ring.c`
- `/__w/takahe-fw/takahe-fw/common/node/src/heartbeat.c`
- `D>button %d long press timer is expired`
- `D>Bus_Off Status, recovering / D>Error Passive / D>Error Warning`
- `E>Image CRC failed %u vs %u / AE>sys_image_allow_update failed ret=%d`
- `D>Serial number: %s / not provisioned / bit < DTC_MAX`

## Ghidra import recipe
1) Language/processor: ARM Cortex (little-endian, Thumb) -> "ARM:LE:32:Cortex" (TI MSPM0 = Cortex-M0+; M0+ Thumb decodes fine under the Cortex variant). 2) Import the FULL file but set IMAGE BASE = 0x1900 (the vector-table/app slot base) — do NOT load at 0x0 and do NOT strip the MCUboot header by hand; instead create the program at base 0x1900 so that file offset 0x100 maps to address 0x1900 (i.e. load the payload region file[0x100:0x6880] at address 0x1900). Practically: carve payload to handlebar_payload.bin = bytes[0x100:0x6880], import as raw binary ARM:LE:32:Cortex at base 0x1900. 3) Vector table is at address 0x1900: initial SP=0x20208000 @0x1900, Reset=0x7251 @0x1904. Define the M0+ vector table and disassemble each handler as an entry point (Reset 0x7250, NMI 0x70d8, HardFault 0x70a8, SVCall/PendSV/default 0x454a, SysTick 0x7220, plus IRQ handlers e.g. 0x591c, 0x6d4c, 0x6d6c, 0x70b8, 0x70c8). 4) Create SRAM block 0x20200000 len 0x8000 (RW) for SP-relative data; flash/code block at 0x1900. 5) reanalyze (full pass) — initial recursive analysis from Reset will miss IRQ-only handlers, so seed entry points from the vector table first. 6) Use folder S6-v1.8.8; name program handlebar; mirror the ble recipe (which used base 0xC000).

## Notes
Key correction to the "known so far": handlebar is NOT a Nordic part — it is a TI MSPM0 (Cortex-M0+) node from VanMoof's "takahe-fw" codebase, distinct from the nRF52840 ble brain. Image base is 0x1900 (not 0x0 and not 0xC000); confirmed by string-XREF mode vote (37 vs 9) plus clean reset/IRQ prologues. SP 0x20208000 => 32KB SRAM at MSPM0 alias 0x20200000 (MSPM0G class, has MCAN). Container is a signed MCUboot image v1.8.8.4974 (hdr 0x100, img 0x6780, TLV trailer at file 0x6880). No VMFW header (MCUboot image). Strong CAN-node + LED-ring + button-UI + OTA-self-update VanMoof app surface, consistent with the S6 user-interface controller replacing S5 user_ecu+eshifter. Suggested per-target dirs from the build paths: handlebar/src/led_ring.c, common/node/src/heartbeat.c, common/mspm0/src/mspm0_flash.c (mspm0_flash.c = vendor/SDK, defer). Cortex-M0+ has no FPU — build with -mcpu=cortex-m0plus -mthumb (no hard-float), unlike the M4F note in CLAUDE.md which applies to other ECUs.

OEM image (not committed): `../../../s6_unpack/v1.8.8.4974/` (from the v1.8.8.4974 OTA zip).
