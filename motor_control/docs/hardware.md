# motor_control — hardware / image layout

> S6 `motor_control` ECU, host-level triage of the `v1.8.8.4974` image (no Ghidra yet).
> Confirmed from the image; MCU/base cross-checked (string-xref vote + disasm).

## Container
MCUboot. magic 0x96f3b83d @file 0 (LE u32). load_addr@4=0x00000000, ih_hdr_size@8=0x400, ih_protect_tlv_size@0xa=0, ih_img_size@0xc=0xaaf0, ih_flags@0x10=0, ih_ver@0x14=1.8.8.4974 (maj=1 min=8 rev=0x0008 build=0x0000136e=4974). hdr+img = 0x400+0xaaf0 = 0xaef0; file 0xb040 (trailer/TLV padding after). Vector table at file offset = ih_hdr_size = 0x400: SP=0x20008000, reset=0x0800a361.

## Image base (Ghidra)
**0x08002000** (corrected 2026-11-10; the 0x08004000 below was wrong). File offset 0 (the MCUboot
header) = 0x08002000, vector table at 0x08002400, reset 0x0800a360 at file 0x8360 (`ldr r0,[pc];
mov sp,r0`, a textbook Reset_Handler). Pinned by the flash OD table (file 0xacb0): its 19 handler
pointers all land on clean function entries at base 0x08002000 (e.g. 01008900 handler 0x80052c0 =
file 0x32c0 `push {r0-r4,lr}; ldr r3,=0x20240627`, the shared hw-id responder), and on mid-function
code at 0x08004000. All 9 non-default vectors also decode as entries. So an 8 KB bootloader sits
below the MCUboot slot. The vector-validity vote in the Notes below used too weak a test.

## MCUboot header
MCUboot image. ih_hdr_size=0x400, ih_img_size=0xaaf0, ih_ver=1.8.8.4974 (build 4974). vector table at file 0x400.

## VMFW header
none. Offset 0x134 (and file 0x534 = 0x400+0x134) is 0xFF/code, no "VMFW" magic — consistent with MCUboot-wrapped images (like ble/modem) which never carry the VMFW header. The single "VMFW" byte-hit in the image is at file 0x2A5C: it is the code literal 0x564d4657 (preceded by ptr word 0x080007d8 at 0x2A58), i.e. an in-code constant, not the 0x134 header.

## MCU
STM32G4 family, ARM Cortex-M4F (FPv4-SP-D16, hard-float). CONFIRMED ARM, NOT TI C2000 (S5's motor_control was C2000; S6 switched to STM32). Evidence: initial SP 0x20008000 => 32KB SRAM at 0x20000000; ~691 VFP single-precision insns (vmul.f32/vdiv.f32) + double vldr d8 => FPU present; Thumb-2 decodes cleanly (push/sub sp/bl). Peripheral pointer map is the STM32G4 signature: RCC@0x40021000 (7), FLASH@0x40022000 (8), GPIO@0x48000000 AHB2 (9), ADC@0x50000000 (6), TIM1 advanced-timer@0x40012C00 (7). 32KB RAM + ~44KB code + ADC@0x50000000 points to STM32G431/G441 (motor-control line). Role: BLDC/FOC motor controller (TIM1 PWM + ADC current sense + heavy float DSP math).

## SDK / framework fingerprint
Heavily string-stripped, no Zephyr/NCS/CubeHAL banner. Debug transport = SEGGER RTT (RTT control block: "Terminal" @img 0xa088, and the RTT block magic stored byte-reversed as "TTR REGGES" = "SEGGER RTT", plus "0123456789ABCDEF" hex table). Firmware-update layer present via a sys_image_* DFU API (strings: "E>sys_image_validate failed ret=%d", "E>sys_image_size failed ret=%d", "E>sys_image_allow_update failed ret=%d", "E>Image CRC failed %u vs %u", "E>failed to erase page %d (err=%d)") — MCUboot-style self-update over CAN. Bare-metal/LL-style (no HAL_/LL_ symbol strings), GCC/FPv4-SP. No FreeRTOS/Zephyr kernel strings observed.

## VanMoof vs vendor
Mostly VanMoof application code by volume — this is a small (~44KB) single-purpose motor-control firmware: FOC float-math control loops (vmul/vdiv.f32 clusters), TIM1/ADC peripheral driving, and a VanMoof CAN/OD + self-update (sys_image_*) layer. Vendor portion is thin: SEGGER RTT (vendor, deferred), libgcc soft/VFP helpers, and CMSIS/STM32 register defines (transcribe #defines only). No large SDK/RTOS blob is linked in. Estimate ~75-85% VanMoof app, the rest RTT + toolchain runtime.

### Sample VanMoof app strings
- `E>sys_image_validate failed ret=%d`
- `E>Image CRC failed %u vs %u`
- `E>sys_image_allow_update failed ret=%d`
- `E>failed to erase page %d (err=%d)`
- `E>sys_image_size failed ret=%d`

## Ghidra import recipe
1) Import /mnt/c/Users/Tobias/dev/vanmoof/s6_unpack/v1.8.8.4974/motor-control.bin into the vanmoof project S6 folder (e.g. S6-v1.8.8/motor_control). 2) Language: ARM Cortex little-endian Thumb — ARM:LE:32:Cortex (default cspec; STM32G4 = Cortex-M4F). 3) Set image base = 0x08002000 (NOT 0x08004000, see above) — the MCUboot slot base; the 0x400-byte MCUboot header maps file 0..0x400 at 0x08004000..0x08004400, so the Cortex-M vector table lands at 0x08004400. 4) The reset/SP vector table is at address 0x08004400 (file 0x400): SP=0x20008000, reset=0x0800a360. Create the vector table there and mark vectors as code; reset handler at 0x0800a360. 5) Optionally carve the 0x400 MCUboot header as data (0x08004000..0x08004400). 6) reanalyze (full pass; ARM aggressive instruction finder + create address tables on). 7) Add SRAM block 0x20000000 size 0x8000 (32KB), and STM32G4 MMIO blocks (0x40000000 APB, 0x48000000 AHB2 GPIO, 0x50000000 ADC, 0xE0000000 PPB). Mirrors the ble recipe (base 0xC000, vectors at base+hdr) but with STM32 base 0x08004000.

## Notes
Base 0x08004000 proof (not 0x0/0x08000000): for the same flash handler word 0x08006cd4, base 0x08000000 maps to file bytes 44 09 00 20 = the RAM pointer 0x20000944 (data, NOT code), whereas base 0x08004000 maps to "ldr r3,[pc]; strd ip,r3,[r0,#0x10]" (clean code); handler 0x08006d14 -> "mov r3,r0; sub sp,#0x140" (textbook prologue); handler 0x0800713c -> "bl 0x8006830" (in-image call). 41/41 vector-table handlers decode to valid Cortex-M code at 0x08004000 (and to garbage/RAM-ptrs at 0x08000000). The string-mode method that fixed ble (0xC000) was INCONCLUSIVE here (only ~8 real strings, no literal->string pointers found — the sys_image_*/RTT strings are reached via RTT/descriptor blocks, not pc-relative literals), so the base was pinned by vector-handler disassembly validity instead; vote margin: 41-vs-0 on clean-handler-decode between 0x08004000 and 0x08000000. Image span 0x08004000..0x0800eaf0 (img_size 0xaaf0); intra-image bl targets (0x8006830, 0x800c4c2) all land in span. ARCHITECTURE CONFIRMED ARM Cortex-M4F (STM32G4) — the S5->S6 change from TI C2000 to STM32 for motor-control is real. Update CLAUDE.md/progress expectations: motor_control is NOT C2000 on S6.

OEM image (not committed): `../../../s6_unpack/v1.8.8.4974/` (from the v1.8.8.4974 OTA zip).
