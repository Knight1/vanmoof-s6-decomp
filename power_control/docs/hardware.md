# power_control — hardware / image layout

> S6 `power_control` ECU, host-level triage of the `v1.8.8.4974` image (no Ghidra yet).
> Confirmed from the image; MCU/base cross-checked (string-xref vote + disasm).

## Container
MCUboot. Magic 0x96f3b83d at file offset 0. Header: ih_load_addr=0x0@4, ih_hdr_size=0x100@8, ih_img_size=0x8988@0xC, ih_flags=0@0x10, ih_ver=1.8.8.4974@0x14 (major=1,minor=8,rev=8,build=4974). Vector table at file offset = ih_hdr_size = 0x100. Layout: 0x100(hdr) + 0x8988(img) + 0x50(TLV trailer) = 0x8ad8, file 0x8bd8. Not a raw image.

## Image base (Ghidra)
0x1900 (NOT 0x0). This is the MCUboot primary-slot offset on the MSPM0 flash; 0x0-0x18FF holds the bootloader. Derived by PC-relative literal-pool voting: base 0x1900 wins 54 votes vs runner-up 0x3530=19 (margin 35). Every winning literal resolves exactly to a real string (e.g. litword@0x374=0x9adf -> str@0x81df "D>Ext1: Invalid Message Occurred"). Cross-check: vector table at file 0x100 disassembles cleanly at base 0x1900 -- reset(vec1)=0x8fe4 is a branch (b 0x88fc), vec2=0x8304 and vec3=0x829c are fault handlers opening with "cpsid i", vec15(SysTick)=0x8fb6 is push{r7,lr}/bl/pop{r7,pc}. Naive base 0x0 is impossible: reset 0x8fe4 lies past the 0x8a88 image end.

## MCUboot header
MCUboot: ih_hdr_size=0x100, ih_img_size=0x8988, ih_ver=1.8.8.4974. magic 0x96f3b83d @ file 0.

## VMFW header
none. Offset 0x134 holds vector-table words (0x0000324b etc.), not "VMFW" magic. Expected absent on MCUboot-wrapped images (VMFW only on raw in-house Cortex-M images).

## MCU
TI MSPM0G (ARM Cortex-M0+, Thumb-only). Evidence: initial SP=0x20208000 -> SRAM base 0x20200000 + 0x8000 = 32 KB SRAM; img ~35 KB flash; peripheral literals match the MSPM0G aperture: 0x400A1000 (UART0), 0x400B0000 (SPI0), 0x40001000 (DMA), 0x40508000 (GPIOA), 0x40428000 (ADC), 0x40085000/0x40082000 (TIMx), 0x40862000/0x40863000. Source path /common/mspm0/src/mspm0_flash.c. M0+ confirmed by fault-handler style (only cpsid+branch, no BusFault/UsageFault split) and SVC/PendSV/SysTick vector layout. Likely an MSPM0G15x/G35x-class part (e.g. MSPM0G3507 family).

## SDK / framework fingerprint
VanMoof in-house "takahe-fw" firmware (GitHub Actions build paths /__w/takahe-fw/takahe-fw/...) on a custom "node" framework, not Zephyr/NCS and not FreeRTOS (no kernel banners found). TI MSPM0 SDK / DriverLib for the MCU HAL (mspm0_flash.c, peripheral register bases). MCUboot for image management: strings sys_image_validate/sys_image_allow_update/sys_image_size, "Image CRC failed %u vs %u", "failed to erase page %d", FLASH_ERASE_SIZE/FLASH_WRITE_SIZE asserts, "RDP %d". External CAN-FD via Microchip MCP251XFD driver (MCP2517/2518FD over SPI) -- many MCP251XFD_* strings. No version banner string beyond the MCUboot ih_ver 1.8.8.4974; no build __DATE__/__TIME__ string found.

## VanMoof vs vendor
Majority VanMoof application code. The image is small (~35 KB) and the string table is dominated by VanMoof takahe-fw app/log content (power node, ADC torque, battery wake, CAN orchestration, serial number, image-update logic). Vendor portions: TI MSPM0 DriverLib/HAL register access, the Microchip MCP251XFD CAN-FD driver (third-party library), and MCUboot image-management/CRC code. Rough split: ~55-65% VanMoof app (power/node/irq_dispatcher/heartbeat/CAN orchestration), ~35-45% vendor (MSPM0 HAL + MCP251XFD driver + MCUboot glue). RTOS: none evident (bare-metal node/IRQ-dispatch model). Reconstruct VanMoof power/node/CAN layer; defer MCP251XFD driver, MSPM0 DriverLib, and MCUboot as vendor.

### Sample VanMoof app strings
- `D>ADC Torque`
- `D>Battery wake pulse %d ms`
- `D>Serial number: %s`
- `E>Init_MCP251XFD err=%d`
- `E>MCP251XFD_StartCAN20 err=%d`
- `D>Bus_Off Status, recovering`
- `E>Image CRC failed %u vs %u`
- `E>sys_image_validate failed ret=%d`
- `E>failed to erase page %d (err=%d)`
- `/__w/takahe-fw/takahe-fw/power/src/irq_dispatcher.c`

## Ghidra import recipe
1) Import /mnt/c/Users/Tobias/dev/vanmoof/s6_unpack/v1.8.8.4974/power-control.bin into the S6 folder of the 'vanmoof' Ghidra project. 2) Language: ARM Cortex little-endian, Thumb (ARM:LE:32:Cortex), variant Cortex-M0+ (Thumb-only). 3) Strip the MCUboot wrapper OR import whole and treat code starting at file 0x100: set image base = 0x1900 (set_image_base 0x1900). Note the loaded code begins at the vector table = file offset 0x100, which maps to address 0x1900. 4) Define the vector table at 0x1900: SP@0x1900=0x20208000, reset@0x1904=0x8fe5 (Thumb), then exception/IRQ vectors; create the SRAM block at 0x20200000 size 0x8000 and the MSPM0 peripheral space 0x40000000.. as needed. 5) reanalyze (full pass), enabling the ARM aggressive-instruction-finder. 6) Mirror the ble recipe but with base 0x1900 (vs ble 0xC000) and M0+ instead of M4. Anchor naming via the literal-pool string xrefs already validated for base 0x1900.

## Notes
Image base 0x1900 is unusual (not a round flash boundary) but solidly confirmed by two independent methods (literal-pool string voting, margin 35; and clean vector-table disassembly). It is the MCUboot slot offset, i.e. the bootloader reserves 0x0-0x18FF. Known-so-far values (MCUboot hdr 0x100, img 0x8988) confirmed. The "Known: hdr 0x100" means the in-Ghidra code/vector base is hdr_size(0x100 in file) mapped to flash 0x1900. CAN is external (MCP251XFD over SPI) -- the MCU's on-chip MCAN is unused; when mapping CAN/OD, the SPI driver + MCP251XFD register model is the wire path. No VMFW, no RTOS banner, no build-date string. Memory note saved at /home/knight/.claude/projects/-mnt-c-Users-Tobias-dev-vanmoof-vanmoof-s6-decomp/memory/power-control-image-base.md. Suggested first targets for reconstruction: power/src/irq_dispatcher.c, common/node/src/heartbeat.c, and the MCP251XFD init/CAN20 orchestration (VanMoof glue around the vendor driver).

OEM image (not committed): `../../../s6_unpack/v1.8.8.4974/` (from the v1.8.8.4974 OTA zip).
