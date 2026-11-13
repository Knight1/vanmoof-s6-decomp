# modem — hardware / image layout

> S6 `modem` ECU, host-level triage of the `v1.8.8.4974` image (no Ghidra yet).
> Confirmed from the image; MCU/base cross-checked (string-xref vote + disasm).

## Container
MCUboot. Magic 0x96f3b83d at file offset 0 (bytes 3d b8 f3 96). Header @0: ih_load_addr=0x0, ih_hdr_size@8=0x200 (512), ih_protect_tlv_size@0xa=0, ih_img_size@0xc=0x67fb0 (425904), ih_flags@0x10=0. Vector table at file offset = ih_hdr_size = 0x200: SP@0x200=0x20000bf8, reset@0x204=0x10891. hdr(0x200)+img(0x67fb0)=426416; remaining 150 bytes = signature TLV trailer.

## Image base (Ghidra)
0x10000 (slot/flash base). String-XREF vote is decisive: every code literal that points at a string equals 0x10200 + (string_offset within VT). Winning candidate VT-base 0x10200 with 1988 votes (ALL 1988 detected strings matched); next candidates ~90-101 votes (noise) -> margin ~20x. VT mapped at 0x10200, so slot base = VT_base - hdr_size = 0x10200 - 0x200 = 0x10000. This is the standard nRF91 layout: MCUboot at flash 0, this signed image (TF-M_S + app_NS merged) at flash 0x10000.

## MCUboot header
MCUboot present. ih_hdr_size=0x200, ih_img_size=0x67fb0, ih_version (ih_ver@0x14: u8 major, u8 minor, u16 rev, u32 build@0x18) = 1.8.8.4974. Matches the bundle version build-release-v1.8.8.4974. Single MCUboot magic in file (only at 0x0) -> one signed slot, not a concatenation.

## VMFW header
none. Offset 0x134 = ff ff ff ff (all 0xFF padding), no "VMFW" magic. Expected: VMFW only appears on raw in-house Cortex-M images; MCUboot-wrapped images (ble/modem) carry the MCUboot header instead.

## MCU
Nordic nRF91x1 cellular SiP, Cortex-M33 with TrustZone (ARMv8-M). Evidence: SP=0x20000bf8 (RAM region 0x2000xxxx); TF-M secure-state strings ("Secure image initializing!", "All pins have been configured as non-secure", "SECURE FAULT", "Unknown SPM SVC requested", SecureFault) = ARMv8-M TrustZone; nRF modem library strings (nrf_modem_lib, nrf_modem_bootloader). "Modem sleep notifications require nRF9160 modem >= v1.3.0" is a runtime compat check, not the part; the SiP here is nRF91x1 per the bundle's mfw_nrf91x1-v2.0.2.cbor modem blob. Image ~0x67fb0 (416 KB) is the merged TF-M_S + app_NS firmware.

## SDK / framework fingerprint
nRF Connect SDK (NCS) v2.9.1-60d0d6c8d42d; Zephyr OS v3.7.99-ca954a6216c9; TF-M v2.1.1-ncs3 (Trusted Firmware-M secure domain, ANSI-colored boot banner); Mbed TLS 3.6.1; Nordic nrf_modem library + nrf_modem_lib_bootloader (modem DFU/FOTA path); nrfx HAL drivers (flash_nrf, uart_nrfx_uarte). MIPS Codescape GCC strings present (6.3.0/9.3.0) belong to the embedded nrf_wifi FMAC firmware blob carried for nRF7002 offload (vendor), NOT the Cortex-M toolchain. App toolchain is GNU Arm (NCS 2.9.1 default). RTOS = Zephyr (not FreeRTOS).

## VanMoof vs vendor
Substantial VanMoof application layer present, all vendor-deferred otherwise. Of ~2940 strings (n>=6): ~109 clearly VanMoof app vs ~255 vendor-flavored; the app is the cellular cloud gateway. VanMoof-authored: cert provisioning with O=VanMoof identity (AT%KEYGEN ...,"O=VanMoof,CN=%s"), AWS IoT MQTT + jobs FOTA (AWS_IOT_EVT_FOTA_*), telemetry pub/sub engine (v1/telemetry/%s, topic/priority/rate_limit, device_shadow_telemetry), bike identity (info/bike_id, info/frame_id), A-GNSS/location reporting, and the modem-control glue. Vendor (do NOT decomp): TF-M secure firmware, Zephyr kernel + nrfx/HAL drivers, nrf_modem library, Mbed TLS, MCUboot, the nrf_wifi FMAC MIPS blob. Estimate roughly 10-20% of the image footprint is VanMoof glue over an otherwise NCS/TF-M stack.

### Sample VanMoof app strings
- `AT%KEYGEN=%u,%u,0,"O=VanMoof,CN=%s"`
- `v1/telemetry/%s  / telemetry subscribe topic=0x%04x, priority=%d, rate_limit=%d`
- `info/bike_id  / info/frame_id  / Frame ID: %s  Bike ID: %s`
- `%s: AWS_IOT_EVT_FOTA_START / _DONE / _DL_PROGRESS / _ERROR`
- `modem certificate not provisioned. I WILL NOT CONNECT! (you can still connect manually :)`
- `Location(%s): %.06f,%.06f (accuracy %.01f m)`
- `device_shadow_telemetry / provision_certificate %d, %d / cert_provisioning`

## Ghidra import recipe
1) Import /mnt/c/Users/Tobias/dev/vanmoof/s6_unpack/v1.8.8.4974/modem.bin into the vanmoof project S6 folder (e.g. S6-v1.8.8), naming it 'modem'. 2) Language: ARM Cortex, little-endian, ARMv8-M / Cortex-M33 with TrustZone (ARM:LE:32:Cortex). 3) Set image base = 0x10000 (set_image_base 0x10000) BEFORE analysis — the slot base, not 0x0; the MCUboot 0x200 header maps to 0x10000-0x101ff and the vector table sits at 0x10200. 4) Vector table / initial PC: SP=0x20000bf8, Reset_Handler at 0x10891 (thumb, =0x10890). Mark 0x10200 as the vector table; create function at 0x10890 (clean prologue: push {r3,lr}; cpsid i; msr BASEPRI...). 5) Optionally skip-import or note the leading 0x200 MCUboot header as non-code. 6) reanalyze for a full pass. 7) RAM at 0x20000000; nRF91 peripheral APB at 0x40000000 / 0x50000000 (secure alias 0x50000000). Expect TF-M secure entry + Zephyr NS app in the same image; tag TF-M/Zephyr/nrf_modem/nrfx/MbedTLS/MCUboot as vendor (deferred), focus on the AWS-IoT/telemetry/cert-provisioning/location VanMoof functions.

## Notes
Reset prologue cross-check at base 0x10000 disassembles cleanly (capstone Thumb): 0x10890 push {r3,lr}; 0x10892 cpsid i; 0x10894 movs r3,#0; followed by msr BASEPRI/CONTROL setup (83f31488 = msr BASEPRI) — canonical CMSIS/TF-M reset. The image is the NCS-merged TF-M_S + app_NS single signed slot (both secure-boot banners and VanMoof NS app strings coexist; only one MCUboot magic at file 0). No source-path leaks in strings. The mfw_nrf91x1-v2.0.2.cbor modem blob shipped alongside is a separate Nordic vendor file (RF/baseband firmware), not part of this image. The embedded MIPS-GCC strings are the nrf_wifi FMAC firmware (nRF7002 companion) bundled as data — vendor. VanMoof app scope to reconstruct: certificate provisioning, AWS IoT MQTT/FOTA, telemetry pub-sub, bike/frame identity, location/A-GNSS reporting.

OEM image (not committed): `../../../s6_unpack/v1.8.8.4974/` (from the v1.8.8.4974 OTA zip).
