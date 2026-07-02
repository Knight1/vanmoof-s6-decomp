# ble — hardware / image layout

> MCU, container format, and the Ghidra load parameters for the S6 `ble` image.
> Confirmed from the v1.8.8.4974 `ble.bin` (host-level analysis); function-level
> detail is in `architecture.md` / `progress.md`.

## MCU

**Nordic nRF52840** (ARM Cortex-M4F, single-precision FPU). Confirmed by:
- SDK strings: `nRF52x`, `Nordic Semiconductor`, `SoftDevice Controller`.
- Initial SP `0x2001e8c0` → RAM in the `0x2000_0000` bank, ~122 KB in use
  (fits the 256 KB nRF52840 SRAM).
- App image is ~551 KB at flash slot `0xC000` → end ≈ `0x96000` (>512 KB), so the
  part has **1 MB flash** = nRF52840 (rules out the 512 KB nRF52833/52832).

| Region | Range | Notes |
| --- | --- | --- |
| Flash | `0x0000_0000`–`0x0010_0000` | 1 MB internal |
| RAM | `0x2000_0000`–`0x2004_0000` | 256 KB |
| Code RAM alias / peripherals | `0x4000_0000`+ | nRF52 APB/AHB peripherals |
| FICR / UICR | `0x1000_0000` / `0x1000_1000` | factory/user config |

## Toolchain / SDK

From the boot banner strings:
- **nRF Connect SDK v2.9.1** (`60d0d6c8d42d`)
- **Zephyr OS v3.7.99** (`ca954a6216c9`) — the NCS 2.9.1 Zephyr fork
- **SoftDevice Controller** (link-layer library; `bt_hci_sdc`, `bt_sdc_crypto`,
  `bt_sdc_ecdh`) — the modern SDC, **not** the legacy S140 SoftDevice.
- Internal VanMoof framework path seen: `dragoon/libs/scheduling/...`
  (`dragoon` appears to be the S6/firmware-internal codename — tentative).

## Container — MCUboot image

`ble.bin` is a signed **MCUboot** image. Header at file offset 0 (little-endian):

| Field | Offset | Value | Meaning |
| --- | --- | --- | --- |
| `ih_magic` | `0x00` | `0x96f3b83d` | MCUboot image magic |
| `ih_load_addr` | `0x04` | `0x00000000` | unused (XIP from slot) |
| `ih_hdr_size` | `0x08` | `0x0200` | **512-byte header** (image follows at file `0x200`) |
| `ih_protect_tlv_size` | `0x0A` | `0x0000` | — |
| `ih_img_size` | `0x0C` | `0x00089ef0` | payload size (564464 B) |
| `ih_flags` | `0x10` | `0x00000000` | — |
| `ih_ver` | `0x14` | `1.8` rev `0x0800` build `4974` | matches release `v1.8.8.4974` |

The image payload (vector table + text + rodata + data-init) is `0x89ef0` bytes
starting at file `0x200`; a signature/TLV trailer follows to EOF. File `0x20`–
`0x200` is `0xFF` padding.

## Flash partition map (inferred)

Standard NCS/nRF52840 + MCUboot layout, derived from the slot base:

| Partition | Flash range | Notes |
| --- | --- | --- |
| MCUboot bootloader | `0x0000`–`0xC000` | 48 KB |
| **App primary slot** | **`0xC000`**–… | this image; MCUboot header at `0xC000`, app vector table at **`0xC200`** |
| (secondary slot / settings / NVS) | TBD | `/fs/settings` + NVS used; exact offsets to confirm |

## Ghidra load parameters

- **Language:** `ARM:LE:32:Cortex` (Cortex-M4, Thumb).
- **Image base:** **`0xC000`** — load the whole `ble.bin` at `0xC000` so file
  offset `F` ↦ vaddr `0xC000 + F`. The MCUboot header then sits at `0xC000`, the
  **vector table at `0xC200`**, and absolute code/data pointers resolve correctly.
  (Getting the base wrong breaks every literal ref — same hazard as the S5 ble at
  `0x23000`; here it is `0xC000`.)
- After import: point VTOR/disassembly at `0xC200`, mark the vector table, then
  **reanalyze**.
- Verification anchors (all at base `0xC000`):
  - initial SP `0x2001e8c0`, **Reset `0x0003b958`** (`movs r0,#0` — Zephyr
    `z_arm_reset`), default fault handler `0x0003b944`.
  - Base was pinned by string-cross-reference (literal `=str` == `0xC000 +
    file_off(str)`): a sharp peak at `0xC000` (≫ any other offset).
