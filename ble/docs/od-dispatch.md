# ble — Object-Dictionary command dispatch surface

The ble ECU (the S6 central controller) exposes every phone-BLE / CAN-OD command
as an **Object-Dictionary object** with a *get* (read) and/or *set* (write)
handler. The dispatch table lives at **`0x957a0`–`0x959ec`** as an array of
**12-byte entries**:

```c
struct od_entry {
    uint16_t od_id;        /* +0x00 (u16, 2 pad bytes)         */
    uint32_t get_handler;  /* +0x04 Thumb ptr, 0 = no read     */
    uint32_t set_handler;  /* +0x08 Thumb ptr, 0 = no write    */
};
```

A command frame's OD id selects the row; the read/write bit picks get vs set.
Two id ranges: a **16-bit** block (od `0x001`–`0x280`) and an **extended
32-bit-keyed** tail (`0x8xxxx`).

## Decoded map (od → get / set → status)

Addresses below are the OEM handler entry (image base `0xC000`). "done" = already
reconstructed to C (file noted); "pending" = named/recovered only.

| od | get | set | handler(s) | status |
|----|-----|-----|------------|--------|
| 0x004 | — | 0x580d0 | | pending |
| 0x005 | — | 0x58288 | | pending |
| 0x006 | — | 0x57390 | | pending |
| 0x008 | 0x77642 | — | (vendor) | vendor |
| 0x030/31/32 | 0x2d56c | 0x6ce18 | `od_get_identity` / `od_set_identity` (ecu/frame/bike id) | **done** (`od_dispatch.c`) |
| 0x100 | 0x27144 | 0x6c6de | `od_cmd_notify_u8` / `od_cmd_elock_set` | **done** (`od_dispatch.c`) |
| 0x101 | 0x2bf34 | 0x2bf34 | `batt_telemetry_dispatch` | done (`batt_telemetry.c`) |
| 0x10a | — | 0x6c6ae | | pending |
| 0x10c | — | 0x27424 | | pending |
| 0x10e | — | 0x6c6a4 | | pending |
| 0x112-0x115 | 0x6d530 | — | `od_cmd_config_read` (shared) | **done** (`od_dispatch.c`) |
| 0x113 | 0x6d530 | 0x31fb8 | + set | set pending |
| 0x118 | 0x26b04 | 0x26e10 | `od_get_flag_0x118` / `od_set_flag_0x118` (bool + commit) | **done** (`od_dispatch.c`) |
| 0x130 | 0x2d0c4 | — | `od_get_config_0x130` (thin u32 getter) | named |
| 0x131/132 | 0x2d0e0.. | 0x2d29c/0x2d2c4 | `od_set_config_0x131` (+ store/side-effects/sound) | named |
| 0x13a | 0x6cc38 | — | | pending |
| 0x144 | 0x26224 | 0x267e8 | `od_get_mode_0x144` / `od_set_mode_0x144` (3-value mode + sound) | **done** (`od_dispatch.c`) |
| 0x145 | — | 0x6c574 | `od_cmd_play_sound` | **done** (`od_dispatch.c`) |
| 0x160 | 0x28558 | 0x6c85a | | pending |
| 0x163 | — | 0x284b8 | `vmtp_cmd_elock` | done (`vmtp_commands.c`) |
| 0x16b | 0x28574 | — | `vmtp_cmd_fmna_event` | done (`vmtp_commands.c`) |
| 0x191 | 0x282a8 | 0x282cc | `vmtp_cmd_lockstate_report/set` | done (`vmtp_commands.c`) |
| 0x1b0 | — | 0x2ff30 | `vmtp_cmd_firmware` | done (`vmtp_commands.c`) |
| 0x1b1 | 0x2f550 | — | `vmtp_cmd_version` | done (`vmtp_commands.c`) |
| 0x1b2 | 0x2f120 | 0x2f6b4 | `vmtp_cmd_diag_report/log` | done (`vmtp_commands.c`) |
| 0x1ca | 0x6c63e | — | | pending |
| 0x200 | 0x6c898 | — | | pending |
| 0x202 | — | 0x6cc32 | | pending |
| 0x230 | 0x6c9cc | — | | pending |
| 0x279 | 0x33744 | — | | pending |
| 0x280 | 0x338b0 | — | | pending |
| 0x001/002 | — | 0x7761a/0x775fe | (vendor) | vendor |
| 0x003 | 0x55274 | — | | pending |
| **ext** 0x80d85 | 0x261d0 | | | pending |
| **ext** 0x815c4 | 0x26890 | | | pending |
| **ext** 0x81820 | 0x269e0 | | | pending |
| **ext** 0x81c6d | 0x28298 | | | pending |
| **ext** 0x83ef5/0x83f0f | 0x2d040/0x2d050 | | | pending |
| **ext** 0x8514b | 0x30e24 | | | pending |
| **ext** 0x85714 | 0x32944 | | | pending |

## Recovered this pass (`od_dispatch.c`)

Reached only via the table (no CALL xref) → `create_function` + reconstruct:
- **`od_cmd_play_sound`** `0x6c574` (od 0x145 write) — reset player, mark busy
  unless in the no-latch table, `audio_enqueue_play_cmd`.
- **`od_cmd_elock_set`** `0x6c6de` (od 0x100 write) — drive the elock FSM to
  `req[5]` via the per-state callback table (stride 0x34, cb @+0x30).
- **`od_cmd_config_read`** `0x6d530` (od 0x112–0x115 read) — shared u32 config
  getter → publish + submit.
- **`od_cmd_notify_u8`** `0x27144` (od 0x100 read, via thunk 0x6c6aa) — publish a
  stored byte (AEM chan1/id 0x100).
- **`od_get_identity`** `0x2d56c` / **`od_set_identity`** `0x6ce18` (od 0x30/0x31/0x32)
  — the ecu_id / frame_id / bike_id objects; response = `[checksum:2 | id:16]`, set
  stores then echoes. **Cross-confirms the modem**: these are exactly the values the
  modem bridges out as `info/ecu_id`(0x30) / `info/frame_id`(0x31) / `info/bike_id`(0x32)
  — same topic-codes (see `modem/docs/progress.md` + the `s6-modem-topic-dictionary`
  memory). 0x32 stores via the already-named `vm_identity_load_id`.

## Remaining

The **extended `0x8xxxx` tail is NOT new work** — those rows point at
already-named functions (e.g. 0x261d0 = `shell_cmd_audio_set`), i.e. shell/other
handlers reused as OD readers. The genuine remainder is ~15 handlers in the 16-bit
block: the thin `0x6cxxx` accessors (config get/set into globals — 0x004/5/6,
0x10a/c/e, 0x1ca, 0x200, 0x202, 0x230, 0x13a) plus a few `0x2xxxx`/`0x2d0xx`
config objects (0x113 set, 0x131/132 set, 0x160, 0x279/0x280). Recover the same
way (create_function at the even address, decompile, reconstruct). The
high-value, side-effecting command objects (identity, elock, lock-state, firmware,
version, diag, battery telemetry, audio, the 0x118/0x144 settings) are all done.
