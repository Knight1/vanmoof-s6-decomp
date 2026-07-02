/*
 * vmtp_commands.c — VanMoof S6 "ble" ECU (Nordic nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * VanMoof Transport-Protocol (VMTP) command / Object-Dictionary handlers reached
 * via the OD-id -> handler dispatch table at 0x958e0. The ble ECU is the S6
 * central controller; the phone/app pokes OD objects over BLE (and the same
 * objects appear on the CAN bus), and each write/read of an OD id lands in one
 * of these handlers. This cluster covers:
 *
 *   firmware staging      cmd "firmware" / OD 0x1?? -> vmtp_cmd_firmware   @0x2ff30
 *   firmware permission   gate                       -> vmtp_cmd_permission_check @0x2ff14
 *   firmware/fs version   OD 0x1b1 (read)            -> vmtp_cmd_version    @0x2f550
 *   e-lock lock/unlock    OD 0x163 (write)           -> vmtp_cmd_elock      @0x284b8
 *   FMNA/find-my trigger  OD 0x16b (write)           -> vmtp_cmd_fmna_event @0x28574
 *   lock-state report     OD 0x191 (read)            -> vmtp_cmd_lockstate_report @0x282a8
 *   lock-state set+cue    OD 0x191 (write)           -> vmtp_cmd_lockstate_set    @0x282cc
 *   diag-blob report      OD 0x1b2 (read)            -> vmtp_cmd_diag_report      @0x2f120
 *   diag-string format    OD 0x1b2 (write)           -> vmtp_cmd_diag_log         @0x2f6b4
 *
 * Reconstructed behaviour-oriented (NOT byte-identical) from the Ghidra
 * decompilation of the named functions; OD object ids, sub-opcodes, magic
 * constants and return codes are taken verbatim. OEM addresses are in the
 * per-function comments. Image base 0xC000; addresses below are file/runtime
 * addresses as Ghidra reports them.
 *
 * Self-contained: only <stdint.h>/<stddef.h>; every vendor/RTOS/SDK/other-module
 * helper is an extern with its OEM address.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 *  Vendor / RTOS / other-module helpers (declared, never reconstructed)
 * ------------------------------------------------------------------ */

/* memset-style fill.                                            0x7b2ba */
extern void  FUN_0007b2ba(void *dst, int val, size_t len);
/* memcpy-style copy (len, dst, src order as decompiled).       0x7b45c */
extern void  FUN_0007b45c(void *dst, const void *src, size_t len);
/* memcpy-style copy (dst, src, len).                           0x7b26a */
extern void  FUN_0007b26a(void *dst, const void *src, size_t len);
/* bounded string copy / compare (strncmp-style, returns 0 eq). 0x7b438 */
extern int   FUN_0007b438(const char *s, const char *pat, size_t n);
/* bounded string copy (strlcpy-style: copy 'src' into 'dst').  0x7b3dc */
extern void  FUN_0007b3dc(char *dst, const char *src);
/* snprintf-style formatter; returns produced length.           0x673e8 */
extern int   FUN_000673e8(char *buf, size_t cap, const char *fmt, ...);

/* 64-bit unsigned divide helper (libgcc/aeabi).                0x1f6a8 */
extern uint64_t FUN_0001f6a8(uint32_t lo, uint32_t hi, uint32_t div, uint32_t rem);

/* Allocate a VMTP/OD response message buffer for object 'id'.  0x77cfc
 * (id, type/flags, length) -> message pointer or NULL.                 */
extern uint8_t *FUN_00077cfc(uint16_t id, int type, int len, int p4);
/* Finalise / dispatch the in-flight VMTP message (commit+send).0x55564 */
extern void  FUN_00055564(void *msg);
/* Publish/broadcast an OD object value (id, src, len).         0x6d274 */
extern void  FUN_0006d274(uint16_t id, const void *src, size_t len);

/* Read a file from the LittleFS '/fs' mount into 'buf'.        0x2f21c
 * (path, buf, len) -> 0 on success.                                    */
extern int   FUN_0002f21c(const char *path, void *buf, size_t len);

/* Emit a structured log/trace line (logger ctx, level, msg).   0x6efd8 */
extern void  FUN_0006efd8(void *log_ctx, int level, const char *msg);

/* Persist a setting/value blob to NVS.                         0x574c8 */
extern void  FUN_000574c8(void *handle, const void *src, size_t len);

/* Application-Event-Manager: submit an event built from a
 * static event descriptor (obj, descriptor, ...args).          0x79bb2 */
extern void  FUN_00079bb2(void *obj, const void *descriptor,
                          int a, int b, int c, int d, int e, int f);

/* Audio player: enqueue clip 'clip' (player, clip, prio, p4).  (module) */
extern void  audio_play(void *player, int clip, int prio, int p4);

/* CAN/OD transmit of a small command frame (node, id, buf, p4).0x364f0 */
extern void  FUN_000364f0(void *node, uint32_t can_id, const void *buf, int p4);
/* Start/restart a millisecond timer with a tick deadline.      0x637f8 */
extern void  FUN_000637f8(void *timer, uint32_t hi, uint32_t lo, uint32_t p4);
/* Cancel/clear a one-shot work item.                           0x7aad4 */
extern void  FUN_0007aad4(void *obj);
/* Kick the e-lock control task / FSM step.                     0x6c7f6 */
extern void  FUN_0006c7f6(int engage);
/* True if the e-lock peripheral is physically present.         (module) */
extern int   elock_is_present(void);
/* Permission/auth check: verify caller may stage firmware.     0x3cfc8
 * (key, scratch[268]) -> 0 if permitted.                               */
extern int   FUN_0003cfc8(uint32_t key, void *scratch);

/* Trigger a CPU reset / reboot-into-bootloader request path.   0x632e4 */
extern void  FUN_000632e4(void *obj);

/* ------------------------------------------------------------------ *
 *  Module data (resolved from the OEM pointer pools)
 * ------------------------------------------------------------------ */

/* Firmware images / staging paths.                                          */
static const char FW_CMD_NAME[]       = "firmware";        /* 0x84b5f */
static const char FW_PAK_PATH[]       = "/fs/firmware.pak"; /* 0x84859 */
static const char FW_PAK_STAGE_PATH[] = "/fs/firmware.pak~";/* 0x84b7b */
static const char MSG_UPDATE_BUSY[]   = "update in progress";  /* 0x84b68 */
static const char MSG_NOT_ALLOWED[]   = "command not allowed";  /* 0x84b81-ish */

/* File-system paths + format used by the version command.                   */
static const char VERSION_PATH[]      = "/fs/version";     /* 0x84835 */
static const char VERSION_FMT[]       = "%u.%u.%u+%u";     /* 0x84841 */
static const char DIAG_FMT_S[]        = "%s";              /* 0x90dac */

/* firmware.pak header magic (MCUboot image magic, little-endian 0x96f3b83d). */
#define FW_PAK_MAGIC  0x96f3b83du

/* Permission-check key (FUN_0003cfc8 argument), OEM DAT_0002ff2c.            */
#define FW_PERM_KEY   0  /* concrete key value lives at 0x2ff2c (data) */

/* Logger context handle, OEM DAT_0002ffc8.                                   */
extern void *g_vmtp_logger;        /* DAT_0002ffc8 */
/* AEM source object for the FMNA event, OEM DAT_00028590.                    */
extern void *g_fmna_event_obj;     /* DAT_00028590 -> 0x7bb18 */
/* Static AEM event descriptor for OD 0x16b, OEM DAT_00028594.               */
extern const void *g_fmna_event_desc; /* DAT_00028594 -> 0x95b6c */

/* OD 0x191 ("lock state") current value byte (RAM global).                  */
extern uint8_t  g_lockstate;       /* DAT_000282c8 / DAT_000282ec -> 0x2013223 */
/* NVS handle used to persist the lock-state byte.                            */
extern void    *g_lockstate_nvs;   /* DAT_000282f0 */
/* Audio player handle for the lock-cue.                                      */
extern void    *g_audio_player;    /* DAT_000267e4 */

/* E-lock control globals.                                                    */
extern int   g_elock_target;       /* DAT_00028514 -> 0x2000688 */
extern int8_t g_elock_dir;         /* DAT_00028518 -> 0x20030e3 (motor dir/flag) */
extern int8_t g_elock_pos;         /* DAT_000284a4 -> *0x20030e3 lock-position */
extern void *g_elock_can_node;     /* DAT_000284a8 -> 0x2001ca4 */
extern void *g_elock_timer;        /* DAT_0002851c */
extern void *g_elock_work;         /* DAT_000284b4 */
extern uint32_t g_elock_can_p1;    /* DAT_000284ac */
extern uint32_t g_elock_can_p2;    /* DAT_000284b0 */

/* Diag-blob (OD 0x1b2) source buffer, OEM DAT_0002f138.                      */
extern const void *g_diag_blob;    /* DAT_0002f138 -> 0x2013382 */
/* Diag-string sink + barriers/state, OEM DAT_0002f6a4/.._ac/.._b0.           */
extern char     *g_diag_strbuf;    /* DAT_0002f6a4 -> 0x20fdf94 */
extern uint32_t *g_diag_lock;      /* DAT_0002f6ac (exclusive-access word)    */
extern void     *g_diag_post_obj;  /* DAT_0002f6b0 */
extern const char *g_diag_src;     /* DAT_0002f6d0 -> "/fs/firmware.pak" tail */

/* ============================================================================
 *  vmtp_cmd_permission_check @ 0x2ff14
 *  Permission gate for firmware staging. Runs the auth/permission verifier with
 *  a 268-byte scratch on the stack; returns true (1) iff the caller is allowed.
 * ==========================================================================*/
int vmtp_cmd_permission_check(void)
{
    uint8_t scratch[268];
    return FUN_0003cfc8(FW_PERM_KEY, scratch) == 0;
}

/* ============================================================================
 *  vmtp_cmd_firmware @ 0x2ff30
 *  Command "firmware": stage/commit the downloaded firmware bundle. The frame
 *  carries a sub-opcode byte at +5 and an up-to-8-byte name at +8 that must
 *  equal the literal "firmware". Sub-opcodes:
 *     1 = begin update: permission-gated; on success copies the staging path
 *         "/fs/firmware.pak~" and answers with status 0x10. On deny: status is
 *         left and an "update in progress" / "command not allowed" log emitted.
 *     4 = commit:   copies the live path "/fs/firmware.pak" and answers 0x11.
 *     0 = query/ack: answers with whatever status is already in the frame.
 *  The reply is built as an OD message (type 4, sel 5) echoing the frame body.
 * ==========================================================================*/
void vmtp_cmd_firmware(uint8_t *frame)
{
    uint16_t name_len = *(uint16_t *)(frame + 6);
    char *name = (char *)(frame + 8);
    uint16_t status;
    uint8_t *reply;
    uint16_t obj_sel;

    if (name_len > 7)
        name_len = 8;

    /* Name must be the literal "firmware". */
    if (FUN_0007b438(name, FW_CMD_NAME, name_len) != 0)
        return;

    switch (frame[5]) {
    case 1: /* begin */
        if (vmtp_cmd_permission_check()) {
            /* not permitted in current state -> reject with diagnostic */
            if ((*(uint32_t *)g_vmtp_logger & 7) != 0)
                FUN_0006efd8(g_vmtp_logger, 1, MSG_UPDATE_BUSY);
            return;
        }
        FUN_0007b3dc(name, FW_PAK_PATH);       /* op1 begin -> live path  (0x2ffd0) */
        status = 0x10;
        break;
    case 4: /* commit */
        FUN_0007b3dc(name, FW_PAK_STAGE_PATH); /* op4 commit -> staging path (0x2ffd4) */
        status = 0x11;
        break;
    case 0: /* query / ack — echo current status */
        status = *(uint16_t *)(frame + 6);
        break;
    default:
        if ((*(uint32_t *)g_vmtp_logger & 7) != 0)
            FUN_0006efd8(g_vmtp_logger, 1, MSG_NOT_ALLOWED);
        return;
    }

    /* Build and send the OD reply echoing the frame body. */
    obj_sel = *(uint16_t *)(frame + 3);
    *(uint16_t *)(frame + 6) = status;
    reply = FUN_00077cfc(obj_sel, 4, 5, 0);
    if (reply != NULL)
        FUN_0007b26a(reply + 5, frame + 5, obj_sel);
    FUN_00055564(reply);
}

/* ============================================================================
 *  vmtp_cmd_version @ 0x2f550 — OD 0x1b1 (read)
 *  Reports the firmware/filesystem version. Reads the 8-byte "/fs/version"
 *  blob (4x u8/u16 -> "%u.%u.%u+%u") and, if present and carrying the expected
 *  MCUboot magic, the version embedded in "/fs/firmware.pak". On a missing/bad
 *  version file the build-string status 0x0b is reported with the literal
 *  "v1.8.8.4..." fallback. The 0x24-byte result is published on OD 0x1b1.
 * ==========================================================================*/
void vmtp_cmd_version(void)
{
    struct {
        uint8_t  v0;
        uint8_t  v1;
        uint16_t v2;
        uint32_t v3;
    } ver, pak;
    uint32_t pak_magic_and_hdr[8]; /* 0x20-byte pak header read; word0 = magic, version fields @ +20 */

    struct {
        uint16_t status_a;
        char     str_a[16];
        uint16_t status_b;
        char     str_b[20];
    } out;

    int rc;

    FUN_0007b2ba(&out, 0, sizeof(out));

    /* "/fs/version" -> "%u.%u.%u+%u" */
    rc = FUN_0002f21c(VERSION_PATH, &ver, sizeof(ver));
    if (rc == 0) {
        out.status_a = (uint16_t)FUN_000673e8(out.str_a, 0x10, VERSION_FMT,
                                              ver.v0, ver.v1, ver.v2, ver.v3);
    } else {
        out.status_a = 0x0b;
        FUN_0007b45c(out.str_a, g_diag_src, 0x10); /* literal build string */
    }

    /* "/fs/firmware.pak": only report if header magic matches. */
    rc = FUN_0002f21c(FW_PAK_PATH, pak_magic_and_hdr, 0x20);
    (void)pak;
    if (rc == 0 && pak_magic_and_hdr[0] == FW_PAK_MAGIC) {
        uint8_t *h = (uint8_t *)pak_magic_and_hdr; /* version fields at byte offset 20 */
        out.status_b = (uint16_t)FUN_000673e8(out.str_b, 0x10, VERSION_FMT,
                                              h[20], h[21],
                                              *(uint16_t *)(h + 22),
                                              *(uint32_t *)(h + 24));
    }

    FUN_0006d274(0x1b1, &out, sizeof(out));
    FUN_00055564(NULL);
}

/* ============================================================================
 *  vmtp_cmd_elock @ 0x284b8 — OD 0x163 (write)
 *  Drive the e-lock motor. No-op if the e-lock peripheral is absent.
 *  Frame +5 is a signed step/target: non-zero requests a move (records the
 *  target + direction byte at frame-4, kicks the e-lock task, then arms a
 *  guard timer at target*1000*0x8000/1000 ticks). Zero requests "open":
 *  if the lock is not already open (pos != -1) and the CAN node flags bit 2 is
 *  set, a 3-byte command is sent over CAN id 0x1900; the position is marked
 *  open (-1), the task is released, and the pending work item is cancelled.
 * ==========================================================================*/
void vmtp_cmd_elock(uint8_t *frame)
{
    int target;
    int64_t ticks;
    uint64_t deadline;
    struct { uint32_t op; uint32_t p1; uint32_t p2; } can_cmd;

    if (elock_is_present() == 0)
        return;

    target = *(int *)(frame + 5);
    if (target != 0) {
        /* Move request: latch target + direction, kick the task, arm timer. */
        g_elock_target = target;
        g_elock_dir    = *(int8_t *)(frame - 4);
        FUN_0006c7f6(1);

        ticks    = (int64_t)(uint32_t)(g_elock_target * 1000) * 0x8000 + 999;
        deadline = FUN_0001f6a8((uint32_t)ticks, (uint32_t)((uint64_t)ticks >> 32),
                                1000, 0);
        FUN_000637f8(g_elock_timer, (uint32_t)(deadline >> 32),
                     (uint32_t)deadline, (uint32_t)(deadline >> 32));
        return;
    }

    /* Open request. */
    if (g_elock_pos != -1) {
        /* If the CAN node advertises support (flags bit 2), send open frame. */
        if ((*(uint32_t *)g_elock_can_node << 0x1d) & 0x80000000u) {
            can_cmd.op = 3;
            can_cmd.p1 = g_elock_can_p1;
            can_cmd.p2 = g_elock_can_p2;
            FUN_000364f0(g_elock_can_node, 0x1900, &can_cmd, 0);
        }
        g_elock_pos = -1;
        FUN_0006c7f6(0);
        FUN_0007aad4(g_elock_work);
    }
}

/* ============================================================================
 *  vmtp_cmd_fmna_event @ 0x28574 — OD 0x16b (write)
 *  Triggers an Application-Event-Manager event for the Find-My (FMNA) subsystem.
 *  Loads the FMNA context object (its [+0x10] field) and submits the static AEM
 *  event descriptor at 0x95b6c with all payload args zeroed. (The descriptor is
 *  the FMNA "MASTER_..." storage/event handler reached over the AEM bus.)
 * ==========================================================================*/
void vmtp_cmd_fmna_event(void)
{
    void *ctx = *(void **)((uint8_t *)g_fmna_event_obj + 0x10);
    FUN_00079bb2(ctx, g_fmna_event_desc, 0, 0, 0, 0, 0, 0);
}

/* ============================================================================
 *  vmtp_cmd_lockstate_report @ 0x282a8 — OD 0x191 (read)
 *  Reports the current "lock state" byte. Allocates a 1-byte OD 0x191 response
 *  (type 1), copies the cached g_lockstate into it, and dispatches.
 * ==========================================================================*/
void vmtp_cmd_lockstate_report(void)
{
    uint8_t state = g_lockstate;
    uint8_t *msg = FUN_00077cfc(1, 0x191, 1, 0);
    if (msg != NULL)
        msg[5] = state;
    FUN_00055564(msg);
}

/* ============================================================================
 *  vmtp_cmd_lockstate_set @ 0x282cc — OD 0x191 (write)
 *  Sets the "lock state" byte from frame +5, persists it to NVS, re-publishes
 *  it via vmtp_cmd_lockstate_report (OD 0x191 read), and plays audio cue 0x0d
 *  (the lock/unlock confirmation chime).
 * ==========================================================================*/
void vmtp_cmd_lockstate_set(uint8_t *frame)
{
    g_lockstate = frame[5];
    FUN_000574c8(g_lockstate_nvs, &g_lockstate, 1);
    vmtp_cmd_lockstate_report();
    audio_play(g_audio_player, 0x0d, 1, 0);
}

/* ============================================================================
 *  vmtp_cmd_diag_report @ 0x2f120 — OD 0x1b2 (read)
 *  Publishes the 0x20-byte diagnostic blob (g_diag_blob @ 0x2013382) on OD 0x1b2.
 * ==========================================================================*/
void vmtp_cmd_diag_report(void)
{
    FUN_0006d274(0x1b2, g_diag_blob, 0x20);
    FUN_00055564(NULL);
}

/* ============================================================================
 *  vmtp_cmd_diag_log @ 0x2f6b4 — OD 0x1b2 (write)
 *  Formats a diagnostic string from the frame into the shared diag string
 *  buffer (g_diag_strbuf @ 0x20fdf94) and posts it. Frame layout:
 *     +5  u16 length
 *     +7  string payload
 *     +0x27 u8 flag -> stored as bool at strbuf+0x11f
 *  The first 0xff bytes are formatted "%s" from g_diag_src, then up to 0x20 more
 *  from the frame payload. Access to the buffer is guarded by an LDREX/STREX
 *  spinlock (clearing bit 1 of *g_diag_lock under a DMB), after which the post
 *  object is signalled (FUN_000632e4). Always returns 0.
 * ==========================================================================*/
uint32_t vmtp_cmd_diag_log(uint8_t *frame)
{
    uint16_t len = *(uint16_t *)(frame + 5);
    char *buf = g_diag_strbuf;
    int8_t flag = *(int8_t *)(frame + 0x27);

    if (len == 0)
        *(char *)(frame + 7) = (char)len;

    buf[0xff]  = 0;
    *(uint32_t *)(buf + 0x120) = 0;
    *(uint8_t  *)(buf + 0x11f) = (flag != 0);

    FUN_000673e8(buf, 0xff, DIAG_FMT_S, g_diag_src, len);
    /* payload (frame+7 is always non-NULL in practice) */
    FUN_000673e8(buf + 0xff, 0x20, DIAG_FMT_S, frame + 7, len);

    /* Release the diag-buffer spinlock: clear bit 1 under LDREX/STREX + DMB. */
    __asm__ volatile ("dmb" ::: "memory");
    {
        uint32_t v;
        do {
            v = __atomic_load_n(g_diag_lock, __ATOMIC_RELAXED);
            v &= 0xfffffffdu;
        } while (!__atomic_compare_exchange_n(g_diag_lock,
                    &(uint32_t){ v | 2u }, v, 0,
                    __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    }
    __asm__ volatile ("dmb" ::: "memory");

    FUN_000632e4(g_diag_post_obj);
    return 0;
}
