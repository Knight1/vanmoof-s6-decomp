/*
 * audio_bell.c — VanMoof S6 "ble" ECU (Nordic nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Audio / bell-cue subsystem. The ble ECU is the S6 central controller; it owns
 * the audio playback queue and the per-user "bell sound" selection. These
 * functions package an audio "play" command into an event/message that is posted
 * to the audio worker (FUN_00062fb8 = a k_msgq/zbus-style submit), plus the
 * helpers that pick which clip to play (event cues, timed cues, the user's
 * currently selected bell, etc.).
 *
 * Reconstructed behaviour-oriented (NOT byte-identical) from the Ghidra
 * decompilation of the named functions. OEM addresses are in the per-function
 * comments. Image base 0xC000; addresses below are file/runtime addresses as
 * Ghidra reports them.
 *
 * Self-contained: only <stdint.h>/<stddef.h>; every vendor/RTOS/SDK helper is an
 * extern with its OEM address.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 *  Vendor / RTOS / other-module helpers (declared, never reconstructed)
 * ------------------------------------------------------------------ */

/* memset-style fill (Zephyr/libc thunk).                      0x7b2ba */
extern void  FUN_0007b2ba(void *dst, int val, size_t len);
/* memcpy-style copy (Zephyr/libc thunk).                      0x7b45c */
extern void  FUN_0007b45c(void *dst, const void *src, size_t len);

/* Post a message to the audio worker queue (k_msgq/zbus put). 0x62fb8 */
extern int   FUN_00062fb8(void *msgq, const void *msg, int p3, int p4);
/* Submit a delayed/one-shot work or event (used by event cue).0x63790 */
extern int   FUN_00063790(void *obj, int r1, int flags, int p4);
/* Schedule a timed work item with a callback (timed cue).     0x64594 */
extern int   FUN_00064594(void *timer, int r1, void *cb, int a, int b, int c);

/* Reset / drain the audio player state object (k_work cancel).0x7a74e */
extern void  FUN_0007a74e(void *player);
/* Reset a small object used by the event cue path.            0x7aad4 */
extern void  FUN_0007aad4(void *obj);
/* Read a millisecond uptime / tick value -> 64-bit.           0x7ae2a */
extern int64_t FUN_0007ae2a(void *clock);

/* DTC (diagnostic trouble code) pattern test: returns 0 on match. 0x???  */
extern int   dtc_pattern_match(uint32_t key, const void *pattern);
/* True if the e-lock peripheral is physically present.            (module) */
extern int   elock_is_present(void);
/* Drive the e-lock FSM one step (cue id 2 routes here).          (module) */
extern void  elock_fsm_transition(void);

/* Modulo-7 random pick helper for the "random bell" feature.   0x3e894 */
extern void  FUN_0003e894(void *out, int n);

/* Persistence: open a settings/blob handle for the bell index. 0x57430 */
extern uint32_t FUN_00057430(void *scratch, uint32_t key);
/* Persistence: begin a write transaction.                      0x3c910 */
extern uint32_t FUN_0003c910(void *txn, void *handle, int len);
/* Persistence: stage 'len' bytes from 'src' into the txn.      0x3caac */
extern uint32_t FUN_0003caac(void *txn, int src, int len);
/* Persistence: commit/close the txn.                           0x3ca34 */
extern void     FUN_0003ca34(void *txn);

/* Config-event helpers used by audio_play_on_config_event. */
extern void  FUN_00038234(void *a, void *b, int c);          /* 0x38234 */
extern void  FUN_00031884(int evt);                           /* 0x31884 */

/* Event-cue internal helpers. */
extern void  FUN_00026eac(int p);                             /* 0x26eac */
extern void  FUN_00027ba4(void);                              /* 0x27ba4 */
extern void  FUN_00027444(void);                              /* 0x27444 */

/* ------------------------------------------------------------------ *
 *  Module globals (resolved from the literal pools; runtime SRAM addrs)
 * ------------------------------------------------------------------ */

/* 1-byte "audio busy / one-shot in progress" flag.   ptr @0x267d0 -> 0x200131da */
extern volatile uint8_t g_audio_busy;                 /* 0x200131da */
/* DTC-set flag toggled when the play key matches a fault pattern.
 *                                                    ptr @0x2678c -> 0x200137dc */
extern volatile uint8_t g_audio_dtc_flag;             /* 0x200137dc */
/* The audio worker message queue handle.             ptr @0x26790 -> 0x200037dc */
extern void *g_audio_msgq;                            /* 0x200037dc */

/* Player state object reset by audio_player_reset.   ptr @0x26734 -> 0x200037dc */
extern void *g_audio_player;                           /* 0x200037dc */
/* Player flag block; byte at +0x4c is cleared on reset.   ptr -> 0x200131da */
extern uint8_t g_audio_player_flags[];                 /* 0x200131da, +0x4c */
/* "current clip" / state word cleared on reset.      ptr -> 0x200037dc */
extern volatile uint32_t g_audio_cur;                  /* 0x200037dc */

/* DTC pattern object referenced by play / enqueue.   const @0x00081430 */
extern const uint8_t g_audio_dtc_pattern[];            /* 0x00081430 */

/* Bell selection state. Indexed by 'channel' (per-side / per-user) param.
 *   pending base = DAT_000269ac == DAT_000269d8 -> 0x200131de
 *   active  base = DAT_000269b0               -> 0x200131dc            */
extern uint8_t g_bell_index_pending[];                 /* 0x200131de (DAT_269ac/269d8) */
extern uint8_t g_bell_index_active[];                  /* 0x200131dc (DAT_269b0)        */

/* Three parallel tables of clip ids, selected by the active bell index 0..6.
 *   tbl_a @0x0007d0f4 (PTR_PTR_000269b4) — variant==0 *gate* table,
 *   tbl_b @0x0007d0d8 (PTR_PTR_000269b8) — clip actually played on both paths,
 *   tbl_c @0x0007d110 (PTR_PTR_000269bc) — zero-entry fallback.        */
extern const uint32_t g_bell_clip_tbl_a[7];            /* 0x0007d0f4 */
extern const uint32_t g_bell_clip_tbl_b[7];            /* 0x0007d0d8 */
extern const uint32_t g_bell_clip_tbl_c[7];            /* 0x0007d110 */

/* audio_play_by_index() clip-id table.                const @0x0007d238 */
extern const uint32_t g_audio_index_tbl[];             /* 0x0007d238 */

/* Settings key for persisting the bell index.         const @0x000815c4 */
extern const uint32_t g_bell_settings_key;             /* 0x000815c4 */

/* Event-cue gate / objects. */
extern volatile uint32_t g_eventcue_gate;              /* 0x200130e4 (ptr @0x27c98) */
extern void *g_eventcue_obj;                           /* 0x20000... (ptr @0x27c9c) */
extern uint32_t g_eventcue_clip;                       /* 0x00027b35 (ptr @0x27ca4) */
extern uint32_t g_eventcue_arg;                        /* ptr @0x27ca0 -> 0x0007.. */
extern void *g_eventcue_submit_obj;                    /* 0x200005e0 (ptr @0x27ca8) */

/* Timed-cue clock object + clip id. */
extern void *g_timedcue_clock;                         /* 0x20003440 (ptr @0x27fe8) */
extern uint32_t g_timedcue_clip;                       /* 0x00081b82 (ptr @0x27fec) */

/* Config-event toggle + clip. */
extern volatile uint8_t g_cfgevt_flag;                 /* 0x20003102 (ptr @0x31970) */
extern void *g_cfgevt_obj;                             /* 0x000854b5 (ptr @0x31974) */
extern uint32_t g_cfgevt_clip;                         /* 0x00081446 (ptr @0x31978) */

/* Mute / volume level byte set by audio_set_mute_level.  0x20013210 (LAB @0x269ec) */
extern volatile uint8_t g_audio_mute_level;            /* 0x20013210 */

/* Logging gate model (matches the OEM vm_log_enabled/vm_logf pattern). */
extern int   vm_log_enabled(int mod);
extern void  vm_logf(int mod, int lvl, const char *fmt, ...);

/* ------------------------------------------------------------------ *
 *  Audio command message layout (16 bytes, built on the stack)
 * ------------------------------------------------------------------ */
typedef struct audio_cmd {
    uint8_t  type;       /* +0x00  clip "type"/priority (param_2, e.g. 0xd/0xe/0xf) */
    uint8_t  pad[3];     /* +0x01 */
    uint32_t play_flag;  /* +0x04  (param_3, usually 1 = play) */
    uint32_t extra;      /* +0x08  (param_4, e.g. volume/arg) */
    uint32_t reserved;   /* +0x0c */
} audio_cmd_t;           /* 16 bytes */

/* ================================================================== *
 *  audio_player_reset — 0x2671c
 *
 *  Drain/cancel any queued playback work and clear the player's
 *  "in progress" flag and current-clip word.
 * ================================================================== */
void audio_player_reset(void)
{
    FUN_0007a74e(g_audio_player);                 /* cancel pending work */
    g_audio_player_flags[0x4c] = 0;               /* clear "busy" flag */
    g_audio_cur = 0;                              /* no current clip */
}

/* ================================================================== *
 *  audio_enqueue_play_cmd — 0x26740
 *
 *  Build a 16-byte audio command (type/flag/extra), wrap it together
 *  with the 64-byte play descriptor 'key', and post it to the audio
 *  worker queue. If the play key matches a DTC pattern, raise the
 *  DTC flag first.
 *
 *  param_1 key       : 64-byte clip/descriptor key
 *  param_2 type      : clip type/priority (u8)
 *  param_3 play_flag
 *  param_4 extra
 *
 *  Declared void in the OEM, but the final FUN_00062fb8 (msgq put) result is
 *  left in r0; audio_play reads it back as the enqueue result, so we return it.
 * ================================================================== */
int32_t audio_enqueue_play_cmd(const void *key, uint8_t type,
                               uint32_t play_flag, uint32_t extra)
{
    audio_cmd_t cmd;
    uint8_t     descriptor[0x40];

    if (dtc_pattern_match((uint32_t)(uintptr_t)key, g_audio_dtc_pattern) == 0) {
        g_audio_dtc_flag = 1;
    }

    FUN_0007b2ba(&cmd, 0, sizeof(cmd));           /* zero the 16-byte command */
    cmd.type      = type;
    cmd.play_flag = play_flag;
    cmd.extra     = extra;

    FUN_0007b45c(descriptor, key, sizeof(descriptor));  /* copy 64-byte key */

    /* Post to the audio worker queue. The OEM passes the descriptor as the
     * message payload; the command struct is consumed inline by the worker. */
    (void)cmd;
    return FUN_00062fb8(g_audio_msgq, descriptor, 0, 0);
}

/* ================================================================== *
 *  audio_play — 0x26794
 *
 *  Top-level "play this clip" entry. If the player is idle:
 *    - reset the player,
 *    - if the key matches the DTC pattern, mark busy,
 *    - enqueue the play command and return its result.
 *  If already busy, return -16 (0xfffffff0, -EBUSY-ish OEM code).
 *
 *  The OEM body itself forwards a fixed extra=0 to audio_enqueue_play_cmd
 *  and only reads three register args, but several callers (current_bell,
 *  timed_cue) pass a 4th word in r3; the slot is carried here for ABI
 *  fidelity even though this body ignores it.
 *
 *  Returns the enqueue result, or -16 if busy.
 * ================================================================== */
int32_t audio_play(uint32_t key, uint8_t type, uint32_t play_flag, uint32_t extra)
{
    (void)extra;

    if (g_audio_busy != 0) {
        return -16;                               /* 0xfffffff0 */
    }

    audio_player_reset();

    if (dtc_pattern_match(key, g_audio_dtc_pattern) == 0) {
        g_audio_busy = 1;
    }

    /* OEM forwards (key,type,play_flag,extra=0) and returns the result. */
    return audio_enqueue_play_cmd((const void *)(uintptr_t)key, type, play_flag, 0);
}

/* ================================================================== *
 *  audio_play_by_index — 0x27568
 *
 *  Look up a clip id in g_audio_index_tbl[index] and play it with
 *  type 0xe, flag 1.
 * ================================================================== */
void audio_play_by_index(int index)
{
    /* OEM call site passes 3 register args; the 4th 'extra' slot is don't-care. */
    audio_play(g_audio_index_tbl[index], 0x0e, 1, 0);
}

/* ================================================================== *
 *  audio_play_current_bell — 0x2694c
 *
 *  Resolve and play the user's currently selected bell sound.
 *
 *  param_1 channel : per-side/per-user index into the bell-index arrays.
 *  param_2 variant : 0 = gate path (config B); non-zero = random/config-A path.
 *  param_3 force   : non-zero suppresses the primary clip and forces the
 *                    fallback / no-play behaviour.
 *  param_4 arg     : forwarded as the 'extra' to audio_play (type 0xf).
 *
 *  Promotes the pending bell index to active, optionally re-rolls a random
 *  index (0..6) when the stored value is out of range, then picks a clip id
 *  from one of the three parallel tables.
 *
 *  Table mapping (from the literal pool):
 *    tbl_a @0x0007d0f4  (PTR_PTR_000269b4) — the variant==0 *gate* table,
 *    tbl_b @0x0007d0d8  (PTR_PTR_000269b8) — the clip actually played,
 *    tbl_c @0x0007d110  (PTR_PTR_000269bc) — the zero-entry fallback.
 *
 *  variant==0: gated on tbl_a[idx]; if tbl_a[idx]==0 OR force!=0 the OEM bails
 *  out with NO play. Otherwise the clip played comes from tbl_b[idx].
 *  variant!=0: re-rolls when idx>6; if tbl_b[idx]!=0 && force==0 play tbl_b[idx],
 *  else play tbl_c[idx].
 * ================================================================== */
void audio_play_current_bell(int channel, int variant, int force, uint32_t arg)
{
    uint32_t idx;
    const uint32_t *tbl;
    uint32_t clip;

    /* Promote pending -> active for this channel, keep the value. */
    idx = g_bell_index_pending[channel];
    g_bell_index_active[channel] = (uint8_t)idx;

    tbl = g_bell_clip_tbl_a;            /* puVar2 = PTR_PTR_000269b4 */

    if (variant == 0) {
        /* Gate on tbl_a[idx]; on either gate condition the OEM returns. The
         * second condition also reassigns the working table to tbl_b, which is
         * the table the surviving (play) path reads from. */
        if (g_bell_clip_tbl_a[idx] == 0) {
            return;
        }
        tbl = g_bell_clip_tbl_b;        /* puVar2 = PTR_PTR_000269b8 */
        if (force != 0) {
            return;
        }
        /* fall through: clip = tbl_b[idx] */
    } else {
        /* config-A path: out-of-range index re-rolls a random 0..6 bell. */
        if (idx > 6) {
            FUN_0003e894(&g_bell_index_active[channel], 1);
            idx = (uint32_t)g_bell_index_active[channel] % 7;
            g_bell_index_active[channel] = (uint8_t)idx;
        }
        clip = g_bell_clip_tbl_b[idx];
        if (clip != 0 && force == 0) {
            audio_play(clip, 0x0f, 1, arg);
            return;
        }
        tbl = g_bell_clip_tbl_c;        /* puVar2 = PTR_PTR_000269bc */
    }

    clip = tbl[idx];
    audio_play(clip, 0x0f, 1, arg);
}

/* ================================================================== *
 *  audio_set_bell_index — 0x269c0
 *
 *  Store a new bell index (0..7) for the given channel and persist it.
 *  Rejects out-of-range indices with -22 (EINVAL).
 *
 *  Returns 0 on success, -22 on bad index, or a negative persistence
 *  error (clamped to <= 0 via 'r & (r>>31)').
 * ================================================================== */
uint32_t audio_set_bell_index(int channel, uint32_t index)
{
    uint32_t rc;
    uint8_t  txn[16];          /* small transaction handle on the stack */
    uint8_t  scratch[52];      /* 0x34 byte settings scratch (0x52 staged below) */
    int      pending_base;     /* iVar1 = DAT_000269d8, captured before range check */

    /* OEM captures DAT_000269d8 (the pending bell-index array base) up front. */
    pending_base = (int)(uintptr_t)g_bell_index_pending;

    if (index > 7) {
        return 0xffffffeau;    /* -22 EINVAL */
    }

    g_bell_index_pending[channel] = (uint8_t)index;

    /* zero the txn header */
    txn[0] = txn[1] = txn[2] = txn[3] = 0;
    txn[4] = txn[5] = txn[6] = txn[7] = 0;
    txn[8] = 0;

    rc = FUN_00057430(scratch, g_bell_settings_key);
    if (rc == 0) {
        rc = FUN_0003c910(txn, scratch, 0x52);
        if (rc == 0) {
            /* Stage the 2-byte index pair from the pending-index array base
             * (OEM passes iVar1 = DAT_000269d8, not the channel integer). */
            rc = FUN_0003caac(txn, pending_base, 2);
            FUN_0003ca34(txn);                    /* commit/close */
            rc = rc & ((int32_t)rc >> 31);        /* clamp positive -> 0 */
        }
    }
    return rc;
}

/* ================================================================== *
 *  audio_set_mute_level — 0x269e0
 *
 *  Setter invoked from a config/OD write handler; only acts when the
 *  write length (param_3) is exactly 1, copying one byte into the
 *  mute/volume level global.
 * ================================================================== */
void audio_set_mute_level(uint32_t obj, const uint8_t *value, int len)
{
    (void)obj;
    if (len == 1) {
        g_audio_mute_level = *value;
    }
}

/* ================================================================== *
 *  audio_play_event_cue — 0x27c4c
 *
 *  Play (or route) an "event" cue. When the cue gate is open OR the e-lock
 *  is present, tear down any in-flight cue and either:
 *    - route cue id 2 into the e-lock FSM, or
 *    - enqueue the standard event clip and submit a follow-up event.
 *  When the gate is closed and no e-lock is present, hand off to the
 *  alternate handler (FUN_00027444).
 *
 *  Always returns 0.
 * ================================================================== */
int32_t audio_play_event_cue(int cue_id)
{
    if (g_eventcue_gate == 0 || elock_is_present() != 0) {
        FUN_00026eac(0);
        FUN_00027ba4();
        FUN_0007aad4(g_eventcue_obj);

        if (cue_id == 2) {
            elock_fsm_transition();
        } else {
            audio_enqueue_play_cmd((const void *)(uintptr_t)g_eventcue_clip,
                                   0x0e, 1, g_eventcue_arg);
            /* OEM: FUN_00063790(DAT_00027ca8, extraout_r1, 0x10000, 0). The 2nd
             * arg is a Ghidra phantom (residual r1 after elock_is_present);
             * FUN_00063790 is a k_work_submit-style call that ignores it, so 0
             * is behaviourally safe. */
            FUN_00063790(g_eventcue_submit_obj, 0, 0x10000, 0);
        }
    } else {
        FUN_00027444();
    }
    return 0;
}

/* ================================================================== *
 *  audio_play_timed_cue — 0x27fa8
 *
 *  Play a cue and arm a one-shot timer (clip + a millisecond delay derived
 *  from the clock). The delay is (clock_ticks * 1000); the OEM range-checks
 *  that the result fits in 47 bits before playing and rescheduling.
 * ================================================================== */
void audio_play_timed_cue(uint32_t a, uint32_t b, uint32_t c)
{
    int64_t  ticks;
    uint64_t delay;

    ticks = FUN_0007ae2a(g_timedcue_clock);
    delay = (uint64_t)ticks * 1000ULL;

    /* OEM guard: (low>>15)==0 && (high 47-bit window clear) — i.e. delay
     * small enough to schedule. */
    if (((uint32_t)delay >> 15) == 0 && (delay & 0x7fff00000000ULL) == 0) {
        /* OEM forwards the upper 32 bits of the 64-bit delay as the extra arg. */
        audio_play(g_timedcue_clip, 0x0e, 1, (uint32_t)(delay >> 32));
        (void)a; (void)b; (void)c;
        FUN_00064594(g_timedcue_clock, 0, (void *)0, 0, 0, 0);  /* reschedule */
    }
}

/* ================================================================== *
 *  audio_play_on_config_event — 0x31944
 *
 *  Handler bound to a configuration event. Copies the event's enable byte
 *  (event+5) into a config flag, runs the config apply/forward helpers, then
 *  plays the config-change confirmation clip (type 0xd).
 *
 *  param_1 evt : pointer to the incoming config event structure.
 * ================================================================== */
void audio_play_on_config_event(int evt)
{
    g_cfgevt_flag = (*(const char *)(evt + 5) != '\0') ? 1 : 0;

    FUN_00038234(g_cfgevt_obj, (void *)&g_cfgevt_flag, 1);
    FUN_00031884(evt);

    /* OEM call site passes 3 register args; the 4th 'extra' slot is don't-care. */
    audio_play(g_cfgevt_clip, 0x0d, 1, 0);
}
