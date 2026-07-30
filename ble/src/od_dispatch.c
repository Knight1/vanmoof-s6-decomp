/*
 * od_dispatch.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * The Object-Dictionary command surface. The ble ECU exposes every phone-BLE /
 * CAN-OD command as an OD object with a read (get) and/or write (set) handler.
 * The dispatch table (@ 0x957xx..0x959xx) is an array of 12-byte entries
 *   { uint16_t od_id; uint32_t get_handler; uint32_t set_handler; }
 * (Thumb-bit handler pointers; a NULL handler = that direction unsupported).
 * A command frame's OD id selects the row; read vs write picks get/set.
 *
 * Most rows point at handlers reconstructed elsewhere (od 0x101 ->
 * batt_telemetry_dispatch, 0x163 -> vmtp_cmd_elock, 0x191 -> lockstate,
 * 0x1b0/1/2 -> firmware/version/diag, 0x16b -> fmna_event, ...). This file
 * reconstructs the handlers that lived only in the table-dispatch gap (no direct
 * CALL xref, so Ghidra left them undefined until a create_function pass):
 *
 *   od 0x145 (write) od_cmd_play_sound   @ 0x6c574
 *   od 0x100 (write) od_cmd_elock_set    @ 0x6c6de
 *   od 0x112-0x115 (read) od_cmd_config_read @ 0x6d530
 *   od 0x10a (via thunk 0x6c6aa) od_cmd_notify_u8 @ 0x27144
 *
 * Behaviour-oriented reconstruction from Ghidra (image base 0xC000, Cortex-M4F);
 * not byte-identical. Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- AEM event bus -------------------------------------------------------- */
extern void *aem_event_alloc(int size, uint16_t id, int chan);        /* 0x77cfc */
/* Deliver a built event to the command subscriber; this is the SAME OEM routine
 * whose body od_publish_record inlines below (0x55564 takes the event pointer). */
extern void  aem_event_submit(void *ev);                              /* 0x55564 */
extern void  aem_log_v(void *mod, uint32_t code, void *arg, int z);   /* 0x364f0 */
extern void  vmtp_pkt_unref(void *ev);                                /* 0x5661c */

/* Deliver a built OD response event to the command subscriber (g_od_subscriber
 * +0x1c -> +0x18 callback); 0 on success, -0x20 no-cb, -0x16 subscriber off.     */
extern uint8_t *g_od_subscriber;   /* DAT_000555a0 (+0x21 enabled, +0x1c subs)    */
static int od_publish_record(void *ev)
{
    uint8_t *ctx = g_od_subscriber;
    if (ctx[0x21] != 0) {
        int subs = *(int *)(ctx + 0x1c);
        int rc;
        if (subs == 0 || *(void **)(subs + 0x18) == NULL)
            rc = -0x20;
        else if ((rc = (**(int (**)(int, void *, void *))(subs + 0x18))(subs, ctx, ev)) == 0)
            return 0;
        vmtp_pkt_unref(ev);
        return rc;
    }
    vmtp_pkt_unref(ev);
    return -0x16;
}

/* ---- audio player (audio_bell.c siblings) --------------------------------- */
extern void audio_player_reset(void);                                 /* (named) */
extern int  audio_enqueue_play_cmd(void *pattern, uint8_t a, uint8_t b, int z); /* (named) */
extern int  dtc_pattern_match(void *pattern, void *table);            /* (named) */
extern uint8_t *g_audio_busy;          /* DAT_000267d0 (1 = a clip is playing)   */
extern void    *g_audio_loop_table;    /* DAT_000267d4                           */

/* ---- elock (elock.c siblings) --------------------------------------------- */
extern void elock_mutex_lock(void *m, void *r1, int lo, int hi);      /* 0x63118 */
extern void elock_mutex_unlock(void);                                 /* (named) */
extern int  elock_state_differs(void);                                /* (named) */
extern void elock_fsm_transition(void);                               /* (named) */
extern void *g_elock_mutex;            /* DAT_00027404                           */
extern uint8_t  g_elock_state[];       /* DAT_00027408 (log module, byte0=level) */
extern uint8_t *g_elock_cur_state;     /* DAT_00027418                           */
extern uint8_t *g_elock_target_state;  /* DAT_0002741c                           */
extern uint8_t *g_elock_fsm_table;     /* DAT_00027420 (per-state, stride 0x34)  */
extern void   **g_elock_state_names;   /* DAT_0002740c                           */
extern uint32_t g_elock_evt_a, g_elock_evt_b;  /* DAT_00027410 / DAT_00027414    */

/* ---- config getter multiplexer ------------------------------------------- */
/* Builds + returns the OD response event (delivered via aem_event_submit).      */
extern void *od_publish_u32(uint16_t od, void *val, int len, uint32_t v, uint16_t od2); /* 0x6d50c */
extern uint16_t *g_cfg_0x112;          /* DAT_00031ef4 (16-bit value) */
extern uint32_t *g_cfg_0x113;          /* DAT_00031ef8 */
extern uint32_t *g_cfg_0x114;          /* DAT_00031efc */
extern uint32_t *g_cfg_0x115;          /* DAT_00031f00 */

/* ---- misc ----------------------------------------------------------------- */
extern uint8_t *g_notify_u8_src;       /* DAT_00027164 */

/* -------------------------------------------------------------------------
 * od_cmd_play_sound  --  0x6c574   (OD 0x145 write)
 *
 * Play an audio pattern: if nothing is currently playing, reset the player, and
 * unless the pattern is in the "no-latch" table mark the player busy, then
 * enqueue the play command (volume/params in req[0x27]/req[0x28], pattern at
 * req+7). Returns -0x10 if a clip is already playing.
 * ------------------------------------------------------------------------- */
int32_t od_cmd_play_sound(const uint8_t *req)
{
    uint8_t b = req[0x28];
    uint8_t a = req[0x27];

    if (*g_audio_busy != 0)
        return -0x10;

    audio_player_reset();
    if (dtc_pattern_match((void *)(req + 7), g_audio_loop_table) == 0)
        *g_audio_busy = 1;
    return audio_enqueue_play_cmd((void *)(req + 7), a, b, 0);
}

/* -------------------------------------------------------------------------
 * od_cmd_elock_set  --  0x6c6de   (OD 0x100 write)
 *
 * Drive the elock FSM to the requested state (req[5]). Under the elock mutex,
 * if the requested state differs from the current one (and the FSM allows the
 * change), latch it as the target and run the current state's transition
 * callback (per-state table, stride 0x34, cb slot +0x30); if the callback is
 * absent or returns non-zero, fall back to the generic FSM transition.
 * ------------------------------------------------------------------------- */
void od_cmd_elock_set(const uint8_t *req, uint32_t r1)
{
    uint8_t want = req[5];

    elock_mutex_lock(g_elock_mutex, (void *)(uintptr_t)r1, -1, -1);

    if ((g_elock_state[0] & 7) > 2) {
        struct { uint32_t b, a; void *name; uint16_t code; } e;
        e.b    = g_elock_evt_b;
        e.a    = g_elock_evt_a;
        e.name = g_elock_state_names[want];
        e.code = 0x200;
        aem_log_v(g_elock_state, 0x1cc0, &e, 0);
    }

    if (*g_elock_cur_state != want && elock_state_differs() == 0) {
        uint8_t cur = *g_elock_cur_state;
        int (*cb)(uint32_t);
        *g_elock_target_state = want;
        cb = *(int (**)(uint32_t))(g_elock_fsm_table + cur * 0x34 + 0x30);
        if (cb == NULL || cb(want) != 0)
            elock_fsm_transition();
    }

    elock_mutex_unlock();
}

/* -------------------------------------------------------------------------
 * od_cmd_config_read  --  0x6d530   (OD 0x112-0x115 read)
 *
 * Shared getter for the four config OD objects 0x112..0x115: read the backing
 * u32 and publish it (4 bytes) on that OD, then submit the event.
 * ------------------------------------------------------------------------- */
void od_cmd_config_read(const uint8_t *req, uint32_t r1, uint32_t r2)
{
    uint16_t od = *(const uint16_t *)(req + 1);
    uint32_t val;

    void *ev;

    (void)r1;
    switch (od) {
    case 0x112: val = *g_cfg_0x112; break;   /* OEM reads 0x112 as a u16 */
    case 0x113: val = *g_cfg_0x113; break;
    case 0x114: val = *g_cfg_0x114; break;
    case 0x115: val = *g_cfg_0x115; break;
    default:    return;
    }

    ev = od_publish_u32(od, &val, 4, val, od);
    (void)r2;
    aem_event_submit(ev);
}

/* -------------------------------------------------------------------------
 * od_cmd_notify_u8  --  0x27144   (OD 0x10a, reached via thunk 0x6c6aa)
 *
 * Publish a stored 1-byte value as an AEM event (chan 1 / id 0x100, byte at
 * payload +5).
 * ------------------------------------------------------------------------- */
void od_cmd_notify_u8(void)
{
    uint8_t v = *g_notify_u8_src;
    uint8_t *ev = aem_event_alloc(1, 0x100, 1);
    if (ev != NULL)
        ev[5] = v;
    aem_event_submit(ev);
}

/* -------------------------------------------------------------------------
 * Identity OD objects — 0x30 = ecu_id, 0x31 = frame_id, 0x32 = bike_id.
 *
 * Each holds a 16-byte identity string; the OD response is
 * [checksum:2][id:16] = 0x12 bytes.  These are exactly the identity values the
 * modem cloud-gateway bridges out as info/ecu_id (0x30) / info/frame_id (0x31)
 * / info/bike_id (0x32) — same topic-codes (see modem topic dictionary).
 * ------------------------------------------------------------------------- */
extern void     id_copy16   (void *dst, const void *src, unsigned n);  /* 0x7b45c memcpy */
extern uint16_t id_checksum (const void *src, unsigned n);             /* 0x76c74 */
extern uint8_t  g_id_ecu[16];    /* _DAT_0002d5f8 (0x30) */
extern uint8_t  g_id_frame[16];  /* _DAT_0002d5fc (0x31) */
extern uint8_t  g_id_bike[16];   /* _DAT_0002d600 (0x32) */
extern void vm_identity_store_ecu  (const void *src);  /* 0x2d85c */
extern void vm_identity_store_frame(const void *src);  /* 0x2d934 */
extern void vm_identity_load_id    (const void *src);  /* bike-id store (0x32)   */

static const uint8_t *identity_blob(uint16_t od)
{
    switch (od) {
    case 0x30: return g_id_ecu;
    case 0x31: return g_id_frame;
    case 0x32: return g_id_bike;
    default:   return NULL;
    }
}

/* -------------------------------------------------------------------------
 * od_get_identity  --  0x2d56c   (OD 0x30/0x31/0x32 read)
 *
 * Build [checksum(id):2 | id:16] and publish it as the OD response event.
 * ------------------------------------------------------------------------- */
int32_t od_get_identity(const uint8_t *req)
{
    uint16_t od = *(const uint16_t *)(req + 1);
    uint8_t  rec[0x12];
    const uint8_t *blob = identity_blob(od);
    uint8_t *ev;

    if (blob != NULL) {
        id_copy16(rec + 2, blob, 0x10);
        *(uint16_t *)rec = id_checksum(blob, 0x10);
    }

    ev = aem_event_alloc(0x12, od, 1);
    if (ev == NULL)
        return -0x16;

    for (int i = 0; i < 0x12; i++)
        ev[5 + i] = rec[i];
    return od_publish_record(ev);
}

/* -------------------------------------------------------------------------
 * od_set_identity  --  0x6ce18   (OD 0x30/0x31/0x32 write)
 *
 * Store the incoming 16-byte id (per object), then echo it back exactly like
 * the getter.
 * ------------------------------------------------------------------------- */
int32_t od_set_identity(const uint8_t *req)
{
    uint16_t od = *(const uint16_t *)(req + 1);

    switch (od) {
    case 0x30: vm_identity_store_ecu(req + 7);   break;
    case 0x31: vm_identity_store_frame(req + 7); break;
    case 0x32: vm_identity_load_id(req + 7);     break;
    default:   break;
    }
    return od_get_identity(req);
}

/* -------------------------------------------------------------------------
 * Boolean setting object — OD 0x118.
 * ------------------------------------------------------------------------- */
extern void *od_publish_val(uint16_t od, void *buf, int len, uint32_t v, void *r); /* 0x6c614 (returns event) */
extern void setting_apply (void *a, void *b, int n);   /* 0x574c8 (commit + notify) */
extern void od_0x118_side_effect(void);                /* 0x267d8 */
extern uint8_t *g_od_0x118_val;    /* _DAT_00026b24 (reported value) */
extern uint8_t *g_od_0x118_flag;   /* _DAT_00026e34 (backing bool)   */
extern void    *g_od_0x118_ctx;    /* _DAT_00026e38                  */

/* od_get_flag_0x118 -- 0x26b04 : publish the 1-byte reported value on OD 0x118. */
void od_get_flag_0x118(void *r)
{
    uint8_t buf[4];
    void *ev;
    buf[0] = *g_od_0x118_val;
    ev = od_publish_val(0x118, buf, 1, *g_od_0x118_val, r);
    aem_event_submit(ev);
}

/* od_set_flag_0x118 -- 0x26e10 : latch req[5]!=0, commit, then re-publish. */
void od_set_flag_0x118(const uint8_t *req)
{
    *g_od_0x118_flag = (req[5] != 0);
    setting_apply(g_od_0x118_ctx, g_od_0x118_flag, 1);
    od_0x118_side_effect();
    od_get_flag_0x118((void *)0);
}

/* -------------------------------------------------------------------------
 * Three-value mode object — OD 0x144 (valid 0..2; a sound confirms a change).
 * ------------------------------------------------------------------------- */
extern void  audio_play(void *clip, int vol, int loop);   /* (named) */
extern uint8_t *g_od_0x144_val;      /* _DAT_00026248 (reported value)  */
extern uint8_t *g_od_0x144_setting;  /* _DAT_00026814 (backing setting) */
extern void    *g_od_0x144_sound;    /* _DAT_00026818 (confirm clip)    */
extern void    *g_od_0x144_ctx;      /* _DAT_0002681c                   */

/* od_get_mode_0x144 -- 0x26224 : publish the mode as a u32 on OD 0x144. */
int32_t od_get_mode_0x144(void)
{
    uint8_t *ev = aem_event_alloc(4, 0x144, 1);
    if (ev == NULL)
        return -0x16;
    *(uint32_t *)(ev + 5) = *g_od_0x144_val;
    return od_publish_record(ev);
}

/* od_set_mode_0x144 -- 0x267e8 : accept 0..2, play confirm sound, commit, echo. */
int32_t od_set_mode_0x144(const uint8_t *req)
{
    uint32_t v = *(const uint32_t *)(req + 5);
    if (v < 3) {
        *g_od_0x144_setting = (uint8_t)v;
        audio_play(g_od_0x144_sound, 0xd, 1);
        setting_apply(g_od_0x144_ctx, g_od_0x144_setting, 1);
    }
    return od_get_mode_0x144();
}

/* -------------------------------------------------------------------------
 * od_get_0x1ca  --  0x6c63e   (OD 0x1ca read)
 *   Publish a constant 1-byte 0 on OD 0x1ca.
 * ------------------------------------------------------------------------- */
void od_get_0x1ca(void *r)
{
    uint8_t buf[4] = {0};
    void *ev = od_publish_val(0x1ca, buf, 1, 0, r);
    aem_event_submit(ev);
}

/* -------------------------------------------------------------------------
 * od_set_elock_evt_0x10a  --  0x6c6ae   (OD 0x10a write)
 *
 * Publish an elock event (chan 5 / id 0x100): payload = 4 when req[5] is set,
 * else 0.  No-op (returns the differ code) if the elock state is already in flux.
 * ------------------------------------------------------------------------- */
int32_t od_set_elock_evt_0x10a(const uint8_t *req)
{
    int diff = elock_state_differs();
    if (diff != 0)
        return diff;

    uint8_t *ev = aem_event_alloc(1, 0x100, 5);
    if (ev == NULL)
        return -0x16;
    ev[5] = req[5] ? 4 : 0;
    return od_publish_record(ev);
}

/* -------------------------------------------------------------------------
 * Power / shipping commands.
 * ------------------------------------------------------------------------- */
extern void vm_logf(void *mod, uint32_t level, const char *fmt, ...);   /* 0x6efea */
extern void actuator_power_domain_enable(int domain);   /* (named) */
extern void ps_set_flag_publish_1b(int on);             /* (named) */
extern void ps_prepare(int a);                          /* 0x319f8 */
extern int  power_precheck(void);                       /* 0x272cc (0 = ok) */
extern void ps_mode_set(int m);                         /* 0x2d378 */
extern void ps_set_state(const char *name, int a, int b); /* 0x3120c */
extern void work_schedule_timer(void *work, void *arg, int lo, int hi); /* 0x6373c */
extern void *g_ps_work;             /* DAT_00063798 */
extern void *g_ps_wake_arg;         /* _DAT_000276c4 */
extern void *g_ps_shipping_arg;     /* _DAT_0002b5dc */
extern void *g_clip_power_on;       /* _DAT_000276c0 */
extern uint8_t g_log_shipping[];    /* _DAT_0002b5cc */

/* -------------------------------------------------------------------------
 * od_cmd_power_on_0x10e  --  0x6c6a4   (OD 0x10e write)
 *
 * Power-on / wake: prep the power state; bit0 of req[5] plays the power-on clip,
 * bit1 brings up actuator power domain 3 (if the pre-check passes), sets the
 * publish-1b flag + mode, and schedules the wake work.
 * ------------------------------------------------------------------------- */
void od_cmd_power_on_0x10e(const uint8_t *req)
{
    ps_prepare(5);

    if (req[5] & 1)
        audio_play(g_clip_power_on, 0xf, 1);

    if (req[5] & 2) {
        if (power_precheck() == 0) {
            actuator_power_domain_enable(3);
            ps_set_flag_publish_1b(1);
        }
        ps_mode_set(1);
        work_schedule_timer(g_ps_work, g_ps_wake_arg, 0x20000, 0);
    }
}

/* -------------------------------------------------------------------------
 * od_cmd_shipping_mode  --  0x6cc32   (OD 0x202 write)
 *
 * Shipping mode: cut power after req[5] seconds (min 5).  Brings up power
 * domain 4, plays /audio/3_sleep.wav, sets the "sleep" state, and arms a timer
 * for (secs * 32768) ticks (32.768 kHz) after which the power is cut.
 * ------------------------------------------------------------------------- */
void od_cmd_shipping_mode(const uint8_t *req)
{
    unsigned secs = req[5];
    if (secs < 5)
        secs = 5;

    if ((g_log_shipping[0] & 7) > 2)
        vm_logf(g_log_shipping, 3, "Shipping mode requested - cut power in %u s", secs);

    actuator_power_domain_enable(4);
    audio_play("/audio/3_sleep.wav", 0xe, 1);
    ps_set_state("sleep", 1, 1);

    /* secs seconds expressed in 32.768 kHz ticks (round up) */
    uint64_t ticks = ((uint64_t)(secs * 1000u) * 0x8000u + 999u) / 1000u;
    work_schedule_timer(g_ps_work, g_ps_shipping_arg,
                        (int)ticks, (int)(ticks >> 32));
}
