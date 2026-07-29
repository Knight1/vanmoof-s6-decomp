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
extern void  aem_event_submit(void);                                  /* 0x55564 */
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
extern void od_publish_u32(uint16_t od, void *val, int len, uint32_t v, uint16_t od2); /* 0x6d50c */
extern uint32_t *g_cfg_0x112;          /* DAT_00031ef4 */
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
        struct { void *name; uint32_t a; uint16_t code; } e;
        e.name = g_elock_state_names[want];
        e.a    = g_elock_evt_b;
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

    (void)r1;
    switch (od) {
    case 0x112: val = *g_cfg_0x112; break;
    case 0x113: val = *g_cfg_0x113; break;
    case 0x114: val = *g_cfg_0x114; break;
    case 0x115: val = *g_cfg_0x115; break;
    default:    return;
    }

    od_publish_u32(od, &val, 4, val, od);
    (void)r2;
    aem_event_submit();
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
    aem_event_submit();
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
extern void od_publish_val(uint16_t od, void *buf, int len, uint32_t v, void *r); /* 0x6c614 */
extern void setting_apply (void *a, void *b, int n);   /* 0x574c8 (commit + notify) */
extern void od_0x118_side_effect(void);                /* 0x267d8 */
extern uint8_t *g_od_0x118_val;    /* _DAT_00026b24 (reported value) */
extern uint8_t *g_od_0x118_flag;   /* _DAT_00026e34 (backing bool)   */
extern void    *g_od_0x118_ctx;    /* _DAT_00026e38                  */

/* od_get_flag_0x118 -- 0x26b04 : publish the 1-byte reported value on OD 0x118. */
void od_get_flag_0x118(void *r)
{
    uint8_t buf[4];
    buf[0] = *g_od_0x118_val;
    od_publish_val(0x118, buf, 1, *g_od_0x118_val, r);
    aem_event_submit();
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
