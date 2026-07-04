/*
 * elock_report.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Elock sensor + state-report handlers.  Recovered from the dispatch-table gap
 * (0x28590-0x28a9b) that sits next to the already-reconstructed elock FSM
 * (elock.c): these are the ble-side handlers that read the kick-lock hall sensor,
 * publish its value + the derived lock state onto the Application-Event-Manager
 * bus and the CAN object-dictionary, and drive the "reported state" transitions.
 *
 *   - elock_sensor_publish     read the hall sensor, log it, publish OD 0x16b
 *   - elock_telemetry_publish  debug-log a 2-field elock telemetry event
 *   - elock_sensor_in_range    is the (scaled) sensor sample ~zero (locked)?
 *   - elock_stuck_handler      "seems to be stuck" -> force state 3, post event
 *   - elock_report_handler     reported-state change reporter + dispatcher
 *   - elock_state_notify       cmd-map read + callback + notify event
 *   - elock_shell_print_state  shell dump of the sensor value + state labels
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) are noted on each function.  Not byte-identical.
 *
 * Self-contained: depends only on <stdint.h> / <stddef.h> plus the vendor / RTOS
 * / SDK externs and the elock.c siblings declared below.
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Vendor / RTOS / SDK externs (OEM image addresses, base 0xC000).
 * ------------------------------------------------------------------------- */

/* AEM event-log helper (log_mod, event-code, arg-block); the elock path uses the
 * 0x6c83c entry (vs 0x364f0 elsewhere).                                         */
extern void     aem_evt_log(void *log_mod, uint32_t code, void *arg_block);    /* 0x6c83c */
/* AEM "raise/assert" log (log_mod, level, str).                                 */
extern void     aem_raise(void *log_mod, uint32_t level, void *str);           /* 0x6efd8 */
/* Publish a value to a CAN OD object, then send the pending AEM event.          */
extern void     od_publish_obj(uint32_t od_id, const void *val);               /* 0x6c818 */
extern void     aem_event_send(void);                                          /* 0x55564 */
/* Post a state-machine event / cancel a delayable work item.                    */
extern void     aem_sm_post_event(void *sm, uint32_t r1, uint32_t event, int z);/* 0x63790 */
extern void     k_work_cancel(void *work);                                     /* 0x7aad4 */
/* Kernel uptime (ticks), 64-bit.                                                */
extern uint64_t k_uptime_ticks(void);                                          /* 0x64484 */
/* Read the elock hall sensor sample (lo=value, hi=validity).                    */
extern uint64_t elock_sensor_measure(void *dev);                               /* 0x7ae2a */
/* Shell fprintf + a command-map value read + memcmp (elock_state_notify).       */
extern void     shell_fprintf(void *ctx, const char *fmt, uint32_t v);         /* 0x6f948 */
extern void    *cmd_value_read(void *ctx, int *out_flag);                      /* 0x6f4d8 */
extern int      cmd_key_match(void *ctx, const void *key, void *v);            /* 0x7b438 */

/* elock.c siblings. */
extern void     elock_report_lock_state(uint8_t state);                        /* 0x28760 */
extern void     elock_set_state(uint32_t state);                               /* 0x2853c */

/* -------------------------------------------------------------------------
 * Global state (resolved from OEM PC-relative literal pools).
 * ------------------------------------------------------------------------- */
extern void    *g_elock_sensor_dev;                /* DAT_00028910                */
extern uint8_t  g_elock_reported_state;            /* DAT_00028a84                */
extern const char *const g_elock_state_names[];    /* PTR_PTR_00028a6c            */
extern uint32_t g_elock_unlock_t0[2];              /* DAT_00028a7c (u64 timestamp)*/

/* Per-handler AEM log-module objects (first byte holds the level/enable bits).   */
extern uint8_t  g_log_elock_sensor[];              /* DAT_000286b0                */
extern uint8_t  g_log_elock_tele[];                /* DAT_000286f8                */
extern uint8_t  g_log_elock_notify[];              /* DAT_00028658                */
extern uint8_t  g_log_elock_stuck[];               /* DAT_00028730                */
extern uint8_t  g_log_elock_report[];              /* DAT_00028a68                */

/* Work items cancelled when the lock re-locks (state 2). */
extern void    *g_elock_work_a;                    /* DAT_00028a8c                */
extern void    *g_elock_work_b;                    /* DAT_00028a90                */
extern void    *g_elock_work_c;                    /* DAT_00028a94                */

/* Documented OEM strings (real pointers from the literal pools).                 */
#define MSG_SENSOR_VAL   "%s: elock sensor val: %d"           /* 0x81d37 */
#define MSG_STUCK        "elock seems to be stuck"            /* 0x81d7c */
#define MSG_REPORTED     "%s: reported elock state: %s"       /* 0x81dcd */
#define MSG_NEW_REPORTED "%s: new reported elock state: %s"   /* 0x81e0b */

/* AEM info gate: OEM tests (first_byte << 0x1d) < 0, i.e. bit 2 (0x4).           */
static inline int aem_info_enabled(const uint8_t *m) { return (m[0] & 0x4) != 0; }

/* -------------------------------------------------------------------------
 * elock_sensor_in_range  --  0x288ec
 *
 * Take a scaled sensor reading (sample * 1000) and report whether it lands in
 * the "locked" band, i.e. whether the top 49 bits are zero (value >> 15 == 0).
 * ------------------------------------------------------------------------- */
int elock_sensor_in_range(void)
{
    uint64_t scaled = elock_sensor_measure(g_elock_sensor_dev) * 1000u;
    return (uint32_t)(scaled >> 15) == 0 && (scaled & 0x7fff00000000ULL) == 0;
}

/* -------------------------------------------------------------------------
 * elock_sensor_publish  --  0x28664
 *
 * Read the elock hall sensor (signed 16-bit) from the event, optionally log
 * "elock sensor val: %d" (event 0x2100), then publish the value on OD 0x16b.
 * ------------------------------------------------------------------------- */
void elock_sensor_publish(const void *evt)
{
    int16_t val = *(const int16_t *)(*(const void *const *)evt);
    int32_t v32;

    if (aem_info_enabled(g_log_elock_sensor)) {
        struct { uint32_t n; const char *tag; const char *mod; int val; } a;
        a.n = 4;
        a.tag = MSG_SENSOR_VAL;
        a.mod = "elock";
        a.val = val;
        aem_evt_log(g_log_elock_sensor, 0x2100, &a);
    }

    v32 = val;
    od_publish_obj(0x16b, &v32);
    aem_event_send();
}

/* -------------------------------------------------------------------------
 * elock_telemetry_publish  --  0x286bc
 *
 * Debug-only: when logging is enabled, emit a 2-field elock telemetry event
 * (0x2900) carrying the two halfwords from the event payload.
 * ------------------------------------------------------------------------- */
void elock_telemetry_publish(const void *evt)
{
    if (aem_info_enabled(g_log_elock_tele)) {
        const uint16_t *p = (const uint16_t *)(*(const void *const *)evt);
        struct { uint32_t n; const char *tag; const char *mod; uint32_t a; uint32_t b; } a;
        a.n = 5;
        a.tag = (const char *)0;   /* DAT_000286fc */
        a.mod = (const char *)0;   /* DAT_00028700 */
        a.a = p[0];
        a.b = p[1];
        aem_evt_log(g_log_elock_tele, 0x2900, &a);
    }
}

/* -------------------------------------------------------------------------
 * elock_stuck_handler  --  0x28704
 *
 * The lock did not reach its commanded position: log "elock seems to be stuck"
 * (level 2), force elock state 3, and post the retry event (0x40000).
 * ------------------------------------------------------------------------- */
void elock_stuck_handler(void)
{
    if ((g_log_elock_stuck[0] & 6) != 0)
        aem_raise(g_log_elock_stuck, 2, (void *)MSG_STUCK);

    elock_set_state(3);
    aem_sm_post_event(g_elock_work_c /* DAT_00028738 */, 0, 0x40000, 0);
}

/* -------------------------------------------------------------------------
 * elock_report_handler  --  0x28914
 *
 * Handle a reported elock-state event.  Trace the reported state; if it is
 * "unlocked" (2) and the unlock timer is running, log the unlock duration and
 * reset it.  When the reported state actually changes, latch it, trace the new
 * state, and drive the transition:
 *   - 1  -> post the unlock work event (0x4000)
 *   - 2  -> cancel the pending work items; if the sensor confirms locked, report
 *           the locked state and (elock_set_state 2)
 *   - 0  -> elock_set_state 0
 *   - >2 -> no action
 * ------------------------------------------------------------------------- */
uint32_t elock_report_handler(const void *evt)
{
    uint8_t new_state = *(const uint8_t *)(*(const void *const *)evt);

    if (aem_info_enabled(g_log_elock_report)) {
        struct { uint32_t code; const char *tag; const char *mod; const char *name; } a;
        a.code = 0x301;
        a.tag  = MSG_REPORTED;
        a.mod  = "elock_state_cb";
        a.name = g_elock_state_names[new_state];
        aem_evt_log(g_log_elock_report, 0x2500, &a);
    }

    /* unlocked + timer running -> report how long the unlock lasted */
    if (new_state == 2 && (g_elock_unlock_t0[0] != 0 || g_elock_unlock_t0[1] != 0)) {
        uint64_t dur_us = k_uptime_ticks() * 1000u;
        uint64_t t0 = ((uint64_t)g_elock_unlock_t0[1] << 32) | g_elock_unlock_t0[0];
        if ((g_log_elock_report[0] & 7) > 2) {
            uint64_t elapsed = (dur_us >> 15) - t0;   /* ticks->us, minus start */
            struct { uint32_t code; const char *mod; uint32_t lo; uint32_t hi; } a;
            a.code = 0x301;
            a.mod  = (const char *)0;
            a.lo   = (uint32_t)elapsed;
            a.hi   = (uint32_t)(elapsed >> 32);
            aem_evt_log(g_log_elock_report, 0x20c0, &a);
        }
        g_elock_unlock_t0[0] = 0;
        g_elock_unlock_t0[1] = 0;
    }

    if (g_elock_reported_state == new_state)
        return 0;

    g_elock_reported_state = new_state;

    if (aem_info_enabled(g_log_elock_report)) {
        struct { uint32_t code; const char *tag; const char *mod; const char *name; } a;
        a.code = 0x301;
        a.tag  = MSG_NEW_REPORTED;
        a.mod  = "elock_state_cb";
        a.name = g_elock_state_names[new_state];
        aem_evt_log(g_log_elock_report, 0x2500, &a);
    }

    if (new_state == 1) {
        aem_sm_post_event(g_elock_work_a, 0, 0x4000, 0);
        return 0;
    }

    if (new_state == 2) {
        k_work_cancel(g_elock_work_a);
        k_work_cancel(g_elock_work_b);
        k_work_cancel(g_elock_work_c);
        if (elock_sensor_in_range() == 0) {
            if (aem_info_enabled(g_log_elock_report)) {
                struct { uint32_t code; const char *mod; } a;
                a.code = 3;
                a.mod  = "elock_state_cb";
                aem_evt_log(g_log_elock_report, 0x1900, &a);
            }
            elock_report_lock_state(0);
        }
        elock_set_state(2);
        return 0;
    }

    if (new_state != 0)
        return 0;

    elock_set_state(0);
    return 0;
}

/* -------------------------------------------------------------------------
 * elock_state_notify  --  0x285e8
 *
 * Command-map handler: read the incoming value, match it against the elock key,
 * and — on a match — invoke the registered callback and (optionally) emit the
 * notify event (0x2100).  Returns 0 on success, -2 (-EBADF-ish) on no match.
 * ------------------------------------------------------------------------- */
int elock_state_notify(void *ctx, uint32_t r1, int (*cb)(void *, void *, int), void *cb_arg)
{
    int flag = 0;
    void *v;
    int rc;

    (void)r1;

    v = cmd_value_read(ctx, &flag);
    if (flag != 0 || cmd_key_match(ctx, (const void *)0 /* DAT_00028650 */, v) != 0)
        return -2;

    rc = cb(cb_arg, (void *)0 /* DAT_00028654 */, 1);
    if (rc < 0)
        return rc;

    if (aem_info_enabled(g_log_elock_notify)) {
        extern uint8_t g_elock_key_byte;   /* DAT_00028654[0] */
        struct { uint32_t n; const char *tag; const char *mod; uint32_t v; } a;
        a.n = 4;
        a.tag = (const char *)0;   /* DAT_0002865c */
        a.mod = (const char *)0;   /* DAT_00028660 */
        a.v = g_elock_key_byte;
        aem_evt_log(g_log_elock_notify, 0x2100, &a);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * elock_shell_print_state  --  0x28598
 *
 * Shell diagnostic: print the raw sensor value and two decoded state labels
 * (indexed out of name tables) to the shell context.
 * ------------------------------------------------------------------------- */
int elock_shell_print_state(void *sh)
{
    extern uint8_t g_elock_state_a;             /* DAT_000285d0 */
    extern uint8_t g_elock_state_b;             /* DAT_000285dc */
    extern const uint32_t g_elock_name_tbl_a[]; /* DAT_000285d8 */
    extern const uint32_t g_elock_name_tbl_b[]; /* DAT_000285e4 */

    shell_fprintf(sh, (const char *)0 /* DAT_000285cc */, 0);
    shell_fprintf(sh, (const char *)0 /* DAT_000285d4 */, g_elock_name_tbl_a[g_elock_state_a]);
    shell_fprintf(sh, (const char *)0 /* DAT_000285e0 */, g_elock_name_tbl_b[g_elock_state_b]);
    return 0;
}
