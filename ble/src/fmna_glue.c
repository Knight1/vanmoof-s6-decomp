/*
 * fmna_glue.c — VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Find-My-Network (FMNA) application glue + anti-theft ("stolen mode") logic.
 * Reconstructed (behaviour-oriented, not byte-identical) from the OEM image at
 * base 0xC000. OEM addresses are noted on each function.
 *
 * Self-contained: only <stdint.h> / <stddef.h>. Every vendor / RTOS / SDK / other
 * VanMoof-module symbol is declared as a local extern with its OEM address.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- */
/* Vendor / cross-module externs (OEM addresses in comments).                */
/* ------------------------------------------------------------------------- */

/* VanMoof logging helpers (printf-style; gated by a per-module verbosity flag). */
extern void vm_logf(void *mod, int level, const char *fmt, ...);          /* 0x6efd8 (FUN_0006efd8) */
/* Structured "tracepoint" log emitter used in the more verbose paths.
 * args: (mod, chan, packed_record, payload). Behaviourally a formatted log. */
extern void vm_log_record(void *mod, uint32_t chan, void *record, void *payload); /* 0x364f0 (FUN_000364f0) */

/* FMNA stack (Apple Find My library glue). */
extern int  fmna_stack_enable(void);                                     /* (named) */
extern int  fmna_serial_number_read(void *out, int len);                 /* 0x2daa0 (FUN_0002daa0) */
extern int  fmna_provisioning_store(const char *key, void *buf, int len);/* 0x38234 (FUN_00038234) */

/* Settings / persistent-storage style helpers. */
extern int  dtc_can_cmd_handler(void *out, int len);                     /* (named) read ECU id over CAN */

/* CAN / OD owner-connection enumeration. */
extern int  fmna_owner_conn_list(int *out_list, uint8_t *io_count);      /* 0x5eb1c (FUN_0005eb1c) */
extern int  fmna_owner_conn_valid(int conn);                             /* 0x2544c (FUN_0002544c) */

/* libc-style string / mem helpers (toolchain / Zephyr minimal libc). */
extern void *vm_memset(void *d, int c, size_t n);                        /* 0x7b2ba (FUN_0007b2ba) */
extern char *vm_strcpy(char *d, const char *s);                          /* 0x7b3dc (FUN_0007b3dc) */
extern int  vm_snprintf(char *d, size_t n, const char *fmt, ...);        /* 0x6e008 (FUN_0006e008) */

/* BLE advertised device-name update (set name then re-arm advertising). */
extern void ble_devname_set(const char *name);                          /* 0x25304 (FUN_00025304) */
extern void ble_devname_apply(void);                                    /* 0x25360 (FUN_00025360) */

/* Audio. */
extern void audio_play(void *clip, int gain, int flags);                 /* (named) */
extern void audio_enqueue_play_cmd(void *clip, int gain, uint32_t a,
                                   int b, uint32_t r3);                   /* (named) */

/* Application-event / state publishing. */
extern int  app_publish_u8(uint32_t obj_id, void *val);                  /* 0x6d586 (FUN_0006d586) */
extern void app_state_commit(void);                                      /* 0x55564 (FUN_00055564) */
extern void app_notify(void);                                            /* 0x6d5aa (FUN_0006d5aa) */
extern void app_sleep_ms(uint32_t ms);                                   /* 0x5e5a4 (FUN_0005e5a4) */

/* Anti-theft / power / lock. */
extern int  alarm_disarm(void);                                          /* 0x61690 (FUN_00061690) */
extern void elock_set_lock_state(int state);                             /* (named) */
extern void alarm_tone_stop(void);                                       /* 0x6c872 (FUN_0006c872) */
extern void alarm_buzzer_off(void *ctx);                                 /* 0x7aad4 (FUN_0007aad4) */
extern uint64_t power_state_get(void);                                   /* 0x272cc (FUN_000272cc) */
extern void ps_power_off_request(int reason, int hi, uint32_t r2, uint32_t r3); /* (named) */

/* Cortex-M data memory barrier intrinsic (vendor/CMSIS). */
extern void DataMemoryBarrier(int opt);

/* ------------------------------------------------------------------------- */
/* Module-level data anchors (RAM/flash globals referenced by the OEM).      */
/*                                                                           */
/* These are real addresses from the image. RAM lives at 0x2000_0000+.       */
/* Modeled as externs so this TU stays self-contained; the load-bearing      */
/* part is the access pattern (bit tests / field offsets), not the layout.   */
/* ------------------------------------------------------------------------- */

extern uint8_t  g_fmna_initialized;        /* 0x200135e3 (*DAT_000338d4) gate for state_get */
extern uint8_t  g_fmna_pairing_state;      /* DAT_0003388c */
extern uint8_t  g_fmna_unpaired_flag;      /* DAT_00033890 */
extern uint8_t  g_fmna_location_enabled;   /* *DAT_00033944 (state[3] source / loc-avail latch) */
extern uint8_t  g_fmna_factory_reset_pend; /* *DAT_00033e40 (factory-reset pending gate) */
extern uint8_t  g_fmna_app_enabled;        /* DAT_00033cdc */
extern uint8_t  g_fmna_stack_disabled;     /* DAT_00033ce0 (!=0 -> EACCES) */
extern uint8_t  g_fmna_owner_suffix_state; /* DAT_00025694 (FindMy suffix latch) */
extern uint8_t  g_fmna_owner_count;        /* *DAT_00025690 */
extern uint8_t  g_fmna_paired;             /* *DAT_000339dc */
extern uint8_t  g_fmna_pairing_busy;       /* *DAT_000339e4 (cleared on paired-state change) */
extern uint8_t  g_fmna_pairing_mode;       /* *DAT_00033a4c (cleared on pairing-mode exit) */
extern uint8_t  g_fmna_pairing_mode_active;/* *DAT_00033a64 (second latch tested/cleared on exit) */
extern uint8_t  g_fmna_paired_reset_pend;  /* *DAT_000339d4 (audio-cue gate on paired change) */
extern uint8_t  g_fmna_location_reset;     /* *DAT_000339e0 (zeroed on paired-state change) */
extern uint8_t  g_alarm_stolen;            /* DAT_000319a8 */
extern uint8_t  g_alarm_stolen_latched;    /* DAT_000319ac */

/* Audio clip / config-word anchors loaded via DAT pointers in the OEM. */
extern void    *g_fmna_reset_audio_clip;   /* DAT_00033e44 (factory-reset audio clip) */
extern void    *g_fmna_paired_clip;        /* DAT_000339d8 (paired audio cue) */
extern void    *g_fmna_unpaired_clip;      /* DAT_000339ec (unpaired audio cue) */
extern void    *g_fmna_pairing_exit_clip;  /* DAT_00033a54 (pairing-mode exit cue) */
extern uint32_t g_fmna_paired_settle_ms;   /* *DAT_000339e8 (paired-state settle delay) */
extern uint32_t g_fmna_pairing_exit_delay_ms; /* *DAT_00033a50 (pairing-exit delay) */

/* Per-module log verbosity words. Low 3 bits = level threshold; the OEM also
 * tests bit (word << 0x1d < 0), i.e. bit 2 (mask 0x4) for the "info" channel. */
extern volatile uint32_t g_fmna_log;       /* *DAT_00033894 / *DAT_0003392c / *DAT_000339c0 ... */
extern volatile uint32_t g_owner_log;      /* *DAT_0002568c */

/* Stolen-mode word: low 3 bits encode state; bits [2] is the stolen flag.
 * fmna_stolen_mode_get() returns (word & 7) >> 2. */
extern volatile uint32_t g_stolen_word;    /* *DAT_00062284 */

/* ------------------------------------------------------------------------- */
/* Log helper macro modelling the OEM "(word << 0x1d) < 0" info-bit test     */
/* (true iff bit 2 / mask 0x4 set) and the "(word & 7) > 2" threshold test.  */
/* ------------------------------------------------------------------------- */
#define LOG_INFO_BIT(w)   ((((uint32_t)(w)) & 0x4u) != 0u)
#define LOG_LEVEL_GT2(w)  ((((uint32_t)(w)) & 0x7u) > 2u)

/* ------------------------------------------------------------------------- */
/* fmna_stolen_mode_get @ 0x62270                                            */
/*                                                                           */
/* Returns the anti-theft "stolen" flag: (g_stolen_word & 7) >> 2.           */
/* Two DMBs bracket the read in the OEM (a relaxed-atomic load).             */
/* ------------------------------------------------------------------------- */
uint32_t fmna_stolen_mode_get(void)
{
    DataMemoryBarrier(0x1b);
    DataMemoryBarrier(0x1b);
    return (g_stolen_word & 7u) >> 2;
}

/* ------------------------------------------------------------------------- */
/* app_fmna_app_state_get @ 0x338c4                                          */
/*                                                                           */
/* Snapshots the current FMNA app state into a small record and publishes it */
/* as application object 0x280, then commits app state. No-op until the FMNA */
/* module has been initialized (g_fmna_initialized == 1).                    */
/* ------------------------------------------------------------------------- */
void app_fmna_app_state_get(void)
{
    /* 4-byte published record: [0]=stolen, [1]=pairing_state, [2]=unpaired,
     * [3]=location_enabled. */
    uint8_t state[4];

    if (g_fmna_initialized != 1)
        return;

    state[0] = (uint8_t)fmna_stolen_mode_get();
    state[1] = g_fmna_pairing_state;
    state[2] = g_fmna_unpaired_flag;
    state[3] = g_fmna_location_enabled;

    if (LOG_INFO_BIT(g_fmna_log)) {
        /* OEM: tracepoint "fmna_state" record (id 0x301), payload = &state. */
        vm_log_record((void *)&g_fmna_log, /*chan*/0x2500, &state, &state);
    }

    app_publish_u8(0x280, &state);
    app_state_commit();
}

/* ------------------------------------------------------------------------- */
/* fmna_app_update_serial_number @ 0x33c38                                   */
/*                                                                           */
/* Reads a 16-byte frame/ECU id and stores it under the FMNA provisioning    */
/* key "fmna_provisioning_997". Falls back to the CAN ECU-id read if the      */
/* primary serial read fails. Returns 0 / negative errno from the store.     */
/* ------------------------------------------------------------------------- */
int fmna_app_update_serial_number(void)
{
    uint8_t sn[16] = { 0 };
    int rc;

    rc = fmna_serial_number_read(&sn, 0x10);
    if (rc < 0) {
        if ((g_fmna_log & 6) != 0)
            vm_logf((void *)&g_fmna_log, 2,
                    "Unable to read frame ID. Fallback ...");
        rc = dtc_can_cmd_handler(&sn, 0x10);
        if (rc < 0) {
            if ((g_fmna_log & 7) != 0)
                vm_logf((void *)&g_fmna_log, 1, "Unable to read ECU ID");
            return rc;
        }
    }

    return fmna_provisioning_store("fmna_provisioning_997", &sn, 0x10);
}

/* ------------------------------------------------------------------------- */
/* fmna_app_enable @ 0x33ca8                                                  */
/*                                                                           */
/* Enables/disables the FMNA app. If the bike is in stolen mode, enable is    */
/* forced off. While the stack is administratively disabled, returns -EACCES  */
/* (-13). Otherwise (re)provisions the serial number, brings the FMNA stack   */
/* up, and republishes app state on success.                                  */
/* ------------------------------------------------------------------------- */
int fmna_app_enable(uint8_t enable)
{
    int rc;

    if (fmna_stolen_mode_get() != 0)
        enable = 0;

    g_fmna_app_enabled = enable;

    if (g_fmna_stack_disabled != 0)
        return -13; /* -EACCES */

    fmna_app_update_serial_number();
    rc = fmna_stack_enable();
    if (rc == 0)
        app_fmna_app_state_get();

    return rc;
}

/* ------------------------------------------------------------------------- */
/* fmna_app_factory_reset @ 0x33e00                                          */
/*                                                                           */
/* Only valid while in stolen mode (otherwise -EINVAL). Disarms the alarm,    */
/* waits 100ms, latches the reset-pending flag, plays the reset audio clip    */
/* (id 0xd), and republishes app state. Idempotent: a second call while       */
/* already pending does nothing and returns 0.                               */
/* ------------------------------------------------------------------------- */
int fmna_app_factory_reset(void)
{
    int rc;

    if (fmna_stolen_mode_get() == 0)
        return -0x16; /* -EINVAL */

    if (g_fmna_factory_reset_pend == 0) {
        rc = alarm_disarm();
        if (rc != 0)
            return rc;

        app_sleep_ms(100);
        g_fmna_factory_reset_pend = 1;
        /* OEM: audio_enqueue_play_cmd(DAT_00033e44, 0xd, 0xffffffff, 0, in_r3). */
        audio_enqueue_play_cmd(g_fmna_reset_audio_clip, 0xd,
                               0xffffffffu, 0, 0);
        app_fmna_app_state_get();
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* fmna_app_location_availability_changed @ 0x338d8                          */
/*                                                                           */
/* Find-My location availability toggled. Logs "Find My location enabled/    */
/* disabled", latches the new value, and republishes app state.              */
/* ------------------------------------------------------------------------- */
void fmna_app_location_availability_changed(uint32_t available)
{
    if (LOG_INFO_BIT(g_fmna_log)) {
        const char *s = available ? "enabled" : "disabled";
        /* OEM string: "%s: Find My location %s" */
        vm_log_record((void *)&g_fmna_log, 0x2500, (void *)s, NULL);
    }

    /* OEM: if (*DAT_00033944 != param_1) *DAT_00033944 = (byte)param_1; */
    if (g_fmna_location_enabled != (uint8_t)available)
        g_fmna_location_enabled = (uint8_t)available;

    app_fmna_app_state_get();
}

/* ------------------------------------------------------------------------- */
/* fmna_app_paired_state_changed @ 0x33948                                   */
/*                                                                           */
/* FMN accessory transitioned to (un)paired. Logs the transition, plays the  */
/* paired/unpaired audio cue (unless a per-change reset is pending), updates  */
/* paired/pairing flags, clears the pairing-busy state, waits the configured  */
/* settle delay, and republishes app state.                                   */
/* ------------------------------------------------------------------------- */
void fmna_app_paired_state_changed(int paired)
{
    if (LOG_LEVEL_GT2(g_fmna_log)) {
        /* OEM: "The FMN accessory transitioned to the %spaired state"
         * with %s = "" when paired, "un" when not. */
        const char *pfx = paired ? "" : "un";
        vm_log_record((void *)&g_fmna_log, 0x1cc0, (void *)pfx, NULL);
    }

    /* Audio cue, gated on *DAT_000339d4 (a per-change pending flag, distinct
     * from the factory-reset-pending byte at 0x33e40). */
    if (g_fmna_paired_reset_pend == 0) {
        /* OEM: uVar3 = DAT_000339ec; if (param_1 != 0) uVar3 = DAT_000339d8; */
        void *clip = paired ? g_fmna_paired_clip : g_fmna_unpaired_clip;
        audio_play(clip, 0xd, 1);
    }

    /* OEM store order: *DAT_000339dc, *DAT_000339e0=0, *DAT_000339d4=0,
     * *DAT_000339e4=0. */
    g_fmna_paired          = (uint8_t)paired;
    g_fmna_location_reset  = 0;           /* DAT_000339e0 */
    g_fmna_paired_reset_pend = 0;         /* DAT_000339d4 (pcVar1) */
    g_fmna_pairing_busy    = 0;           /* DAT_000339e4 */

    app_sleep_ms(g_fmna_paired_settle_ms); /* FUN_0005e5a4(*DAT_000339e8) */
    app_fmna_app_state_get();
}

/* ------------------------------------------------------------------------- */
/* fmna_app_pairing_mode_exited @ 0x339f0                                    */
/*                                                                           */
/* Left FMNA pairing mode: clear pairing flag, wait the configured delay,     */
/* play the exit cue (id 0xd), log the transition, and if pairing-mode was    */
/* active clear it and notify the app. Republishes app state.                 */
/* ------------------------------------------------------------------------- */
void fmna_app_pairing_mode_exited(void)
{
    g_fmna_pairing_mode = 0;              /* *DAT_00033a4c */
    app_sleep_ms(g_fmna_pairing_exit_delay_ms); /* FUN_0005e5a4(*DAT_00033a50) */
    audio_play(g_fmna_pairing_exit_clip, 0xd, 1); /* DAT_00033a54 */

    if (LOG_INFO_BIT(g_fmna_log)) {
        /* OEM: vm_log_record(... , chan 0x1900, record id 3). */
        vm_log_record((void *)&g_fmna_log, 0x1900, NULL, NULL);
    }

    if (g_fmna_pairing_mode_active != 0) {  /* DAT_00033a64 — distinct latch */
        g_fmna_pairing_mode_active = 0;
        app_notify();
    }

    app_fmna_app_state_get();
}

/* ------------------------------------------------------------------------- */
/* fmna_update_owner_connections @ 0x254f8                                   */
/*                                                                           */
/* Rebuilds the cached list of FMNA owner BLE connections from the live OD    */
/* connection table, and toggles the "FindMy" BLE name suffix.               */
/*                                                                           */
/* @param ctx  pointer to a small state block; ctx[7] = "any owner connected",*/
/*             ctx[5] = "FMNA active" — both must be non-zero to populate.     */
/*                                                                           */
/* When inactive: zero the 0x70-byte owner cache and reset the owner count.   */
/* When active: enumerate up to 4 owner connections, log each, and append it  */
/* to a 7-byte-per-entry cache (max 16 entries).                              */
/* Finally, when the connected state flips, add/remove the " FindMy" suffix    */
/* from the advertised device name ("VANMOOF" vs "VANMOOF FindMy").           */
/* ------------------------------------------------------------------------- */

/* Owner-cache entry layout (7 bytes), mirrored from the OEM stores:
 *   off 0..3 : copy of conn->addr (conn+0x70 .. +0x73, 4 bytes)
 *   off 4..5 : copy of conn bytes +0x74..+0x75
 *   off 6    : conn byte +0x76
 */
extern uint8_t *g_owner_cache;             /* DAT_000256b4, 0x70 bytes (16*7) */

void fmna_update_owner_connections(void *ctx_)
{
    uint8_t *ctx = (uint8_t *)ctx_;

    if (ctx[7] == 0 || ctx[5] == 0) {
        /* Inactive: clear cache + count. */
        vm_memset(g_owner_cache, 0, 0x70);
        g_fmna_owner_count = 0;
    } else {
        int conns[4];
        uint8_t count = 4;
        int rc = fmna_owner_conn_list(conns, &count);

        if (rc == 0) {
            int i;
            for (i = 0; i < (int)count; i++) {
                uint8_t *conn = (uint8_t *)(intptr_t)conns[i];

                if (fmna_owner_conn_valid((int)(intptr_t)(conn + 0x70)) != 0)
                    continue;

                /* Address-type label, purely for logging. */
                if (LOG_INFO_BIT(g_owner_log)) {
                    char typebuf[12];
                    const char *type;
                    switch (conn[0x70]) {
                    case 0: type = "public";    break;
                    case 1: type = "random";    break;
                    case 2: type = "public id"; break;
                    case 3: type = "random id"; break;
                    default:
                        vm_snprintf(typebuf, 10, "0x%02x", conn[0x70]);
                        type = NULL; /* already formatted into typebuf */
                        break;
                    }
                    if (type != NULL)
                        vm_strcpy(typebuf, type);
                    {
                        char addrbuf[24];
                        vm_snprintf(addrbuf, 0x12,
                                    "%02X:%02X:%02X:%02X:%02X:%02X",
                                    conn[0x76]);
                        /* OEM: "%s: Store %s as FMNA owner address ..." */
                        vm_log_record((void *)&g_owner_log, 0x2500,
                                      addrbuf, NULL);
                    }
                }

                /* Append entry to the 7-byte-stride cache (wraps at 16). */
                {
                    uint8_t  idx   = g_fmna_owner_count;
                    uint8_t *slot  = g_owner_cache + (uint32_t)idx * 7u;
                    uint8_t  next  = (uint8_t)(idx + 1);

                    /* 4-byte addr copy. */
                    slot[0] = conn[0x70];
                    slot[1] = conn[0x71];
                    slot[2] = conn[0x72];
                    slot[3] = conn[0x73];
                    /* 2-byte field. */
                    slot[4] = conn[0x74];
                    slot[5] = conn[0x75];
                    /* 1-byte field. */
                    slot[6] = conn[0x76];

                    g_fmna_owner_count = next;
                    if (next > 0xf)            /* cap at 16 entries */
                        g_fmna_owner_count = 0;
                }
            }
        }
    }

    /* Toggle the "FindMy" advertised-name suffix on connected-state change. */
    {
        char connected = (char)ctx[7];
        if ((char)g_fmna_owner_suffix_state != connected) {
            const char *name;
            g_fmna_owner_suffix_state = (connected != 0);

            if (connected == 0 || (char)ctx[5] == 0) {
                if (LOG_LEVEL_GT2(g_owner_log))
                    vm_logf((void *)&g_owner_log, 3, "Remove FindMy suffix");
                name = "VANMOOF";
            } else {
                if (LOG_LEVEL_GT2(g_owner_log))
                    vm_logf((void *)&g_owner_log, 3, "Add FindMy suffix");
                name = "VANMOOF FindMy";
            }

            ble_devname_set(name);
            ble_devname_apply();
        }
    }
}

/* ------------------------------------------------------------------------- */
/* alarm_stolen_set @ 0x3197c                                                */
/*                                                                           */
/* Sets/clears the anti-theft "stolen" flag. When set: latch it, persist via  */
/* provisioning, stop the alarm tone, and force the e-lock to the unlocked     */
/* state (0). Always persists the current stolen byte.                         */
/* ------------------------------------------------------------------------- */
void alarm_stolen_set(int stolen)
{
    g_alarm_stolen = (uint8_t)stolen;

    if (stolen != 0) {
        g_alarm_stolen_latched = 1;
        /* OEM: fmna_provisioning_store(DAT_000319b0) — persist stolen state. */
        fmna_provisioning_store((const char *)0 /*stolen key*/, NULL, 0);
        alarm_tone_stop();
        elock_set_lock_state(0);
    }

    /* Persist the stolen byte (DAT_000319b4 key, 1 byte). */
    fmna_provisioning_store((const char *)0 /*stolen byte key*/,
                            &g_alarm_stolen, 1);
}

/* ------------------------------------------------------------------------- */
/* alarm_stolen_clear @ 0x319b8                                              */
/*                                                                           */
/* Clears stolen mode: silence the buzzer, clear the stolen flag, then unless  */
/* the bike is already in power state 2, request a power-off (reason 4).       */
/* ------------------------------------------------------------------------- */
void alarm_stolen_clear(void)
{
    uint64_t st;

    alarm_buzzer_off((void *)0 /*DAT_000319dc*/);
    alarm_stolen_set(0);

    st = power_state_get();
    if ((int)st != 2)
        ps_power_off_request(4, (int)(st >> 32), 0, 0);
}
