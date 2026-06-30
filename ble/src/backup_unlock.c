/* backup_unlock.c — VanMoof "backup unlock" code subsystem.
 *
 * S6 `ble` (nRF52840, NCS 2.9.1 / Zephyr 3.7.99). Reconstructed from Ghidra
 * (image base 0xC000):
 *   backup_unlock_get_lockout_count @ 0x31620
 *   backup_unlock_set_active        @ 0x31650
 *   backup_unlock_reset_lockout     @ 0x31668
 *   backup_unlock_log_code          @ 0x31688
 *   backup_unlock_publish_event     @ 0x316a4
 *   backup_unlock_verify            @ 0x316e4
 *   backup_unlock_verify_fail       @ 0x31750
 *   backup_unlock_is_active         @ 0x31780
 *   backup_unlock_store_code        @ 0x3178c
 *
 * The "backup unlock" feature lets the app store a short numeric unlock code and
 * later have the bike verify a presented code, with a lockout counter that caps
 * the number of attempts. The active flag / lockout reset side drives an OD-set
 * notification (backup_unlock_get_lockout_count), and matches publish an
 * Application-Event-Manager event (backup_unlock_publish_event).
 *
 * Behaviour-oriented: the on-flash codec, OD set helper, AEM event bus and the
 * VanMoof logging core are vendor/SDK and modelled as externs. The state lives
 * in two OEM globals in RAM:
 *   - the backup-unlock record blob  (0x20fec0)  [code(u32) | len(u8) | active(u8) ...]
 *   - the policy bytes               (0x2030ff lockout-mode, 0x203080 lockout-cap)
 *   - the published lockout count     (0x2035b4)
 */
#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 * VanMoof logging core (vendor/SDK) — a log "module" descriptor whose
 * first byte holds, in its low 3 bits, the configured verbosity level.
 * vm_log_emit() formats at a given level when the module is enabled.
 * ------------------------------------------------------------------ */
typedef struct vm_log_module vm_log_module;     /* opaque descriptor */

extern void vm_log_emit_2(vm_log_module *mod, int level, const char *fmt,
                          uint32_t a0, uint8_t a1);            /* 0x6effe */
extern void vm_log_emit_str(vm_log_module *mod, int level, const char *fmt,
                            uint32_t a0, uint32_t a1);          /* 0x6efd8 */
extern void vm_log_emit_code(uint32_t a0, const char *fmt,
                             uint32_t code, uint8_t len, uint32_t a3);/* 0x6f948 */

/* on-flash / record codec + OD helpers (vendor) */
extern uint32_t record_blob_pack(uint32_t ctx, int *err, void *cb, uint32_t a3,
                                  uint32_t a4, uint32_t a5, void *cb2);  /* 0x6f4d8 */
extern int  record_field_get(uint32_t ctx, const char *key, uint32_t blob); /* 0x7b438 */
extern int  backup_code_len_query(void);                                   /* 0x6d47c */
extern int  backup_unlock_persist(const char *key);                        /* 0x38334 */
extern void od_set_notify(uint32_t obj, uint32_t a1, int a2, void *src,
                          int a4, int a5, int a6, uint32_t a7);            /* 0x79bb2 */

/* Application Event Manager (vendor) */
extern void *aem_event_alloc(int chan, uint16_t id, int a2, int a3, void *src);/* 0x77cfc */
extern void  aem_event_submit(void *ev);                                  /* 0x55564 */

/* ------------------------------------------------------------------ *
 * OEM globals (RAM/flash literal-pool targets).
 * ------------------------------------------------------------------ */

/* Backup-unlock record blob @ 0x20fec0.
 *   +0: u32 code
 *   +1: u8  len   (note: OEM writes the length byte at +1, overlapping the
 *                  low code bytes — preserved verbatim below)
 *   +4: u8  active flag (is_active)
 *   +5: u32 event field A (publish)
 *   +9: u32 event field B (publish) */
extern uint8_t backup_unlock_blob[];            /* 0x20fec0 */
#define BU_BLOB     ((uint32_t *)backup_unlock_blob)
#define BU_BLOB_U8  (backup_unlock_blob)

/* policy / lockout state */
extern uint8_t bu_lockout_mode;                 /* 0x2030ff (0,1,other) */
extern int8_t  bu_lockout_cap;                  /* 0x203080 (signed cap override) */
extern uint8_t bu_published_count;              /* 0x2035b4 (published lockout count) */

/* OD-set notification context */
extern uint8_t bu_od_ctx[];                     /* 0x7bb18  (+0x10 holds handle) */
extern uint32_t bu_od_arg;                      /* 0x95c44 */

/* log module descriptor for this subsystem */
extern vm_log_module bu_log;                    /* 0x2031b0 */

/* literal strings (read verbatim from the image, used as behaviour docs) */
static const char S_MODULE[]    = "backup_unlock";                       /* 0x853f6 */
static const char S_CODE_NL[]   = "Backup unlock code: %d, len: %d\n";   /* 0x853d5 */
static const char S_CODE[]      = "Backup unlock code: %d, len: %d";     /* 0x85404 */
static const char S_VERIFY_FAIL[] = "backup_unlock_verify failed, aborting"; /* 0x85424 */
static const char S_SAVE_FAIL[] = "backup_unlock save failed";          /* 0x8544a */

/* The OEM gates a level-1 log when the module's low-3-bit level is nonzero
 * after masking ((*mod << 0x1d) != 0  <=> (*mod & 7) != 0), and a level-3 log
 * when that level is > 2 ((*mod & 7) > 2). */
#define BU_LOG_LVL(m)        ((*(const uint8_t *)(m)) & 7u)
/* The OEM passes the module byte shifted left 29 bits as the log call's 4th
 * argument (its low 3 level bits rotated to the top), not the masked level. */
#define BU_LOG_SHIFTED(m)    ((uint32_t)(*(const uint8_t *)(m)) << 0x1d)

/* ------------------------------------------------------------------ *
 * backup_unlock_get_lockout_count @ 0x31620
 * Recompute the effective lockout count from the policy bytes and publish it.
 *   mode 0 -> base 5
 *   mode 1 -> base 0x40
 *   other  -> 0 (no cap clamp, publish straight away)
 * A signed cap override (bu_lockout_cap) lowers the base when in [0, base).
 * ------------------------------------------------------------------ */
void backup_unlock_get_lockout_count(void)
{
    unsigned base;
    unsigned mode = bu_lockout_mode;

    if (mode == 0) {
        base = 5;
    } else if (mode == 1) {
        base = 0x40;
    } else {
        base = 0;
        bu_published_count = (uint8_t)base;
        od_set_notify(*(uint32_t *)(bu_od_ctx + 0x10), bu_od_arg, 0,
                      &bu_published_count, 3, 0, 0, mode);
        return;
    }

    {
        int cap = (int)bu_lockout_cap;          /* signed override */
        if (cap >= 0 && cap < (int)base)
            base = (uint8_t)bu_lockout_cap;     /* clamp down to override */
    }

    bu_published_count = (uint8_t)base;
    od_set_notify(*(uint32_t *)(bu_od_ctx + 0x10), bu_od_arg, 0,
                  &bu_published_count, 3, 0, 0, mode);
}

/* ------------------------------------------------------------------ *
 * backup_unlock_set_active @ 0x31650
 * Adopt a new lockout-mode (taken from req[+8]); recompute on change.
 * ------------------------------------------------------------------ */
void backup_unlock_set_active(const uint8_t *req)
{
    if (bu_lockout_mode != req[8]) {
        bu_lockout_mode = req[8];
        backup_unlock_get_lockout_count();
    }
}

/* ------------------------------------------------------------------ *
 * backup_unlock_reset_lockout @ 0x31668
 * Store a fresh signed cap override and recompute the published count.
 * (OEM stores a 16-bit value into the cap byte slot; preserved as-is.)
 * ------------------------------------------------------------------ */
void backup_unlock_reset_lockout(uint16_t cap)
{
    *(uint16_t *)&bu_lockout_cap = cap;
    backup_unlock_get_lockout_count();
}

/* ------------------------------------------------------------------ *
 * backup_unlock_log_code @ 0x31688
 * Emit "Backup unlock code: %d, len: %d\n" with the stored code/len.
 * Returns 0.
 * ------------------------------------------------------------------ */
uint32_t backup_unlock_log_code(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)
{
    (void)a1; (void)a2;
    vm_log_emit_code(a0, S_CODE_NL, BU_BLOB[0], BU_BLOB_U8[1], a3);
    return 0;
}

/* ------------------------------------------------------------------ *
 * backup_unlock_publish_event @ 0x316a4
 * Publish an Application-Event-Manager event carrying the active/inactive
 * state (0xffff when the stored code is active, else 0) plus a payload word.
 * ------------------------------------------------------------------ */
void backup_unlock_publish_event(const uint8_t *req, uint32_t a1, uint32_t payload)
{
    void *ev;
    uint32_t state = 0;

    (void)a1;
    if (BU_BLOB_U8[0] != 0)                 /* code present -> "active" */
        state = 0xffff;

    /* event id taken from req[+1..+2] (u16) */
    ev = aem_event_alloc(8, *(const uint16_t *)(req + 1), 1, 1, (void *)req);
    if (ev != NULL) {
        *(uint32_t *)((uint8_t *)ev + 5) = state;
        *(uint32_t *)((uint8_t *)ev + 9) = payload;
    }
    aem_event_submit(ev);
}

/* ------------------------------------------------------------------ *
 * backup_unlock_verify @ 0x316e4
 * Verify a presented unlock code against the stored record.
 *   - pack the inbound record (record_blob_pack); abort (-2) if it errored.
 *   - look up the "backup_unlock" field; -22 (EINVAL) if absent.
 *   - hand the 8-byte field to the caller's compare callback; on a positive
 *     match, optionally log "Backup unlock code: %d, len: %d" at level 3.
 * Returns 0 on success (or no-match handled by callback), negative on error.
 * ------------------------------------------------------------------ */
int backup_unlock_verify(uint32_t ctx, uint32_t a1, int (*cb)(uint32_t, uint32_t *, int),
                         int field_arg)
{
    uint32_t *code = BU_BLOB;               /* DAT_00031744 = 0x20fec0 */
    uint32_t packed;
    int err = field_arg;
    int rc;

    packed = record_blob_pack(ctx, &err, (void *)(uintptr_t)cb, (uint32_t)field_arg,
                              ctx, a1, (void *)(uintptr_t)cb);
    if (err != 0)
        return -2;

    rc = record_field_get(ctx, S_MODULE, packed);
    if (rc == 0)
        return -0x16;                       /* -22 EINVAL: no such field */

    rc = ((int (*)(int, uint32_t *, int))cb)(field_arg, code, 8);
    if (rc < 0)
        return rc;

    if (rc != 0 && BU_LOG_LVL(&bu_log) > 2)
        vm_log_emit_2(&bu_log, 3, S_CODE, code[0], BU_BLOB_U8[1]);

    return 0;
}

/* ------------------------------------------------------------------ *
 * backup_unlock_verify_fail @ 0x31750
 * Log "backup_unlock_verify failed, aborting" (level 1) and return -22.
 * ------------------------------------------------------------------ */
uint32_t backup_unlock_verify_fail(void)
{
    if (BU_LOG_LVL(&bu_log) != 0)
        vm_log_emit_str(&bu_log, 1, S_VERIFY_FAIL, BU_LOG_SHIFTED(&bu_log), 0);
    return 0xffffffeau;                     /* -22 */
}

/* ------------------------------------------------------------------ *
 * backup_unlock_is_active @ 0x31780
 * Return the active flag (blob+4).
 * ------------------------------------------------------------------ */
uint8_t backup_unlock_is_active(void)
{
    return BU_BLOB_U8[4];                    /* 0x20fec0 + 4 */
}

/* ------------------------------------------------------------------ *
 * backup_unlock_store_code @ 0x3178c
 * Store a new backup unlock code:
 *   - query its length (backup_code_len_query); abort on negative.
 *   - write len into blob[+1], code into blob[+0].
 *   - persist the record; on failure, log "backup_unlock save failed".
 * Returns the length on success, or a negative error.
 * ------------------------------------------------------------------ */
int backup_unlock_store_code(uint32_t code, uint32_t a1, uint32_t a2, uint32_t a3)
{
    int len;

    (void)a1; (void)a2;
    len = backup_code_len_query();
    if (len < 0)
        return len;

    BU_BLOB_U8[1] = (uint8_t)len;           /* length byte */
    BU_BLOB[0]    = code;                    /* the code itself */

    len = backup_unlock_persist(S_MODULE);
    if (len != 0) {
        if (BU_LOG_LVL(&bu_log) != 0)       /* (*mod << 0x1d) != 0 */
            vm_log_emit_str(&bu_log, 1, S_SAVE_FAIL, BU_LOG_SHIFTED(&bu_log), a3);
    }
    return len;
}
