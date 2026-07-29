/*
 * telemetry.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * The `device_shadow_telemetry` control plane: the cloud tells the bike which
 * topic-codes it wants streamed and at what priority / rate, and the modem keeps
 * a subscription set that drives the periodic telemetry publish to
 * `v1/telemetry/<thing>`.
 *
 * Wire model (per topic key in a telemetry-config message):
 *   - key resolves to a compact topic-code (named key -> setting_id_by_key ->
 *     setting_code_by_id, or a literal "0xNNNN"), same code space as
 *     subscriptions.c.
 *   - optional field 'p' = priority (0 = "low"/drop -> unsubscribe, else keep),
 *     optional field 'r' = rate_limit (ms).
 *   -> telemetry_subscribe(code, priority, rate)  or  telemetry_unsubscribe(code)
 *
 * Every subscribe/unsubscribe also emits a small "subscription changed" event
 * (telemetry_notify) to the settings subscriber so the rest of the gateway can
 * react. A telemetry-config message with an empty body clears the whole set.
 *
 * Behaviour-oriented reconstruction from Ghidra (image base 0x10000, Cortex-M33);
 * not byte-identical. Self-contained: <stdint.h>/<stddef.h> + the externs below.
 *   telemetry_notify           @ 0x25bb8
 *   telemetry_subscribe        @ 0x25d50
 *   telemetry_unsubscribe      @ 0x25de0
 *   telemetry_clear            @ 0x25dc4
 *   telemetry_message_dispatch @ 0x26620
 *
 * (The periodic data-plane publish to `v1/telemetry/%s`, `telemetry_publish`
 *  @0x25ca8, is the record-encoder/MQTT emit; left as a named anchor for now.)
 */

#include <stdint.h>
#include <stddef.h>

/* ---- setting-table accessors (subscriptions.c) --------------------------- */
extern int      setting_id_by_key (const char *key);   /* 0x47a74 */
extern uint16_t setting_code_by_id(unsigned id);       /* 0x47a4c */

/* ---- record (message) field access — vendor ------------------------------ */
extern int      vm_memcmp   (const void *a, const void *b, unsigned n);    /* 0x5c8b0 */
extern uint16_t parse_hex_u16(const char *s, int base, int width);         /* 0x4f8dc */
extern int      rec_field_find (void *node, const char *key);              /* 0x58098 (nonzero=present) */
extern int      rec_field_get  (void *node, const char *key, ...);         /* 0x58092 (-> field, val@+0x14) */
extern int      rec_release    (void *node, int f);                        /* 0x4223c */
extern void     route_settings (const char *grp, uint32_t key, void *node, int f); /* 0x26440 */

/* ---- subscription container (vendor) ------------------------------------- */
/* Opaque handle; slot +0x08 = add, +0x0c = remove, +0x04 = clear (vtable-ish). */
extern void *g_sub_add;      /* DAT_00025dc0 */
extern void *g_sub_remove;   /* DAT_00025e28 */
extern void *g_sub_clear;    /* DAT_00025dd8 */

/* ---- event bus / settings subscriber ------------------------------------- */
extern void *evt_alloc (int len, uint32_t topic_code, int chan);   /* 0x59bbe */
extern void  evt_drop  (void *evt);                                /* 0x49738 */
extern uint8_t *g_settings_ctx;   /* DAT_00025bf8 (+0x89 enabled, +0x1c subscriber) */
extern int   modem_is_ready(void);                                 /* 0x5823c */

/* ---- logging ------------------------------------------------------------- */
extern void  log_fmt (void *mod, int code, void *arg);             /* 0x2973c */
extern void  log_msg (void *mod, int lvl, const void *fmt, ...);   /* 0x53280 */
extern uint32_t *g_tele_sub_log;    /* DAT_00025db8 */
extern uint32_t *g_tele_unsub_log;  /* DAT_00025e20 */

/* the "0x" literal-topic prefix and the "p"/"r" field keys (rodata). */
extern const char s_hex_prefix[];       /* 0x60f3e "0x"           */
extern const char s_field_priority[];   /* 0x7121c "p"            */
extern const char s_field_rate[];       /* 0x758ac "r"            */
extern const char s_telemetry_grp[];    /* 0x60f41 "device_shadow_telemetry" */

/* return codes */
#define TELE_OK          0
#define TELE_ESUB      (-0xc)     /* 0xfffffff4: add rejected  */
#define TELE_EUNSUB    (-0x2)     /* 0xfffffffe: remove missing */

/* -------------------------------------------------------------------------
 * telemetry_notify  --  0x25bb8
 *
 * Emit a zero-length "subscription changed" event tagged with the topic-code
 * (chan 2 = added, chan 3 = removed) to the settings subscriber, if the gateway
 * is enabled (g_settings_ctx+0x89). Dropped if delivery fails.
 * ------------------------------------------------------------------------- */
static void telemetry_notify(uint16_t code, int added)
{
    uint8_t *ctx = g_settings_ctx;
    if (ctx[0x89] == 0)
        return;

    void *evt = evt_alloc(0, code, added ? 2 : 3);
    int   subs = *(int *)(ctx + 0x1c);
    if (subs == 0 || *(void **)(subs + 0x18) == NULL ||
        (**(int (**)(int, void *, void *))(subs + 0x18))(subs, ctx, evt) != 0) {
        evt_drop(evt);
    }
}

/* -------------------------------------------------------------------------
 * telemetry_subscribe  --  0x25d50
 *   Register topic-code for streaming at (priority, rate_limit_ms).
 * ------------------------------------------------------------------------- */
int telemetry_subscribe(uint16_t code, int priority, int rate_ms)
{
    if ((*g_tele_sub_log & 7) > 2)
        log_fmt(g_tele_sub_log, 0x28c0, &(struct { uint16_t c; int p, r; }){ code, priority, rate_ms });

    telemetry_notify(code, 1);

    int rc = (**(int (**)(void *, void *, uint16_t))((char *)g_sub_add + 8))
                 (g_sub_add, *(void **)((char *)g_sub_add + 8), code);
    return (rc < 0) ? TELE_ESUB : TELE_OK;
}

/* -------------------------------------------------------------------------
 * telemetry_unsubscribe  --  0x25de0
 *   Drop a topic-code from the streaming set.
 * ------------------------------------------------------------------------- */
int telemetry_unsubscribe(uint16_t code)
{
    if ((*g_tele_unsub_log & 7) > 2)
        log_msg(g_tele_unsub_log, 3, "telemetry unsubscribe topic=0x%04x", code);

    telemetry_notify(code, 0);

    int found = (**(int (**)(void *, void *, uint16_t, int, int))((char *)g_sub_remove + 0xc))
                    (g_sub_remove, *(void **)((char *)g_sub_remove + 0xc), code, 0, 0);
    return (found == 0) ? TELE_EUNSUB : TELE_OK;
}

/* -------------------------------------------------------------------------
 * telemetry_clear  --  0x25dc4
 *   Clear the entire subscription set (empty telemetry-config body).
 * ------------------------------------------------------------------------- */
int telemetry_clear(void)
{
    (**(int (**)(void *, void *, int))((char *)g_sub_clear + 4))
        (g_sub_clear, (void *)s_telemetry_grp, 0);
    return TELE_OK;
}

/* -------------------------------------------------------------------------
 * telemetry_message_dispatch  --  0x26620
 *
 * Inbound `device_shadow_telemetry` config router. Empty body clears the set.
 * Otherwise, per key: resolve topic-code (named or "0xNNNN"); read optional
 * 'p' (priority) and 'r' (rate). priority 0 or absent -> unsubscribe; else
 * subscribe(code, priority, rate).
 * ------------------------------------------------------------------------- */
void telemetry_message_dispatch(void *req, int has_body)
{
    if (!modem_is_ready())
        return;
    if (has_body == 0)
        telemetry_clear();

    for (int *node = *(int **)((uint8_t *)req + 8); node != NULL; node = (int *)*node) {
        const char *key = *(const char **)((uint8_t *)node + 0x20);
        uint16_t    code;
        char        priority = 0;
        int16_t     rate = 0;

        if (vm_memcmp(key, s_hex_prefix, 2) == 0) {
            code = parse_hex_u16(key + 2, 0, 0x10);
        } else {
            int id = setting_id_by_key(key);
            if (id < 0)
                continue;
            code = setting_code_by_id((unsigned)id);
        }

        if (rec_field_find(node, s_field_priority) == 0) {
            /* no priority field -> unsubscribe (and strip a stray 'r') */
            if (rec_field_find(node, s_field_rate) != 0)
                rec_field_get(node, s_field_rate);
            telemetry_unsubscribe(code);
        } else {
            int pf = rec_field_get(node, s_field_priority);
            priority = *(char *)(pf + 0x14);
            if (rec_field_find(node, s_field_rate) != 0) {
                int rf = rec_field_get(node, s_field_rate, pf);
                rate = *(int16_t *)(rf + 0x14);
            }
            if (priority == 0)
                telemetry_unsubscribe(code);
            else
                telemetry_subscribe(code, priority, rate);
        }

        node = (int *)(intptr_t)rec_release(node, 1);
        route_settings(s_telemetry_grp, *(uint32_t *)((uint8_t *)node + 0x20), node, 0);
    }
}
