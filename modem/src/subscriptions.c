/*
 * subscriptions.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * The cloud-gateway "subscription" / settings-topic framework: the table that
 * maps every VanMoof cloud<->bike topic to a compact numeric topic-code, the
 * four accessors over it, and the inbound MQTT "setting message" router that
 * turns a JSON payload on a topic into an internal event.
 *
 * Two OEM rodata arrays, both indexed by the same setting id (0..0x8a = 139):
 *   key_string_table[id]  @ 0x5f070   const char *  (topic key string)
 *   topic_code_table[id]  @ 0x5f7f8   uint16_t      (compact topic-code)
 *
 * Decoded VanMoof-app entries (id -> code -> key), verbatim from the image:
 *
 *   id  code    key
 *   --  ------  -------------------------------
 *    0  0x0000  batch_operation
 *    1  0xff00  authentication
 *    2  0xff02  security_updated
 *    3  0xff03  authentication_role     <- the cert-role topic; the ble ECU
 *                                          emits the role on AEM chan4/id 0xff03
 *                                          (see ble vmtp_auth) -> bridged here
 *                                          -> cloud (role ACL is cloud-side).
 *    4  0xffff  allow_all
 *    5  0x0001  ble/reset       )
 *    6  0x0002  ble/ping        )
 *    7  0x0003  ble/version     )  CAN<->cloud bridge topics: the modem's
 *    8  0x0004  ble/ftp/command )  window onto the ble ECU (the S6 central
 *    9  0x0005  ble/ftp/data    )  controller). Cloud commands to these are
 *   10  0x0006  ble/log         )  relayed to ble; ble telemetry comes back
 *   11  0x0007  ble/shell       )  out the same way.
 *   12  0x0008  ble/hwid        )
 *   13  0x0010  ble/connection  )
 *   14  0x0030  info/ecu_id     )  device identity (see identity.c)
 *   15  0x0031  info/frame_id   )
 *   16  0x0032  info/bike_id    )
 *   17  0x0033  provisioning/region            )
 *   18  0x0034  provisioning/server_public_key )  trust / Find-My bootstrap.
 *   19  0x0035  provisioning/owner_public_key  )  NOTE: owner_public_key and
 *   20  0x0036  provisioning/apple_fmna        )  apple_fmna are ORDINARY
 *   21  0x1110  provisioning/generate_key      )  STORED SETTINGS in the low
 *                                                 topic-code range (0x33..0x36)
 *   ... id 22..138 continue with telemetry / device-shadow event topics
 *       (codes 0x1110.., 0x12xx) that carry a real handler in the event table
 *       at 0x78120.
 *
 * The Find-My owner-key ingress is therefore NOT a bespoke handler: the cloud
 * publishes the key on `provisioning/owner_public_key`, the generic router
 * below (setting_message_dispatch) tags it with topic-code 0x35 and hands the
 * built event to the single settings subscriber, which persists it and (for
 * the ble/.. and provisioning keys) forwards it to the ble ECU. Only
 * `generate_key` (code 0x1110) has a dedicated handler (keygen, provisioning.c);
 * region/server/owner/apple are plain stored values with get-responders.
 *
 * Behaviour-oriented reconstruction from Ghidra (image base 0x10000, Cortex-M33);
 * not byte-identical. Self-contained: <stdint.h>/<stddef.h> + the externs below.
 *   setting_key_by_id        @ 0x47a60
 *   setting_code_by_id       @ 0x47a4c
 *   setting_id_by_key        @ 0x47a74
 *   setting_id_by_code       @ 0x47a2c
 *   setting_message_dispatch @ 0x2670c
 *   telemetry_message_dispatch @ 0x26620
 *   cmd_subscriptions        @ 0x25b14
 */

#include <stdint.h>
#include <stddef.h>

/* ---- the two OEM setting tables (rodata), indexed by setting id 0..0x8a ---- */
#define SETTING_COUNT   0x8b        /* 139 ids */
extern const char * const key_string_table[SETTING_COUNT];   /* 0x5f070 */
extern const uint16_t      topic_code_table[SETTING_COUNT];  /* 0x5f7f8 */

/* ---- libc / record / event helpers (vendor) ------------------------------- */
extern int      vm_strcmp (const char *a, const char *b);              /* 0x20c60 (0 == equal) */
extern unsigned vm_strlen (const char *s);                             /* 0x20c74 */
extern int      vm_memcmp (const void *a, const void *b, unsigned n);  /* 0x5c8b0 (0 == equal) */
extern uint16_t parse_hex_u16(const char *s, int base, int width);     /* 0x4f8dc ("0xNNNN") */

/* App Event Manager: alloc(len, topic_code, chan, flags) -> event, then fill + submit. */
extern void  *evt_alloc  (int len, unsigned topic_code, int chan, int flags);   /* 0x59bbe */
extern void   evt_fill   (void *evt, const void *src, int len);                 /* 0x5c526 */
extern void   evt_drop   (void *evt);                                           /* 0x49738 */

/* CBOR/record encoder used to pack the JSON array payload (vendor). */
extern void   rec_init   (int *w, int n, void *buf, int cap);   /* 0x5953a */
extern int    rec_open   (int *w);                              /* 0x59508/0x5950a */
extern void   rec_close  (int *w, int mark);                    /* 0x5951a */
extern void   rec_add_i32(int *w, const void *p, int n);        /* 0x59448 */
extern void   rec_add_str(int *w, const char *s, unsigned n);   /* 0x594f8 */

/* subscription list iterator (vendor container) used by the debug dump. */
extern int    subs_first (void *ctx, void *cursor);            /* (*ctx)(ctx,cursor) */
extern void   sh_print   (void *sh, const char *fmt, ...);     /* 0x53994 */

/* logging */
extern void   log_msg    (void *mod, int lvl, const void *fmt, ...);  /* 0x53280 */
extern void   log_fmt    (void *mod, int code, void *arg);            /* 0x2973c */
extern uint32_t *g_settings_log;                                      /* DAT_00026910 */
extern void   *g_settings_ctx;                                       /* DAT_000268e8 (subscriber root) */
extern int    modem_is_ready(void);                                  /* 0x5823c */

/* record (key/value list) accessors on the inbound message (vendor). */
extern int    rec_next_kind (int *node);          /* node[3]: 8=int, 0x10=string */
extern int    rec_is_active (void *msg);          /* 0x5822e */
extern int    rec_iter_begin(void *msg);          /* 0x58076 */
extern int    rec_release   (void *msg, int f);   /* 0x4223c */
extern void   route_settings(const char *grp, uint32_t key, void *msg, int f); /* 0x26440 */

/* the "0x%04x" literal-topic prefix ("0x") and format strings (rodata). */
extern const char s_hex_prefix[];      /* 0x60f3e "0x" */
extern const char s_settings_grp[];    /* 0x76617 "settings" */

/* -------------------------------------------------------------------------
 * setting_key_by_id  --  0x47a60
 * setting_code_by_id --  0x47a4c
 *   id -> topic key string / compact topic-code (bounds-checked).
 * ------------------------------------------------------------------------- */
const char *setting_key_by_id(unsigned id)
{
    return (id < SETTING_COUNT) ? key_string_table[id] : NULL;
}

uint16_t setting_code_by_id(unsigned id)
{
    return (id < SETTING_COUNT) ? topic_code_table[id] : (uint16_t)0xffff;
}

/* -------------------------------------------------------------------------
 * setting_id_by_key  --  0x47a74   (topic key string -> id, linear strcmp)
 * setting_id_by_code --  0x47a2c   (compact topic-code -> id, linear scan)
 *   Both scan 0x8a entries and return the matching id, or -1.
 * ------------------------------------------------------------------------- */
int setting_id_by_key(const char *key)
{
    for (int id = 0; id != 0x8a; id++)
        if (vm_strcmp(key_string_table[id], key) == 0)
            return id;
    return -1;
}

int setting_id_by_code(uint16_t code)
{
    for (int id = 0; id != 0x8a; id++)
        if (topic_code_table[id] == code)
            return id;
    return -1;
}

/* -------------------------------------------------------------------------
 * setting_message_dispatch  --  0x2670c
 *
 * Inbound MQTT "setting message" router. Walks the decoded message's key/value
 * list; for each entry the key is either a named topic ("provisioning/..",
 * "ble/..", ..) resolved via setting_id_by_key -> setting_code_by_id, or a
 * literal "0xNNNN" topic-code. It re-encodes the JSON array of values into the
 * internal record (i32 for numbers, string for text), allocates an event tagged
 * with the topic-code, copies the record in, logs "Setting message on topic %u",
 * and delivers it to the settings subscriber's callback (g_settings_ctx+0x1c ->
 * +0x18). That subscriber persists the value and, for the bridge/provisioning
 * keys, forwards it to the ble ECU. This is the ONLY path the Find-My owner key
 * (provisioning/owner_public_key, code 0x35) takes into the bike.
 * ------------------------------------------------------------------------- */
void setting_message_dispatch(void *req)
{
    uint8_t *ctx = (uint8_t *)g_settings_ctx;
    int     *node;

    /* the framework must be enabled (ctx+0xac/+0xad) and the modem ready */
    if (ctx[0xac] == 0 || ctx[0xad] == 0 || !modem_is_ready())
        return;

    for (node = *(int **)((uint8_t *)req + 8); node != NULL; node = (int *)*node) {
        const char *key = *(const char **)((uint8_t *)node + 0x20);
        uint16_t    code;
        int         rec[27];
        uint8_t     buf[132];
        void       *evt;
        int         len;

        if (vm_memcmp(key, s_hex_prefix, 2) == 0) {
            code = parse_hex_u16(key + 2, 0, 0x10);          /* literal "0xNNNN" */
        } else {
            int id = setting_id_by_key(key);                 /* named topic */
            if (id < 0)
                continue;
            code = setting_code_by_id((unsigned)id);
        }

        rec_init(rec, 3, buf, 0x80);
        if (!rec_is_active(node)) {
            if ((*g_settings_log & 7) != 0)
                log_msg(g_settings_log, 1, "Invalid JSON array for topic %u", code);
        } else {
            int mark = rec_iter_begin(node);
            rec_open(rec);
            for (int *v = (int *)node[2]; v != NULL; v = (int *)*v) {
                if (v[3] == 8) {                             /* number -> i32 */
                    rec_add_i32(rec, v + 5, 4);
                } else if (v[3] == 0x10) {                   /* text -> string */
                    const char *s = (const char *)v[4];
                    rec_add_str(rec, s, vm_strlen(s));
                } else {
                    goto release;                            /* unsupported type */
                }
            }
            rec_close(rec, mark);

            len = rec[0] - (int)(intptr_t)buf;
            evt = evt_alloc(len, code, 5, 0);
            if (evt != NULL) {
                evt_fill((uint8_t *)evt + 5, buf, len);

                if ((*g_settings_log & 4) != 0)
                    log_msg(g_settings_log, 0x2100, "%s: Setting message on topic %u",
                            "setting_topic_set", code);

                /* deliver to the settings subscriber (ctx+0x1c -> +0x18 cb) */
                int subs = *(int *)(ctx + 0x1c);
                int rc = (subs == 0 || *(void **)(subs + 0x18) == NULL)
                             ? -0x20
                             : (**(int (**)(int, void *, void *))(subs + 0x18))(subs, ctx, evt);
                if (rc != 0) {
                    if ((*g_settings_log & 7) != 0)
                        log_msg(g_settings_log, 1, "setting delivery failed %d", rc);
                    evt_drop(evt);
                }
            }
        }
release:
        node = (int *)rec_release(node, 1);
        route_settings(s_settings_grp, *(uint32_t *)((uint8_t *)node + 0x20), node, 0);
    }
}

/* -------------------------------------------------------------------------
 * cmd_subscriptions  --  0x25b14
 *
 * Debug-shell "subscriptions" command: dumps the active subscription table as
 *   Topic          0x04x   Priority   Rate-Limit(ms)
 * resolving each entry's compact topic-code back to its key string via
 * setting_id_by_code -> setting_key_by_id.
 * ------------------------------------------------------------------------- */
/* Iterator cursor (memset 0, 0x28); OEM byte offsets. */
struct sub_cursor {
    uint8_t   pad0[4];        /* 0x00 */
    void    (*next)(void *);  /* 0x04 */
    uint8_t   pad1[8];        /* 0x08 */
    uint16_t  code;           /* 0x10 */
    uint8_t   pad2[6];        /* 0x12 */
    char      priority;       /* 0x18 (2 == high, else low) */
    uint8_t   pad3[3];        /* 0x19 */
    uint32_t  rate_ms;        /* 0x1c */
    uint32_t  count;          /* 0x20 */
    uint32_t  index;          /* 0x24 */
};

extern void **g_subs_container;   /* DAT_00025b9c (subscription container) */

int cmd_subscriptions(void *sh)
{
    /* empty when container[2] (offset +8 of the inner list @ +8) is 0 */
    int *list = (int *)g_subs_container[2];
    if (list[2] == 0) {
        sh_print(sh, "No subscriptions found");
        return 0;
    }

    struct sub_cursor cur = {0};
    sh_print(sh, "Topic         Priority  Rate Limit ms");
    sh_print(sh, "----------------------------------");
    subs_first(g_subs_container, &cur);

    while (cur.index < cur.count) {
        cur.next(&cur);
        int id = setting_id_by_code(cur.code);
        const char *key = setting_key_by_id((unsigned)id);
        sh_print(sh, "%-12s 0x%04x %8s %u",
                 key, cur.code, (cur.priority == 2) ? "high" : "low", cur.rate_ms);
    }
    return 0;
}
