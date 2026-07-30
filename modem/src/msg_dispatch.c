/*
 * msg_dispatch.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * The OUTBOUND half of the cloud gateway: internal messages (device state,
 * provisioning results, status/error events) are packed into AEM events and
 * handed to the settings subscriber for publication to AWS-IoT. This is the
 * counterpart to the inbound `setting_message_dispatch` (subscriptions.c).
 *
 * These handlers were reached only via the event-dispatch table (0x780f0..) or
 * work/registration pointers, so the analyzer left them undefined — recovered by
 * a create_function pass over the evt_alloc (0x59bbe) caller set.
 *
 *   cloud_message_dispatch      @ 0x26b40  (dedup + type-route + publish)
 *   provisioning_result_publish @ 0x254d0  (event 0x1103, 0xba B)
 *   device_string_publish       @ 0x24778  (event 0x1112, 0x102 B)
 *   device_string_set           @ 0x247c4  (store <=0x40 B, apply, republish)
 *   status_publish_0x1105/0x1107, error_event_publish_a/b (thin publishers)
 *
 * Behaviour-oriented reconstruction from Ghidra (image base 0x10000, Cortex-M33);
 * not byte-identical. Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- AEM event bus + subscriber ------------------------------------------ */
extern void *evt_alloc (int len, uint16_t id, int chan, int flags);   /* 0x59bbe */
extern void  evt_send  (void *evt);                                   /* 0x4866c */
extern void  evt_fill  (void *dst, const void *src, int len);         /* 0x5c526 */
extern void  evt_drop  (void *evt);                                   /* 0x49738 */
extern void  work_schedule(void *work, int a, int flags, int b);      /* 0x4dba4 */

/* settings subscriber root: +0xac/+0xad enabled, +0xbe last-topic cache,
 * +0x1c -> +0x18 deliver callback. */
extern uint8_t *g_cloud_ctx;   /* DAT_00026ce8 */

/* ---- record reader / libc (vendor) --------------------------------------- */
extern int  parse_message_topic(void *src, const void *fmt, void *out);   /* 0x4f730 (1 = ok) */
extern int  vm_memcmp (const void *a, const void *b, unsigned n);         /* 0x5c8b0 */
extern void vm_memcpy (void *dst, const void *src, unsigned n);          /* 0x5c8d4 */
extern void vm_memset (void *dst, int v, unsigned n);                    /* 0x5c574 */
extern unsigned vm_strlen(const char *s);                                /* 0x20c74 */
extern void rec_reader_init(void *rd, int n, void *buf, int len, int a, void *scratch, int z); /* 0x58fa8 */
extern int  rec_reader_valid(void *rd);                                  /* 0x5933c */
extern int  rec_reader_get  (void *rd, void *out, int n);                /* 0x592ae */
extern void apply_setting(void *ctx);                                    /* 0x2a2bc */

/* ---- logging ------------------------------------------------------------- */
extern void  log_msg (void *mod, int lvl, const void *fmt, ...);         /* 0x53280 */
extern void  log_fmt (void *mod, int code, void *arg);                   /* 0x2973c */
extern uint32_t *g_msg_log;     /* DAT_00026cf0 */

/* message field constants (rodata) */
extern const void *g_topic_fmt;   /* DAT_00026cec */
extern void       *g_cloud_work;  /* DAT_00026cf8 */

/* return codes */
#define MSG_EINVAL   (-0x16)
#define MSG_EDUP     (-0x78)   /* identical to last message -> dropped */
#define MSG_ETYPE    (-0x86)   /* unsupported message type            */
#define MSG_ENODELIV (-0x20)   /* no subscriber callback              */
#define MSG_ENOMEM   (-0xc)

/* deliver an event to the settings subscriber (ctx+0x1c -> +0x18). */
static int cloud_deliver(uint8_t *ctx, void *evt)
{
    int subs = *(int *)(ctx + 0x1c);
    if (subs == 0 || *(void **)(subs + 0x18) == NULL)
        return MSG_ENODELIV;
    return (**(int (**)(int, void *, void *))(subs + 0x18))(subs, ctx, evt);
}

/* -------------------------------------------------------------------------
 * cloud_message_dispatch  --  0x26b40
 *
 * Publish an internal message to the cloud. Steps: (1) require the gateway
 * enabled; (2) parse the message's topic key and drop it if identical to the
 * last one sent (dedup, caches 0x28 bytes at ctx+0xbe); (3) read the record's
 * type byte + topic id; (4) build the AEM event by type — 4 = empty (chan 4),
 * 5 = data (chan 5), 1 = data (chan 1), else unsupported; (5) schedule the
 * publish work; (6) deliver a subscribe event then the message event to the
 * subscriber. Returns 0 on success or a negative code.
 * ------------------------------------------------------------------------- */
int cloud_message_dispatch(const uint8_t *msg)
{
    uint8_t *ctx = g_cloud_ctx;
    uint8_t  topic_key[0x28];
    uint8_t  scratch[36];
    int      rd[4];        /* reader: rd[0]=current ptr, rd[3]=end ptr */
    char     type;
    uint16_t topic_id;
    void    *msg_evt, *sub_evt;
    int      rc;

    if (ctx[0xac] == 0 || ctx[0xad] == 0)
        return MSG_EINVAL;

    /* parse + dedup the topic */
    rc = parse_message_topic(*(void **)(msg + 4), g_topic_fmt, topic_key);
    if (rc != 1) {
        if ((*g_msg_log & 7) != 0)
            log_msg(g_msg_log, 1, "failed to parse topic %d", rc);
        return MSG_EINVAL;
    }
    if (vm_memcmp(topic_key, ctx + 0xbe, 0x28) == 0)
        return MSG_EDUP;
    vm_memcpy(ctx + 0xbe, topic_key, 0x28);

    /* read type + topic-id from the record */
    rec_reader_init(rd, 3, *(void **)(msg + 0xc), *(int *)(msg + 0x10), 1, scratch, 0);
    if (rec_reader_valid(rd) == 0)
        return MSG_EINVAL;
    if (rec_reader_get(rd, &type, 1) == 0)
        return MSG_EINVAL;
    if (rec_reader_get(rd, &topic_id, 2) == 0)
        return MSG_EINVAL;

    /* build the message event by type */
    if (type == 4) {
        msg_evt = evt_alloc(0, topic_id, 4, 0);
    } else if (type == 5 || type == 1) {
        int chan  = (type == 5) ? 5 : 1;
        int flags = (type == 5) ? 0 : 1;
        int len   = rd[3] - rd[0];          /* remaining payload = end - current */
        msg_evt = evt_alloc(len, topic_id, chan, flags);
        if (msg_evt != NULL && rd[0] != 0)
            evt_fill((uint8_t *)msg_evt + 5, (void *)(intptr_t)rd[0], len);
    } else {
        if ((*g_msg_log & 7) != 0)
            log_msg(g_msg_log, 1, "Unsupported message type: %d", type);
        return MSG_ETYPE;
    }

    work_schedule(g_cloud_work, 0, 0x8000, 0);

    /* deliver: subscribe event, then the message event */
    sub_evt = evt_alloc(0, topic_id, 2, 0);
    if (sub_evt == NULL)
        return MSG_ENOMEM;

    rc = cloud_deliver(ctx, sub_evt);
    if (rc == 0) {
        rc = cloud_deliver(ctx, msg_evt);
        if (rc == 0)
            return 0;
        if ((*g_msg_log & 7) != 0)
            log_msg(g_msg_log, 1, "Failed to dispatch message, err %d", rc);
        evt_drop(msg_evt);
        return rc;
    }
    if ((*g_msg_log & 7) != 0)
        log_msg(g_msg_log, 1, "Failed to subscribe on topic %d", rc);
    evt_drop(sub_evt);
    return rc;
}

/* -------------------------------------------------------------------------
 * provisioning_result_publish  --  0x254d0
 *
 * Pack two blobs from a provisioning message (a <=0x15-byte field at +9 and a
 * body at +0x30) into a 0xba-byte record and publish it as event 0x1103; traces
 * the two blobs at debug level.
 * ------------------------------------------------------------------------- */
extern uint32_t *g_prov_log;     /* DAT_00025564 */
void provisioning_result_publish(const uint8_t *msg)
{
    struct {
        uint16_t a_len;          /* +0x00 */
        uint8_t  a[21];          /* +0x02 field @ msg+9  */
        uint16_t b_len;          /* +0x17 */
        uint8_t  b[167];         /* +0x19 body @ msg+0x30 */
    } rec;
    unsigned blen = *(uint32_t *)(msg + 0x2c);
    uint8_t  alen = msg[0x1e];
    void    *evt;

    vm_memset((uint8_t *)&rec + 2, 0, 0xb8);   /* zero a[] + b_len + b[] */
    vm_memcpy(rec.b, msg + 0x30, blen);        /* body -> rec.b (offset 0x19) */
    rec.b_len = (uint16_t)blen;
    vm_memcpy(rec.a, msg + 9, alen);
    rec.a_len = alen;

    evt = evt_alloc(0xba, 0x1103, 1, 1);
    if (evt != NULL)
        evt_fill((uint8_t *)evt + 5, &rec, 0xba);
    evt_send(evt);

    if ((*g_prov_log & 7) > 2) {
        struct { void *a, *b, *c; const uint8_t *p, *q; } t;
        t.p = msg + 9; t.q = msg + 0x30;
        log_fmt(g_prov_log, 0x28c0, &t);
    }
}

/* -------------------------------------------------------------------------
 * device_string_publish  --  0x24778   (event 0x1112)
 * device_string_set      --  0x247c4
 *
 * A device string setting (<=0x100 B stored, <=0x40 B accepted on set). The
 * getter publishes [len:2 | string] as event 0x1112; the setter stores the new
 * value, applies it, and republishes.
 * ------------------------------------------------------------------------- */
extern char *g_dev_string;       /* DAT_000247c0 (published source)  */
extern char *g_dev_string_store; /* DAT_000247e8 (backing store)     */
extern void *g_dev_string_ctx;   /* DAT_000247ec */

void device_string_publish(void)
{
    struct { uint16_t len; char s[256]; } rec;
    void *evt;

    vm_memcpy(rec.s, g_dev_string, 0x100);
    rec.len = (uint16_t)vm_strlen(g_dev_string);

    evt = evt_alloc(0x102, 0x1112, 1, 1);
    if (evt != NULL)
        evt_fill((uint8_t *)evt + 5, &rec, 0x102);
    evt_send(evt);
}

void device_string_set(const uint8_t *req)
{
    unsigned len = *(const uint16_t *)(req + 5);
    if (len > 0x3f)
        len = 0x40;
    vm_memcpy(g_dev_string_store, req + 7, len);
    apply_setting(g_dev_string_ctx);
    device_string_publish();
}

/* -------------------------------------------------------------------------
 * status_publish_0x1105 / 0x1107  --  0x2438c / 0x26044
 *   Thin 1-byte status publishers.
 * ------------------------------------------------------------------------- */
extern uint8_t *g_status_1105_src;   /* DAT_000243ac */
extern uint8_t *g_status_1107_src;   /* DAT_00026064 (byte at +1) */

void status_publish_0x1105(void)
{
    uint8_t *ev = evt_alloc(1, 0x1105, 1, 1);
    if (ev != NULL)
        ev[5] = *g_status_1105_src;
    evt_send(ev);
}

void status_publish_0x1107(void)
{
    uint8_t *ev = evt_alloc(1, 0x1107, 1, 1);
    if (ev != NULL)
        ev[5] = g_status_1107_src[1];
    evt_send(ev);
}

/* -------------------------------------------------------------------------
 * stream_chunk_publish  --  0x5a17a
 *
 * Publish one chunk of a byte stream (e.g. ble/log or ble/ftp/data) as event
 * 0x1007. The stream handle is at src+4; when its first byte is 0 the stream is
 * closed (-0x13). Otherwise clamp the chunk to 0x100 bytes, build the event
 * (marking header bit 3 + a u16 length at +5, payload at +7), publish, and fire
 * the stream's "consumed" callback (handle+4). Reports the accepted length in
 * *out_len. Returns 0 on success, -0x13 closed, -0xc on alloc failure.
 * ------------------------------------------------------------------------- */
int stream_chunk_publish(void *src, const void *data, unsigned len, unsigned *out_len)
{
    uint8_t *handle = *(uint8_t **)((uint8_t *)src + 4);

    if (handle[0] == 0) {              /* stream closed */
        *out_len = 0;
        return -0x13;
    }
    if (len > 0xff)
        len = 0x100;

    {
        uint8_t *ev = evt_alloc(len + 2, 0x1007, 1, 1);
        if (ev == NULL) {
            *out_len = len;
            return -0xc;
        }
        ev[0] |= 8;                    /* header flag */
        *(uint16_t *)(ev + 5) = (uint16_t)len;
        evt_fill(ev + 7, data, len);
        evt_send(ev);
        *out_len = len;
        /* notify the stream it was consumed */
        (**(void (**)(int, void *))(handle + 4))(1, *(void **)(handle + 8));
    }
    return 0;
}
