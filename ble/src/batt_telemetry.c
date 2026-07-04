/*
 * batt_telemetry.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Battery telemetry + charger CAN-event layer.  Recovered from the same
 * dispatch/work-table gap as batt_mgmt.c (0x2be40-0x2bfdc) and continues that
 * subsystem: it formats each pack's measurement into an Application-Event-Manager
 * telemetry record and reacts to the charger's CAN status frames.
 *
 *   - batt_telemetry_format    build + publish one pack's telemetry event
 *   - batt_telemetry_dispatch  publish one (targeted) or all nine packs
 *   - batt_pack_work_handler   per-pack k_work handler (format + lazy CAN init)
 *   - batt_charger_can_evt     charger CAN status frames 0x22c/0x24a -> pack update
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) are noted on each function.  Not byte-identical.
 *
 * Self-contained: depends only on <stdint.h> / <stddef.h> plus the vendor / RTOS
 * / SDK externs and the batt_mgmt.c siblings declared below.
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Pack table layout (shared with batt_mgmt.c).
 * ------------------------------------------------------------------------- */
#define NUM_PACKS          9
#define PACK_STRIDE        0x58
#define META_STRIDE        0x0c

#define PACK_WORK(p)       ((uint8_t *)(p) + 0x38)   /* k_work                   */
#define PACK_STATUS(p)     (*(uint8_t  *)((uint8_t *)(p) + 0x48)) /* charger byte */
#define PACK_VOLT(p)       (*(uint16_t *)((uint8_t *)(p) + 0x53)) /* packed volts */
#define PACK_CURR(p)       (*(uint16_t *)((uint8_t *)(p) + 0x55)) /* 13-bit curr  */

#define META_ID(m)         ((m)[0x00])                  /* CAN object-id byte     */
#define META_WORD(m)       (*(uint32_t *)((m) + 0x04))  /* meta payload word      */

/* -------------------------------------------------------------------------
 * Vendor / RTOS / SDK externs.  Addresses are OEM (image base 0xC000).
 * ------------------------------------------------------------------------- */

/* Field encoder: format 'value(s)' into 'out' (width bytes) per 'spec', returns
 * the encoded halfword.  (OEM htons/bit-pack helper used for CAN fields.)        */
extern uint16_t batt_field_encode(void *out, int width, const void *spec, ...); /* 0x673e8 */
/* Bounded name/string copy + measure (used for the per-pack label).             */
extern void     str_copy_bounded(void *dst, const void *src);                  /* 0x7b45c */
extern uint16_t str_measure(const void *s, int max);                           /* 0x76c74 */
extern void     mem_zero(void *dst, int v, unsigned n);                        /* 0x7b2ba */

/* AEM event alloc/send. */
extern void    *aem_event_alloc(int chan, int id, int sz);                     /* 0x77cfc */
extern void     aem_event_send(void *evt);                                     /* 0x55564 */

/* Read one pack's measurement (lo=value, hi=validity); zero == no sample.        */
extern uint64_t batt_pack_measure(void *pack);                                 /* 0x7ae2a */

/* AEM logging + SM plumbing. */
extern void     aem_log_v(void *log_mod, uint32_t code, void *arg_block, int z);/* 0x364f0 */
extern void     aem_raise(void *log_mod, uint32_t level, void *str);           /* 0x6efd8 */
extern void     aem_log_str(void *log_mod, uint32_t level, void *arg, ...);    /* 0x6effe */
extern void     vm_logf(void *log_mod, uint32_t level, const char *fmt, ...);  /* 0x6efea */

/* Zephyr CAN driver (second interface brought up lazily by the work handler).    */
extern int      can_bind(void *client, void *cfg, int mode);                   /* 0x3c910 */
extern void     can_add_rx_filter2(void *client, void *filter, int id, int z); /* 0x3caac */
extern void     can_start(void *client);                                       /* 0x3ca34 */
/* CAN OD "read device version" (uses batt_can_od_rx as its RX callback).  The OEM
 * passes trailing zero args at the serial/version call sites; variadic here.      */
extern int      od_read_version(void *transport, void *spec, void *out, ...);  /* 0x79bb2 */

/* Zephyr work-queue. */
extern void     k_work_submit(void *work);                                     /* 0x636b4 */
extern void     k_work_reschedule(void *work, uint32_t r1, uint32_t timeout, int z); /* 0x64594 */

/* batt_mgmt.c siblings. */
extern uint8_t  g_batt_packs[NUM_PACKS * PACK_STRIDE]; /* DAT_0002bf1c / 0x2be20 */
extern uint8_t  g_batt_meta[NUM_PACKS * META_STRIDE];  /* DAT_0002bf24 / 0x2be1c */
extern int32_t  batt_can_od_rx(void *dev, void *arg, const uint8_t *frame, uint32_t *ctr);
extern void     batt_charge_stop(void);                /* 0x2bc08                  */

/* Charge-retry + device-version-query state. */
extern uint8_t *g_batt_charge_retry_count;             /* DAT_0002c12c             */
extern uint8_t  g_log_batt_charge2[];                  /* DAT_0002c130             */
extern const char *g_msg_batt_charge_fail;             /* DAT_0002c134             */
extern const uint32_t *g_batt_serial_spec;             /* DAT_0002c0e4             */
extern const uint32_t *g_batt_version_spec;            /* PTR_DAT_0002c0f0         */
extern uint8_t  g_log_batt_query[];                    /* DAT_0002c0e8             */

/* Auxiliary tables / specs / log-modules addressed through the literal pools.     */
extern const uint8_t g_batt_name_table[];             /* DAT_0002bf2c (0xd/entry) */
extern const void   *g_batt_volt_spec;                /* DAT_0002bf30             */
extern const void   *g_batt_meta_spec;                /* DAT_0002bf28             */
extern uint8_t       g_log_batt_tele[];               /* DAT_0002c038             */
extern uint8_t       g_log_batt_evt[];                /* DAT_0002be14             */
extern uint8_t       g_batt_second_can_pending;       /* DAT_0002c034             */
extern void         *g_batt_second_can_client;        /* DAT_0002c058             */
extern void         *g_batt_second_can_cfg;           /* DAT_0002c05c             */
extern void         *g_batt_second_can_filter;        /* DAT_0002c04c             */
extern void         *g_batt_od_transport;             /* PTR_DAT_0002be38         */
extern void         *g_batt_ver_spec;                 /* PTR_DAT_0002be30         */

/* AEM telemetry event (chan 0x39, id 0x101, payload at +5; bit 3 = "targeted"). */
#define TELE_EVT_CHAN      0x39
#define TELE_EVT_ID        0x101
#define TELE_EVT_PAYLOAD   5
#define TELE_REC_SIZE      0x38

/* -------------------------------------------------------------------------
 * batt_telemetry_format  --  0x2be40
 *
 * Assemble one pack's telemetry record (CAN id, encoded pack voltage split
 * hi/lo, 13-bit current, charger-status byte, a copied name label and the sample
 * validity) and publish it as an AEM telemetry event.  'targeted' is carried in
 * bit 3 of the event's control byte.
 * ------------------------------------------------------------------------- */
void batt_telemetry_format(uint8_t *pack, uint8_t targeted)
{
    int      idx  = (int)(pack - g_batt_packs) / PACK_STRIDE;
    uint8_t *meta = g_batt_meta + idx * META_STRIDE;

    /* record laid out in a 0x38-byte scratch buffer (OEM stack frame) */
    struct {
        uint8_t  id;
        uint16_t volt_enc;
        uint8_t  status;
        uint8_t  name[16];
        uint16_t name_len;
        uint16_t curr_enc;
        uint8_t  curr_buf[16];
        uint8_t  valid;
        uint8_t  pad[8];
    } rec;
    uint8_t *evt;

    mem_zero(&rec, 0, TELE_REC_SIZE);

    rec.id       = META_ID(meta);
    rec.volt_enc = batt_field_encode(&rec.status, 0x10, g_batt_meta_spec, META_WORD(meta));
    rec.status   = PACK_STATUS(pack);

    str_copy_bounded(rec.name, g_batt_name_table + idx * 0x0d);
    rec.name_len = str_measure(rec.name, 0x10);

    /* voltage packed as {hi = [0x53]>>8, lo = (int8)[0x53]}, current 13-bit */
    rec.curr_enc = batt_field_encode(rec.curr_buf, 0x10, g_batt_volt_spec,
                                     (uint32_t)(PACK_VOLT(pack) >> 8),
                                     (uint32_t)(int8_t)PACK_VOLT(pack),
                                     (uint32_t)(PACK_CURR(pack) & 0x1fff));

    rec.valid = (batt_pack_measure(pack) != 0);

    evt = (uint8_t *)aem_event_alloc(TELE_EVT_CHAN, TELE_EVT_ID, 1);
    if (evt != NULL) {
        uint8_t *dst = evt + TELE_EVT_PAYLOAD;
        const uint8_t *src = (const uint8_t *)&rec;
        unsigned i;
        for (i = 0; i < TELE_REC_SIZE; i++)
            dst[i] = src[i];
        evt[0] = (uint8_t)((evt[0] & 0xf7) | ((targeted & 1) << 3));
        aem_event_send(evt);
    }
}

/* -------------------------------------------------------------------------
 * batt_telemetry_dispatch  --  0x2bf34
 *
 * Publish telemetry for a single targeted pack (when the event is a type-5
 * request naming a pack id in byte +5) or, otherwise, for all nine packs.
 * ------------------------------------------------------------------------- */
void batt_telemetry_dispatch(const uint8_t *evt)
{
    int i;

    if ((evt[0] & 7) == 5) {
        for (i = 0; i < NUM_PACKS; i++) {
            if (g_batt_meta[i * META_STRIDE] == evt[5]) {
                batt_telemetry_format(g_batt_packs + i * PACK_STRIDE, 0);
                return;
            }
        }
    } else {
        for (i = 0; i < NUM_PACKS; i++)
            batt_telemetry_format(g_batt_packs + i * PACK_STRIDE, 1);
    }
}

/* -------------------------------------------------------------------------
 * batt_pack_work_handler  --  0x2bf8c
 *
 * Per-pack k_work handler ('work' is the pack's +0x38 work item).  Publish the
 * pack's telemetry, then — the first time it runs (a pending flag) — lazily bind
 * and start the secondary CAN interface (RX filter id 0x75).
 * ------------------------------------------------------------------------- */
void batt_pack_work_handler(uint8_t *work)
{
    uint8_t *pack = work - 0x38;
    int rc;

    batt_telemetry_format(pack, 1);

    if (g_batt_second_can_pending == 0)
        return;
    g_batt_second_can_pending = 0;

    if ((g_log_batt_tele[0] & 7) > 2) {
        /* trace the pack that triggered the lazy bring-up (event code 0x30c0) */
        int idx = (int)(pack - g_batt_packs) / PACK_STRIDE;
        struct { uint32_t a; uint32_t b; uint32_t word; uint32_t id; int name; uint32_t c; } t;
        t.word = META_WORD(g_batt_meta + idx * META_STRIDE);
        t.id   = g_batt_meta[idx * META_STRIDE];
        t.name = idx * 0x0d;   /* + name table base */
        t.a = 0; t.b = 0; t.c = 0;
        aem_log_v(g_log_batt_tele, 0x30c0, &t, 0);
    }

    /* clear + bring up the secondary CAN client */
    ((uint32_t *)g_batt_second_can_client)[0] = 0;
    ((uint32_t *)g_batt_second_can_client)[1] = 0;
    ((uint8_t  *)g_batt_second_can_client)[8] = 0;

    rc = can_bind(g_batt_second_can_client, g_batt_second_can_cfg, 0x12);
    if (rc == 0) {
        can_add_rx_filter2(g_batt_second_can_client, g_batt_second_can_filter, 0x75, 0);
        can_start(g_batt_second_can_client);
    } else if ((g_log_batt_tele[0] & 7) != 0) {
        vm_logf(g_log_batt_tele, 1, "Unable to register secondary battery CAN rx");
    }
}

/* -------------------------------------------------------------------------
 * batt_charger_can_evt  --  0x2bcf4
 *
 * Charger CAN status frames.  Frame id 0x22c maps to object class 0xA4, 0x24a to
 * 0xA7.  Find the pack for that class, latch the frame's status byte (+0x48), and
 * take a measurement.  If there is no valid sample: (optionally) trace, raise the
 * AEM "no data" event (0x22b / 0x24b), query the device firmware version over the
 * OD (via batt_can_od_rx), and submit the pack's work.  Always re-arm the pack's
 * poll (0xc000 ticks).
 * ------------------------------------------------------------------------- */
void batt_charger_can_evt(const uint8_t *frame)
{
    uint16_t frame_id = *(const uint16_t *)(frame + 1);
    uint32_t no_data_evt;
    uint32_t klass;
    int i;

    if (frame_id == 0x22c) {
        no_data_evt = 0x22b;
        klass       = 0xa4;
    } else if (frame_id == 0x24a) {
        no_data_evt = 0x24b;
        klass       = 0xa7;
    } else {
        if ((g_log_batt_evt[0] & 7) != 0)
            aem_raise(g_log_batt_evt, 1, (void *)0 /* DAT_0002be18 */);
        return;
    }

    for (i = 0; i < NUM_PACKS; i++) {
        uint8_t *meta = g_batt_meta + i * META_STRIDE;
        uint8_t *pack = g_batt_packs + i * PACK_STRIDE;

        if (META_ID(meta) != klass)
            continue;

        PACK_STATUS(pack) = frame[5];

        if (batt_pack_measure(pack) == 0) {
            if ((int)(g_log_batt_evt[0] << 0x1d) < 0) {
                struct { uint32_t a; uint32_t b; int c; void *word; uint32_t id; uint16_t code; } t;
                t.word = (void *)(uintptr_t)META_WORD(meta);
                t.code = 0x301;
                t.id   = klass;
                t.a = 0; t.b = 0; t.c = 0;
                aem_log_v(g_log_batt_evt, 0x2d00, &t, 0);
            }

            /* publish the "no data" AEM event for this class */
            aem_event_alloc(0, no_data_evt, 4);
            aem_event_send(NULL);

            /* query the pack's device firmware version over the OD */
            {
                uint8_t ver_req[8];
                int rc;
                ver_req[0] = (uint8_t)klass;
                ver_req[1] = 0;      /* filled by the version spec */
                ver_req[2] = 0xa3;
                rc = od_read_version(*(void **)((uint8_t *)g_batt_od_transport + 0x10),
                                     g_batt_ver_spec, ver_req);
                if (rc != 0 && (g_log_batt_evt[0] & 7) != 0)
                    aem_log_str(g_log_batt_evt, 1,
                                (void *)"unable to query version for device %d", klass);
            }
            k_work_submit(PACK_WORK(pack));
        }

        k_work_reschedule(pack, 0, 0xc000, 0);
        return;
    }
}

/* -------------------------------------------------------------------------
 * batt_charge_retry  --  0x2c0f8
 *
 * Charge-attempt watchdog.  On success (result == 0) reset the retry counter;
 * on failure trace (level 2), increment the counter, and stop charging once it
 * exceeds 3 consecutive failures.
 * ------------------------------------------------------------------------- */
void batt_charge_retry(int result)
{
    if (result == 0) {
        *g_batt_charge_retry_count = 0;
        return;
    }

    if ((g_log_batt_charge2[0] & 6) != 0)
        aem_raise(g_log_batt_charge2, 2, (void *)g_msg_batt_charge_fail);

    if ((uint8_t)(++(*g_batt_charge_retry_count)) > 3)
        batt_charge_stop();
}

/* -------------------------------------------------------------------------
 * batt_query_versions  --  0x2c064
 *
 * Query a charger/battery device's serial number and firmware version over the
 * OD (two reads, keyed by 'device_id'); log each failure.  The 3-byte request
 * carries the device id plus the spec's OD-address bytes.
 * ------------------------------------------------------------------------- */
void batt_query_versions(void *transport, uint8_t device_id)
{
    uint8_t req[3];
    int rc;

    /* serial number */
    req[0] = device_id;
    req[1] = (uint8_t)(*g_batt_serial_spec >> 8);
    req[2] = (uint8_t)(*g_batt_serial_spec >> 16);
    rc = od_read_version(transport, (void *)g_batt_serial_spec, req, 0, 0, 0, 0);
    if (rc != 0 && (g_log_batt_query[0] & 7) != 0)
        aem_log_str(g_log_batt_query, 1,
                    (void *)"unable to query serial number for device %d",
                    device_id, rc);

    /* firmware version */
    req[0] = device_id;
    req[1] = (uint8_t)(*g_batt_version_spec >> 8);
    req[2] = (uint8_t)(*g_batt_version_spec >> 16);
    rc = od_read_version(transport, (void *)g_batt_version_spec, req, 0, 0, 0, 0);
    if (rc != 0 && (g_log_batt_query[0] & 7) != 0)
        aem_log_str(g_log_batt_query, 1,
                    (void *)"unable to query version for device %d",
                    device_id, rc);
}
