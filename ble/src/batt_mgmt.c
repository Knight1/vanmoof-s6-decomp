/*
 * batt_mgmt.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Battery / pack manager.  Recovered from the dispatch-table gap in the
 * power-state / charger region of ble.bin (0x2b8d6-0x2ce30): these functions are
 * reached only through a Zephyr CAN RX callback and k_work handler pointers, so
 * the analyzer left them undefined (no direct CALL xref).
 *
 * The subsystem maintains a fixed table of NUM_PACKS = 9 battery/pack records
 * (0x58 bytes each: a per-pack mutex at +0x00, a k_work item at +0x38, and the
 * latest CAN payload at +0x50) plus a parallel "meta" table (0x0c bytes each:
 * the pack's CAN object-id at +0x00, a "publish over OD" flag at +0x08, and a
 * DTC code at +0x0a).  It:
 *
 *   - batt_packs_init          brings up the 9 packs + registers the CAN receiver
 *   - batt_can_od_rx           CAN RX callback: decode classes 0xA4/0xA7 into a pack
 *   - batt_publish_all_packs   periodic run: publish each enabled pack (or set DTC)
 *   - batt_charge_evt_dispatch start/stop the poll based on a charge event
 *   - batt_pack_event_publish  trace + submit one pack's work item
 *   - batt_pack_read_inputs    read a pack's online/status/health discrete inputs
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) are noted on each function.  Not byte-identical.
 *
 * Self-contained: depends only on <stdint.h> / <stddef.h> plus the vendor / RTOS
 * / SDK externs declared below.
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Vendor / RTOS / SDK externs (NOT reconstructed here).
 * Addresses are OEM image addresses (image base 0xC000).
 * ------------------------------------------------------------------------- */

/* Zephyr kernel objects. */
extern void  k_mutex_init(void *mutex, void *r1, int z);                       /* 0x7aef8 */
extern void  k_work_init(void *work, void *handler);                           /* 0x7a9e2 */
extern void  k_work_submit(void *work);                                        /* 0x636b4 */
extern void  k_work_cancel(void *work);                                        /* 0x7aad4 */
extern void  mem_zero(void *dst, int v, unsigned n);                           /* 0x7b2ba memset */

/* Zephyr CAN driver: bind the controller, add an RX filter, start it.          */
extern int   can_bind(void *client, void *cfg, int mode);                      /* 0x3c910 */
extern void  can_add_rx_filter(void *client, void *filter, int id, int z);     /* 0x3ca70 */
extern void  can_start(void *client);                                          /* 0x3ca34 */

/* Discrete input read (GPIO / expander channel), <0 on error.                   */
extern int   batt_input_read(void *dev, int chan, uint32_t *out);              /* 0x6cc90 */
/* Diagnostic sink (shell/log fprintf-style: ctx, "label: %d", value).           */
extern void  batt_diag_print(void *ctx, const char *label, uint32_t value);    /* 0x6f948 */

/* Read one pack's measurement: returns a 64-bit {lo = value, hi = validity};
 * a zero result means "no valid sample".                                        */
extern uint64_t batt_pack_measure(void *pack);                                 /* 0x7ae2a */

/* AEM logging + state-machine event post (as modelled in power_state.c).        */
extern void  aem_log_v(void *log_mod, uint32_t code, void *arg_block, int z);  /* 0x364f0 */
extern void  aem_sm_post_transition(void *sm, uint32_t r1, void *target, int z);/* 0x63790 */
extern void  vm_logf(void *log_mod, uint32_t level, const char *fmt, ...);     /* 0x6efea */

/* power_state.c siblings. */
extern void  dtc_set(uint32_t od_id);                                          /* 0x2ce30 */
extern void  ps_canbus_od_send(uint32_t od_id);                                /* 0x2cec4 */

/* -------------------------------------------------------------------------
 * Pack table layout.
 * ------------------------------------------------------------------------- */
#define NUM_PACKS          9
#define PACK_STRIDE        0x58
#define META_STRIDE        0x0c

/* Per-pack record (byte offsets kept OEM-faithful). */
#define PACK_LOCK(p)       ((uint8_t *)(p) + 0x00)   /* k_mutex                  */
#define PACK_WORK(p)       ((uint8_t *)(p) + 0x38)   /* k_work                   */
#define PACK_VAL(p)        (*(uint32_t *)((uint8_t *)(p) + 0x50)) /* CAN u32 word */
#define PACK_HALF(p)       (*(uint16_t *)((uint8_t *)(p) + 0x54)) /* CAN u16      */
#define PACK_BYTE(p)       (*(uint8_t  *)((uint8_t *)(p) + 0x56)) /* CAN u8       */

/* Per-pack meta record. */
#define META_ID(m)         ((m)[0x00])                  /* CAN object-id byte     */
#define META_PUBLISH(m)    ((m)[0x08])                  /* publish-over-OD flag   */
#define META_DTC(m)        (*(uint16_t *)((m) + 0x0a))  /* DTC code               */

/* CAN object classes handled by the RX decoder (signed byte compares in the OEM:
 * -0x5c == 0xa4, -0x59 == 0xa7).                                                 */
#define CAN_CLASS_A4       0xa4
#define CAN_CLASS_A7       0xa7

/* CAN RX filter id installed at bring-up. */
#define BATT_CAN_FILTER_ID 0x75

/* AEM reschedule/charge event targets. */
#define BATT_RUN_RESCHEDULE  0x10000
#define BATT_CHARGE_START    0x40000

/* -------------------------------------------------------------------------
 * Global state (resolved from OEM PC-relative literal pools).
 * ------------------------------------------------------------------------- */
extern uint8_t  g_batt_packs[NUM_PACKS * PACK_STRIDE]; /* DAT_0002badc / 0x2ba4c */
extern uint8_t  g_batt_meta[NUM_PACKS * META_STRIDE];  /* DAT_0002bae0 / 0x2ba48 */
extern void    *g_batt_can_client;                     /* DAT_0002baec           */
extern void    *g_batt_can_cfg;                        /* DAT_0002baf0           */
extern uint8_t  g_batt_initialized;                    /* DAT_0002bafc           */
extern void    *g_batt_run_sm;                         /* DAT_0002b99c           */
extern void    *g_batt_charge_sm;                      /* DAT_0002b9b8           */
extern void    *g_batt_input_dev;                      /* PTR_DAT_0002b940       */
extern void    *g_batt_pack_work_handler;              /* DAT_0002bae4           */
extern void    *g_batt_mutex_arg;                      /* DAT_0002bae8           */

/* Log-module objects (first byte holds the level bits). */
extern uint8_t  g_log_batt_init[];                     /* DAT_0002baf4           */
extern uint8_t  g_log_batt_rx[];                       /* DAT_0002ba40           */
extern uint8_t  g_log_batt_pub[];                      /* DAT_0002bbf0           */

/* Diagnostic labels (real pointers from the literal pool). */
#define LBL_ONLINE   "online: %d"                      /* PTR_s_online__d_0002b944 */
#define LBL_STATUS   "status: %d"                      /* PTR_s_status__d_0002b948 */
#define LBL_HEALTH   "health: %d"                      /* PTR_s_health__d_0002b94c */

/* -------------------------------------------------------------------------
 * batt_packs_init  --  0x2ba50
 *
 * Bring up the 9 pack records (per-pack mutex + work item, cleared CAN payload
 * and meta entry), then bind the CAN controller and install an RX filter for id
 * 0x75.  Sets the module "initialized" flag.
 * ------------------------------------------------------------------------- */
int32_t batt_packs_init(void)
{
    uint8_t *pack = g_batt_packs;
    uint8_t *meta = g_batt_meta;
    int i;
    int rc;

    for (i = 0; i < NUM_PACKS; i++) {
        k_mutex_init(PACK_LOCK(pack), g_batt_pack_work_handler, 0);
        k_work_init(PACK_WORK(pack), g_batt_mutex_arg);
        PACK_VAL(pack)      = 0;
        *(uint32_t *)(pack + 0x53) = 0;   /* OEM zeroes +0x53 too (overlaps +0x50) */
        mem_zero(meta, 0, 0x0d);
        pack += PACK_STRIDE;
        meta += META_STRIDE;
    }

    /* clear the CAN client header */
    ((uint8_t *)g_batt_can_client)[2] = 0;
    ((uint32_t *)g_batt_can_client)[0] = 0;
    ((uint32_t *)g_batt_can_client)[1] = 0;

    rc = can_bind(g_batt_can_client, g_batt_can_cfg, 1);
    if (rc == 0) {
        can_add_rx_filter(g_batt_can_client, g_batt_meta, BATT_CAN_FILTER_ID, 0);
        can_start(g_batt_can_client);
    } else if ((g_log_batt_init[0] & 7) != 0) {
        vm_logf(g_log_batt_init, 1, "Unable to register battery CAN rx (err=%d)", rc);
    }

    g_batt_initialized = 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * batt_can_od_rx  --  0x2b9bc
 *
 * CAN RX callback.  When the frame carries direct data (container word [2] == 0)
 * and its object class is 0xA4 or 0xA7, byte-swap the two payload halfwords
 * (network -> host) and clear the trailing status bytes, then find the pack whose
 * meta id matches the frame's object byte and copy the payload into it, signalling
 * that pack's work item.  Returns 0 on a stored frame, -EINVAL otherwise.
 * ------------------------------------------------------------------------- */
int32_t batt_can_od_rx(void *dev, void *arg, const uint8_t *frame, uint32_t *container)
{
    int i;

    (void)dev;
    (void)arg;

    if (container[2] != 0) {
        if ((g_log_batt_rx[0] & 7) != 0)
            vm_logf(g_log_batt_rx, 1, "unexpected battery CAN frame %d", frame[2]);
        return -22;   /* -EINVAL */
    }

    {
        uint8_t *payload = (uint8_t *)(uintptr_t)container[0];

        if (frame[0] == CAN_CLASS_A4 || frame[0] == CAN_CLASS_A7) {
            uint16_t *h3 = (uint16_t *)(payload + 3);
            uint16_t *h1 = (uint16_t *)(payload + 1);
            *h3 = (uint16_t)((*h3 << 8) | (*h3 >> 8));
            *h1 = (uint16_t)((*h1 << 8) | (*h1 >> 8));
            payload[5] = 0;
            payload[6] = 0;
        }

        for (i = 0; i < NUM_PACKS; i++) {
            uint8_t *meta = g_batt_meta + i * META_STRIDE;
            uint8_t *pack = g_batt_packs + i * PACK_STRIDE;

            if (META_ID(meta) == frame[0]) {
                PACK_VAL(pack)  = *(uint32_t *)payload;
                PACK_HALF(pack) = *(uint16_t *)(payload + 4);
                PACK_BYTE(pack) = payload[6];
                k_work_submit(PACK_WORK(pack));
                return 0;
            }
        }
    }
    return -22;
}

/* -------------------------------------------------------------------------
 * batt_publish_all_packs  --  0x2b950
 *
 * Periodic run action: for each of the 9 packs, take a measurement; for packs
 * flagged "publish", either publish the pack over the CAN OD (valid sample) or
 * set the pack's DTC (no sample).  Finally re-post the reschedule event.
 * ------------------------------------------------------------------------- */
void batt_publish_all_packs(void)
{
    uint8_t *pack = g_batt_packs;
    uint8_t *meta = g_batt_meta;
    int i;

    for (i = 0; i < NUM_PACKS; i++) {
        uint64_t sample = batt_pack_measure(pack);

        if (META_PUBLISH(meta) != 0) {
            if (sample == 0)
                dtc_set(META_DTC(meta));
            else
                ps_canbus_od_send(META_DTC(meta));
        }
        pack += PACK_STRIDE;
        meta += META_STRIDE;
    }

    aem_sm_post_transition(g_batt_run_sm, 0, (void *)BATT_RUN_RESCHEDULE, 0);
}

/* -------------------------------------------------------------------------
 * batt_charge_evt_dispatch  --  0x2b9a0
 *
 * Start or stop the pack poll based on a charge event: byte +5 == 1 arms the
 * poll (post the charge-start transition); otherwise cancel the poll work.
 * ------------------------------------------------------------------------- */
void batt_charge_evt_dispatch(const uint8_t *evt, uint32_t r1)
{
    if (evt[5] == 1)
        aem_sm_post_transition(g_batt_charge_sm, r1, (void *)BATT_CHARGE_START, 0);
    else
        k_work_cancel(g_batt_charge_sm);
}

/* -------------------------------------------------------------------------
 * batt_pack_event_publish  --  0x2bb98
 *
 * Trace one pack (id + tag) at level > 2, then submit that pack's work item.
 * 'pack' is the pack record base; the meta index is recovered from the pack's
 * offset in the table (OEM strength-reduced arithmetic reproduced verbatim).
 * ------------------------------------------------------------------------- */
void batt_pack_event_publish(uint8_t *pack)
{
    if ((g_log_batt_pub[0] & 7) > 2) {
        /* OEM: idx = ((pack - base) >> 3) * meta_stride -> meta byte offset */
        int meta_off = META_STRIDE * ((int)(pack - g_batt_packs) >> 3);
        struct {
            uint32_t tag0;
            uint32_t tag1;
            uint32_t value;
            uint32_t id;
            uint16_t code;
        } a;
        a.value = *(uint32_t *)(g_batt_meta + meta_off + 4);
        a.id    = g_batt_meta[meta_off];
        a.code  = 0x200;
        a.tag0  = 0;   /* DAT_0002bc04 */
        a.tag1  = 0;   /* DAT_0002bc00 */
        aem_log_v(g_log_batt_pub, 0x24c0, &a, 0);
    }
    k_work_submit(PACK_WORK(pack));
}

/* -------------------------------------------------------------------------
 * batt_pack_read_inputs  --  0x2b8e8
 *
 * Read a pack's three discrete inputs (online / status / health) from the input
 * device (channels 0, 2, 4) and hand each to the diagnostic sink.  Stops at the
 * first read error; returns 0 on success or the negative read error.
 * ------------------------------------------------------------------------- */
int32_t batt_pack_read_inputs(void *ctx)
{
    uint32_t val = 0;
    int rc;

    rc = batt_input_read(g_batt_input_dev, 0, &val);
    if (rc < 0)
        return rc;
    batt_diag_print(ctx, LBL_ONLINE, val & 0xff);

    rc = batt_input_read(g_batt_input_dev, 2, &val);
    if (rc < 0)
        return rc;
    batt_diag_print(ctx, LBL_STATUS, val & 0xff);

    rc = batt_input_read(g_batt_input_dev, 4, &val);
    if (rc < 0)
        return rc;
    batt_diag_print(ctx, LBL_HEALTH, val & 0xff);

    return 0;
}

/* -------------------------------------------------------------------------
 * Charge-control helpers.
 * ------------------------------------------------------------------------- */
extern void  charger_set_enable(int on);                                       /* 0x2ae88 */
extern void  aem_sm_post_event2(void *sm, uint32_t r1, uint32_t event, int z); /* 0x637f8 */
extern void  aem_raise(void *log_mod, uint32_t level, void *str);              /* 0x6efd8 */
extern void *g_batt_charge_sm2;                    /* DAT_0002a5bc               */
extern uint8_t  g_log_batt_charge[];               /* DAT_0002bc28               */
extern uint8_t *g_batt_charging_flag;              /* DAT_0002bc30               */
extern const char *g_msg_batt_charge_stop;         /* DAT_0002bc2c               */

/* -------------------------------------------------------------------------
 * batt_charge_disable  --  0x2a5a4
 *
 * Disable the charger hardware and post the charge state-machine event 0x2000.
 * ------------------------------------------------------------------------- */
void batt_charge_disable(void)
{
    charger_set_enable(0);
    aem_sm_post_event2(g_batt_charge_sm2, 0, 0x2000, 0);
}

/* -------------------------------------------------------------------------
 * batt_charge_stop  --  0x2bc08
 *
 * Stop charging: optionally trace, disable the charger (batt_charge_disable),
 * then clear the "charging in progress" flag.
 * ------------------------------------------------------------------------- */
void batt_charge_stop(void)
{
    if ((g_log_batt_charge[0] & 7) != 0)
        aem_raise(g_log_batt_charge, 1, (void *)g_msg_batt_charge_stop);
    batt_charge_disable();
    *g_batt_charging_flag = 0;
}
