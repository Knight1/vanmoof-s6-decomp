/*
 * power_state_smf.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Power-state SMF handlers recovered from the dispatch/state-table gap.
 *
 * These three functions live in the power-state region of ble.bin but were not
 * initially defined by the analyzer: they are reached only through the Zephyr
 * SMF state-descriptor table and a k_work handler pointer, so no direct CALL
 * xref exists.  They complement the state-machine core in power_state.c:
 *
 *   - ps_shipping_power_off_request (0x291c4)  battery-empty / shipping shutdown
 *   - ps_charger_present_reschedule (0x2b220)  charger plug/unplug -> re-arm the
 *                                              battery-supervisor work item
 *   - ps_battery_supervisor_run     (0x2b270)  periodic RSOC/VBAT supervisor:
 *                                              low-battery shutdown, recharge
 *                                              wake, and charge telemetry publish
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) are noted on each function.  Not byte-identical.
 *
 * Self-contained: depends only on <stdint.h> / <stddef.h> plus the vendor / RTOS
 * / SDK externs and the power_state.c siblings declared below.
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Vendor / RTOS / SDK externs (NOT reconstructed here).
 * Addresses are OEM image addresses (image base 0xC000).
 * ------------------------------------------------------------------------- */

/* AEM (Application Event Manager) logging primitives -- thin variadic helpers
 * that take (log_module*, code/level, arg_block*[, z]).  The OEM uses several
 * entry points that differ only in how many trailing args they marshal.        */
extern void aem_log_v(void *log_mod, uint32_t code, void *arg_block, int z);   /* 0x364f0 */
extern void aem_raise(void *log_mod, uint32_t level, void *str);               /* 0x6efd8 */
extern void aem_log_str(void *log_mod, uint32_t level, void *arg_block);       /* 0x6effe */
extern void aem_log_1(void *log_mod, uint32_t level, void *str);               /* 0x6cc2e */

/* AEM event allocation + send (chan, id, size).  A non-NULL return is a raw
 * event buffer; the payload begins at byte +5 as elsewhere in the ble image.    */
extern void *aem_event_alloc(int chan, int id, int sz);                        /* 0x77cfc */
extern void  aem_event_send(void);                                             /* 0x55564 */

/* Post a state-machine transition/event: (sm_ctx, r1, target_state, 0).         */
extern void  aem_sm_post_transition(void *sm, uint32_t r1, void *target, int z);/* 0x63790 */

/* Zephyr work-queue: re-arm a delayable work item after 'timeout' ticks.  The
 * OEM passes a full k_timeout_t; we keep the two observed tick constants.        */
extern void  k_work_reschedule(void *work, uint32_t timeout_ticks_lo,
                               uint32_t timeout_ticks_hi);                      /* 0x64594 */

/* Fuel-gauge / lipo gas-gauge accessors (I2C-backed device driver, vendor).     */
extern int   fuel_gauge_read_rsoc(void *dev, uint8_t *out_rsoc);               /* 0x78cd0 */
extern int   fuel_gauge_read_state(void *dev, void *out_state);               /* 0x78b80 */
extern void  lipo_sensor_lock(void *lipo);                                     /* 0x6337c */
extern void  lipo_sensor_fetch(void *lipo, int chan, void *sample);           /* 0x58ed0 */
extern int   lipo_sensor_wait(void *lipo, uint32_t r1, uint32_t chan_mask, int z); /* 0x63330 */
extern int   lipo_channel_get(void *chan_spec, int chan, void *out_val);      /* 0x58f28 */
extern int   lipo_channel_read(void *chan_spec, void *out_sample);            /* 0x58df8 */

/* DTC (Diagnostic Trouble Code) store: set a fault code.                         */
extern void  dtc_set(uint32_t od_id);                                          /* 0x2ce30 */

/* Battery-readiness metric: reads a lipo sensor channel (fetch 0x3c / get 0xd),
 * pulses GPIO 0x18a and computes a fixed-point level; the supervisor treats a
 * value < 2 as "not ready to power on".                                          */
extern int   ps_charge_readiness(void);                                        /* 0x2b870 */

/* Republish the 14-byte charge-telemetry struct as an AEM event (chan 0xe,
 * id 0x260) and send it.                                                         */
extern void  ps_charge_status_refresh(void);                                   /* 0x2af2c */

/* power_state.c siblings. */
extern void  ps_consumer_bit_clear(uint32_t consumer);                         /* 0x28e14 */
extern void  ps_power_state_publish(void);                                     /* 0x28f38 */
extern int32_t ps_power_on_request(uint32_t consumer);                         /* 0x29048 */
extern void  ps_canbus_od_send(uint32_t od_id);                                /* 0x2cec4 */
extern void  pwr_hw_set_rail(int off);                                         /* 0x6c8b6 */

/* -------------------------------------------------------------------------
 * Global state objects (resolved from OEM PC-relative literal pools).
 * ------------------------------------------------------------------------- */

/* Shipping/shutdown gate word.  Setting bit 0 blocks subsequent power-on
 * requests (ps_power_on_request rejects while the gate is non-zero).            */
extern volatile uint32_t g_shipping_gate;      /* DAT_00029238                  */

/* Log-module objects (first byte holds AEM enable flags: bit 2 = info, low 3
 * bits = level).                                                                */
extern uint8_t g_log_shipping[];               /* DAT_0002923c                  */
extern uint8_t g_log_batt[];                   /* DAT_0002b510                  */

/* Cached charger-present state driving the supervisor reschedule.
 *   [0] last-seen charger-present byte
 *   [1] charging flag (selects telemetry OD object / strings)
 *   [3] "power-on already requested" latch                                      */
extern uint8_t g_charger_state[];              /* DAT_0002b52c                  */

/* Devices / OD client handles addressed through the literal pool.               */
extern void *g_fuel_gauge;                     /* DAT_0002b50c                  */
extern void *g_lipo_sensor;                    /* DAT_0002b518                  */
extern void *g_lipo_chan;                      /* PTR_DAT_0002b520              */
extern void *g_batt_supervisor_work;           /* DAT_0002b26c                  */
extern void *g_batt_sm_ctx;                    /* DAT_0002b528                  */

/* The telemetry snapshot struct the supervisor fills and republishes.           */
extern uint16_t g_batt_telemetry[];            /* DAT_0002b550                  */

/* Documented OEM message strings (real pointers come from the literal pool).     */
#define MSG_RSOC_READ_FAIL   "Unable to get the lipo RSOC!"                     /* 0x82df9 */
#define MSG_VBAT_READ_FAIL   "Unable to get lipo VBAT"                          /* 0x82... */
#define MSG_SHUTDOWN         "RSOC at %d%% - below the shutdown threshold (%d%%)- Going to shipping mode in 5 seconds!" /* 0x82e2e */
#define MSG_RECHARGE         "RSOC is %d - below the recharge threshold (%d%%)" /* 0x82e87 */
#define MSG_FG_STATE_FAIL    "Unable to get state from the fuel gauge"          /* 0x82... */
#define MSG_LIPO_STATE_FAIL  "Unable to get state from the lipo"                /* 0x82... */

/* Battery thresholds (OEM literal constants). */
#define RSOC_SHUTDOWN_PCT     10        /* logged shutdown threshold             */
#define RSOC_RECHARGE_PCT     30        /* logged recharge threshold             */
#define RSOC_SHUTDOWN_MIN     0x0b      /* rsoc < 11%  -> shutdown               */
#define RSOC_RECHARGE_MAX     0x1e      /* rsoc <= 30% -> recharge candidate     */
#define VBAT_SHUTDOWN_MV      0x0d49    /* 3401 mV  -> shutdown                   */
#define VBAT_RECHARGE_MV      0x0df9    /* 3577 mV  -> recharge                   */
#define RSOC_UNKNOWN          0xff

/* OD object ids used for battery DTC / telemetry. */
#define OD_DTC_RSOC           0x9050
#define OD_DTC_VBAT           0x9052
#define OD_DTC_SHUTDOWN       0x9053
#define OD_TELE_NOT_CHARGING  0x28c0
#define OD_TELE_CHARGING      0x34c0

/* AEM low-battery shutdown event (chan 1, id 0x261, 1 byte). */
#define BATT_SHUTDOWN_EVT_CHAN  1
#define BATT_SHUTDOWN_EVT_ID    0x261
#define BATT_SHUTDOWN_EVT_SZ    1
#define BATT_SHUTDOWN_EVT_PAY   5

/* AEM info-log gate: OEM tests (first_byte << 0x1d) < 0, i.e. bit 2 (0x4).       */
static inline int aem_info_enabled(const uint8_t *log_mod)
{
    return (log_mod[0] & 0x4) != 0;
}
static inline int aem_level_set(const uint8_t *log_mod)
{
    return (log_mod[0] & 0x7) != 0;
}

/* -------------------------------------------------------------------------
 * ps_shipping_power_off_request  --  0x291c4
 *
 * Battery-empty / shipping-mode shutdown.  Latches the shipping gate bit
 * (blocking any further power-on request), releases every consumer's hold on the
 * rail (ids 0..4), logs "Power off request due to shipping mode", drops the
 * power rail and republishes the (now off) power state.  Returns 0.
 * ------------------------------------------------------------------------- */
int32_t ps_shipping_power_off_request(void)
{
    /* atomic set of the shipping-block bit */
    __atomic_fetch_or(&g_shipping_gate, 1u, __ATOMIC_SEQ_CST);

    ps_consumer_bit_clear(0);
    ps_consumer_bit_clear(1);
    ps_consumer_bit_clear(2);
    ps_consumer_bit_clear(3);
    ps_consumer_bit_clear(4);

    if (aem_info_enabled(g_log_shipping)) {
        /* level 3, "Power off request due to shipping mode" (0x820fc) */
        struct { uint32_t level; const char *msg; const char *aux; } a;
        a.level = 3;
        a.msg   = "Power off request due to shipping mode";
        a.aux   = (const char *)0;
        aem_log_v(g_log_shipping, 0x1900, &a, 0);
    }

    pwr_hw_set_rail(1);        /* power off */
    ps_power_state_publish();
    return 0;
}

/* -------------------------------------------------------------------------
 * ps_charger_present_reschedule  --  0x2b220
 *
 * Charger plug/unplug edge handler.  When the charger-present byte (event +5)
 * changes, re-arm the battery-supervisor delayable work: unplugged -> poll
 * slowly (0x2580000 ticks); plugged -> poll soon (0xf0000 ticks) and clear the
 * "power-on already requested" latch so the next recharge event can fire.
 * ------------------------------------------------------------------------- */
void ps_charger_present_reschedule(const uint8_t *evt)
{
    uint8_t present = evt[5];

    if (g_charger_state[0] == present)
        return;

    if (present == 0) {
        /* charger removed: relax the supervisor cadence */
        k_work_reschedule(g_batt_supervisor_work, 0x2580000, 0);
    } else {
        /* charger inserted: tighten cadence and re-arm recharge latch */
        k_work_reschedule(g_batt_supervisor_work, 0xf0000, 0);
        g_charger_state[3] = 0;
    }
    g_charger_state[0] = present;
}

/* -------------------------------------------------------------------------
 * ps_battery_supervisor_run  --  0x2b270
 *
 * Periodic battery supervisor (a k_work handler / SMF run action).  Reads the
 * fuel-gauge RSOC and the lipo pack VBAT, keeps their DTCs in sync, and drives
 * the low-battery policy:
 *
 *   - RSOC < 11% or VBAT < 3401 mV        -> low-battery shutdown: post the AEM
 *                                            shutdown event, set DTC 0x9053 and
 *                                            hand off to the shipping shutdown.
 *   - 11% <= RSOC <= 30% (or RSOC>30% but
 *     VBAT < 3577 mV)                     -> recharge wake: if the pack has been
 *                                            healthy for >= 2 samples, request
 *                                            power-on (consumer 1) and latch it.
 *
 * It then snapshots the charge telemetry (charging state, remaining capacity,
 * VBAT, current) and publishes it over the CAN OD (0x28c0 when idle, 0x34c0 when
 * charging), refreshing the charge status LED if a charger is present.
 * ------------------------------------------------------------------------- */
void ps_battery_supervisor_run(void)
{
    uint8_t  rsoc = RSOC_UNKNOWN;
    int      rc;
    int32_t  vbat_raw = 0;
    int16_t  vbat_mv;
    int      shutdown = 0;
    int      recharge = 0;

    /* ---- RSOC ---------------------------------------------------------- */
    rc = fuel_gauge_read_rsoc(g_fuel_gauge, &rsoc);
    if (rc == 0) {
        ps_canbus_od_send(OD_DTC_RSOC);          /* clear RSOC-read DTC */
    } else {
        if (aem_level_set(g_log_batt))
            aem_raise(g_log_batt, 1, (void *)MSG_RSOC_READ_FAIL);
        dtc_set(OD_DTC_RSOC);
    }

    /* ---- VBAT ---------------------------------------------------------- */
    lipo_sensor_lock(g_lipo_sensor);
    lipo_sensor_fetch(g_lipo_chan, 0x10, (void *)0 /* PTR_LAB_0002afc4 */);
    rc = lipo_sensor_wait(g_lipo_sensor, 0, 0xccd, 0);
    if (rc == 0)
        rc = lipo_channel_get(g_lipo_chan, 4, &vbat_raw);

    if (rc != 0) {
        /* VBAT unavailable */
        if (aem_level_set(g_log_batt))
            aem_raise(g_log_batt, 1, (void *)MSG_VBAT_READ_FAIL);
        dtc_set(OD_DTC_VBAT);
        vbat_mv = (int16_t)(vbat_raw >> 16);
        if (rsoc == RSOC_UNKNOWN)
            goto power_off;
        if (g_charger_state[0] == 0) {
            if (vbat_mv < VBAT_SHUTDOWN_MV)
                shutdown = 1;
        }
    } else {
        vbat_mv = (int16_t)(vbat_raw >> 16);
        ps_canbus_od_send(OD_DTC_VBAT);          /* clear VBAT DTC */

        if (rsoc == RSOC_UNKNOWN) {
            if (vbat_mv == -1)
                goto power_off;
            if (g_charger_state[0] == 0) {
                if (vbat_mv < VBAT_SHUTDOWN_MV)       shutdown = 1;
                else if (vbat_mv < VBAT_RECHARGE_MV)  recharge = 1;
            }
        } else if (g_charger_state[0] == 0) {
            if (rsoc < RSOC_SHUTDOWN_MIN || vbat_mv < VBAT_SHUTDOWN_MV)
                shutdown = 1;
            else if (rsoc > RSOC_RECHARGE_MAX) {
                if (vbat_mv < VBAT_RECHARGE_MV)       recharge = 1;
            } else {
                recharge = 1;
            }
        }
    }

    /* ---- low-battery policy ------------------------------------------- */
    if (recharge) {
        if (aem_level_set(g_log_batt)) {
            struct { uint32_t threshold; } a;
            a.threshold = RSOC_RECHARGE_PCT;
            aem_log_str(g_log_batt, 3, &a);          /* MSG_RECHARGE */
        }
        if (ps_charge_readiness() < 2) {
            if (aem_level_set(g_log_batt)) {
                struct { uint32_t count; } a;
                a.count = 2;
                aem_log_str(g_log_batt, 3, (void *)&a);
            }
        } else {
            ps_power_on_request(1);
            g_charger_state[3] = 1;                   /* latch: power-on requested */
        }
    }

    if (shutdown) {
        if (aem_level_set(g_log_batt)) {
            struct { uint32_t threshold; } a;
            a.threshold = RSOC_SHUTDOWN_PCT;
            aem_log_str(g_log_batt, 3, &a);          /* MSG_SHUTDOWN */
        }
        /* post the low-battery shutdown event, then trigger shipping shutdown */
        {
            uint8_t *evt = (uint8_t *)aem_event_alloc(BATT_SHUTDOWN_EVT_CHAN,
                                                      BATT_SHUTDOWN_EVT_ID,
                                                      BATT_SHUTDOWN_EVT_SZ);
            if (evt != NULL)
                evt[BATT_SHUTDOWN_EVT_PAY] = 1;
        }
        aem_event_send();
        dtc_set(OD_DTC_SHUTDOWN);
    power_off:
        aem_sm_post_transition(g_batt_sm_ctx, 0, (void *)0x28000 /* LAB_00028000 */, 0);
        return;
    }

    /* ---- charge telemetry snapshot + publish -------------------------- */
    {
        uint8_t  state[8];
        int32_t  sample = 0;
        int      charging = (g_charger_state[1] != 0);

        rc = fuel_gauge_read_state(g_fuel_gauge, &sample);
        if (rc != 0) {
            if (aem_level_set(g_log_batt))
                aem_raise(g_log_batt, 1, (void *)MSG_FG_STATE_FAIL);
            return;
        }
        rc = lipo_channel_read(g_lipo_chan, state);
        if (rc != 0) {
            if (aem_level_set(g_log_batt))
                aem_raise(g_log_batt, 1, (void *)MSG_LIPO_STATE_FAIL);
            return;
        }

        switch (g_charger_state[1]) {
        case 0:   /* Not Charging */
            if (aem_info_enabled(g_log_batt)) {
                struct { uint32_t n; const char *fmt; } a;
                a.n = 5;
                a.fmt = "Status: Not Charging (%d) (%dmA)...";  /* 0x2b54c */
                aem_log_v(g_log_batt, OD_TELE_NOT_CHARGING, &a, 0);
            }
            break;
        case 1:   /* Charging */
        case 2:
        case 3:
            if ((g_log_batt[0] & 0x7) > 2) {
                struct { uint32_t code; const char *fmt; } a;
                a.code = 0x200;
                a.fmt = "Status: Charging ...";                  /* 0x2b554/... */
                aem_log_v(g_log_batt, OD_TELE_CHARGING, &a, 0);
            }
            break;
        default:
            break;
        }

        /* store the telemetry snapshot for the OD reader */
        g_batt_telemetry[0] = (uint16_t)(sample >> 16);   /* VBAT mV */
        (void)charging;

        if (g_charger_state[0] != 0)
            ps_charge_status_refresh();
    }
}
