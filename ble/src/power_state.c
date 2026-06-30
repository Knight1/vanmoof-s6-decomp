/*
 * power_state.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Power-state management subsystem.  This translation unit reconstructs the
 * VanMoof-authored power-state machine that lives in the nRF52840 "ble" central
 * controller: power-on / power-off consumer reference counting (an atomic
 * consumer-bitmap, like a refcount of who wants the bike powered), publication
 * of the current power state onto the Application-Event-Manager (AEM) bus and
 * over the proprietary CAN object-dictionary (OD), and the per-state
 * entry/run handlers of the power state machine (standby / charge / discharge /
 * update).
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses are noted on each function.  Not byte-identical.
 *
 * Self-contained: depends only on <stdint.h> / <stddef.h> plus the vendor /
 * RTOS / SDK externs declared below.
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Vendor / RTOS / SDK externs (NOT reconstructed here).
 * Addresses are OEM image addresses (image base 0xC000).
 * ------------------------------------------------------------------------- */

/* AEM (Application Event Manager) logging primitive.  Two flavours are used in
 * the OEM image (FUN_000364f0 / FUN_0006c930 / FUN_0006c93a / FUN_0006c8b6);
 * they are thin variadic log helpers that take (log_module*, level_arg,
 * arg_block*, ...).  We model them all through aem_log() / aem_log_arg().     */
extern void aem_log(void *log_mod, uint32_t level, void *arg_block);            /* 0x364f0 */
extern void aem_log_v(void *log_mod, uint32_t level, void *arg_block, int z);   /* 0x364f0 */

/* Per-state log shims emitted by the OEM (FUN_0006c930 / FUN_0006c93a) -- AEM
 * state-machine "entered/running" trace helpers.                              */
extern void aem_sm_log_a(void *log_mod, uint32_t code, void *arg_block);        /* 0x6c930 */
extern void aem_sm_log_b(void *log_mod, uint32_t code, void *arg_block);        /* 0x6c93a */

/* FUN_0006c8b6 -- transition the power supply hardware on(0)/off(1).           */
extern void pwr_hw_set_rail(int off);                                          /* 0x6c8b6 */

/* AEM state-machine plumbing.                                                  */
extern void aem_sm_post_event(void *sm, uint32_t r1, uint32_t event, int z);   /* 0x6c89c */
extern void aem_sm_set_handled(void *sm);                                      /* 0x6c8b0 */

/* AEM "raise level / assert" helper (FUN_0006efd8) used when the consumer
 * bitmap word is non-zero on a forced transition; (log_mod, level, str).       */
extern void aem_raise(void *log_mod, uint32_t level, void *str);              /* 0x6efd8 */

/* AEM event allocation + send (FUN_00077cfc / FUN_00055564).                  */
extern void *aem_event_alloc(int chan, int id, int sz);                       /* 0x77cfc */
extern void  aem_event_send(void);                                            /* 0x55564 */

/* Charge / discharge / update-mode side effects.                              */
extern void pwr_charge_setup(void);                                          /* 0x2a8b4 */
extern void pwr_update_setup(void);                                          /* 0x2a8d8 */
extern void ps_publish_state_evt2(int state);                               /* sibling */
extern void charger_publish_status_event(int arg);                          /* sibling */

/* CAN object-dictionary client (vtable-based OD client object).               */
extern void ps_od_clear_dtc(uint32_t od_id, void *valbuf);                   /* 0x6ccce */

/* Proprietary VanMoof logging gate / printf used by the OD path.              */
extern void vm_logf(void *log_mod, uint32_t level, const char *fmt, ...);    /* extern */

/* -------------------------------------------------------------------------
 * Global state objects (resolved from OEM PC-relative literal pools).
 *
 * The OEM addresses these through PC-relative DAT_* literals; we model the
 * referenced objects directly.  Each "log module" object's low byte carries
 * the AEM enable flags: the OEM tests (*log_mod << 0x1d) < 0  i.e. bit 2 (0x4)
 * of the first byte is the "info logging enabled" flag, and (*log_mod & 7) is
 * the level field tested for forced transitions.
 * ------------------------------------------------------------------------- */

/* Power-state machine context.  All four state handlers receive a pointer to
 * the AEM state-machine object; the VanMoof-owned fields we touch:            */
#define PS_SM_OFF_USERDATA   0x50   /* u32: state tag written on standby entry */
#define PS_SM_OFF_FLAG54     0x54   /* u32: cleared on standby entry           */
#define PS_SM_OFF_FLAG80     0x80   /* u16: cleared on standby entry           */

/* AEM event id used to publish the power-state byte (alloc chan 1, id 0x200). */
#define PS_PUBLISH_EVT_CHAN  1
#define PS_PUBLISH_EVT_ID    0x200
#define PS_PUBLISH_EVT_SZ    1
#define PS_PUBLISH_EVT_PAYLOAD_OFF 5   /* event payload byte offset            */

/* AEM log "format" codes used as the 2nd arg to aem_log():                    */
#define AEM_LOG_INFO   0x1900   /* "%s: <msg>" (module + tag, no extra args)   */
#define AEM_LOG_ARG1   0x2100   /* "%s: <msg> %d" (one trailing arg)           */
#define AEM_LOG_ARG2   0x3100   /* "%s: <msg> %s to %s" (two string args)      */

/* Power-state enumeration (byte value stored in g_power_state).               */
/* Observed: 3 == STANDBY/off; charge/discharge/update use evt2 codes 5/2/3.   */

/* The consumer bitmap: an array of u32 words, atomically toggled per consumer
 * id.  param>>5 selects the word, param&0x1f the bit.                          */
extern uint32_t g_pwr_consumer_bitmap[];   /* DAT_0002910c / 0x28e40 base       */

/* The "is powered" gate word tested before (de)asserting the rail.  The OEM
 * uses two distinct DAT addresses: ps_power_on_request gates on DAT_00029100,
 * ps_power_off_request gates on DAT_000291b0 -- keep them separate.            */
extern volatile uint32_t g_pwr_gate_on;    /* DAT_00029100                      */
extern volatile uint32_t g_pwr_gate_off;   /* DAT_000291b0                      */

/* The published power-state byte.                                             */
extern uint8_t g_power_state;              /* DAT_00028f8c / 0x00028ff0 / 0x29014 */

/* Log-module objects (first byte holds AEM enable flags).                      */
extern uint8_t g_log_power_on[];           /* DAT_00029104 etc.                 */
extern uint8_t g_log_power_off[];          /* DAT_000291b4 etc.                 */
extern uint8_t g_log_pwr_state[];          /* DAT_00028f88 / 0x00028ff4         */

/* Per-state-handler log-module objects.  The OEM uses a DISTINCT log module
 * per state function (nine different DAT_* addresses); they are NOT one shared
 * object, so the info/level gate in each state reads its own flag byte.        */
extern uint8_t g_log_sm_state_log_only[];  /* DAT_0002950c                      */
extern uint8_t g_log_sm_charge[];          /* DAT_0002963c                      */
extern uint8_t g_log_sm_charge_wakeup[];   /* DAT_00029720                      */
extern uint8_t g_log_sm_standby[];         /* DAT_00029940                      */
extern uint8_t g_log_sm_reschedule[];      /* DAT_0002988c                      */
extern uint8_t g_log_sm_standby_run[];     /* DAT_00029ae0                      */
extern uint8_t g_log_sm_discharge[];       /* DAT_00029ce4                      */
extern uint8_t g_log_sm_discharge_wakeup[];/* DAT_00029dcc                      */
extern uint8_t g_log_sm_update[];          /* DAT_00029f40                      */

/* Forward declarations of intra-unit functions. */
void ps_power_state_publish(void);
void ps_power_state_set(uint32_t state);
void ps_consumer_bit_clear(uint32_t consumer);
void ps_canbus_od_send(uint32_t od_id);

/* -------------------------------------------------------------------------
 * Atomic helpers.
 *
 * The OEM uses Cortex-M LDREX/STREX with DMB barriers (DataMemoryBarrier(0x1b))
 * to update the consumer bitmap.  We model that with the GCC builtin so the
 * behaviour (atomic set/clear of one bit) is preserved; the surrounding DMBs
 * map onto the builtin's full barrier.
 * ------------------------------------------------------------------------- */
static inline void consumer_bit_set(uint32_t consumer)
{
    __atomic_fetch_or(&g_pwr_consumer_bitmap[consumer >> 5],
                      (uint32_t)1u << (consumer & 0x1f), __ATOMIC_SEQ_CST);
}

static inline void consumer_bit_clr(uint32_t consumer)
{
    __atomic_fetch_and(&g_pwr_consumer_bitmap[consumer >> 5],
                      ~((uint32_t)1u << (consumer & 0x1f)), __ATOMIC_SEQ_CST);
}

/* AEM info-log gate: OEM tests (first_byte << 0x1d) < 0, i.e. bit 2 (0x4).     */
static inline int aem_info_enabled(const uint8_t *log_mod)
{
    return (log_mod[0] & 0x4) != 0;
}

/* -------------------------------------------------------------------------
 * ps_consumer_bit_clear  --  0x28e14
 *
 * Atomically clear this consumer's bit in the power-consumer bitmap.
 * ------------------------------------------------------------------------- */
void ps_consumer_bit_clear(uint32_t consumer)
{
    consumer_bit_clr(consumer);
}

/* -------------------------------------------------------------------------
 * ps_power_state_publish  --  0x28f38
 *
 * Publish the current power-state byte: optionally AEM-log it, then allocate an
 * AEM event (chan 1, id 0x200, 1 byte payload), stuff the state byte at payload
 * offset +5, and send it.
 * ------------------------------------------------------------------------- */
void ps_power_state_publish(void)
{
    uint8_t st = g_power_state;
    uint8_t *evt;

    if (aem_info_enabled(g_log_pwr_state)) {
        /* "%s: power state %d" */
        struct { uint32_t fmt; const char *tag; const char *mod; uint32_t val; } a;
        a.fmt = AEM_LOG_ARG1;
        a.tag = "%s: power state %d";   /* documented; real ptr from lit pool */
        a.mod = "power_state";
        a.val = st;
        aem_log_v(g_log_pwr_state, AEM_LOG_ARG1, &a, 0);
    }

    evt = (uint8_t *)aem_event_alloc(PS_PUBLISH_EVT_CHAN,
                                     PS_PUBLISH_EVT_ID, PS_PUBLISH_EVT_SZ);
    if (evt != NULL) {
        evt[PS_PUBLISH_EVT_PAYLOAD_OFF] = st;
    }
    aem_event_send();
}

/* -------------------------------------------------------------------------
 * ps_power_state_set  --  0x28f98
 *
 * Change the published power state to 'state'.  No-op if unchanged; otherwise
 * optionally AEM-logs the "Change state from %s to %s" transition (state names
 * indexed out of a name table), stores the new byte and republishes.
 * ------------------------------------------------------------------------- */
void ps_power_state_set(uint32_t state)
{
    /* name table indexed by state value */
    extern const char *const g_pwr_state_names[];   /* PTR_PTR_00028ff8 */

    if (g_power_state == (uint8_t)state)
        return;

    if (aem_info_enabled(g_log_pwr_state)) {
        /* "%s: Change state from %s to %s" */
        struct {
            uint32_t fmt;
            const char *tag;
            const char *mod;
            const char *from;
            const char *to;
        } a;
        a.fmt  = AEM_LOG_ARG2;
        a.tag  = "%s: Change state from %s to %s";  /* documented */
        a.mod  = "power_state_set";
        a.from = g_pwr_state_names[g_power_state];
        a.to   = g_pwr_state_names[state];
        aem_log_v(g_log_pwr_state, AEM_LOG_ARG2, &a, 0);
    }

    g_power_state = (uint8_t)state;
    ps_power_state_publish();
}

/* -------------------------------------------------------------------------
 * ps_power_state_get  --  0x2900c
 * ------------------------------------------------------------------------- */
uint8_t ps_power_state_get(void)
{
    return g_power_state;
}

/* -------------------------------------------------------------------------
 * ps_power_on_request  --  0x29048
 *
 * A consumer requests the bike to be powered on.  If the power gate is open
 * (g_pwr_gate_on == 0): set this consumer's bit, log "Request power on", assert
 * the rail (pwr_hw_set_rail(0)), log "power_on consumer %d", and publish.
 * Returns 0 on success.
 *
 * If the gate is closed (already in a blocking state such as Shipping mode):
 * for a "high enough" log level raise the "Request power on failed, Shipping
 * mode" message, and return -EINVAL (-22 / 0xffffffea).
 * ------------------------------------------------------------------------- */
int32_t ps_power_on_request(uint32_t consumer)
{
    if (g_pwr_gate_on != 0) {
        /* gate closed: request rejected */
        if ((g_log_power_on[0] & 7) > 2) {
            aem_raise(g_log_power_on, 3,
                      (void *)"Request power on failed, Shipping mode i...");
        }
        return -22;   /* -EINVAL */
    }

    consumer_bit_set(consumer);

    if (aem_info_enabled(g_log_power_on)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: Request power on";
        a.mod = "power_on";
        aem_log(g_log_power_on, AEM_LOG_INFO, &a);
    }

    pwr_hw_set_rail(0);   /* power on */

    if (aem_info_enabled(g_log_power_on)) {
        struct { uint32_t fmt; const char *tag; const char *mod; uint32_t c; } a;
        a.fmt = AEM_LOG_ARG1;
        a.tag = "%s: power_on consumer %d";
        a.mod = "power_on";
        a.c   = consumer;
        aem_log_v(g_log_power_on, AEM_LOG_ARG1, &a, 0);
    }

    ps_power_state_publish();
    return 0;
}

/* -------------------------------------------------------------------------
 * ps_power_off_request  --  0x29134
 *
 * A consumer releases its power-on request.  Clear the consumer bit, and if the
 * gate is open (g_pwr_gate_off == 0) log "Request power off" and deassert the
 * rail (pwr_hw_set_rail(1)).  Always log "power_off consumer %d" (when enabled)
 * and republish.  Returns 0.
 *
 * Note the OEM clears the consumer bit unconditionally up front (so the refcount
 * decrements even when something else is still holding the rail up), then only
 * actually drops the rail when the gate word is zero.
 * ------------------------------------------------------------------------- */
int32_t ps_power_off_request(uint32_t consumer)
{
    ps_consumer_bit_clear(consumer);

    if (g_pwr_gate_off == 0) {
        if (aem_info_enabled(g_log_power_off)) {
            struct { uint32_t fmt; const char *tag; const char *mod; } a;
            a.fmt = AEM_LOG_INFO;
            a.tag = "%s: Request power off";
            a.mod = "power_off";
            aem_log(g_log_power_off, AEM_LOG_INFO, &a);
        }
        pwr_hw_set_rail(1);   /* power off */
    }

    if (aem_info_enabled(g_log_power_off)) {
        struct { uint32_t fmt; const char *tag; const char *mod; uint32_t c; } a;
        a.fmt = AEM_LOG_ARG1;
        a.tag = "%s: power_off consumer %d";
        a.mod = "power_off";
        a.c   = consumer;
        aem_log_v(g_log_power_off, AEM_LOG_ARG1, &a, 0);
    }

    ps_power_state_publish();
    return 0;
}

/* -------------------------------------------------------------------------
 * ps_state_entry_log_only  --  0x294d4
 *
 * Generic AEM state-entry handler that just logs "<state> entered" then marks
 * the event handled.  Used as the entry action for states with no side effects.
 * ------------------------------------------------------------------------- */
void ps_state_entry_log_only(void *sm)
{
    if (aem_info_enabled(g_log_sm_state_log_only)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: entered";
        a.mod = "state";
        aem_sm_log_a(g_log_sm_state_log_only, AEM_LOG_INFO, &a);
    }
    aem_sm_set_handled(sm);
}

/* -------------------------------------------------------------------------
 * ps_state_run_reschedule  --  0x29868
 *
 * State "run" action: if the AEM log level field is non-zero, emit a level-1
 * trace, then re-post event 0x8000 to the state machine (reschedule / keep the
 * state's periodic work running).
 * ------------------------------------------------------------------------- */
void ps_state_run_reschedule(void *sm, uint32_t r1)
{
    if ((g_log_sm_reschedule[0] & 7) != 0) {
        aem_raise(g_log_sm_reschedule, 1, (void *)0 /* DAT_00029890 */);
        r1 = 0;   /* OEM picks up extraout_r1 here */
    }
    aem_sm_post_event(sm, r1, 0x8000, 0);
}

/* -------------------------------------------------------------------------
 * ps_standby_entry  --  0x29904
 *
 * Entry action for STANDBY.  If the AEM level is high enough, raise a level-3
 * trace; tear down charge setup (pwr_charge_setup), post the AEM "standby"
 * event (0x8000), clear the state-machine work fields (+0x54, +0x80), tag the
 * SM state field (+0x50) with 3, and publish power state 3 (STANDBY).
 * ------------------------------------------------------------------------- */
void ps_standby_entry(void *sm)
{
    uint8_t *p = (uint8_t *)sm;

    if ((g_log_sm_standby[0] & 7) > 2) {
        aem_raise(g_log_sm_standby, 3, (void *)0 /* DAT_00029944 */);
    }

    pwr_charge_setup();
    aem_sm_post_event(sm, 0, 0x8000, 0);

    *(uint32_t *)(p + PS_SM_OFF_FLAG54)   = 0;
    *(uint16_t *)(p + PS_SM_OFF_FLAG80)   = 0;
    *(uint32_t *)(p + PS_SM_OFF_USERDATA) = 3;

    ps_power_state_set(3);   /* OEM call has no visible arg; state == 3 */
}

/* -------------------------------------------------------------------------
 * ps_standby_run  --  0x29a9c
 *
 * STANDBY "run" action: optional level-3 trace, force power state to 3
 * (STANDBY), then post AEM event 0x50000 (longer reschedule interval than the
 * generic 0x8000 path).
 * ------------------------------------------------------------------------- */
void ps_standby_run(void *sm)
{
    if (aem_info_enabled(g_log_sm_standby_run)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: standby run";
        a.mod = "standby";
        aem_sm_log_b(g_log_sm_standby_run, AEM_LOG_INFO, &a);
    }
    ps_power_state_set(3);
    aem_sm_post_event(sm, 0, 0x50000, 0);
}

/* -------------------------------------------------------------------------
 * ps_charge_state_entry  --  0x295f0
 *
 * CHARGE entry: optional trace, clear DTC 0xA300 over the CAN OD, post AEM
 * 0x8000, then publish state-evt2 code 5 (charging).
 * ------------------------------------------------------------------------- */
void ps_charge_state_entry(void *sm)
{
    if (aem_info_enabled(g_log_sm_charge)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: charge entered";
        a.mod = "charge";
        aem_sm_log_a(g_log_sm_charge, AEM_LOG_INFO, &a);
    }
    ps_canbus_od_send(0xa300);
    aem_sm_post_event(sm, 0, 0x8000, 0);
    ps_publish_state_evt2(5);
}

/* -------------------------------------------------------------------------
 * ps_charge_wakeup_run  --  0x296dc
 *
 * CHARGE wakeup "run": optional trace, clear DTC 0xA301, re-post AEM 0x8000.
 * ------------------------------------------------------------------------- */
void ps_charge_wakeup_run(void *sm)
{
    if (aem_info_enabled(g_log_sm_charge_wakeup)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: charge wakeup run";
        a.mod = "charge";
        aem_sm_log_a(g_log_sm_charge_wakeup, AEM_LOG_INFO, &a);
    }
    ps_canbus_od_send(0xa301);
    aem_sm_post_event(sm, 0, 0x8000, 0);
}

/* -------------------------------------------------------------------------
 * ps_discharge_state_entry  --  0x29c98
 *
 * DISCHARGE entry: optional trace, clear DTC 0xA303, post AEM 0x8000, publish
 * state-evt2 code 2 (discharging).
 * ------------------------------------------------------------------------- */
void ps_discharge_state_entry(void *sm)
{
    if (aem_info_enabled(g_log_sm_discharge)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: discharge entered";
        a.mod = "discharge";
        aem_sm_log_b(g_log_sm_discharge, AEM_LOG_INFO, &a);
    }
    ps_canbus_od_send(0xa303);
    aem_sm_post_event(sm, 0, 0x8000, 0);
    ps_publish_state_evt2(2);
}

/* -------------------------------------------------------------------------
 * ps_discharge_wakeup_run  --  0x29d88
 *
 * DISCHARGE wakeup "run": optional trace, clear DTC 0xA304, re-post AEM 0x8000.
 * ------------------------------------------------------------------------- */
void ps_discharge_wakeup_run(void *sm)
{
    if (aem_info_enabled(g_log_sm_discharge_wakeup)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: discharge wakeup run";
        a.mod = "discharge";
        aem_sm_log_b(g_log_sm_discharge_wakeup, AEM_LOG_INFO, &a);
    }
    ps_canbus_od_send(0xa304);
    aem_sm_post_event(sm, 0, 0x8000, 0);
}

/* -------------------------------------------------------------------------
 * ps_update_state_entry  --  0x29ef4
 *
 * UPDATE (firmware update) entry: optional trace, run update setup
 * (pwr_update_setup), publish state-evt2 code 3, publish charger status
 * (charger_publish_status_event(0)), then post a (data-driven) AEM event id.
 * ------------------------------------------------------------------------- */
void ps_update_state_entry(void *sm)
{
    extern const uint32_t g_ps_update_event_id;   /* DAT_00029f4c */

    if (aem_info_enabled(g_log_sm_update)) {
        struct { uint32_t fmt; const char *tag; const char *mod; } a;
        a.fmt = AEM_LOG_INFO;
        a.tag = "%s: update entered";
        a.mod = "update";
        aem_sm_log_b(g_log_sm_update, AEM_LOG_INFO, &a);
    }
    pwr_update_setup();
    ps_publish_state_evt2(3);
    charger_publish_status_event(0);
    aem_sm_post_event(sm, 0, g_ps_update_event_id, 0);
}

/* -------------------------------------------------------------------------
 * ps_canbus_od_send  --  0x2cec4
 *
 * Clear a Diagnostic Trouble Code (DTC) over the proprietary CAN
 * object-dictionary.  Uses a vtable-based OD client object:
 *
 *   - vtable[+0x10]: "read OD entry" -> fills a contiguous output buffer:
 *     the u32 value followed by an 8-byte status block.  The status block's
 *     byte [2] is the "DTC currently set" flag.  In the OEM, the value local
 *     (local_20) and the status local (auStack_1c[8]) are adjacent on the
 *     stack and form one output region; only the value's address is passed,
 *     yet the read writes through into the trailing status bytes.
 *   - vtable[+0x08]: "write OD entry" -> if the DTC was present, clear it.
 *
 * On a successful clear: set the global "DTC store dirty" flag, log
 * "DTC_%04X CLEARED" (gated by vm log level), and notify via ps_od_clear_dtc().
 * ------------------------------------------------------------------------- */
void ps_canbus_od_send(uint32_t od_id)
{
    /* OD client object + its vtable.  Layout per OEM:
     *   client[0]      -> vtable pointer
     *   vtable[0x10]   -> read(client, fn, od_id, 0, &valbuf)
     *   vtable[0x08]   -> write(client, fn, od_id, 0, val, status, 0)        */
    extern void   *g_od_client;     /* DAT_0002cf24 */
    extern uint8_t g_dtc_dirty;     /* DAT_0002cf28 */
    extern uint8_t g_log_od[];      /* DAT_0002cf2c */

    void **client = (void **)g_od_client;
    void **vtab   = (void **)client[0];

    /* Single contiguous output region: the u32 value (== OEM local_20)
     * immediately followed by the 8-byte status block (== OEM auStack_1c).
     * The read fills both; only &out.val is handed to it, matching the OEM
     * stack layout where the status bytes trail the value.                    */
    struct { uint32_t val; uint8_t status[8]; } out = { 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
    int rc;

    int (*od_read)(void *, void *, uint32_t, int, uint32_t *) =
        (int (*)(void *, void *, uint32_t, int, uint32_t *))(uintptr_t)vtab[4];   /* +0x10 */

    rc = od_read(client, vtab[4], od_id, 0, &out.val);

    /* status byte [2] is the "DTC currently set" flag returned by the read.   */
    if (rc != 0 && out.status[2] != 0) {
        void (*od_write)(void *, void *, uint32_t, int, uint32_t, uint32_t, int) =
            (void (*)(void *, void *, uint32_t, int, uint32_t, uint32_t, int))(uintptr_t)vtab[2]; /* +0x08 */

        out.status[2] = 0;
        od_write(client, vtab[2], od_id, 0, out.val,
                 *(uint32_t *)out.status, 0);

        g_dtc_dirty = 1;

        if ((g_log_od[0] & 7) != 0) {
            vm_logf(g_log_od, 1, "DTC_%04X CLEARED", od_id);
        }

        ps_od_clear_dtc(od_id, &out.val);
    }
}
