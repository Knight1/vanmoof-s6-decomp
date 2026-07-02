/*
 * elock_lock.c — VanMoof S6 elock ECU: solenoid lock/unlock state machine,
 *                solenoid drive + current/voltage monitoring, and the TMAG
 *                hall-effect sensor state machine.
 *
 * Target: TI MSPM0G (ARM Cortex-M0+, no FPU), VanMoof in-house takahe-fw
 *         (NoRTOS; common/mspm0 + common/node).  Image base 0x1800
 *         (MCUboot slot), vector table at 0x1900.
 *
 * Clean-room reconstruction from the stripped OEM image (elock.bin).  This
 * file reproduces the ACTUAL decompiled control flow, constants, thresholds,
 * DTC codes, state enums and CAN/OD publish calls — it is behaviour-oriented,
 * not byte-identical.  All non-VanMoof code (TI MSPM0 DriverLib register I/O,
 * the udivmod helper, the log/printf core, the CAN/OD transport, the DTC
 * table machinery) is referenced through 'extern' declarations carrying the
 * OEM address; none of it is reconstructed here.
 *
 * Anchors:
 *   solenoid_state_handler   FUN_000019c0  @ 0x19c0
 *   tmag_sensor_handler      FUN_000028bc  @ 0x28bc
 *   solenoid_request_unlock  FUN_00006c7c  @ 0x6c7c
 *   solenoid_timer_tick      FUN_00006cac  @ 0x6cac
 *
 * Build: cc -Wall -Wextra -Wpedantic -std=c11 -c elock_lock.c
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 *  Vendor / cross-module functions (declared, never reconstructed).
 *  Each carries its OEM address in a comment.
 * ------------------------------------------------------------------ */

/* Variadic log core: log_printf(level, fmt, ...) — OEM is a thin wrapper
 * FUN_000071c4 @ 0x71c4 that marshals varargs into FUN_00001d0c @ 0x1d0c.
 * Level 0 == "D>" debug here. */
extern void log_printf(uint32_t level, const char *fmt, ...); /* 0x71c4 */

/* Unsigned 32-bit divide (returns quotient; remainder in the high half of
 * the OEM's 64-bit return).  OEM FUN_00006628 @ 0x6628. Integer-only. */
extern uint32_t u32_div(uint32_t num, uint32_t den);          /* 0x6628 */

/* Set / clear a Diagnostic Trouble Code in the node DTC bitmap.
 * code is in [0x14 .. 0x4B] (i.e. DTC index 0..0x37). 'latch' non-zero also
 * records the code into the reported-DTC word. OEM FUN_00005d74 / 0x60a0. */
extern void dtc_set(uint8_t code, int latch);                 /* 0x5d74 */
extern void dtc_clear(uint8_t code);                          /* 0x60a0 */

/* CAN / Object-Dictionary publish: write 'len' bytes of 'data' to OD entry
 * 'od'. Only fires if the entry is in the published state (type byte == 2).
 * OEM FUN_000071a4 @ 0x71a4 -> FUN_00003194. */
extern int od_publish(uint32_t ctx, void *od, const void *data, uint32_t len); /* 0x71a4 */

/* Set a PWM/timer compare (duty) value for a solenoid drive channel.
 * OEM FUN_000074f8 @ 0x74f8: *(base + chan*4 + CCP_OFFSET) = duty. */
extern void pwm_set_duty(uint32_t base, uint32_t duty, int chan);   /* 0x74f8 */

/* Read the lid/charger presence status byte. OEM FUN_000075f4 @ 0x75f4. */
extern uint8_t read_lid_status(void);                         /* 0x75f4 */

/* Node state-machine dispatch: latch next state 'st' (with delay 'arg') and
 * invoke its handler via the dispatch table. OEM node_sm_dispatch @ 0x69dc. */
extern int node_sm_dispatch(int st, uint32_t arg);            /* 0x69dc */

/* Apply the lock/unlock decision derived from the hall threshold: drives the
 * lock-state OD publish and re-arms the TMAG SM via node_sm_dispatch. Returns a
 * status (0 == ok). OEM tmag_threshold_handler @ 0x43f0. */
extern int tmag_threshold_handler(int decision);              /* 0x43f0 */

/* Forward a captured TMAG threshold-event frame onto the OD (the OEM passes
 * the raw 2-byte sample). OEM FUN_00007558 @ 0x7558 -> FUN_00003194. */
extern int tmag_publish_event(uint32_t a, uint32_t b, void *od,
                              const void *data, uint32_t len); /* 0x7558/0x3194 */

/* Reset the TMAG sensor bus before a re-init attempt. OEM tmag_bus_reset
 * @ 0x7318. */
extern void tmag_bus_reset(void);                             /* 0x7318 */

/* ------------------------------------------------------------------ *
 *  Hardware register handles (MMIO addresses resolved from the OEM
 *  literal pool; accessed verbatim, no abstraction).
 * ------------------------------------------------------------------ */

/* GPIO/ADC enable register block touched while sampling the three solenoid
 * monitor channels (current, supply mV, MCU mV). OEM DAT_00001c90. */
static volatile uint32_t *const SOL_ADC_CTL_A = (volatile uint32_t *)0x40001028u;
static volatile uint32_t *const SOL_ADC_CTL_B = (volatile uint32_t *)0x40003028u;

/* Solenoid H-bridge GPIO / timer enable registers (case 1 / case 5). */
static volatile uint32_t *const SOL_GPIO_A   = (volatile uint32_t *)0x40003100u; /* DAT_00001cd4 */
static volatile uint32_t *const SOL_GPIO_B   = (volatile uint32_t *)0x40001100u; /* DAT_00001cdc */
static volatile uint32_t *const SOL_PINCM    = (volatile uint32_t *)0x400a1290u; /* DAT_00001ce0 */
static volatile uint32_t *const SOL_TIMER_EN = (volatile uint32_t *)0x40091804u; /* DAT_00001ce4 */
static volatile uint32_t *const SOL_PWM_BASE = (volatile uint32_t *)0x40090000u; /* DAT_00001cf0 */
static volatile uint32_t *const SOL_PWM_BASE2= (volatile uint32_t *)0x40869804u; /* DAT_00001cec */

/* ------------------------------------------------------------------ *
 *  Monitor scaling constants (OEM literal pool @ 0x1c88..).
 *  All integer mV / mA math (Cortex-M0+ has no FPU).
 * ------------------------------------------------------------------ */
#define ADC_VREF_MV          3300u   /* DAT_00001c94  reference, mV          */
#define ADC_FULL_SCALE       4095u   /* DAT_00001ca0  12-bit ADC full scale  */
#define CUR_SHUNT_DIV        1500u   /* DAT_00001ca4  current shunt divisor   */
#define VBUS_NUM             1177u   /* DAT_00001cb4  supply-rail divider num */
#define VBUS_DEN             0x10bu  /* 0x10b = 267    supply-rail divider den */
#define CUR_OK_MIN_MA         100u   /* current < 100 mA -> open-circuit DTC  */
#define VBUS_OK_MAX           9999u  /* DAT_00001cc8  supply mV upper bound    */

/* Unlock retry budget (case 3). */
#define UNLOCK_RETRY_MAX        8u   /* OEM: retry while count < 8            */

/* Solenoid drive timings (PWM duty / dwell, OEM literals). */
#define DRIVE_DUTY_FULL      1000u   /* enable_power / locking full drive     */
#define DRIVE_DUTY_RETRY      200u   /* retry pulse                           */
#define HOLD_DWELL_DEFAULT    200u   /* check window default                  */
#define HOLD_DWELL_RETRY      800u   /* retry dwell                           */
#define HOLD_DWELL_FINISH      10u   /* settle dwell                          */
#define UNLOCK_HOLD_MS       5000u   /* DAT_00001cf8                          */

/* DTC codes raised by the monitor (relative to the node DTC base 0x14). */
#define DTC_SOL_CUR_LOW       0xC115u  /* DAT_00001cc0  current too low       */
#define DTC_SOL_VBUS_LOW      (DTC_SOL_CUR_LOW + 1u) /* supply rail too low    */

/* ------------------------------------------------------------------ *
 *  Solenoid state machine.
 * ------------------------------------------------------------------ */

/* Solenoid FSM states (param to solenoid_state_handler). Names from the OEM
 * state-name table logged via "D>Solenoid state: %s". */
enum sol_state {
    SOL_CHECK_UNLOCK  = 0,  /* check_unlock                                   */
    SOL_ENABLE_POWER  = 1,  /* enable_power  — energise H-bridge, start drive */
    SOL_LOCKING       = 2,  /* locking       — drive to lock                  */
    SOL_RETRY_UNLOCK  = 3,  /* retry_unlock  — retry drive, count-limited     */
    SOL_CHECK_LOCKING = 4,  /* check_locking — verify lid, settle             */
    SOL_DISABLE_POWER = 5,  /* disable_power — de-energise H-bridge           */
};

/* ------------------------------------------------------------------ *
 *  RAM state (addresses from the OEM literal pool; modelled as the OEM
 *  globals they alias).
 * ------------------------------------------------------------------ */

/* Raw monitor ADC accumulators + their "valid sample" flags
 * (DAT_00001c98/.._c9c current, .._ca8/.._cb0 supply, .._cb8/.._cbc mcu). */
struct sol_monitor {
    uint32_t cur_count;   /* DAT_00001c98 sample count (0 => no sample)       */
    uint32_t cur_acc;     /* DAT_00001c9c accumulated raw                     */
    uint32_t vbus_count;  /* DAT_00001ca8                                     */
    uint32_t vbus_acc;    /* DAT_00001cb0                                     */
    uint32_t mcu_count;   /* DAT_00001cb8                                     */
    uint32_t mcu_acc;     /* DAT_00001cbc                                     */
};
extern struct sol_monitor g_sol_mon;        /* 0x20200aac region            */

extern uint8_t  g_sol_lid_locked;           /* DAT_00001cf4 (0x20200aeb)    */
extern uint8_t  g_sol_drive_state;          /* DAT_00001ce8 (0x20200aec)    */
extern uint32_t g_sol_retry_count;          /* DAT_00001d00 (0xc117)        */
extern void    *g_sol_state_names[];        /* DAT_00001c88 (name table)    */
extern void    *g_sol_curmon_od;            /* DAT_00001ccc / 0x1cd0 OD     */

/* The OD lock-state entry published on actuation. */
extern void *g_sol_lock_od;                 /* DAT_00001cfc                  */

/*
 * solenoid_monitor_sample — sample + scale the three solenoid monitor
 * channels (drive current, supply rail, MCU rail), publish them over the OD,
 * and raise DTCs on out-of-range readings.  Runs for every non-idle state
 * (param > 1).  OEM: inlined at the head of FUN_000019c0.
 *
 * Returns the packed 6-byte frame {current_mA(u16), vbus_mV(u16),
 * mcu_mV(s16)} via *out (little-endian, as published).
 */
static void solenoid_monitor_sample(uint16_t out[3])
{
    uint16_t cur_ma  = 0;
    uint16_t vbus_mv = 0;
    int16_t  mcu_mv  = 0;

    /* --- drive current channel --- */
    if (g_sol_mon.cur_count != 0) {
        uint32_t raw;
        *SOL_ADC_CTL_A &= 0xfffffff6u;                 /* freeze channel  */
        raw  = u32_div(g_sol_mon.cur_acc, g_sol_mon.cur_count); /* average */
        g_sol_mon.cur_count = 0;
        g_sol_mon.cur_acc   = 0;
        *SOL_ADC_CTL_A |= 9u;                          /* re-arm          */
        /* raw -> mV -> mA: (raw*Vref/FS) then /1500 with two *1000 steps */
        raw = u32_div(ADC_VREF_MV * raw, ADC_FULL_SCALE);
        raw = u32_div(raw * 1000u, CUR_SHUNT_DIV);
        cur_ma = (uint16_t)u32_div(raw * 1000u, CUR_SHUNT_DIV);
    }

    /* --- supply-rail channel --- */
    if (g_sol_mon.vbus_count != 0) {
        uint32_t raw;
        *SOL_ADC_CTL_B &= 0xfffffff6u;
        raw  = u32_div(g_sol_mon.vbus_acc, g_sol_mon.vbus_count);
        g_sol_mon.vbus_count = 0;
        g_sol_mon.vbus_acc   = 0;
        *SOL_ADC_CTL_B |= 9u;
        raw     = u32_div(ADC_VREF_MV * raw, ADC_FULL_SCALE);
        vbus_mv = (uint16_t)u32_div(VBUS_NUM * raw, VBUS_DEN);
    }

    /* --- MCU-rail channel --- */
    if (g_sol_mon.mcu_count != 0) {
        uint32_t raw;
        *SOL_ADC_CTL_A &= 0xfffffff6u;
        raw  = u32_div(g_sol_mon.mcu_acc, g_sol_mon.mcu_count);
        g_sol_mon.mcu_count = 0;
        g_sol_mon.mcu_acc   = 0;
        *SOL_ADC_CTL_A |= 9u;
        mcu_mv  = (int16_t)u32_div(ADC_VREF_MV * raw, ADC_FULL_SCALE);
        mcu_mv  = (int16_t)(mcu_mv * 3);               /* /3 divider rail  */
    }

    log_printf(0, "D>Solenoid current mA: %u, voltage mV: %d, mcu voltage mV: %d\n",
               cur_ma, vbus_mv, mcu_mv);

    if (cur_ma < CUR_OK_MIN_MA)
        dtc_set((uint8_t)DTC_SOL_CUR_LOW, 1);
    if (vbus_mv <= VBUS_OK_MAX)
        dtc_set((uint8_t)DTC_SOL_VBUS_LOW, 1);

    out[0] = cur_ma;
    out[1] = vbus_mv;
    out[2] = (uint16_t)mcu_mv;

    /* publish 6-byte monitor frame */
    od_publish((uint32_t)(uintptr_t)g_sol_curmon_od, &g_sol_lock_od, out, 6);
}

/*
 * solenoid_state_handler — the solenoid actuation FSM.
 * OEM FUN_000019c0 @ 0x19c0.  'state' selects the action; for every working
 * state (>1) it first samples the drive monitors above.
 */
void solenoid_state_handler(unsigned int state)
{
    uint16_t frame[3];

    log_printf(0, "D>Solenoid state: %s\n", g_sol_state_names[state]);

    if (state > 1u)
        solenoid_monitor_sample(frame);

    switch (state) {
    case SOL_ENABLE_POWER:  /* energise H-bridge, then fall into drive */
        *SOL_PINCM     = 0x8800000u;
        *SOL_TIMER_EN |= 1u;
        *SOL_GPIO_A   |= 1u;
        SOL_GPIO_A[1] |= 0x100u;
        *SOL_GPIO_B   |= 1u;
        SOL_GPIO_B[1] |= 0x100u;
        /* fallthrough */

    case SOL_LOCKING: {     /* drive PWM, arm settle timer, pick next state */
        pwm_set_duty((uint32_t)(uintptr_t)SOL_PWM_BASE, DRIVE_DUTY_FULL, 0);
        /* g_sol_drive_state[] timer arm: if not running, load default dwell */
        if ((*SOL_PWM_BASE2 & 1u) == 0u) {
            ((volatile uint32_t *)SOL_PWM_BASE2)[1] = HOLD_DWELL_DEFAULT;
            *SOL_PWM_BASE2 |= 1u;
        }
        if (g_sol_lid_locked == 0u) {
            g_sol_drive_state = 3;          /* -> retry_unlock                */
        } else {
            g_sol_drive_state = 4;          /* -> check_locking               */
            dtc_set((uint8_t)(uintptr_t)g_sol_lock_od, 0); /* latch=0          */
        }
        return;
    }

    case SOL_RETRY_UNLOCK: { /* count-limited retry of the unlock pulse */
        int lid = read_lid_status();
        uint32_t n = g_sol_retry_count++;
        if (lid != 2 && n < UNLOCK_RETRY_MAX) {
            log_printf(0, "D>Unlock retry: %u\n", n);
            g_sol_drive_state = 2;          /* stay driving (locking)         */
            pwm_set_duty((uint32_t)(uintptr_t)SOL_PWM_BASE, DRIVE_DUTY_RETRY, 0);
            if ((*SOL_PWM_BASE2 & 1u) != 0u)
                return;
            ((volatile uint32_t *)SOL_PWM_BASE2)[1] = HOLD_DWELL_RETRY;
            *SOL_PWM_BASE2 |= 1u;
            return;
        }
        /* budget exhausted / lid present -> stop drive, settle, disable */
        pwm_set_duty((uint32_t)(uintptr_t)SOL_PWM_BASE, 0, 0);
        if ((*SOL_PWM_BASE2 & 1u) == 0u) {
            ((volatile uint32_t *)SOL_PWM_BASE2)[1] = HOLD_DWELL_FINISH;
            *SOL_PWM_BASE2 |= 1u;
        }
        g_sol_drive_state = 5;              /* -> disable_power               */
        return;
    }

    case SOL_CHECK_LOCKING: /* verify lid latched; settle then disable */
        if (g_sol_lid_locked != 0u) {
            g_sol_lid_locked = 0u;
            pwm_set_duty((uint32_t)(uintptr_t)SOL_PWM_BASE, DRIVE_DUTY_RETRY, 0);
            if ((*SOL_PWM_BASE2 & 1u) == 0u) {
                ((volatile uint32_t *)SOL_PWM_BASE2)[1] = UNLOCK_HOLD_MS;
                *SOL_PWM_BASE2 |= 1u;
            }
            dtc_clear((uint8_t)(uintptr_t)g_sol_lock_od);
            return;
        }
        pwm_set_duty((uint32_t)(uintptr_t)SOL_PWM_BASE, 0, 0);
        if ((*SOL_PWM_BASE2 & 1u) == 0u) {
            ((volatile uint32_t *)SOL_PWM_BASE2)[1] = HOLD_DWELL_FINISH;
            *SOL_PWM_BASE2 |= 1u;
        }
        g_sol_drive_state = 5;              /* -> disable_power               */
        return;

    case SOL_DISABLE_POWER: /* de-energise the H-bridge, return to idle */
        *SOL_GPIO_A   &= 0xfffffffeu;
        SOL_GPIO_A[1] &= 0xfffffeffu;       /* DAT_00001cd8 mask              */
        *SOL_GPIO_B   &= 0xfffffffeu;
        SOL_GPIO_B[1] &= 0xfffffeffu;
        SOL_PINCM[4]   = 0x8800000u;
        *SOL_TIMER_EN &= 0xfffffffeu;
        g_sol_drive_state = 0;
        return;

    default:
        log_printf(0, "D>solenoid_state_handler state error\n");
        return;
    }
}

/*
 * solenoid_request_unlock — entry point that kicks the FSM into enable_power.
 * OEM FUN_00006c7c @ 0x6c7c.  Rejected (-0x10) if a drive is already busy.
 */
extern uint8_t g_sol_req_arg;        /* DAT_00006ca0 */
extern uint8_t g_sol_busy;           /* DAT_00006ca4 */
extern uint32_t g_sol_retry_reset;   /* DAT_00006ca8 */

uint32_t solenoid_request_unlock(uint8_t arg)
{
    g_sol_req_arg = arg;
    if (g_sol_busy == 0u) {
        g_sol_retry_reset = 0;
        solenoid_state_handler(SOL_ENABLE_POWER);
        return 0;
    }
    return 0xfffffff0u; /* -EBUSY */
}

/*
 * solenoid_timer_tick — settle-timer expiry callback: advances the FSM to the
 * latched next drive state.  OEM FUN_00006cac @ 0x6cac.
 */
extern uint8_t  g_sol_timer_flag;    /* DAT_00006ccc */
extern uint32_t *g_sol_timer_reg;    /* DAT_00006cd0 */
extern uint8_t  g_sol_next_state;    /* DAT_00006cd4 */

void solenoid_timer_tick(void)
{
    if ((g_sol_timer_flag & 0xffu) == 1u) {
        *g_sol_timer_reg &= 0xfffffffeu;
        solenoid_state_handler(g_sol_next_state);
    }
}

/* ------------------------------------------------------------------ *
 *  TMAG hall-effect sensor state machine.
 * ------------------------------------------------------------------ */

/* TMAG FSM states (param to tmag_sensor_handler). Names from the OEM
 * state-name table logged via "D>Sensor tmag callback: %s". */
enum tmag_state {
    TMAG_DEVICE_RESET         = 0, /* DEVICE_RESET — power-up / reset begin   */
    TMAG_STATUS_READ          = 1, /* STATUS_READ                             */
    TMAG_ID_CHECKED           = 2, /* ID_CHECKED                              */
    TMAG_Z_VAL_READ           = 3, /* Z_VAL_READ — magnitude sample           */
    TMAG_THRESHOLD_CONFIGURED = 4, /* THRESHOLD_CONFIGURED                    */
    TMAG_THRESHOLD_DETECTED   = 5, /* THRESHOLD_DETECTED                      */
    TMAG_DEVICE_AWAKE         = 6, /* DEVICE_AWAKE                            */
    TMAG_DEVICE_ERROR         = 7, /* DEVICE_ERROR                            */
};

/* Hall magnitude threshold separating "lid open" from "lid closed". */
#define TMAG_Z_LOCK_THRESHOLD   0x0e   /* z_val < 0x0e -> locked decision      */

/* TMAG retry / fault budget (OEM retries while pre-increment count < 2). */
#define TMAG_FAULT_RETRY_MAX       2u  /* re-init while count < 2              */

extern void    *g_tmag_state_names[]; /* DAT_00002a18 (name table @ 0x7ddc)   */
extern uint8_t  g_tmag_phase;         /* DAT_00002a24 — config/event phase     */
extern uint8_t  g_tmag_lock_decision; /* DAT_00002a28 — 1=unlock / 2=lock dec  */
extern uint32_t g_tmag_event_pending; /* DAT_00002a2c                          */
extern uint8_t  g_tmag_last_state;    /* DAT_00002a60                          */
extern uint8_t  g_tmag_fault_count;   /* DAT_00002a58                          */
extern void    *g_tmag_event_od;      /* DAT_00002a30 — event OD ctx           */
extern void    *g_tmag_event_od2;     /* DAT_00002a34 — event OD entry         */

/*
 * tmag_sensor_handler — the TMAG sensor configuration / sampling FSM.
 * OEM FUN_000028bc @ 0x28bc.  'state' selects the step; 'sample' points at the
 * sensor's reported data (z-magnitude / status / id) for the relevant steps.
 * On success it records the state; on error it raises a DTC and (up to 2x)
 * re-inits the sensor.
 */
void tmag_sensor_handler(int state, short *sample)
{
    int rc = 0;

    log_printf(0, "D>Sensor tmag callback: %s\n", g_tmag_state_names[state]);

    switch (state) {
    case TMAG_DEVICE_RESET:
        rc = node_sm_dispatch(2 /* ID_CHECKED */, 0);
        break;

    case TMAG_STATUS_READ: {
        const char *s = ((char)*sample != 0) ? "ERR" : "OK";
        log_printf(0, "D>Tmag status: %s \n", s);
        rc = node_sm_dispatch(3 /* Z_VAL_READ */, 0);
        break;
    }

    case TMAG_ID_CHECKED: {
        const char *s = ((char)*sample != 0) ? "OK" : "ERR";
        log_printf(0, "D>Tmag Id: %s\n", s);
        if ((char)*sample == 0) {            /* wrong / no ID -> error path   */
            rc = -0x13;                      /* -ENODEV-ish                   */
            break;
        }
        rc = node_sm_dispatch(4 /* THRESHOLD_CONFIGURED */, 0);
        break;
    }

    case TMAG_Z_VAL_READ: {                  /* magnitude sample -> decision  */
        short z;
        /* if a threshold event was armed, forward the captured frame */
        if (g_tmag_phase == 4 && g_tmag_event_pending != 0) {
            tmag_publish_event((uint32_t)(uintptr_t)g_tmag_event_od,
                               (uint32_t)(uintptr_t)g_tmag_event_od2,
                               &g_tmag_event_pending, sample, 2);
            g_tmag_event_pending = 0;
        }
        g_tmag_phase = 0;
        z = *sample;
        log_printf(0, "D>Tmag z_val: %d\n", (int)z);
        /* z below threshold -> "lid present" (unlock-decision 1), else lock 2 */
        g_tmag_lock_decision = (z < TMAG_Z_LOCK_THRESHOLD) ? 1u : 2u;
        rc = tmag_threshold_handler(g_tmag_lock_decision);
        break;
    }

    case TMAG_THRESHOLD_CONFIGURED:
        if (g_tmag_phase == 5)
            g_tmag_phase = 0;
        break;

    case TMAG_THRESHOLD_DETECTED:            /* hardware threshold IRQ fired  */
        rc = tmag_threshold_handler(g_tmag_lock_decision);
        break;

    case TMAG_DEVICE_AWAKE:
        if (g_tmag_phase == 5) {
            rc = tmag_threshold_handler(g_tmag_lock_decision);
        } else if (g_tmag_phase == 4) {
            rc = node_sm_dispatch(4 /* THRESHOLD_CONFIGURED */, 0);
        } else {
            rc = -0x16;                      /* -EINVAL                        */
        }
        break;

    case TMAG_DEVICE_ERROR:
        /* OEM logs the operation byte + raw error code from the sample tail. */
        log_printf(0, "D>Operation: %d, return: %d \n",
                   (int)(char)*sample, *(int *)(sample + 2));
        rc = *(int *)(sample + 2);           /* propagate the sensor errno    */
        break;

    default:
        log_printf(0, "D>Default case\n");
        rc = -0x16;                          /* -EINVAL                        */
        break;
    }

    if (rc == 0) {
        g_tmag_last_state = (uint8_t)state;
    } else {
        uint8_t n;
        log_printf(0, "D>sensor ret err: %d\n", rc);
        dtc_set((uint8_t)/* TMAG sensor fault */ 0xC114u, 1);
        n = g_tmag_fault_count++;
        if (n < TMAG_FAULT_RETRY_MAX) {
            log_printf(0, "D>Sensor init error\n", (int)(n + 1));
            tmag_bus_reset();
            node_sm_dispatch(1 /* STATUS_READ — restart probe */, 0);
        }
    }
}