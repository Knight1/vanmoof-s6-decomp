/*
 * motor_glue.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * VanMoof glue between the assist layer (assist.c) and the ST Motor Control
 * SDK (MCSDK). The FOC loop, the MC state machine (TSK_MediumFrequencyTaskM1,
 * merged by the analyser into the TIM1_BRK handler), ramps and the speed/
 * torque controller are vendor MCSDK code and are not reconstructed. This file
 * only drives the MCSDK handle the way the OEM does and maps its faults to
 * VanMoof DTCs.
 *
 *   motor_stop            @ 0x8005af8  STOP command (MCI_StopMotor logic, no
 *                                      return value; flagged as possibly MCSDK)
 *   motor_enable          @ 0x8005b20  start/stop per MCSDK state; auto-ack faults
 *   assist_timeout_cb     @ 0x8005b9c  command-watchdog expiry
 *   motor_set_torque_ref  @ 0x8005598  Q16.16 A -> MCSDK torque reference
 *   motor_set_current_ma  @ 0x8005608
 *   motor_set_speed_cap   @ 0x8004bdc  motor rpm -> MCSDK speed limits (Q30)
 *   motor_speed_q30       @ 0x8006520
 *   motor_speed           @ 0x8006540  motor rpm, >= 0
 *   mc_fault_to_dtc       @ 0x800a822  MCSDK fault bit -> DTC 0x8d14..0x8d1c
 *   dtc_raise             @ 0x8004a60
 *
 * MCSDK enum values used (MCI_State_t / MCI_Command_t): IDLE 0, START 4,
 * RUN 6, FAULT_NOW 10, FAULT_OVER 11, ICLWAIT 12; MCI_START 1, MCI_ACK_FAULTS 2,
 * MCI_STOP 4.
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- MCSDK handles (fields at the OEM offsets) ----------------------------- */
struct mci {                       /* *g_mci (0x20000a10) */
    uint8_t   pad0[4];
    uint8_t  *stc;                 /* +0x04 speed/torque controller */
    uint8_t   pad8[4];
    uint8_t  *spd;                 /* +0x0c speed sensor wrapper    */
    uint8_t   pad10[0x14];
    uint8_t   command;             /* +0x24 MCI_Command_t */
    uint8_t   state;               /* +0x25 MCI_State_t   */
    uint16_t  cur_faults;          /* +0x26 */
    uint16_t  past_faults;         /* +0x28 */
};
extern struct mci *g_mci;          /* 0x20000a10 */

struct vm_motor {                  /* g_motor (0x200009e4) */
    uint8_t  pad0[4];
    uint8_t *tc;                   /* +0x04 torque controller (ref @+0x70, inv @+0xa0) */
    uint8_t  pad8[0x18];
    uint8_t *params;               /* +0x20 (+0x09 mode byte, +0x34 float speed factor) */
};
extern struct vm_motor g_motor;    /* 0x200009e4 */
extern int32_t g_last_current_ma;  /* 0x200009e0 */

/* ---- assist state (assist.c) --------------------------------------------- */
struct assist_profile { int32_t base_ma, max_ma, boost_ma, gain_div; float speed_cap_rpm; int32_t power_lim; };
extern struct assist_profile g_profile;     /* 0x20000e14 */
extern volatile uint8_t g_drive_mode;       /* 0x200016e8 */
extern volatile uint8_t g_wheel_moving;     /* 0x200016e9 */
extern volatile uint8_t g_pedal_debounce;   /* 0x200016ea */
struct evt_timer;
extern struct evt_timer g_mode_timer;       /* 0x20000dcc */
extern struct evt_timer g_speed_timer;      /* 0x20000de4 */
extern struct evt_timer g_torque_timer;     /* 0x20000dfc */

/* ---- DTC state ------------------------------------------------------------ */
extern volatile uint8_t  g_dtc_bitmap[];    /* 0x20000700 (bits from byte +2) */
extern volatile uint32_t g_dtc_event[2];    /* 0x200006f8 = heartbeat clear mask (transient DTCs) */

#define MC_IDLE        0
#define MC_START       4
#define MC_RUN         6
#define MC_FAULT_NOW   10
#define MC_FAULT_OVER  11
#define MC_ICLWAIT     12
#define MCI_CMD_START  1
#define MCI_CMD_ACK    2
#define MCI_CMD_STOP   4

#define Q30            1073741824.0
#define Q24            16777216.0
#define Q16            65536.0

/* -------------------------------------------------------------------------
 * dtc_raise  --  0x8004a60
 *   Set DTC bit (code & 0xff) - 20 in the heartbeat payload (bitmap from byte 2);
 *   if notify (= transient), also set the same bit, (code & 0xff) - 4 of the
 *   64-bit word, in the heartbeat clear mask so it is reported once.
 *   The OEM sign-extends the 32-bit bit value into the high word
 *   (orr hi, b asr #31), kept here. The bitmap base 0x20000700 IS the 8-B
 *   heartbeat payload (mc_task.c).
 * ------------------------------------------------------------------------- */
void dtc_raise(uint16_t code, int notify)
{
    uint8_t  lo  = (uint8_t)code;
    uint32_t idx = (uint32_t)lo - 20u;

    g_dtc_bitmap[2 + ((idx >> 3) & 0x1f)] |= (uint8_t)(1u << (idx & 7));

    if (notify) {
        uint8_t  sh = (uint8_t)(lo - 4);
        uint32_t b  = (sh < 32) ? (1u << sh) : 0u;   /* ARM lsl by >= 32 gives 0 */
        g_dtc_event[0] |= b;
        g_dtc_event[1] |= (uint32_t)((int32_t)b >> 31);
    }
}

/* -------------------------------------------------------------------------
 * mc_fault_to_dtc  --  0x800a822
 *   Exact single-bit match only (a combined fault word raises nothing);
 *   0x10 / 0x20 have no DTC.
 * ------------------------------------------------------------------------- */
void mc_fault_to_dtc(uint16_t fault, int notify)
{
    switch (fault) {
    case 0x001: dtc_raise(0x8d14, notify); break;   /* FOC_RATE          */
    case 0x002: dtc_raise(0x8d15, notify); break;   /* OVER_VOLTAGE      */
    case 0x004: dtc_raise(0x8d16, notify); break;   /* UNDER_VOLTAGE     */
    case 0x008: dtc_raise(0x8d17, notify); break;   /* OVER_TEMPERATURE  */
    case 0x040: dtc_raise(0x8d18, notify); break;   /* OVER_CURRENT      */
    case 0x080: dtc_raise(0x8d19, notify); break;   /* SOFTWARE_ERROR    */
    case 0x100: dtc_raise(0x8d1a, notify); break;   /* SAMPLE_FAULT      */
    case 0x200: dtc_raise(0x8d1b, notify); break;   /* OVERCURRENT_SW    */
    case 0x400: dtc_raise(0x8d1c, notify); break;   /* DRIVER_PROTECTION */
    default: break;
    }
}

/* -------------------------------------------------------------------------
 * motor_stop  --  0x8005af8
 * ------------------------------------------------------------------------- */
void motor_stop(void)
{
    struct mci *m = g_mci;
    int can_stop = (m->state != MC_IDLE) && (m->state != MC_ICLWAIT);

    if (m->past_faults == 0 && m->cur_faults == 0 && can_stop)
        m->command = MCI_CMD_STOP;
}

/* -------------------------------------------------------------------------
 * motor_enable  --  0x8005b20
 *   Returns 1 only when the motor is in RUN and enable was requested.
 *   IDLE + enable (no faults) -> START; START/RUN without enable -> stop;
 *   FAULT_NOW reports the current fault; FAULT_OVER reports the past fault and,
 *   once no fault is active, clears it and acknowledges.
 * ------------------------------------------------------------------------- */
int motor_enable(int enable)
{
    struct mci *m = g_mci;

    switch (m->state) {
    case MC_IDLE:
        if (enable && m->past_faults == 0 && m->cur_faults == 0)
            m->command = MCI_CMD_START;
        break;
    case MC_START:
        if (!enable)
            motor_stop();
        break;
    case MC_RUN:
        if (enable)
            return enable;
        motor_stop();
        break;
    case MC_FAULT_NOW:
        if (m->cur_faults != 0)
            mc_fault_to_dtc(m->cur_faults, 0);
        break;
    case MC_FAULT_OVER:
        if (m->past_faults != 0) {
            mc_fault_to_dtc(m->past_faults, 1);
            if (m->state == MC_FAULT_OVER && m->cur_faults == 0) {
                m->past_faults = 0;
                m->command = MCI_CMD_ACK;
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * motor_set_torque_ref  --  0x8005598   (Q16.16 amps)
 *   Clamp to [0, 60 A], or [0, 72.05 A] when params->mode == 5; torque ref =
 *   I / 4.5 (Q30, factor 0x38e38e in Q24); inverse term 2^24 / ref_f.
 * ------------------------------------------------------------------------- */
void motor_set_torque_ref(int32_t q16_amps)
{
    uint8_t *tc;
    int32_t  q;
    float    inv;

    if (q16_amps < 0)
        q16_amps = 0;
    if (g_motor.params[9] == 5) {
        if (q16_amps >= 0x480d6a)
            q16_amps = 0x480d6a;
    } else {
        if (q16_amps >= 0x3c0000)
            q16_amps = 0x3c0000;
    }

    tc = g_motor.tc;
    q  = (int32_t)(((int64_t)q16_amps * 0x38e38e) >> 16);
    inv = 1.0f / ((float)q / (float)Q30);
    *(int32_t *)(tc + 0x70) = q;
    *(int32_t *)(tc + 0xa0) = (int32_t)((double)inv * Q24);
}

/* -------------------------------------------------------------------------
 * motor_set_current_ma  --  0x8005608
 * ------------------------------------------------------------------------- */
void motor_set_current_ma(int32_t ma)
{
    if (ma >= 60000)
        ma = 60000;
    if (g_last_current_ma == ma)
        return;
    g_last_current_ma = ma;
    motor_set_torque_ref((int32_t)((double)((float)ma / 1000.0f) * Q16));
}

/* -------------------------------------------------------------------------
 * motor_set_speed_cap  --  0x8004bdc   (motor rpm)
 * ------------------------------------------------------------------------- */
void motor_set_speed_cap(float rpm)
{
    uint8_t *stc = g_mci->stc;
    float    k   = *(const float *)(g_motor.params + 0x34);
    int32_t  q;

    q = (int32_t)((double)(((rpm * k) / 60.0f) / 1000.0f) * Q30);
    *(int32_t *)(stc + 0x58) = q;
    *(int32_t *)(stc + 0x5c) = q;
}

/* -------------------------------------------------------------------------
 * motor_speed_q30  --  0x8006520   (obj->[+4]->[+0x74], Q30, x 1000)
 * motor_speed      --  0x8006540   (rpm = that * 60 / k, floored at 0)
 * ------------------------------------------------------------------------- */
float motor_speed_q30(const uint8_t *obj)
{
    const uint8_t *s = *(uint8_t *const *)(obj + 4);
    int32_t q = *(const int32_t *)(s + 0x74);

    return ((float)q / (float)Q30) * 1000.0f;
}

float motor_speed(void)
{
    float v = (motor_speed_q30(g_mci->spd) * 60.0f) /
              *(const float *)(g_motor.params + 0x34);

    if (v < 0.0f)
        v = 0.0f;
    return v;
}

/* -------------------------------------------------------------------------
 * assist_timeout_cb  --  0x8005b9c
 *   An assist input stopped arriving: stop the motor, drop to base current and
 *   clear that input's state. Any other timer raises MESSAGE_TIMEOUT.
 * ------------------------------------------------------------------------- */
void assist_timeout_cb(struct evt_timer *t)
{
    motor_enable(0);
    motor_set_current_ma(g_profile.base_ma);

    if (t == &g_torque_timer)
        g_pedal_debounce = 0;
    else if (t == &g_speed_timer)
        g_wheel_moving = 0;
    else if (t == &g_mode_timer)
        g_drive_mode = 0;
    else
        dtc_raise(0x8d1d, 1);                      /* MESSAGE_TIMEOUT */
}
