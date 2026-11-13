/*
 * assist.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * Pedal-assist command layer: the CAN/OD handlers of motor_control's own
 * objects (node byte 0x8d) and of its two subscriptions, which turn the assist
 * profile, the drive mode, the pedal-torque stream and the wheel-speed stream
 * into a motor current target for the FOC layer.
 *
 *   od_write_assist_profile @ 0x8004b30  OD 0100038d write (8 B)
 *   od_notify_068d          @ 0x8004b20  OD 0100068d (2 B): external current cap
 *   od_rx_wheel_speed       @ 0x8005790  OD 008d01a1 = motor_sensor 010001a1 (4 B)
 *   od_notify_018d          @ 0x8005d24  OD 0100018d (1 B): drive mode
 *   od_rx_pedal_torque      @ 0x8006580  OD 008d04a2 = power_control obj 04 (6 B)
 *   mavg_push               @ 0x800a88e  moving average, returns sum/len
 *   mavg_reset              @ 0x800af6e
 *
 * Drive modes (g_drive_mode): 0 off, 1 walk assist (fixed 14 A ramp, speed cap
 * 75 m/min ~ 4.5 km/h), 2 torque-proportional assist, 3 boost (fixed profile
 * current while pedalling). Modes 2/3 use the profile's speed cap.
 *
 * Units, from the constants: currents in mA (profile bytes x1000, 60 A hard clamp
 * in motor_set_current_ma); speed caps are motor rpm computed from a road speed
 * through the wheel circumference g_wheel_circ_m and the gear ratio 12.67.
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;
struct od_payload { uint8_t *data; uint32_t len; };

/* ---- motor / FOC layer and timers (externs) -------------------------------- */
extern int   motor_enable(int enable);                 /* 0x8005b20: !0 = running  */
extern void  motor_set_current_ma(int ma);             /* 0x8005608: clamp 60000   */
extern void  motor_set_speed_cap(float motor_rpm);     /* 0x8004bdc                */
extern float motor_speed(void);                        /* 0x8006540: >= 0          */
struct evt_timer;
/* (re)arm a one-shot event timer: disarm; if active, arm for ms*1000+100000 us */
extern void  evt_timer_restart(struct evt_timer *t, int active, unsigned ms); /* 0x80056f8 */

/* ---- moving-average filter ------------------------------------------------ */
struct mavg {
    uint16_t len;      /* +0 */
    uint16_t idx;      /* +2 */
    int32_t *buf;      /* +4 */
    int32_t  sum;      /* +8 */
};
extern void *vm_memset(void *dst, int c, size_t n);   /* 0x800b1f6 */

/* ---- state (RAM) --------------------------------------------------------- */
struct assist_profile {          /* 0x20000e14 */
    int32_t base_ma;             /* +0x00 d[0]*1000: floor / idle current      */
    int32_t max_ma;              /* +0x04 d[1]*1000: assist current ceiling    */
    int32_t boost_ma;            /* +0x08 d[2]*1000: mode-3 current            */
    int32_t gain_div;            /* +0x0c d[3]*100 : torque -> current divisor */
    float   speed_cap_rpm;       /* +0x10 from u16 d[4] (0.01 km/h)            */
    int32_t power_lim;           /* +0x14 u16 d[6]                             */
};
extern struct assist_profile g_profile;                /* 0x20000e14 */
extern float              g_power_k;                   /* 0x20000e2c */
extern float              g_wheel_circ_m;              /* 0x20000e30 (0 = unknown) */
extern volatile int32_t   g_ext_current_cap_ma;        /* 0x20000658 */
extern volatile uint8_t   g_mode_dirty;                /* 0x200016e6 */
extern volatile uint8_t   g_profile_valid;             /* 0x200016e7 */
extern volatile uint8_t   g_drive_mode;                /* 0x200016e8 */
extern volatile uint8_t   g_wheel_moving;              /* 0x200016e9 */
extern volatile uint8_t   g_pedal_debounce;            /* 0x200016ea */
extern struct mavg        g_torque_avg;                /* 0x20000db4 */
extern struct mavg        g_current_avg;               /* 0x20000dc0 */
extern struct evt_timer   g_mode_timer;                /* 0x20000dcc */
extern struct evt_timer   g_speed_timer;               /* 0x20000de4 */
extern struct evt_timer   g_torque_timer;              /* 0x20000dfc */

#define GEAR_RATIO        12.67f      /* 0x414ab852 */
#define WALK_SPEED_M_MIN  75.0f       /* 0x42960000 */
#define WALK_CURRENT_MA   14000
#define POWER_K           120.993f    /* 0x42f1fc80 */

/* -------------------------------------------------------------------------
 * mavg_push  --  0x800a88e
 * ------------------------------------------------------------------------- */
int32_t mavg_push(struct mavg *f, int32_t x)
{
    uint16_t len = f->len;
    uint16_t i;

    if (f->idx >= len)
        f->idx = 0;
    i = f->idx;
    f->sum -= f->buf[i];
    f->idx = (uint16_t)(i + 1);
    f->buf[i] = x;
    f->sum += x;
    return f->sum / (int32_t)len;
}

/* -------------------------------------------------------------------------
 * mavg_reset  --  0x800af6e
 * ------------------------------------------------------------------------- */
void mavg_reset(struct mavg *f)
{
    f->idx = 0;
    f->sum = 0;
    vm_memset(f->buf, 0, (size_t)f->len * 4u);
}

/* -------------------------------------------------------------------------
 * od_write_assist_profile  --  0x8004b30   (OD 0100038d write, 8 B)
 *   Ignored until the wheel circumference is known. Every field is range
 *   checked; an out-of-range frame is dropped (still rc 0):
 *     d[0..2] <= 60 (A), d[3] <= 100, u16 d[4] <= 2750 (0.01 km/h),
 *     u16 d[6] <= 2000.
 *   speed cap = ((d4 + 50) * 10 / 60) m/min / circumference * 12.67 = motor rpm
 *   (i.e. at most 27.5 + 0.5 km/h).
 * ------------------------------------------------------------------------- */
int od_write_assist_profile(struct od_slot *slots, struct od_reg *reg, void *addr,
                            struct od_payload *p)
{
    const uint8_t *d = p->data;
    uint32_t h4, h6;
    float    m_per_min;

    if (g_wheel_circ_m == 0.0f)
        return 0;

    if (d[1] > 60 || d[0] > 60 || d[2] > 60 || d[3] > 100)
        return 0;
    h4 = *(const uint16_t *)&d[4];
    if (h4 > 2750)
        return 0;
    h6 = *(const uint16_t *)&d[6];
    if (h6 > 2000)
        return 0;

    m_per_min = ((float)(int32_t)(h4 + 50) * 10.0f) / 60.0f;

    g_profile.base_ma   = d[0] * 1000;
    g_profile.max_ma    = d[1] * 1000;
    g_profile.boost_ma  = d[2] * 1000;
    g_profile.gain_div  = d[3] * 100;
    g_profile.power_lim = (int32_t)h6;
    g_profile.speed_cap_rpm = (m_per_min / g_wheel_circ_m) * GEAR_RATIO;

    g_profile_valid = 1;
    g_mode_dirty = 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * od_notify_068d  --  0x8004b20   (OD 0100068d, 2 B): external current cap (mA)
 * ------------------------------------------------------------------------- */
int od_notify_068d(struct od_slot *slots, struct od_reg *reg, void *addr,
                   struct od_payload *p)
{
    g_ext_current_cap_ma = *(const uint16_t *)p->data;
    return 0;
}

/* -------------------------------------------------------------------------
 * od_rx_wheel_speed  --  0x8005790   (motor_sensor 010001a1: {u16 speed, u16 window})
 *   Latches "wheel moving" and re-arms the speed timeout for window + 100 ms.
 * ------------------------------------------------------------------------- */
int od_rx_wheel_speed(struct od_slot *slots, struct od_reg *reg, void *addr,
                      struct od_payload *p)
{
    const uint16_t *d = (const uint16_t *)p->data;
    int moving = (d[0] != 0);

    g_wheel_moving = (uint8_t)moving;
    evt_timer_restart(&g_speed_timer, moving, d[1]);
    return 0;
}

/* -------------------------------------------------------------------------
 * od_notify_018d  --  0x8005d24   (OD 0100018d, 1 B): drive mode
 *   Only after a profile was received. A changed mode (or a fresh profile)
 *   re-applies the speed cap; leaving walk assist stops the motor and resets
 *   the current ramp. Re-arms the 200 ms mode watchdog while mode != 0.
 * ------------------------------------------------------------------------- */
int od_notify_018d(struct od_slot *slots, struct od_reg *reg, void *addr,
                   struct od_payload *p)
{
    uint8_t m, old;

    if (g_profile_valid == 0)
        return 0;

    m   = p->data[0];
    old = g_drive_mode;

    if (old != m || g_mode_dirty != 0) {
        if (old == 1 && m != 1) {                       /* leave walk assist */
            motor_enable(0);
            motor_set_current_ma(g_profile.base_ma);
            mavg_reset(&g_current_avg);
        }
        g_drive_mode = m;
        g_mode_dirty = 0;

        if (m == 1) {
            float cap = 0.0f;
            if (g_wheel_circ_m != 0.0f)
                cap = (WALK_SPEED_M_MIN / g_wheel_circ_m) * GEAR_RATIO;
            motor_set_speed_cap(cap);
        } else if ((uint8_t)(m - 2) <= 1) {
            motor_set_speed_cap(g_profile.speed_cap_rpm);
        }
    }

    m = g_drive_mode;
    if (m == 0) {
        motor_enable(0);
    } else if (m == 1) {
        if (motor_enable(1) != 0)
            motor_set_current_ma(mavg_push(&g_current_avg, WALK_CURRENT_MA));
    }
    evt_timer_restart(&g_mode_timer, m != 0, 200);
    return 0;
}

/* -------------------------------------------------------------------------
 * od_rx_pedal_torque  --  0x8006580   (power_control obj 04:
 *                                       {u16 pedalling, u16 torque, u16 timeout})
 *   Assist modes 2/3 only. Active when (max current > 0 or boost) and pedalling
 *   has been seen on 4 consecutive frames and the wheel is moving.
 *     mode 3 : target = boost current
 *     mode 2 : lim    = min(power_lim * (int)(120.993 / g_power_k) * 1000 / spd, max)
 *              (spd = motor speed clamped to [cap/8, cap])
 *              v      = avg_torque * lim / gain_div
 *              target = v > base ? min(v, max) : base
 *   target is capped by the external cap, ramped through the current average
 *   and floored at base. Inactive: motor off, averages reset, base current.
 * ------------------------------------------------------------------------- */
int od_rx_pedal_torque(struct od_slot *slots, struct od_reg *reg, void *addr,
                       struct od_payload *p)
{
    const uint16_t *d = (const uint16_t *)p->data;
    uint8_t mode = g_drive_mode;
    int active, out;

    if (mode <= 1)
        return 0;

    active = (g_profile.max_ma > 0) ? 1 : (mode == 3);

    if (d[0] == 0) {
        g_pedal_debounce = 0;
        active = 0;
    } else if (g_pedal_debounce <= 2) {
        g_pedal_debounce++;
        active = 0;
    } else if (g_wheel_moving == 0) {
        active = 0;
    }

    if (motor_enable(active) == 0) {
        mavg_reset(&g_torque_avg);
        mavg_reset(&g_current_avg);
        out = g_profile.base_ma;
    } else {
        uint16_t torque = d[1];
        float    cap    = g_profile.speed_cap_rpm;
        float    spd    = motor_speed();
        float    k      = g_power_k;
        int32_t  power  = g_profile.power_lim;
        int32_t  max    = g_profile.max_ma;
        int32_t  base, target, tq;

        if (spd > cap * 0.125f)
            spd = (spd >= cap) ? cap : spd;
        else
            spd = cap * 0.125f;

        tq   = mavg_push(&g_torque_avg, torque);
        base = g_profile.base_ma;

        if (mode == 3) {
            target = g_profile.boost_ma;
        } else {
            int32_t lim = (power * (int32_t)(POWER_K / k) * 1000) / (int32_t)spd;
            int32_t v;
            if (lim >= max)
                lim = max;
            v = ((int32_t)(uint16_t)tq * lim) / g_profile.gain_div;
            if (base < v)
                target = (v >= max) ? max : v;
            else
                target = base;
        }

        if (g_ext_current_cap_ma < target)
            target = g_ext_current_cap_ma;
        out = mavg_push(&g_current_avg, target);
        if (out < base)
            out = base;
    }

    motor_set_current_ma(out);
    evt_timer_restart(&g_torque_timer, active, d[2]);
    return 0;
}
