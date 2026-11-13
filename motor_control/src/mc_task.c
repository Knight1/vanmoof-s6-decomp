/*
 * mc_task.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * The 1 s housekeeping task and the wheel-variant decoder.
 *
 *   od_rsp_variant   @ 0x8004ac8  completion cb of the 008d8700 read request:
 *                                 provisioning byte 0 -> wheel circumference
 *   mc_periodic_1s   @ 0x8006398  heartbeat (+DTC bits), variant / profile
 *                                 requests, bus-voltage + temperature publish,
 *                                 IWDG refresh
 *
 * Wheel variant: 'A' or 'V' -> 1.916 m and power constant 1.3; anything else
 * -> 2.114 m and 1.4. These are the same two wheel sizes motor_sensor uses
 * (191 / 211 cm) for the same 'A'/'V' test of the same 13-B provisioning
 * record; motor_control fetches it from motor_sensor (node 0xa1).
 *
 * OD records (flash table 0x0800ccb0..0x0800cef0):
 *   0x0800ce00 01008808 heartbeat        0x0800ce18 008d8700 variant request
 *   0x0800ce78 0100058d {u16, u8} status 0x0800cea8 0100028d profile request
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;
struct od_payload { uint8_t *data; uint32_t len; };

typedef int (*od_done_cb_t)(struct od_slot *, struct od_reg *, void *, struct od_payload *);
extern void od_publish(const struct od_reg *rec, const void *data, unsigned len);  /* 0x80058e0 */
extern void od_request(const struct od_reg *rec, const uint8_t *addr, const void *data,
                       unsigned len, od_done_cb_t cb);                            /* 0x8006334 */

extern const struct od_reg od_rec_heartbeat;      /* 0x0800ce00 */
extern const struct od_reg od_rec_variant_req;    /* 0x0800ce18 */
extern const struct od_reg od_rec_status;         /* 0x0800ce78 */
extern const struct od_reg od_rec_profile_req;    /* 0x0800cea8 */

extern uint8_t            g_hb_payload[8];        /* 0x20000700: [0] seq, DTC bits from [2] */
extern volatile uint32_t  g_hb_clear_mask[2];     /* 0x200006f8: transient DTC bits */
extern float              g_wheel_circ_m;         /* 0x20000e30 */
extern float              g_power_k;              /* 0x20000e2c */
extern volatile uint8_t   g_profile_valid;        /* 0x200016e7 */
extern const uint8_t     *g_vbus_sensor;          /* 0x20000630: Q30 avg @+0x0c */
extern const uint8_t      g_temp_sensor[];        /* 0x20000640 (MCSDK NTC handle) */

#define IWDG_KR         (*(volatile uint32_t *)0x40003000u)
#define VBUS_SCALE      166488.0f                 /* 0x48231600 */

/* -------------------------------------------------------------------------
 * od_rsp_variant  --  0x8004ac8
 * ------------------------------------------------------------------------- */
int od_rsp_variant(struct od_slot *slots, struct od_reg *reg, void *addr,
                   struct od_payload *p)
{
    uint8_t v = p->data[0];
    float circ, k;

    if (v == 'A') {
        circ = 1.916f;
        k    = 1.3f;
    } else {
        circ = 2.114f;
        k    = 1.4f;
        if (v == 'V') {
            circ = 1.916f;
            k    = 1.3f;
        }
    }
    g_wheel_circ_m = circ;
    g_power_k = k;
    return 0;
}

/* -------------------------------------------------------------------------
 * mc_periodic_1s  --  0x8006398
 * ------------------------------------------------------------------------- */
void mc_periodic_1s(void)
{
    uint32_t *w = (uint32_t *)g_hb_payload;
    uint8_t buf[4];

    /* heartbeat, then drop the transient (one-shot) DTC bits */
    od_publish(&od_rec_heartbeat, g_hb_payload, 8);
    g_hb_payload[0]++;
    w[0] &= ~g_hb_clear_mask[0];
    w[1] &= ~g_hb_clear_mask[1];
    g_hb_clear_mask[0] = 0;
    g_hb_clear_mask[1] = 0;

    if (g_wheel_circ_m == 0.0f) {
        /* ask motor_sensor (node 0xa1) for its provisioning record */
        const uint8_t *rid = (const uint8_t *)&od_rec_variant_req;
        uint8_t a[3];
        a[0] = 0xa1;
        a[1] = rid[1];
        a[2] = rid[2];
        od_request(&od_rec_variant_req, a, NULL, 0, od_rsp_variant);
    } else if (g_profile_valid == 0) {
        uint8_t zero = 0;
        od_request(&od_rec_profile_req, NULL, &zero, 1, NULL);
    }

    /* status 0100058d: {u16 bus voltage, u8 temperature (deg C)} */
    {
        int32_t  q = *(const int32_t *)(g_vbus_sensor + 0x0c);
        uint16_t v = (uint16_t)(uint32_t)(((float)q / 1073741824.0f) * VBUS_SCALE);
        int32_t  t;

        /* inlined MCSDK NTC_GetAvTemp_C: real sensor -> linear around V0/T0 */
        if (g_temp_sensor[0] == 0) {
            int32_t d = (int32_t)*(const uint16_t *)(g_temp_sensor + 2)
                      - (int32_t)*(const uint32_t *)(g_temp_sensor + 0x10);
            t = (int32_t)*(const uint16_t *)(g_temp_sensor + 0x14)
              + (((int32_t)*(const int16_t *)(g_temp_sensor + 0x0e) * d) >> 16);
        } else {
            t = *(const uint16_t *)(g_temp_sensor + 6);
        }

        buf[0] = (uint8_t)v;
        buf[1] = (uint8_t)(v >> 8);
        buf[2] = (uint8_t)t;
        od_publish(&od_rec_status, buf, 3);
    }

    IWDG_KR = 0xaaaa;                             /* refresh the independent watchdog */
}

/* ---- drive telemetry ------------------------------------------------------ */
struct mci;
extern struct mci *g_mci;                       /* 0x20000a10 (MCSDK MCI handle) */
struct vm_motor { uint8_t pad0[4]; uint8_t *tc; uint8_t pad8[0x18]; uint8_t *params; };
extern struct vm_motor g_motor;                 /* 0x200009e4 (params+0x34 = pole pairs, float) */
extern const struct od_reg od_rec_telemetry;    /* 0x0800ce60: 0100048d */
extern float motor_speed(void);                 /* 0x8006540 (motor rpm) */
extern float motor_speed_q30(const uint8_t *obj);   /* 0x8006520 */
/* MCSDK current getter (vendor): out[0], out[1] = Q30 current components */
extern void  mcsdk_get_iqd(int32_t out[2], const void *foc);    /* 0x8002814 */

#define GEAR_RATIO   12.67f
#define I_FULLSCALE  288.0f                     /* 0x43900000 */
#define TWO_PI       6.2831f                    /* 0x40c90f28 */
#define Q30F         1073741824.0f

static int32_t q30mul(int32_t a, int32_t b)
{
    return (int32_t)(((int64_t)a * b) >> 30);
}

/* -------------------------------------------------------------------------
 * motor_torque_est  --  0x800649c   (Nm at the motor shaft)
 *   T = 1.5 * pole_pairs * (lambda_b * i0 - lambda_a * i1) * 288 A full scale
 *   lambda_a/b = MCI[0]+0x74/+0x78, i0/i1 from the MCSDK current getter.
 * ------------------------------------------------------------------------- */
float motor_torque_est(const uint8_t *mci)
{
    const uint8_t *h   = *(uint8_t *const *)mci;
    int32_t la = *(const int32_t *)(h + 0x74);
    int32_t lb = *(const int32_t *)(h + 0x78);
    const uint8_t *spd = *(uint8_t *const *)(mci + 0x0c);
    int32_t i[2];
    int32_t x;

    mcsdk_get_iqd(i, *(void *const *)(spd + 4));
    x = q30mul(lb, i[0]) - q30mul(la, i[1]);
    /* pole pairs via the handle's own params pointer (mci+0x20); the same
     * object as g_motor when g_mci points at 0x200009e4 */
    return (((float)x / Q30F) * 1.5f) * I_FULLSCALE *
           *(const float *)(*(uint8_t *const *)(mci + 0x20) + 0x34);
}

/* -------------------------------------------------------------------------
 * mc_publish_telemetry  --  0x80066d0   (OD 0100048d, 8 B)
 *   [0] s16 road speed, 0.01 km/h (0 until the wheel size is known)
 *   [1] u16 torque at the wheel x1000 (motor torque * 12.67)
 *   [2] u16 mechanical power (speed_q30/pole_pairs * torque * 2pi)
 *   [3] s16 current, mA, floored at 0 (MCI[8]+0x80 Q30 * 288 A)
 * ------------------------------------------------------------------------- */
void mc_publish_telemetry(void)
{
    const uint8_t *mci = (const uint8_t *)g_mci;
    float   rpm = motor_speed();
    int16_t d[4];
    float   t;

    if (g_wheel_circ_m != 0.0f)
        d[0] = (int16_t)(int32_t)((((rpm / GEAR_RATIO) * g_wheel_circ_m) * 60.0f) / 10.0f);
    else
        d[0] = 0;

    d[1] = (int16_t)(uint16_t)(uint32_t)((motor_torque_est(mci) * GEAR_RATIO) * 1000.0f);

    t = motor_torque_est(mci);
    d[2] = (int16_t)(uint16_t)(uint32_t)(((motor_speed_q30(*(uint8_t *const *)(mci + 0x0c)) /
                     *(const float *)(g_motor.params + 0x34)) * t) * TWO_PI);
    {
        const uint8_t *p = *(uint8_t *const *)(mci + 8);
        int32_t ma = (int32_t)((((float)*(const int32_t *)(p + 0x80) / Q30F) * I_FULLSCALE) * 1000.0f);
        if (ma < 0)
            ma = 0;
        d[3] = (int16_t)ma;
    }

    od_publish(&od_rec_telemetry, d, 8);
}
