/*
 * main_loop.c  --  VanMoof S6 "motor_sensor" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * Tail of main (0x33c4..0x34ae, never returns): wheel-scale selection from the
 * provisioning record, odometer restore, sensor start, then the superloop
 * (heartbeat + watchdog feed + temperature trigger every 1 s, OD request retry).
 * Same framework loop as frontlight/rearlight light_anim.c, without animation.
 *
 *   sensor_main_loop     @ 0x33c4
 *   sw_timer_start_1s    @ 0x1678  sw_timer_start(id, 1000), constant-propagated
 *                                  by the compiler (r1 is not an argument)
 *
 * The 8-B heartbeat payload (OD 01008808) is g_hb_payload: byte 0 = sequence,
 * byte 1 = reset-cause flags ORed in earlier in main, other bits = event flags
 * cleared after each send via g_hb_clear_mask.
 *
 * Addresses are link addresses (Ghidra image base 0xC00). Reconstructed from the
 * disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;

extern int  can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);  /* 0x48ac */
extern void od_send_if_active(const struct od_reg *reg, void *data, unsigned len); /* 0x16b8 */
extern void od_slot_finish(void *slot_obj, int rc);                     /* 0x164c */
extern int  report13_get(void *out);                                    /* 0x1524 */
extern int  odometer_load(uint32_t *out);                               /* 0x1bc4 */

struct wheel_state { uint32_t pulses; uint32_t scale; };
extern struct wheel_state g_wheel;                  /* 0x20000324 */

extern volatile uint32_t  g_tmr_remaining[16];      /* 0x2000032c */
extern volatile uint8_t   g_tmr_running[2];         /* 0x20000d29 */
extern void (* volatile g_tmr_cb[16])(int id);      /* 0x200002a8 */
extern volatile uint32_t  g_ms_now;                 /* 0x2000036c */
extern int                g_tmr_heartbeat;          /* 0x20000710 */
extern uint8_t            g_can_slots_mem[];        /* 0x20000370 (struct od_slot[10]) */
#define g_can_slots ((struct od_slot *)g_can_slots_mem)
extern uint8_t            g_hb_payload[8];          /* 0x20000030 */
extern volatile uint32_t  g_hb_clear_mask[2];       /* 0x20000028 */
extern const struct od_reg od_rec_heartbeat;        /* 0x51e0: 01008808 */

#define CTIMER0_TCR     (*(volatile uint32_t *)0x40008004u)
#define GPIO_B0_9       (*(volatile uint8_t  *)0x4008c009u)
#define WWDT_FEED       (*(volatile uint32_t *)0x4000c008u)
#define ADC0_SWTRIG     (*(volatile uint32_t *)0x400a0034u)

struct od_retry {                 /* = &slot.obj, stride 0x5c (see can_od.c) */
    struct od_reg *obj;
    uint16_t addr_lo;
    uint8_t  addrC;
    uint8_t  pad;
    uint32_t total;
    uint8_t  buf[0x40];
    uint8_t  retries;
    uint8_t  pad2[3];
    uint32_t deadline;
};
#define OD_REG_FLAG3(r)   (((uint8_t *)(r))[3])
#define OD_REG_TIMEOUT(r) (((uint32_t *)(r))[3])

/* -------------------------------------------------------------------------
 * sw_timer_start_1s  --  0x1678
 * ------------------------------------------------------------------------- */
void sw_timer_start_1s(int id)
{
    if (id > 15)
        return;
    g_tmr_remaining[id] = 1000;
    g_tmr_cb[id] = NULL;
    g_tmr_running[id / 8] |= (uint8_t)(1u << (id & 7));
}

/* -------------------------------------------------------------------------
 * sensor_main_loop  --  0x33c4
 * ------------------------------------------------------------------------- */
void sensor_main_loop(void)
{
    uint8_t rec[13];

    /* wheel scale: 191 for variant 'A'/'V' (provisioning record byte 0), else
     * 211 (also when the record is missing/invalid) */
    if (report13_get(rec) == 0 && (rec[0] == 'A' || rec[0] == 'V'))
        g_wheel.scale = 191;
    else
        g_wheel.scale = 211;

    odometer_load(&g_wheel.pulses);
    CTIMER0_TCR |= 1u;                       /* start the wheel-pulse timer */
    GPIO_B0_9 = 1;

    for (;;) {
        int id = g_tmr_heartbeat;
        int i;
        struct od_retry *r;

        /* ---- 1 s heartbeat: send, feed WWDT, trigger a temperature sample ---- */
        if (id <= 15 && g_tmr_remaining[id] == 0) {
            uint32_t pm, *w = (uint32_t *)g_hb_payload;

            od_send_if_active(&od_rec_heartbeat, g_hb_payload, 8);
            g_hb_payload[0]++;
            w[0] &= ~g_hb_clear_mask[0];
            w[1] &= ~g_hb_clear_mask[1];
            g_hb_clear_mask[0] = 0;
            g_hb_clear_mask[1] = 0;

            __asm volatile ("mrs %0, primask" : "=r"(pm));
            __asm volatile ("cpsid i");
            WWDT_FEED = 0xaa;
            WWDT_FEED = 0x55;
            __asm volatile ("msr primask, %0" :: "r"(pm));

            ADC0_SWTRIG = 1;                 /* -> temp_adc_isr -> OD 010003a1 */
            sw_timer_start_1s(g_tmr_heartbeat);
        }

        /* ---- OD request retry (10 slots) ---- */
        {
            uint32_t now = g_ms_now;
            r = (struct od_retry *)((uint8_t *)g_can_slots + 8);
            for (i = 0; i != 10; i++, r = (struct od_retry *)((uint8_t *)r + 0x5c)) {
                int rc;
                if (r->obj == NULL || r->deadline >= now)
                    continue;
                if (OD_REG_FLAG3(r->obj) == 0 && r->retries != 0) {
                    r->retries--;
                    r->deadline = OD_REG_TIMEOUT(r->obj) + now;
                    rc = can_frame_encode(g_can_slots, r->obj, (uint8_t *)&r->addr_lo,
                                          (int)(uintptr_t)r->buf, r->total);
                    if (rc == 0)
                        continue;
                } else {
                    rc = -116;
                }
                od_slot_finish(r, rc);
            }
        }
    }
}
