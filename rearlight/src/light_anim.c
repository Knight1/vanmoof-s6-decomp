/*
 * light_anim.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * Soft-timer module + main superloop, single-channel counterpart of
 * frontlight/src/light_anim.c (see there for the state table). The rear light
 * has one channel (the 20-LED ring) and no PWM beam, so the loop is heartbeat,
 * OD retry and one animation state machine. Per-state code was compared case by
 * case against frontlight channel A: identical except the LED count (sweep-on
 * starts at LED 20, sweep-off ends at LED 19) and register allocation.
 *
 *   sw_timer_tick      @ 0x0eec  SysTick handler (vector 15)
 *   sw_timer_alloc     @ 0x1220
 *   sw_timer_expired   @ 0x1280
 *   sw_timer_running   @ 0x129c
 *   sw_timer_start     @ 0x150c
 *   sw_timer_stop      @ 0x15bc
 *   light_main_loop    @ 0x3160  tail of main, never returns
 *
 * The timer functions below are the frontlight reconstruction (their inline
 * address comments are frontlight addresses); the rearlight RAM layout differs
 * only in the externs' addresses noted here.
 *
 * Addresses are link addresses (Ghidra image base 0xC00).
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;

extern int  can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);  /* 0x3ba0 */
extern void od_slot_finish(void *slot_obj, int rc);                     /* 0x12c8 */
extern int  led_set_level(uint8_t led, uint8_t level);                  /* 0x1700 */
extern void led_set_all(uint8_t level);                                 /* 0x3d68 */
extern int  report13_get(void *out);                                    /* 0x13a4 */

typedef void (*sw_timer_cb_t)(int id);
extern volatile uint32_t     g_tmr_remaining[16];
extern sw_timer_cb_t volatile g_tmr_cb[16];
extern volatile uint8_t      g_tmr_used[2];
extern volatile uint8_t      g_tmr_running[2];
extern volatile uint32_t     g_ms_now;              /* 0x20000298 */

extern int                g_tmr_heartbeat;          /* 0x20000004 */
extern int                g_tmr_light;              /* 0x20000008 */
extern uint8_t            g_can_slots_mem[];        /* 0x2000029c (struct od_slot[10]) */
#define g_can_slots ((struct od_slot *)g_can_slots_mem)
extern uint8_t            g_hb_payload[8];          /* 0x20000020 */
extern volatile uint32_t  g_hb_clear_mask[2];       /* 0x20000018 */
extern volatile uint8_t   g_led_remap_en;           /* 0x20000cad */
extern volatile uint8_t   g_light_cmd_seen;         /* 0x20000cae */
extern volatile uint8_t   g_light_on;               /* 0x20000caf */
extern volatile uint8_t   g_light_state;            /* 0x20000cb0 */
extern volatile uint8_t   g_light_restart;          /* 0x20000cb1 */
extern int                g_anim_step;              /* 0x20000644 */
extern struct { int level; int dir; } g_anim_fade;  /* 0x2000063c */

extern struct od_reg od_rec_heartbeat;              /* 0x4368: 01008808 */
extern struct od_reg od_rec_light_notify;           /* 0x43c8: 01000ac3 */

static const uint8_t blink[10] = { 1, 2, 4, 8, 10, 8, 4, 2, 1, 0 };          /* 0x41f0 */

#define WWDT_FEED       (*(volatile uint32_t *)0x4000c008u)

struct od_retry {
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
 * soft timers
 * ------------------------------------------------------------------------- */
void sw_timer_tick(void)                                     /* 0x0f28 */
{
    int i;

    for (i = 0; i != 16; i++) {
        if (((g_tmr_running[i >> 3] >> (i & 7)) & 1u) == 0)
            continue;
        if (g_tmr_remaining[i] == 0)
            continue;
        if (--g_tmr_remaining[i] == 1 && g_tmr_cb[i] != NULL)   /* fires one tick early */
            g_tmr_cb[i](i);
    }
    g_ms_now++;
}

int sw_timer_alloc(void)                                     /* 0x137c */
{
    int byte, idx;
    uint8_t b, bit;

    if (g_tmr_used[0] != 0xff)
        byte = 0;
    else if (g_tmr_used[1] != 0xff)
        byte = 1;
    else
        return -12;

    b = g_tmr_used[byte];
    idx = 0;
    bit = 1;
    if ((b & 1u) != 0) {
        do {
            idx++;
            bit = (uint8_t)(bit << 1);
        } while (idx != 8 && (bit & b) != 0);
    }

    idx += byte * 8;
    g_tmr_remaining[idx] = 0;
    g_tmr_cb[idx] = NULL;
    g_tmr_used[byte] = (uint8_t)(b | bit);
    return idx;
}

int sw_timer_expired(int id)                                 /* 0x13dc */
{
    if (id > 15)
        return 0;
    return g_tmr_remaining[id] == 0;
}

int sw_timer_running(int id)                                 /* 0x13f8 */
{
    if (id > 15)
        return 0;
    return (g_tmr_running[id / 8] & (1u << (id & 7))) != 0;
}

void sw_timer_start(int id, uint32_t ms)                     /* 0x16f4 */
{
    if (id > 15)
        return;
    g_tmr_remaining[id] = ms;
    g_tmr_cb[id] = NULL;
    g_tmr_running[id / 8] |= (uint8_t)(1u << (id & 7));
}

void sw_timer_stop(int id)                                   /* 0x17a4 */
{
    if (id > 15)
        return;
    g_tmr_running[id / 8] &= (uint8_t)~(1u << (id & 7));
}

/* step when the timer expired or is not running (a stopped timer = run now) */
static int tmr_due(int id)
{
    return sw_timer_expired(id) || !sw_timer_running(id);
}

/* -------------------------------------------------------------------------
 * light_main_loop  --  0x3160 (superloop tail of main, never returns)
 *   Prologue: allocate the light timer; enable the LED-order remap when the
 *   provisioning record (01008800/01008700, 13 B) starts with 'A' or 'V'
 *   (the same variant code motor_sensor uses for its wheel scale).
 * ------------------------------------------------------------------------- */
void light_main_loop(void)
{
    uint8_t rec[13];

    g_tmr_light = sw_timer_alloc();
    if (report13_get(rec) == 0 && (rec[0] == 'A' || rec[0] == 'V'))
        g_led_remap_en = 1;

    for (;;) {
        int t, s, n, i;
        struct od_retry *r;

        /* ---- heartbeat (1 s) + watchdog feed ---- */
        t = g_tmr_heartbeat;
        if (!sw_timer_running(t) || sw_timer_expired(t)) {
            uint32_t pm, *w = (uint32_t *)g_hb_payload;

            can_frame_encode(g_can_slots, &od_rec_heartbeat, NULL,
                             (int)(uintptr_t)g_hb_payload, 8);
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

            sw_timer_start(g_tmr_heartbeat, 1000);
            if (g_light_cmd_seen == 0)
                can_frame_encode(g_can_slots, &od_rec_light_notify, NULL, 0, 0);
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

        /* ---- light: 20-LED ring ---- */
        if (g_light_restart != 0) {
            g_light_restart = 0;
            g_light_state = 0;
            led_set_all((uint8_t)((g_light_on << 3) & 0xf8));
            continue;
        }

        switch (g_light_state) {
        case 1:                                         /* sweep on */
            g_anim_step = 20;
            led_set_all(0);
            g_light_state = 2;
            sw_timer_stop(g_tmr_light);
            /* fall through */
        case 2:
            t = g_tmr_light;
            if (!tmr_due(t))
                break;
            s = g_anim_step;
            led_set_level((uint8_t)s, 8);
            g_anim_step = s - 1;
            if (s > 0) {
                sw_timer_start(t, 50);
            } else {
                g_light_on = 1;
                g_light_state = 0;
            }
            break;

        case 3:                                         /* sweep off */
            g_anim_step = 0;
            g_light_state = 4;
            sw_timer_stop(g_tmr_light);
            /* fall through */
        case 4:
            t = g_tmr_light;
            if (!tmr_due(t))
                break;
            s = g_anim_step;
            led_set_level((uint8_t)s, 0);
            g_anim_step = s + 1;
            if (s + 1 <= 19) {
                sw_timer_start(t, 50);
            } else {
                g_light_on = 0;
                g_light_state = 0;
            }
            break;

        case 5:                                         /* fade loop */
            g_light_state = 6;
            g_anim_step = 15;
            sw_timer_stop(g_tmr_light);
            /* fall through */
        case 6:
            t = g_tmr_light;
            if (!tmr_due(t))
                break;
            s = g_anim_step;
            led_set_all((uint8_t)s);
            g_anim_step = s - 1;
            if (s > 0) {
                sw_timer_start(t, 16);
            } else {
                g_anim_step = 15;
                sw_timer_start(t, 160);
            }
            break;

        case 7:                                         /* table blink */
            g_light_state = 8;
            g_anim_step = 0;
            sw_timer_stop(g_tmr_light);
            /* fall through */
        case 8:
            t = g_tmr_light;
            if (!tmr_due(t))
                break;
            s = g_anim_step;
            led_set_all((s & 1) ? blink[s / 2] : 0);
            g_anim_step = ((unsigned)(s + 1) >= 20) ? 0 : s + 1;
            sw_timer_start(t, 100);
            break;

        case 9:                                         /* breathe */
            g_light_state = 10;
            g_anim_step = 0;
            g_anim_fade.level = 15;
            g_anim_fade.dir = -1;
            sw_timer_stop(g_tmr_light);
            /* fall through */
        case 10:
            t = g_tmr_light;
            if (!tmr_due(t))
                break;
            sw_timer_start(t, ((unsigned)(g_anim_fade.level - 1) <= 13) ? 10 : 400);
            s = g_anim_fade.level;
            led_set_all((uint8_t)s);
            n = g_anim_fade.dir + s;
            if (n > 14) {
                g_anim_fade.level = 15;
                g_anim_fade.dir = -1;
            } else if (n > 0) {
                g_anim_fade.level = n;
            } else {
                g_anim_fade.level = 0;
                g_anim_fade.dir = 1;
            }
            break;

        case 11:                                        /* SOS */
            g_anim_step = 0;
            led_set_all(0);
            g_light_state = 12;
            sw_timer_stop(g_tmr_light);
            /* fall through */
        case 12:
            t = g_tmr_light;
            if (!tmr_due(t))
                break;
            led_set_all(8);
            s = g_anim_step;
            if ((s & 1) == 0) {
                sw_timer_start(t, 200);
                led_set_all(0);
            } else {
                led_set_all(8);
                sw_timer_start(t, ((unsigned)(s - 7) > 4) ? 200 : 400);
            }
            g_anim_step = s + 1;
            if (s > 16)
                g_light_state = 0;
            break;

        default:
            break;
        }
    }
}
