/*
 * light_anim.c  --  VanMoof S6 "frontlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * Soft-timer module (16 slots, SysTick driven) and the main superloop: CAN
 * heartbeat + watchdog feed, OD request retry, and the two light-animation state
 * machines that consume the states set by the OD write handlers (light_ctrl.c).
 *
 *   sw_timer_tick      @ 0x0f28  SysTick handler (vector 15)
 *   sw_timer_alloc     @ 0x137c  first free slot, -12 if all 16 used
 *   sw_timer_expired   @ 0x13dc  remaining == 0
 *   sw_timer_running   @ 0x13f8  running bit set
 *   sw_timer_start     @ 0x16f4  remaining = ms, clear callback, set running
 *   sw_timer_stop      @ 0x17a4  clear running
 *   light_main_loop    @ 0x33d8  tail of main (0x33d8..0x39e6), never returns
 *
 * Channel A = the 16-LED ring (LED driver levels 0..15), channel B = the PWM
 * beam (light_set_brightness_pct). Each has a u8 state: odd = "enter" (set up,
 * stop the timer so the first step runs at once), even = "run" (one step per
 * timer expiry). The OD handlers only ever store an "enter" state; state 0 is
 * idle. Corrects light_ctrl.c's naming: g_light_{a,b}_cmd are these states.
 *
 *   A 1/2   sweep on : LED 16..0 to level 8, 50 ms each, then A_on = 1
 *   A 3/4   sweep off: LED 0..15 to 0, 50 ms each, then A_on = 0
 *   A 5/6   fade loop: all LEDs 15..0 at 16 ms, 160 ms pause, repeat
 *   A 7/8   blink    : 20 steps of 100 ms, odd steps = blink_a[step/2]
 *   A 9/10  breathe  : triangle 0..15 at 10 ms, 400 ms dwell at the ends
 *   A 11/12 SOS      : 3 short, 3 long (400 ms), 3 short, then idle
 *   B 1/2   ramp on  : 0..69 % at 10 ms, then B_on = 1
 *   B 3/4   ramp off : current pct..0 at 10 ms, then B_on = 0
 *   B 5/6   strobe   : 70 % for 10 ms, off for 140 ms, repeat
 *   B 7/8   blink    : 20 steps of 100 ms, odd steps = blink_b[step/2] %
 *
 * Addresses are link addresses (Ghidra image base 0xC00). Behaviour-oriented
 * reconstruction from the disassembly (main is one large function; this file
 * covers its superloop only, the clock/peripheral init before it is vendor-shaped).
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;

/* ---- externs ------------------------------------------------------------- */
extern int  can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);  /* 0x3ffc */
extern void od_slot_finish(void *slot_obj, int rc);                     /* 0x1424 */
extern int  led_set_level(uint8_t led, uint8_t level);                  /* 0x41c8 */
extern void led_set_all(uint8_t level);                                 /* 0x41d2 */
extern int  light_set_brightness_pct(uint8_t pct);                      /* 0x1048 */

/* ---- soft-timer state (RAM) ---------------------------------------------- */
typedef void (*sw_timer_cb_t)(int id);
extern volatile uint32_t     g_tmr_remaining[16];   /* 0x200000fc */
extern sw_timer_cb_t volatile g_tmr_cb[16];         /* 0x200000bc */
extern volatile uint8_t      g_tmr_used[2];         /* 0x20000af8 (alloc bitmap)   */
extern volatile uint8_t      g_tmr_running[2];      /* 0x20000cfb (running bitmap) */
extern volatile uint32_t     g_ms_now;              /* 0x200002f0 */

/* ---- main-loop state (RAM) ------------------------------------------------ */
extern int                g_tmr_heartbeat;          /* 0x20000004 */
extern int                g_tmr_a;                  /* 0x20000008 */
extern int                g_tmr_b;                  /* 0x2000000c */
extern uint8_t            g_can_slots_mem[];        /* 0x200002f4 (struct od_slot[10]) */
#define g_can_slots ((struct od_slot *)g_can_slots_mem)
extern uint8_t            g_hb_payload[8];          /* 0x20000020 (byte0 = seq) */
extern volatile uint32_t  g_hb_clear_mask[2];       /* 0x20000018 */
extern volatile uint8_t   g_light_cmd_seen;         /* 0x20000d09 */
extern volatile uint8_t   g_light_a_on;             /* 0x20000d0a */
extern volatile uint8_t   g_light_a_state;          /* 0x20000d0b */
extern volatile uint8_t   g_light_a_restart;        /* 0x20000d0c */
extern volatile uint8_t   g_light_pct;              /* 0x20000d0d */
extern volatile uint8_t   g_light_b_on;             /* 0x20000d0e */
extern volatile uint8_t   g_light_b_state;          /* 0x20000d0f */
extern volatile uint8_t   g_light_b_restart;        /* 0x20000d10 */
extern int                g_anim_a_step;            /* 0x2000069c */
extern struct { int level; int dir; } g_anim_a_fade;/* 0x20000694 */
extern int                g_anim_b_step;            /* 0x200006a0 */

extern struct od_reg od_rec_heartbeat;              /* 0x4858: 01008808 */
extern struct od_reg od_rec_light_notify;           /* 0x46d8: 01000ac4 */

static const uint8_t blink_a[10] = { 1, 2, 4, 8, 10, 8, 4, 2, 1, 0 };        /* 0x4644 */
static const uint8_t blink_b[10] = { 10, 20, 30, 40, 70, 40, 30, 20, 10, 0 }; /* 0x464e */

#define GPIO_B0_21      (*(volatile uint8_t *)0x4008c015u)
#define WWDT_FEED       (*(volatile uint32_t *)0x4000c008u)

/* OD request slot as seen from the retry loop (pointer = &slot.obj, stride
 * 0x5c; field offsets match can_od.c struct od_slot +0x08..+0x58). */
struct od_retry {
    struct od_reg *obj;      /* +0x00 (slot+0x08) */
    uint16_t addr_lo;        /* +0x04 (slot+0x0c) */
    uint8_t  addrC;
    uint8_t  pad;
    uint32_t total;          /* +0x08 (slot+0x10) */
    uint8_t  buf[0x40];      /* +0x0c (slot+0x14) */
    uint8_t  retries;        /* +0x4c (slot+0x54) */
    uint8_t  pad2[3];
    uint32_t deadline;       /* +0x50 (slot+0x58) */
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
 * light_main_loop  --  0x33d8 (superloop tail of main, never returns)
 * ------------------------------------------------------------------------- */
void light_main_loop(void)
{
    GPIO_B0_21 = 0;
    g_tmr_a = sw_timer_alloc();

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
            if (g_light_cmd_seen == 0)          /* announce until first command */
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
                    rc = -116;                  /* timed out, no retries left */
                }
                od_slot_finish(r, rc);
            }
        }

        /* ---- channel A: LED ring ---- */
        if (g_light_a_restart != 0) {
            g_light_a_restart = 0;
            g_light_a_state = 0;
            led_set_all((uint8_t)((g_light_a_on << 3) & 0xf8));
        } else {
            switch (g_light_a_state) {
            case 1:                                         /* sweep on */
                g_anim_a_step = 16;
                led_set_all(0);
                g_light_a_state = 2;
                sw_timer_stop(g_tmr_a);
                /* fall through */
            case 2:
                t = g_tmr_a;
                if (!tmr_due(t))
                    break;
                s = g_anim_a_step;
                led_set_level((uint8_t)s, 8);
                g_anim_a_step = s - 1;
                if (s > 0) {
                    sw_timer_start(t, 50);
                } else {
                    g_light_a_on = 1;
                    g_light_a_state = 0;
                }
                break;

            case 3:                                         /* sweep off */
                g_anim_a_step = 0;
                g_light_a_state = 4;
                sw_timer_stop(g_tmr_a);
                /* fall through */
            case 4:
                t = g_tmr_a;
                if (!tmr_due(t))
                    break;
                s = g_anim_a_step;
                led_set_level((uint8_t)s, 0);
                g_anim_a_step = s + 1;
                if (s + 1 <= 15) {
                    sw_timer_start(t, 50);
                } else {
                    g_light_a_on = 0;
                    g_light_a_state = 0;
                }
                break;

            case 5:                                         /* fade loop */
                g_light_a_state = 6;
                g_anim_a_step = 15;
                sw_timer_stop(g_tmr_a);
                /* fall through */
            case 6:
                t = g_tmr_a;
                if (!tmr_due(t))
                    break;
                s = g_anim_a_step;
                led_set_all((uint8_t)s);
                g_anim_a_step = s - 1;
                if (s > 0) {
                    sw_timer_start(t, 16);
                } else {
                    g_anim_a_step = 15;
                    sw_timer_start(t, 160);
                }
                break;

            case 7:                                         /* table blink */
                g_light_a_state = 8;
                g_anim_a_step = 0;
                sw_timer_stop(g_tmr_a);
                /* fall through */
            case 8:
                t = g_tmr_a;
                if (!tmr_due(t))
                    break;
                s = g_anim_a_step;
                led_set_all((s & 1) ? blink_a[s / 2] : 0);
                g_anim_a_step = ((unsigned)(s + 1) >= 20) ? 0 : s + 1;
                sw_timer_start(t, 100);
                break;

            case 9:                                         /* breathe */
                g_light_a_state = 10;
                g_anim_a_step = 0;
                g_anim_a_fade.level = 15;
                g_anim_a_fade.dir = -1;
                sw_timer_stop(g_tmr_a);
                /* fall through */
            case 10:
                t = g_tmr_a;
                if (!tmr_due(t))
                    break;
                sw_timer_start(t, ((unsigned)(g_anim_a_fade.level - 1) <= 13) ? 10 : 400);
                s = g_anim_a_fade.level;
                led_set_all((uint8_t)s);
                n = g_anim_a_fade.dir + s;
                if (n > 14) {
                    g_anim_a_fade.level = 15;
                    g_anim_a_fade.dir = -1;
                } else if (n > 0) {
                    g_anim_a_fade.level = n;
                } else {
                    g_anim_a_fade.level = 0;
                    g_anim_a_fade.dir = 1;
                }
                break;

            case 11:                                        /* SOS */
                g_anim_a_step = 0;
                led_set_all(0);
                g_light_a_state = 12;
                sw_timer_stop(g_tmr_a);
                /* fall through */
            case 12:
                t = g_tmr_a;
                if (!tmr_due(t))
                    break;
                led_set_all(8);
                s = g_anim_a_step;
                if ((s & 1) == 0) {
                    sw_timer_start(t, 200);
                    led_set_all(0);
                } else {
                    led_set_all(8);
                    sw_timer_start(t, ((unsigned)(s - 7) > 4) ? 200 : 400);
                }
                g_anim_a_step = s + 1;
                if (s > 16)
                    g_light_a_state = 0;
                break;

            default:
                break;
            }
        }

        /* ---- channel B: PWM beam ---- */
        if (g_light_b_restart != 0) {
            g_light_b_restart = 0;
            g_light_b_state = 0;
            light_set_brightness_pct(g_light_b_on ? 70 : 0);
            continue;
        }

        switch (g_light_b_state) {
        case 1:                                             /* ramp on */
            g_anim_b_step = 0;
            light_set_brightness_pct(0);
            g_light_b_state = 2;
            sw_timer_stop(g_tmr_b);
            /* fall through */
        case 2:
            t = g_tmr_b;
            if (!tmr_due(t))
                break;
            s = g_anim_b_step;
            light_set_brightness_pct((uint8_t)s);
            g_anim_b_step = s + 1;
            if (s + 1 <= 69) {
                sw_timer_start(t, 10);
            } else {
                g_light_b_on = 1;
                g_light_b_state = 0;
            }
            break;

        case 3:                                             /* ramp off */
            g_anim_b_step = g_light_pct;
            g_light_b_state = 4;
            sw_timer_stop(g_tmr_b);
            /* fall through */
        case 4:
            t = g_tmr_b;
            if (!tmr_due(t))
                break;
            s = g_anim_b_step;
            light_set_brightness_pct((uint8_t)s);
            g_anim_b_step = s - 1;
            if (s > 0) {
                sw_timer_start(t, 10);
            } else {
                g_light_b_on = 0;
                g_light_b_state = 0;
            }
            break;

        case 5:                                             /* strobe */
            g_anim_b_step = 1;
            light_set_brightness_pct(70);
            g_light_b_state = 6;
            sw_timer_stop(g_tmr_b);
            /* fall through */
        case 6:
            t = g_tmr_b;
            if (!tmr_due(t))
                break;
            if (g_anim_b_step != 0) {
                light_set_brightness_pct(0);
                sw_timer_start(t, 140);
                g_anim_b_step = 0;
            } else {
                light_set_brightness_pct(70);
                sw_timer_start(t, 10);
                g_anim_b_step = 1;
            }
            break;

        case 7:                                             /* table blink */
            g_light_b_state = 8;
            g_anim_b_step = 0;
            sw_timer_stop(g_tmr_b);
            /* fall through */
        case 8:
            t = g_tmr_b;
            if (!tmr_due(t))
                break;
            s = g_anim_b_step;
            light_set_brightness_pct((s & 1) ? blink_b[s / 2] : 0);
            g_anim_b_step = ((unsigned)(s + 1) >= 20) ? 0 : s + 1;
            sw_timer_start(t, 100);
            break;

        default:
            break;
        }
    }
}
