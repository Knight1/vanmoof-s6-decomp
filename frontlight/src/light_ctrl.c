/*
 * light_ctrl.c  --  VanMoof S6 "frontlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * Front-light control app layer: the write handlers of the frontlight-specific OD
 * objects (node byte 0xc4, flash OD table g_od_regs @0x4678) plus the LED-driver
 * level encoder and the SCT0 PWM brightness setter they use.
 *
 *   light_set_mode            @ 0x0f80  OD 01000bc4 write (1 B): mode 0/1/2
 *   light_set_effect          @ 0x0ff4  OD 01000dc4 write (1 B): effect 0..4
 *   light_set_brightness_pct  @ 0x1048  SCT0 PWM duty = pct (0..70) of the period
 *   od_write_brightness       @ 0x10c4  OD 010002c4 write (1 B): brightness pct
 *   od_write_led_level        @ 0x18e8  OD 010003c4 write (2 B): {led, level}
 *   od_write_led_pattern      @ 0x18fc  OD 01000cc4 write (9 B): 16 nibbles + pct
 *   led_driver_set            @ 0x4188  LED level 0..15 -> two driver registers
 *   led_set_level             @ 0x41c8  wrapper, returns 0
 *   led_set_all               @ 0x41d2  all 16 LEDs to one level
 *
 * Handler ABI (can_od.c od_handler_t): (slots, reg, addr, pdata) where pdata
 * points at the received-payload pointer; these handlers only use *pdata.
 *
 * Addresses are link addresses (Ghidra image base 0xC00). Behaviour-oriented
 * reconstruction from the Ghidra decompile, cross-checked against disassembly.
 */

#include <stdint.h>

struct od_slot;
struct od_reg;

/* ---- LED SPI output (led.c) ---------------------------------------------- */
/* 2-byte LED-driver register write {reg<<1, value} (led.c). */
extern void led_spi_transfer(uint8_t reg, uint8_t value); /* 0x17cc */

/* ---- light state (RAM) --------------------------------------------------- */
extern volatile uint8_t g_light_cmd_seen;   /* 0x20000d09: set by every light write  */
extern volatile uint8_t g_light_mode;       /* 0x20000cfa: last mode (01000bc4)      */
extern volatile uint8_t g_light_a_on;       /* 0x20000d0a: channel A is on           */
extern volatile uint8_t g_light_a_state;      /* 0x20000d0b: channel A animation state */
extern volatile uint8_t g_light_a_restart;  /* 0x20000d0c                            */
extern volatile uint8_t g_light_pct;        /* 0x20000d0d: brightness pct            */
extern volatile uint8_t g_light_b_on;       /* 0x20000d0e: channel B is on           */
extern volatile uint8_t g_light_b_state;      /* 0x20000d0f: channel B animation state */
extern volatile uint8_t g_light_b_restart;  /* 0x20000d10                            */
extern volatile uint32_t g_sct_pwm_event;   /* 0x20000190: SCT PWM period event idx  */

/* ---- SCT0 (LPC55xx SCTimer/PWM, base 0x40085000) -------------------------- */
#define SCT0_BASE        0x40085000u
#define SCT0_REG(off)    (*(volatile uint32_t *)(SCT0_BASE + (off)))
#define SCT0_CTRL        SCT0_REG(0x004)
#define SCT0_MATCH(n)    SCT0_REG(0x100 + (n) * 4u)
#define SCT0_MATCHREL(n) SCT0_REG(0x200 + (n) * 4u)
#define SCT0_EV_CTRL(n)  SCT0_REG(0x304 + (n) * 8u)
#define SCT_CTRL_HALT_L  0x4u

/* Values written to g_light_{a,b}_state are "enter" states of the animation
 * state machines in light_anim.c (main superloop): 1 sweep/ramp on, 3 off,
 * 5 fade loop / strobe, 7 table blink, 9 breathe (A), 11 SOS (A). Channel A =
 * LED ring, channel B = PWM beam. */

/* -------------------------------------------------------------------------
 * light_set_mode  --  0x0f80   (OD 01000bc4, 1 B)
 *   mode 0: both off   (A on -> A cmd 3; B on -> B cmd 3)
 *   mode 1: A only     (A off -> A cmd 1; B on -> B cmd 3)
 *   mode 2: A and B    (A off -> A cmd 1; B off -> B cmd 1)
 *   other : stored, no channel change.
 * ------------------------------------------------------------------------- */
int light_set_mode(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t mode = **pdata;

    g_light_cmd_seen = 1;
    g_light_mode = mode;

    if (mode == 1) {
        if (g_light_a_on == 0)
            g_light_a_state = 1;
    } else if (mode == 2) {
        if (g_light_a_on == 0)
            g_light_a_state = 1;
        if (g_light_b_on == 0)
            g_light_b_state = 1;
        return 0;
    } else if (mode == 0) {
        if (g_light_a_on != 0)
            g_light_a_state = 3;
    } else {
        return 0;
    }

    if (g_light_b_on != 0)
        g_light_b_state = 3;
    return 0;
}

/* -------------------------------------------------------------------------
 * light_set_effect  --  0x0ff4   (OD 01000dc4, 1 B)
 *   0: A restart = 1, B restart = 1     1: A cmd 5
 *   2: A cmd 7, B cmd 7                 3: B cmd 5
 *   4: A cmd 9                          other: ignored
 * ------------------------------------------------------------------------- */
int light_set_effect(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t sel = **pdata;

    g_light_cmd_seen = 1;

    switch (sel) {
    case 0:
        g_light_b_restart = 1;
        g_light_a_restart = 1;
        break;
    case 1:
        g_light_a_state = 5;
        break;
    case 2:
        g_light_a_state = 7;
        g_light_b_state = 7;
        break;
    case 3:
        g_light_b_state = 5;
        break;
    case 4:
        g_light_a_state = 9;
        break;
    default:
        break;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * light_set_brightness_pct  --  0x1048
 *   pct > 70 -> -22. Otherwise store it and set the SCT0 PWM duty to
 *   pct % of the period match of event g_sct_pwm_event (the duty match is the
 *   next event's match register). The halt / MATCH+MATCHREL / unhalt sequence
 *   is the NXP SDK SCTIMER duty-cycle update, inlined; the 70 % cap is VanMoof's.
 * ------------------------------------------------------------------------- */
int light_set_brightness_pct(uint8_t pct)
{
    uint32_t ev, period_m, duty_m, period, duty;

    if (pct > 70)
        return -22;

    g_light_pct = pct;
    (void)SCT0_REG(0x52c);                      /* OEM dummy read (kept) */

    ev       = g_sct_pwm_event;
    period_m = SCT0_EV_CTRL(ev) & 0xfu;
    duty_m   = SCT0_EV_CTRL(ev + 1) & 0xfu;
    period   = SCT0_MATCH(period_m);

    SCT0_CTRL |= SCT_CTRL_HALT_L;
    duty = (uint32_t)(((uint64_t)pct * period) / 100u);
    SCT0_MATCH(duty_m)    = duty;
    SCT0_MATCHREL(duty_m) = duty;
    SCT0_CTRL &= ~SCT_CTRL_HALT_L;
    return 0;
}

/* -------------------------------------------------------------------------
 * od_write_brightness  --  0x10c4   (OD 010002c4, 1 B)
 * ------------------------------------------------------------------------- */
int od_write_brightness(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t pct = **pdata;

    g_light_cmd_seen = 1;
    return light_set_brightness_pct(pct);
}

/* -------------------------------------------------------------------------
 * led_driver_set  --  0x4188
 *   LED `led` (0..15) -> driver registers reg = (led+8)*4 and reg+1.
 *   level 0      : reg   <- 0
 *   level 1..15  : reg+1 <- 20 + 10*((level-1) & 3)
 *                  reg   <- ((level-1) >> 2) * 2 | 1
 *   (levels above 15 clamp to 15)
 * ------------------------------------------------------------------------- */
void led_driver_set(uint8_t led, uint8_t level)
{
    uint8_t  reg = (uint8_t)((led + 8u) * 4u);
    unsigned l   = level;

    if (l > 15)
        l = 15;
    else if (l == 0) {
        led_spi_transfer(reg, 0);
        return;
    }

    l -= 1;
    led_spi_transfer((uint8_t)(reg + 1), (uint8_t)((l & 3u) * 10u + 20u));
    led_spi_transfer(reg, (uint8_t)((((l & 0xffu) >> 2) << 1) | 1u));
}

/* -------------------------------------------------------------------------
 * led_set_level  --  0x41c8
 * ------------------------------------------------------------------------- */
int led_set_level(uint8_t led, uint8_t level)
{
    led_driver_set(led, level);
    return 0;
}

/* -------------------------------------------------------------------------
 * led_set_all  --  0x41d2
 * ------------------------------------------------------------------------- */
void led_set_all(uint8_t level)
{
    unsigned i;

    for (i = 0; i != 16; i++)
        led_set_level((uint8_t)i, level);
}

/* -------------------------------------------------------------------------
 * od_write_led_level  --  0x18e8   (OD 010003c4, 2 B: {led, level})
 * ------------------------------------------------------------------------- */
int od_write_led_level(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t *d = *pdata;

    g_light_cmd_seen = 1;
    return led_set_level(d[0], d[1]);
}

/* -------------------------------------------------------------------------
 * od_write_led_pattern  --  0x18fc   (OD 01000cc4, 9 B)
 *   d[8] = brightness pct (rejected -> -22). d[0..7] = 16 LED levels as
 *   nibbles, high nibble first: LED 2k = d[k] >> 4, LED 2k+1 = d[k] & 0xf.
 * ------------------------------------------------------------------------- */
int od_write_led_pattern(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t *d = *pdata;
    unsigned i;

    g_light_cmd_seen = 1;
    if (light_set_brightness_pct(d[8]) != 0)
        return -22;

    for (i = 0; i != 16; i += 2) {
        uint8_t b = d[i >> 1];
        led_set_level((uint8_t)i, (uint8_t)(b >> 4));
        led_set_level((uint8_t)(i + 1), (uint8_t)(b & 0xf));
    }
    return 0;
}
