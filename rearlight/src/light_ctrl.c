/*
 * light_ctrl.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * Rear-light control app layer: write handlers of the rearlight-specific OD
 * objects (node byte 0xc3, flash OD table g_od_regs @0x4218) plus the LED level
 * path. Single-channel counterpart of frontlight/src/light_ctrl.c (20 LEDs,
 * no PWM brightness object, optional LED-order remap).
 *
 *   light_set_mode        @ 0x0f44  OD 01000bc3 write (1 B): mode 0/1/2
 *   led_set_level         @ 0x1700  (optionally remapped) LED level, returns 0
 *   od_write_led_level    @ 0x171c  OD 010003c3 write (2 B): {led, level}
 *   od_write_led_pattern  @ 0x1730  OD 01000cc3 write (10 B): 20 nibbles
 *   light_set_effect      @ 0x176c  OD 01000dc3 write (1 B): effect 0..5
 *   led_driver_set        @ 0x3d28  byte-identical to frontlight 0x4188
 *   led_set_all           @ 0x3d68  all 20 LEDs to one level
 *
 * Handler ABI (can_od.c od_handler_t): (slots, reg, addr, pdata), pdata points
 * at the received-payload pointer.
 *
 * Addresses are link addresses (Ghidra image base 0xC00). Behaviour-oriented
 * reconstruction from the Ghidra decompile, cross-checked against disassembly.
 */

#include <stdint.h>

struct od_slot;
struct od_reg;

/* 2-byte LED-driver register write {reg<<1, value} (led.c). */
extern void led_spi_transfer(uint8_t reg, uint8_t value); /* 0x15e4 */

/* ---- light state (RAM) --------------------------------------------------- */
extern volatile uint8_t g_light_cmd_seen;   /* 0x20000cae: set by every light write  */
extern volatile uint8_t g_light_mode;       /* 0x20000c9e: last mode (01000bc3)      */
extern volatile uint8_t g_light_on;         /* 0x20000caf: light is on               */
extern volatile uint8_t g_light_state;        /* 0x20000cb0: animation state (main loop) */
extern volatile uint8_t g_light_restart;    /* 0x20000cb1                            */
extern volatile uint8_t g_led_remap_en;     /* 0x20000cad: set during init (main)    */

/* LED index remap applied when g_led_remap_en != 0 (flash @0x41dc). */
static const uint8_t led_remap[20] = {
    11, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2, 3, 4, 5, 0,
};

/* -------------------------------------------------------------------------
 * light_set_mode  --  0x0f44   (OD 01000bc3, 1 B)
 *   mode 0   : on -> cmd 3 (off)
 *   mode 1/2 : off -> cmd 1 (on)
 *   other    : stored only
 * ------------------------------------------------------------------------- */
int light_set_mode(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t mode = **pdata;

    g_light_cmd_seen = 1;
    g_light_mode = mode;

    if (mode == 0) {
        if (g_light_on != 0)
            g_light_state = 3;
    } else if ((uint8_t)(mode - 1) <= 1) {
        if (g_light_on == 0)
            g_light_state = 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * led_driver_set  --  0x3d28   (identical to frontlight 0x4188)
 *   reg = (led+8)*4; level 0 -> reg <- 0; level 1..15 (clamped) ->
 *   reg+1 <- 20 + 10*((level-1)&3), reg <- ((level-1)>>2)*2 | 1.
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
 * led_set_level  --  0x1700
 * ------------------------------------------------------------------------- */
int led_set_level(uint8_t led, uint8_t level)
{
    if (g_led_remap_en != 0)
        led = led_remap[led];
    led_driver_set(led, level);
    return 0;
}

/* -------------------------------------------------------------------------
 * led_set_all  --  0x3d68
 * ------------------------------------------------------------------------- */
void led_set_all(uint8_t level)
{
    unsigned i;

    for (i = 0; i != 20; i++)
        led_set_level((uint8_t)i, level);
}

/* -------------------------------------------------------------------------
 * od_write_led_level  --  0x171c   (OD 010003c3, 2 B: {led, level})
 * ------------------------------------------------------------------------- */
int od_write_led_level(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t *d = *pdata;

    g_light_cmd_seen = 1;
    return led_set_level(d[0], d[1]);
}

/* -------------------------------------------------------------------------
 * od_write_led_pattern  --  0x1730   (OD 01000cc3, 10 B)
 *   20 LED levels as nibbles, high nibble first (LED 2k = d[k] >> 4).
 * ------------------------------------------------------------------------- */
int od_write_led_pattern(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t *d = *pdata;
    unsigned i;

    g_light_cmd_seen = 1;
    for (i = 0; i != 20; i += 2) {
        uint8_t b = d[i >> 1];
        led_set_level((uint8_t)i, (uint8_t)(b >> 4));
        led_set_level((uint8_t)(i + 1), (uint8_t)(b & 0xf));
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * light_set_effect  --  0x176c   (OD 01000dc3, 1 B)
 *   0: restart = 1   1: cmd 5   2: cmd 7   3: all LEDs full (15)
 *   4: cmd 9         5: cmd 11  other: ignored
 * ------------------------------------------------------------------------- */
int light_set_effect(struct od_slot *slots, struct od_reg *reg, void *addr, uint8_t **pdata)
{
    uint8_t sel = **pdata;

    g_light_cmd_seen = 1;

    switch (sel) {
    case 0: g_light_restart = 1; break;
    case 1: g_light_state = 5;     break;
    case 2: g_light_state = 7;     break;
    case 3: led_set_all(15);     break;
    case 4: g_light_state = 9;     break;
    case 5: g_light_state = 11;    break;
    default:                     break;
    }
    return 0;
}
