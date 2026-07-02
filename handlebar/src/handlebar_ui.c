/*
 * handlebar_ui.c  -  VanMoof S6 handlebar ECU user-interface layer
 *
 * Target : TI MSPM0G (ARM Cortex-M0+, no FPU), in-house takahe-fw (NoRTOS).
 * Image  : "handlebar.bin", MCUboot slot base 0x1800, vector table 0x1900.
 *
 * The handlebar is the S6 user-ECU (replaces the S5 user_ecu + eshifter).
 * This file reconstructs the two VanMoof-authored UI subsystems:
 *
 *   1. The push-button state machine (button.c) - debounce sampling,
 *      single / multi-press counting and long-press detection, publishing
 *      the button state over the OD/CAN bus.  Driven as a periodic timer
 *      callback (installed as button_fsm_tick, OEM 0x0000313c).
 *
 *   2. The dual (Right / Left) RGB LED ring (led_ring.c) - enable/disable,
 *      per-pixel colour set, and the CAN "set led new data" command handler.
 *      NUM_LEDS == 10 per ring.
 *
 * Everything below is transcribed from the decompiled/disassembled OEM
 * machine code.  Vendor primitives (TI MSPM0 DriverLib register I/O, the
 * MCAN transport, the OD publish core, the takahe printf-style logger) are
 * declared 'extern' with their OEM address and are NOT reconstructed here.
 *
 * Build: cc -std=c11 -Wall -Wextra -Wpedantic -mcpu=cortex-m0plus -c handlebar_ui.c
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- */
/* Vendor / cross-module primitives (declared, not reconstructed)            */
/* ------------------------------------------------------------------------- */

/* takahe printf-style logger.  Variadic wrapper around the core formatter
 * (FUN_000019c0); fmt strings are the "D>"/"E>" tagged format strings.
 * OEM: vm_log @ 0x00006dec */
extern void vm_log(int level, const char *fmt, ...);

/* OD/CAN publish: takes (handle, od_descriptor, payload, len).  Only emits
 * when the descriptor's transport is in the running state (desc[4]==2),
 * else returns -EINVAL (-22).  OEM: od_publish @ 0x00006dcc */
extern int od_publish(void *handle, const void *od_desc,
                      const void *payload, uint32_t len);

/* Software timer arm: schedule callback after 'ms' ms on timer slot 'id'.
 * id must be < 16, returns -EINVAL otherwise.  OEM: timer_arm @ 0x000062d0 */
extern int timer_arm(uint32_t id, uint32_t ms, void (*cb)(uint32_t));

/* Button context table lookup: returns button_ctx_tbl[id], the context
 * pointer stored in the 4-byte pointer table at 0x20201f10 (DAT_000071d4).
 * OEM: button_ctx @ 0x000071cc */
extern void *button_ctx(uint32_t id);

/* Critical-section / IRQ guard toggle used around the LED SPI init.
 * OEM: FUN_000071e4 @ 0x000071e4 */
extern void irq_guard(uint32_t mask);

/* MCAN/MCP251XFD frame transmit used by the LED-ring data flush.
 * OEM: can_send @ 0x00003568 */
extern int can_send(void *bus, int id, uint8_t fdf, const void *data,
                    uint32_t len, uint32_t flags);

/* Low-level SPI/peripheral pin + clock bring-up for one LED ring, banged
 * straight onto MSPM0 DriverLib registers (vendor).  Two variants select
 * the Right vs Left ring's IOMUX/clock routing.
 * OEM: led_ring_spi_init_a @ 0x000047cc (ring whose SPI base == 0x..._A)
 *      led_ring_spi_init_b @ 0x00004734 (ring whose SPI base == 0x..._B) */
extern void led_ring_spi_init_a(void);
extern void led_ring_spi_init_b(void);

/* CAN object/filter (re)open used inside the LED-ring enable sequence.
 * OEM: can_obj_open @ 0x00005b84 */
extern int can_obj_open(void *obj, void *bus);

/* ------------------------------------------------------------------------- */
/* Externally placed objects (addresses are the OEM data symbols)            */
/* ------------------------------------------------------------------------- */

/* Button OD object descriptor published every tick.
 * OEM data @ 0x00007e60 : { id=0x010008c0, fmt=2, len=3, period=100 } */
extern const uint8_t button_od_desc[16];

/* Publish handle / OD owner passed as od_publish() arg0.
 * OEM SRAM @ 0x20200c00 (DAT_0000322c) */
extern void *g_od_handle;

/* The two LED-ring control blocks (see struct led_ring below).
 * OEM SRAM : g_led_ring_left  @ 0x203212a0 ("L" channel, mask bit0)
 *            g_led_ring_right @ 0x2032133c ("R" channel, mask bit1) */
struct led_ring;
extern struct led_ring g_led_ring_left;
extern struct led_ring g_led_ring_right;

/* SPI TXDATA shadow register pointer used by the enable path.
 * OEM @ 0x400a1290 (DAT_000043d4) -> u32[ ] */
extern volatile uint32_t led_spi_tx[16];

/* ------------------------------------------------------------------------- */
/* Constants                                                                 */
/* ------------------------------------------------------------------------- */

#define NUM_LEDS                10u     /* led_ring.c: count <= NUM_LEDS, idx < NUM_LEDS */

#define BTN_MULTIPRESS_TIMER_MS 500u    /* 0x7d<<2 : inter-press window     */
#define BTN_LONGPRESS_TIMER_MS  1000u   /* 0x7d<<3 : hold-to-fire window    */

/* GPIO DIN (data-in) register offset within the port base. */
#define GPIO_DIN_OFFSET         0x1380u /* 0x27 << 7 */

/* button.sample_state - the debounce/sample sub-state (struct off 0x10). */
enum btn_sample {
    BTN_SAMPLE_IDLE     = 0,            /* released, waiting for press      */
    BTN_SAMPLE_PRESSED  = 1,            /* pressed, confirm/debounce        */
    BTN_SAMPLE_DEBOUNCE = 2,            /* one-tick debounce settle         */
    BTN_SAMPLE_RELEASE  = 3,            /* pressed-held, watch for release  */
};

/* button.event - FSM event reported to the publish/log layer (off 0x18). */
enum btn_event {
    BTN_EVT_PRESSED  = 0,              /* edge: just pressed               */
    BTN_EVT_RELEASED = 1,             /* edge: just released              */
    BTN_EVT_MULTI    = 2,             /* multi-press window expired        */
    BTN_EVT_LONG     = 3,             /* long-press timer expired          */
};

/* ------------------------------------------------------------------------- */
/* Button context                                                            */
/* ------------------------------------------------------------------------- */

/* Layout matches the OEM struct field offsets exactly. */
struct button {
    uint8_t  id;                /* 0x00 : button index, logged as %d        */
    uint8_t  _pad01[3];
    uint32_t gpio_base;         /* 0x04 : GPIO port base (DIN at +0x1380)   */
    uint32_t pin_mask;          /* 0x08 : this button's pin bit             */
    uint32_t sample;            /* 0x0c : last masked DIN sample            */
    uint8_t  sample_state;      /* 0x10 : enum btn_sample                   */
    uint8_t  _pad11[7];
    uint8_t  event;             /* 0x18 : enum btn_event                    */
    uint8_t  counter;           /* 0x19 : press counter (0xff = long sentinel) */
    uint8_t  _pad1a[2];
    uint32_t timer_id;          /* 0x1c : software-timer slot id            */
};

/*
 * Periodic button tick + multi/long-press timer expiry callback.
 *
 * Installed as the timer callback (timer_arm(..., button_fsm_tick)); the
 * timer dispatcher (OEM 0x00005b2c) invokes it with the timer-slot id in r0,
 * which indexes the button context table.  It samples the pin,
 * advances the debounce state machine, publishes the 3-byte {id, event,
 * counter} OD frame every call, and on edges arms the multi-press / long-
 * press timers or logs the corresponding event.
 *
 * OEM: button_fsm_tick @ 0x0000313c
 */
void button_fsm_tick(uint32_t id)
{
    struct button *b = (struct button *)button_ctx(id);
    uint32_t sampled;
    uint8_t frame[3];

    switch (b->sample_state) {
    case BTN_SAMPLE_RELEASE:                                 /* 0x03 */
        /* Held button: watch the masked DIN for the release transition. */
        sampled = *(volatile uint32_t *)(uintptr_t)(b->gpio_base + GPIO_DIN_OFFSET) & b->pin_mask;
        b->sample = sampled;
        if (sampled == 0) {
            /* Not settled yet: take one more debounce tick (no event). */
            b->sample_state = BTN_SAMPLE_DEBOUNCE;
        } else {
            /* Release edge: back to idle, report RELEASED. */
            b->sample_state = BTN_SAMPLE_IDLE;
            b->event = BTN_EVT_RELEASED;
        }
        break;

    case BTN_SAMPLE_DEBOUNCE:                                /* 0x02 */
        /* Settle: reload event(0x18)/counter(0x19) sentinel (0xff03). */
        b->event   = (uint8_t)BTN_EVT_LONG;   /* 0x03 */
        b->counter = 0xff;                    /* high byte of 0x0000ff03 */
        break;

    case BTN_SAMPLE_PRESSED:                                 /* 0x01 */
        sampled = *(volatile uint32_t *)(uintptr_t)(b->gpio_base + GPIO_DIN_OFFSET) & b->pin_mask;
        b->sample = sampled;
        if (sampled != 0) {
            /* Bounced back: return to idle (no event, no count). */
            b->sample_state = BTN_SAMPLE_IDLE;
        } else {
            /* Press edge confirmed: debounce, report PRESSED, advance counter. */
            b->sample_state = BTN_SAMPLE_DEBOUNCE;
            b->event = BTN_EVT_PRESSED;       /* 0x00 */
            b->counter++;
        }
        break;

    default:                                                /* BTN_SAMPLE_IDLE */
        break;
    }

    /* Publish {id, event, counter} (3 bytes) every tick. */
    frame[0] = b->id;
    frame[1] = b->event;
    frame[2] = b->counter;
    od_publish(g_od_handle, button_od_desc, frame, 3);

    /* React to the current event. */
    switch (b->event) {
    case BTN_EVT_PRESSED:
        /* Press edge: arm the long-press timer (1000 ms). */
        timer_arm(b->timer_id, BTN_LONGPRESS_TIMER_MS, button_fsm_tick);
        vm_log(0, "D>button %d is pressed\n", b->id);
        break;

    case BTN_EVT_RELEASED:
        if (b->counter != 0xff) {
            /* Normal release: start the multi-press window (500 ms). */
            vm_log(0, "D>button %d is released, multi press timer is started\n", b->id);
            timer_arm(b->timer_id, BTN_MULTIPRESS_TIMER_MS, button_fsm_tick);
            b->event = BTN_EVT_MULTI;
            return;
        }
        /* Released after a long-press: just reset the counter. */
        vm_log(0, "D>button %d is released, counter is set to 0\n", b->id);
        b->counter = 0;
        return;

    case BTN_EVT_MULTI:
        /* Multi-press window elapsed: report the final tap count. */
        vm_log(0, "D>button %d multi press timer is expired, counter was %d\n",
               b->id, b->counter);
        b->counter = 0;
        return;

    case BTN_EVT_LONG:
        /* Long-press timer elapsed while held. */
        vm_log(0, "D>button %d long press timer is expired\n", b->id);
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------------- */
/* LED ring                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * LED-ring control block.  Field offsets match the OEM struct:
 *   0x00 enabled        - 0 = disabled, non-zero = ready
 *   0x01 dirty          - set to 2 ("new data") when pixels change
 *   0x04 bus            - CAN/SPI bus handle
 *   0x08 tx_id          - frame id used by can_send (0x33 R/L specific)
 *   0x48 pixel[NUM_LEDS]- 32-bit packed colour per LED
 */
struct led_ring {
    uint8_t  enabled;           /* 0x00 */
    uint8_t  dirty;             /* 0x01 */
    uint8_t  _pad02[2];
    void    *bus;               /* 0x04 */
    uint8_t  tx_id;             /* 0x08 */
    uint8_t  _pad09[0x3f];
    uint32_t pixel[NUM_LEDS];   /* 0x48 .. 0x6f */
};

/*
 * Set a single LED's colour.  Asserts index < NUM_LEDS, stores the packed
 * 32-bit colour at pixel[index] and flags the ring "new data" (dirty=2).
 * Returns -EINVAL (-22) if the ring is disabled.
 *
 * OEM: led_ring_set_pixel @ 0x00006610
 */
int led_ring_set_pixel(struct led_ring *r, uint32_t index, uint32_t rgb)
{
    if (r->enabled == 0)
        return -22;                              /* -EINVAL */

    if (index >= NUM_LEDS) {
        /* assert(index < NUM_LEDS) -> led_ring.c line 0x5a (90) */
        extern void __assert_fail_index_lt_num_leds(void);
        __assert_fail_index_lt_num_leds();       /* OEM FUN_000060cc(...) */
    }

    r->pixel[index] = rgb;
    r->dirty = 2;                                /* "new data" */
    return 0;
}

/*
 * CAN command handler: "set led new data".  The 5-byte command payload is
 *   [0] channel-mask bit0=L, bit1=R
 *   [1] led index
 *   [2..4] 24-bit RGB colour (big-endian: R<<16 | G<<8 | B)
 * For each selected channel it logs and pushes the pixel into that ring.
 *
 * OEM: led_ring_cmd_set_new_data @ 0x000057a4
 */
int led_ring_cmd_set_new_data(const uint8_t **arg)
{
    const uint8_t *p = *arg;            /* command payload */
    uint8_t mask = p[0];
    uint32_t rgb = ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | (uint32_t)p[4];
    uint8_t index = p[1];

    if (mask & 1) {                     /* L channel */
        vm_log(0, "D>L set led new data\n");
        led_ring_set_pixel(&g_led_ring_left, index, rgb);
    }
    if (mask & 2) {                     /* R channel */
        vm_log(0, "D>R set led new data\n");
        led_ring_set_pixel(&g_led_ring_right, index, rgb);
    }
    return 0;
}

/*
 * Flush the current ring frame onto the bus.  Sends a 3-byte control frame
 * (the OEM passes the ring's first three header bytes).  Returns -EINVAL if
 * the ring is disabled.
 *
 * OEM: led_ring_flush @ 0x00006854
 */
int led_ring_flush(struct led_ring *r, uint8_t b0, uint8_t b1, uint8_t b2)
{
    uint8_t frame[3];

    if (r->enabled == 0)
        return -22;                              /* -EINVAL */

    /* OEM stores in order {b1, b0, b2} into the local buffer. */
    frame[0] = b1;
    frame[1] = b0;
    frame[2] = b2;
    return can_send(r->bus, r->tx_id, 0x6e, frame, 3, 10);
}

/*
 * Enable / (re)initialise a LED ring.  Up to 3 attempts: program the SPI
 * control word, route the ring-specific IOMUX (A/B variant chosen by the
 * SPI base), (re)open the CAN object, then push the initial frame and mark
 * the ring enabled (dirty=1).  Returns the last can_obj_open() result.
 *
 * OEM: led_ring_enable @ 0x00004338
 */
int led_ring_enable(struct led_ring *r)
{
    /* OEM treats the block via word offsets; mirror with a raw view. */
    uint32_t *w = (uint32_t *)r;
    void *spi_base;
    int ret = 0;
    int retries = 3;

    do {
        vm_log(0, "D>led_ring_enable retries left %d\n", retries);

        spi_base = (void *)(uintptr_t)w[1];      /* r->bus / SPI base */

        /* Kick the SPI control register: disable then re-enable TX. */
        *(volatile uint32_t *)((char *)spi_base + 0x800) = 0x26000000;
        led_spi_tx[4] = w[7];                    /* preload TX shadow */
        irq_guard(0x0009c400 /* DAT_000043d8 */);
        led_spi_tx[0] = w[7];

        *(volatile uint32_t *)((char *)spi_base + 0x804) = 0xb1000003; /* DAT_000043e0 */
        *(volatile uint32_t *)((char *)spi_base + 0x800) = 0x26000001;

        /* Ring-specific pin/clock routing (vendor DriverLib): the SPI base
         * selects ring A (0x400f0000) vs ring B (0x400f2000). */
        if (spi_base == (void *)0x400f0000)      /* DAT_000043e4 */
            led_ring_spi_init_a();
        else if (spi_base == (void *)0x400f2000) /* DAT_000043e8 */
            led_ring_spi_init_b();

        irq_guard(0x0009c400 /* DAT_000043d8 */);

        ret = can_obj_open((char *)r + 0x0c, (char *)r + 0x04);
    } while (ret != 0 && --retries != 0);

    /* Initial frame from the ring's header bytes.  The OEM passes the CAN
     * sub-object at r+0x0c (param_1+6 as undefined2*), not the ring base. */
    led_ring_flush((struct led_ring *)((char *)r + 0x0c),
                   ((uint8_t *)r)[0x74], ((uint8_t *)r)[0x75], ((uint8_t *)r)[0x76]);
    *(uint16_t *)r = 1;                          /* enabled=1, dirty=0 */
    return ret;
}

/*
 * Disable a LED ring: clear the enabled flag and snapshot a status word
 * (struct off 0x1c) out to the disable register.
 *
 * OEM: led_ring_disable @ 0x00006ca0
 */
int led_ring_disable(struct led_ring *r)
{
    *(uint16_t *)r = 0;                          /* enabled=0, dirty=0 */
    vm_log(0, "D>led_ring_disable\n");
    /* *DAT_00006cc0 = *(u32 *)(r + 0x1c) */
    *(volatile uint32_t *)0x400a12a0 = *(uint32_t *)((char *)r + 0x1c);
    return 0;
}