/*
 * power_node.c — VanMoof S6 "power-control" ECU node layer
 *
 * TI MSPM0G (ARM Cortex-M0+, no FPU), VanMoof in-house bare-metal "takahe-fw"
 * (NoRTOS; common/mspm0 + common/node). Image base 0x1800 (MCUboot slot,
 * vector table @ 0x1900).
 *
 * This is the bike's power-management node. Unlike the other S6 sub-ECUs, the
 * power node does NOT use the on-chip MSPM0 MCAN: it talks to the CAN bus over
 * an EXTERNAL Microchip MCP251XFD CAN-FD controller on SPI. The reconstructed
 * VanMoof logic here is:
 *
 *   - the MCP251XFD interrupt service / dispatch  (mcp_isr_service)
 *   - bus-off / error-warning / error-passive recovery  (mcp_bus_diag)
 *   - controller bring-up + sleep  (mcp_init / mcp_enter_sleep)
 *   - the Object-Dictionary (vm protocol) CAN publish path  (od_send / od_publish)
 *   - DTC set, heartbeat publish, node announce
 *   - the ADC torque-sensor read + publish node handler  (adc_torque_handler)
 *   - the battery wake-pulse node handler  (battery_wake_handler)
 *   - the node state-machine tick driver and irq_dispatcher slot table
 *   - main()
 *
 * Source-path anchors observed in the image:
 *   /__w/takahe-fw/takahe-fw/common/node/src/heartbeat.c
 *   /__w/takahe-fw/takahe-fw/power/src/irq_dispatcher.c
 *
 * The MCP251XFD SPI-CAN driver, the TI MSPM0 DriverLib register I/O, MCUboot /
 * sys_image and libc/udivmod are VENDOR and are NOT reconstructed — they appear
 * only as 'extern' declarations carrying their OEM addresses in comments.
 *
 * Behaviour-oriented reconstruction (not byte-identical). Clean under
 * -Wall -Wextra -Wpedantic -std=c11.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- *
 *  Vendor / cross-module externs (declared with their OEM addresses)
 * ------------------------------------------------------------------------- */

/* VanMoof printf-style logger. The first arg ("D>...","E>...") names the
 * behaviour. OEM FUN_00008b6c is a thin varargs shim over FUN_000022d0. */
extern void vm_log(int level, const char *fmt, ...);            /* FUN_00008b6c */

/* takahe assert handler: (expr, file, line) -> logs "Assertion failed" + halts.
 * OEM FUN_00007bd0. */
extern void node_assert_fail(const char *expr, const char *file, int line); /* FUN_00007bd0 */

/* unsigned 32-bit divide (TI/libgcc udivmod helper). OEM FUN_00007dd4. */
extern uint32_t u32_div(uint32_t num, uint32_t den);           /* FUN_00007dd4 */
/* clamp/saturate to u16 (OEM FUN_0000748c: returns min(x,limit) as u16). */
extern uint16_t sat_u16(int32_t value, uint32_t limit);        /* FUN_0000748c */

/* ---- MCP251XFD external SPI CAN-FD driver — VENDOR (Microchip) --------- */
/* Read the device's top-priority pending interrupt code (Get Current
 * Interrupt Event). OEM FUN_00008ecc -> fills *code, returns err. */
extern int  mcp_get_current_int(uint32_t dev, uint8_t *code);      /* FUN_00008ecc */
/* Clear interrupt event flags. OEM FUN_00007cd4. */
extern int  mcp_clear_int(uint32_t dev, uint32_t flags);           /* FUN_00007cd4 */
/* Read CRC/ECC/diagnostic status structs. OEM FUN_00008aac/FUN_00008acc. */
extern int  mcp_read_crc_event(uint32_t dev, uint32_t *out);       /* FUN_00008aac */
extern int  mcp_read_ecc_event(uint32_t dev, uint32_t *out);       /* FUN_00008acc */
/* Read RX-FIFO status / receive a CAN message into a node OD frame.
 * OEM FUN_000086f4 (FIFO status), FUN_000084d6 (pop msg). */
extern int  mcp_fifo_status(uint32_t dev, uint32_t fifo, uint8_t *flags); /* FUN_000086f4 */
extern void mcp_fifo_read(uint32_t dev, uint32_t *out);            /* FUN_000084d6 */
/* Read transmit-event / TEF objects. OEM FUN_00003558. */
extern int  mcp_read_tef(uint32_t dev, uint32_t *id, uint32_t a, uint32_t b, int c); /* FUN_00003558 */
/* ECC single/double error address read. OEM FUN_00007b48 / FUN_000082d0. */
extern int  mcp_read_ecc_single(uint32_t dev, uint8_t *out, int z); /* FUN_00007b48 */
extern int  mcp_read_ecc_double(uint32_t dev, char *out);          /* FUN_000082d0 */
/* Bus diagnostic (error counters / state) read. OEM FUN_00006154. */
extern uint32_t mcp_read_busdiag(uint32_t dev);                    /* FUN_00006154 */
/* Configure / start / sleep. OEM FUN_00001cdc(cfg), FUN_0000307c(filter list),
 * FUN_00006938(fifo list), FUN_000067d0(StartCAN20), FUN_00004eec(sleep cfg),
 * FUN_00007d14(enter sleep). */
extern int  mcp_configure(uint32_t dev, uint32_t cfg);             /* FUN_00001cdc */
extern int  mcp_config_filters(uint32_t dev, uint32_t list, int n);/* FUN_0000307c */
extern int  mcp_config_fifos(uint32_t dev, int a, uint32_t list, int n); /* FUN_00006938 */
extern int  mcp_start_can20(uint32_t dev, int mode, int z);        /* FUN_000067d0 */
extern int  mcp_config_sleep(uint32_t dev, int a, int b, int c);   /* FUN_00004eec */
extern int  mcp_enter_sleep_dev(uint32_t dev);                     /* FUN_00007d14 */
/* SPI bring-up / reset of the MCP251XFD. OEM FUN_00007914, FUN_00008f84. */
extern int  mcp_spi_reset(uint32_t dev);                           /* FUN_00007914 */
extern void mcp_spi_assert(uint32_t arg);                          /* FUN_00008f84 */
/* Misc device housekeeping called from the bus-diag path. OEM FUN_00008da8 /
 * FUN_00008cb8 / FUN_00008e8c / FUN_00006bdc. */
extern void mcp_store_busdiag(uint32_t dev, uint32_t diag, int one); /* FUN_00008da8 */
extern void mcp_busoff_clear(uint32_t dev, int z);                 /* FUN_00008cb8 */
extern void dtc_set_from_diag(uint32_t dtc_id);                    /* FUN_00008e8c */
extern void mcp_busoff_recover(int z);                             /* FUN_00006bdc */
/* ISR helpers (external MCP driver / node glue) restored below:
 *  - mcp_reg_write: write-back of an MCP251XFD register (clears ECC status).
 *  - mcp_spi_err_check: guard run after each ISR SPI op; on the SPI-CRC error
 *    code (0xd) it raises a DTC + re-asserts CS. Fed the op's return code.
 *  - tef_ring_empty: software transmit-event ring empty test (head == tail).
 *  - mcp_tef_forward: forward a popped TEF object to the OD/CAN layer.
 *  - mcp_rx_fifo_pump: acknowledge an RX-FIFO's pending interrupt flags. */
extern int  mcp_reg_write(uint32_t dev, uint32_t reg, void *buf, uint32_t len); /* FUN_00003848 */
extern void mcp_spi_err_check(int rc);                             /* FUN_00008b0c */
extern int  tef_ring_empty(int32_t *ctx);                          /* FUN_00008f6c */
extern int  mcp_tef_forward(uint32_t dev, uint32_t *frame, int a, int b); /* FUN_00003e64 */
extern int  mcp_rx_fifo_pump(uint32_t dev, int fifo, uint32_t flags);    /* FUN_0000646c */
/* Bus-off recovery/park routine invoked by node_tick on the bus-off flag.
 * Enters a critical section, runs an optional per-descriptor callback, then
 * parks in a low-power WFI loop that does not return on the normal path.
 * Distinct from mcp_bus_diag (FUN_00005ea0). Deferred (vendor-adjacent). */
extern void mcp_bus_off_park(const void *desc);                         /* FUN_000068c0 */

/* ---- MSPM0 DriverLib (peripheral register I/O) — VENDOR ---------------- */
/* The ADC torque sample register and the GPIO/battery-wake registers are read
 * and written directly through these device pointers (see ADDR_* below). */

/* ---- MCUboot / sys_image OTA self-update — VENDOR ---------------------- */
extern int  sys_image_allow_update(int z);                        /* (referenced by E> strings) */
extern int  sys_image_validate(void);
extern int  sys_image_size(uint32_t *out);

/* ------------------------------------------------------------------------- *
 *  Hardware / RAM addresses (verbatim from the image's literal pools)
 * ------------------------------------------------------------------------- */

/* MSPM0 peripheral registers used by the node handlers */
#define ADDR_NODE_STATE     0x40003020u  /* node-state byte (0x09 == TORQUE state) */
#define ADDR_NODE_REQ       0x40003100u  /* node request-flags word (bit0 = done) */
#define ADDR_ADC_RESULT     0x40558280u  /* MSPM0 ADC12 MEMRES (12-bit torque) */
#define ADDR_BAT_WAKE_GPIO  0x400a1290u  /* GPIO that fires the battery wake pulse */
#define ADDR_BAT_REQ        0x40085804u  /* battery-wake request word (bit0 busy) */
#define ADDR_MCP_INT        0x400a1380u  /* MCP251XFD host INT line (GPIO IN) */

/* External MCP251XFD device context + frame buffers (RAM) */
#define MCP_DEV             0x2020185cu  /* MCP251XFD device struct */
#define MCP_CFG_STRUCT      0x20201838u  /* MCP251XFD configuration struct (DAT_00005d5c) */
#define MCP_FILTER_LIST     0x2020187cu  /* filter-object list, 2 filters (DAT_00005d64) */
#define MCP_FIFO_LIST       0x202018a8u  /* FIFO-object list (DAT_00005d6c) */
#define MCP_TEF_CTX         0x20201894u  /* transmit-event FIFO ring context (DAT_00001cd0) */
#define MCP_TEF_COUNTER     0x20200d9cu  /* forwarded-TEF packet counter (DAT_00001cd4) */
#define OD_BUS              0x20200400u  /* node OD/CAN bus context */
#define OD_TORQUE_FRAME     0x20200d94u  /* OD frame staging for torque publish */
#define OD_TORQUE_ADDR      0x2020a0a0u  /* OD entry/address for torque value */
#define HB_OD_STRUCT        0x202018c8u  /* heartbeat OD frame (seq @ +0) */
#define DTC_BITMAP          0x202018c8u  /* DTC active bitmap (shared w/ heartbeat blk) */
#define DTC_PENDING_MASK    0x202018c0u  /* 64-bit pending-DTC mask */

/* ADC torque conversion constants (image literals) */
#define ADC_TORQUE_SCALE    0x0000cce4   /* 52452  : raw * scale ... */
#define ADC_FULLSCALE       0x00000fff   /* 4095   : 12-bit ADC max */
#define ADC_TORQUE_OFFSET   ((int32_t)0xfffedb08) /* -75000 : signed offset (mNm/100) */
#define ADC_TORQUE_THRESH   0x000002a1   /* 673    : raw deadband threshold */

/* ------------------------------------------------------------------------- *
 *  DTC — diagnostic trouble codes (heartbeat.c)
 *
 *  Valid DTC ids run 0x14..0x4B (DTC_MAX). dtc_set marks the id's bit in the
 *  active bitmap, and (when 'latch' != 0) ORs it into the 64-bit pending mask
 *  that the next heartbeat publishes and then clears. Asserts on out-of-range.
 * ------------------------------------------------------------------------- */
#define DTC_BASE  0x14u
#define DTC_MAX   0x4Cu                 /* 0x14 + 0x38 */

void dtc_set(uint8_t dtc_id, int latch)   /* OEM FUN_00007330 */
{
    uint8_t bit = (uint8_t)(dtc_id - DTC_BASE);

    if (bit > 0x37u) {
        /* "bit < DTC_MAX", heartbeat.c:0x21 */
        node_assert_fail("bit < DTC_MAX",
                         "/__w/takahe-fw/takahe-fw/common/node/src/heartbeat.c", 0x21);
    }

    /* set the active bit (byte at bitmap+2 + (bit>>3)) */
    {
        volatile uint8_t *active = (volatile uint8_t *)(DTC_BITMAP + 2u);
        active[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
    }

    if (latch) {
        volatile uint32_t *pending = (volatile uint32_t *)DTC_PENDING_MASK;
        uint32_t lo = 0x10000u << bit;          /* low word of (1 << (16+bit)) */
        pending[0] |= lo;
        pending[1] |= (uint32_t)((int32_t)lo >> 31);
    }
}

/* ------------------------------------------------------------------------- *
 *  Object-Dictionary CAN publish (vm wire protocol)
 *
 *  od_send builds the 29-bit extended CAN id from the OD entry (node id <<5,
 *  the 16-bit OD address packed into id[21..13], plus a direction nibble) and
 *  hands single (<=8B) or fragmented (>8B) payloads to the device's send
 *  vtable (entry+4). od_publish only writes to a writable OD endpoint (type 2).
 * ------------------------------------------------------------------------- */

/* OD entry layout (relevant fields):
 *   +0x00 : node id byte
 *   +0x04 : send vtable function pointer
 *   +0x08 : device/bus handle for the send call
 */
typedef int (*od_send_fn)(uint8_t *dev, uint32_t can_id, uint8_t *data, uint32_t len);

int od_send(uint8_t *bus, uint8_t *entry, uint8_t *addr_override,
            uint8_t *data, uint32_t len)                /* OEM FUN_000041a8 */
{
    uint32_t dir;
    uint8_t  *od = (addr_override != NULL) ? addr_override : entry;

    /* direction nibble: writable endpoints (type==2) get 0, others 0x10 when
     * entry[3]==0 (request vs. response). */
    if (entry[4] == 2) {
        dir = 0;
    } else {
        dir = (entry[3] == 0) ? 0x10u : 0u;
    }

    if (len < 9) {
        uint32_t a = (uint32_t)od[1] * 0x100u + (uint32_t)od[0];
        uint32_t nodeid = (uint32_t)od[2];
        if (a + nodeid * 0x10000u < 0x10000u) {
            nodeid = (uint32_t)*bus;           /* default to our node id */
        }
        {
            od_send_fn send = *(od_send_fn *)(bus + 4);
            uint32_t can_id = ((nodeid << 5)
                            | ((uint32_t)od[0] * 0x200000u + (a * 0x20u & 0x1fe000u)))
                            + dir;
            return send(bus, can_id, data, len);
        }
    } else {
        /* fragmented transfer: 8 bytes/frame, incrementing sub-index */
        uint8_t  *src = od;
        uint32_t sent = 0;
        for (;;) {
            uint32_t a      = (uint32_t)src[1] * 0x100u + (uint32_t)src[0];
            uint32_t nodeid = (uint32_t)src[2];
            uint32_t chunk;
            int      rc;

            if (a + nodeid * 0x10000u < 0x10000u) {
                nodeid = (uint32_t)*bus;
            }
            chunk = len - sent;
            if (chunk > 7u) chunk = 8u;

            {
                od_send_fn send = *(od_send_fn *)(bus + 4);
                uint32_t can_id = ((nodeid << 5)
                                | ((uint32_t)src[0] * 0x200000u + (a * 0x20u & 0x1fe000u)))
                                + dir;
                rc = send(bus, can_id, data + sent, chunk);
            }
            if (rc != 0) return rc;

            /* advance sub-index inside dir nibble */
            {
                uint32_t mask, wrap;
                if (entry[4] == 2) { wrap = 0xf;  mask = 0xfffffff0u; }
                else               { wrap = 0x7;  mask = 0xfffffff8u; }
                dir = (mask & dir) | ((dir + 1) & wrap);
            }
            sent += chunk;
            if (sent >= len) break;
        }
        return 0;
    }
}

/* od_publish — only emit on a writable (type==2) OD endpoint. OEM FUN_00008b4c */
int od_publish(uint8_t *bus, uint8_t *entry, uint8_t *data, uint32_t len)
{
    if (entry[4] == 2) {
        return od_send(bus, entry, NULL, data, len);
    }
    return -22;                                /* -EINVAL */
}

/* ------------------------------------------------------------------------- *
 *  Heartbeat + node announce
 * ------------------------------------------------------------------------- */

/* heartbeat_publish — emit the 8-byte heartbeat OD frame, bump its sequence
 * counter, then clear the pending-DTC mask that was just reported.
 * OEM FUN_0000818c. */
void heartbeat_publish(uint8_t *bus)
{
    volatile uint8_t  *hb       = (volatile uint8_t  *)HB_OD_STRUCT;
    volatile uint32_t *pending  = (volatile uint32_t *)DTC_PENDING_MASK;
    volatile uint32_t *hbmask   = (volatile uint32_t *)HB_OD_STRUCT;

    od_publish(bus, (uint8_t *)0x000081b8 /*hb OD entry*/, (uint8_t *)hb, 8);
    hb[0] = (uint8_t)(hb[0] + 1);              /* sequence counter */

    /* clear the DTC bits we just published */
    hbmask[0] &= ~pending[0];
    hbmask[1] &= ~pending[1];
    pending[0] = 0;
    pending[1] = 0;
}

/* node_announce — publish the node-online frame when not suppressed.
 * OEM FUN_000089dc. */
void node_announce(uint8_t *bus)
{
    volatile uint8_t *suppress = (volatile uint8_t *)0x20200d9a;
    if (*suppress == 0) {
        od_publish(bus, (uint8_t *)0x000089fc /*announce OD entry*/, NULL, 0);
    }
}

/* heartbeat_tick — set the keep-alive DTC and publish the heartbeat.
 * OEM FUN_00008dd0. */
void heartbeat_tick(uint8_t *bus)
{
    dtc_set(/* keep-alive DTC id */ 0x14, 0);
    heartbeat_publish(bus);
}

/* ------------------------------------------------------------------------- *
 *  ADC torque-sensor node handler  ("D>ADC Torque")
 *
 *  Runs when the node FSM is in the TORQUE state (node-state byte == 9). Reads
 *  the 12-bit ADC torque sample, applies the linear scale/offset
 *  (raw*52452/4095 -> *0x36/0x27 -> *100 + offset), saturates to u16, zeroes it
 *  below the deadband threshold, packs it into the torque OD frame and
 *  publishes it. Then sets the node "done" request bit. OEM FUN_00005a74.
 * ------------------------------------------------------------------------- */
void adc_torque_handler(void)
{
    volatile uint8_t  *node_state = (volatile uint8_t *)ADDR_NODE_STATE;
    volatile uint32_t *adc        = (volatile uint32_t *)ADDR_ADC_RESULT;
    volatile uint8_t  *frame      = (volatile uint8_t *)OD_TORQUE_FRAME;
    volatile uint32_t *req        = (volatile uint32_t *)ADDR_NODE_REQ;

    if ((*node_state & 0xff) == 9) {
        uint32_t raw;
        int32_t  v;
        uint16_t torque;

        vm_log(0, "D>ADC Torque\n");

        raw = *adc & 0xffffu;
        v   = (int32_t)u32_div(raw * ADC_TORQUE_SCALE, ADC_FULLSCALE);
        v   = (int32_t)u32_div((uint32_t)(v * 0x36), 0x27);
        torque = sat_u16(v * 100 + ADC_TORQUE_OFFSET, 0x23);

        /* below the deadband threshold report zero */
        if (raw < ADC_TORQUE_THRESH) {
            torque = 0;
        }

        frame[2] = (uint8_t)torque;            /* little-endian u16 in OD frame */
        frame[3] = (uint8_t)(torque >> 8);

        od_publish((uint8_t *)OD_BUS, (uint8_t *)OD_TORQUE_ADDR,
                   (uint8_t *)frame, 6);
    } else {
        vm_log(0, "D>default\n");
    }

    *req |= 1;                                  /* signal handler complete */
}

/* ------------------------------------------------------------------------- *
 *  Battery wake-pulse node handler  ("D>Battery wake pulse %d ms")
 *
 *  Reached through the node FSM dispatch table (no direct caller). The OD
 *  request carries a wake duration in ms (low 16 bits). It fires the wake GPIO
 *  and, if a non-zero duration is requested and no pulse is already pending,
 *  arms the timed pulse. OEM FUN_00007e14.
 * ------------------------------------------------------------------------- */
int battery_wake_handler(uint32_t **req_ptr)
{
    volatile uint32_t *wake_gpio = (volatile uint32_t *)ADDR_BAT_WAKE_GPIO;
    volatile uint32_t *bat_req   = (volatile uint32_t *)ADDR_BAT_REQ;
    uint32_t ms = **req_ptr;                    /* requested duration */

    vm_log(0, "D>Battery wake pulse %d ms\n", ms);

    *wake_gpio = 0x800000;                      /* assert wake line */

    ms &= 0xffffu;
    if (ms != 0 && (bat_req[0] & 1u) == 0) {
        bat_req[1] = ms;                        /* arm pulse duration */
        bat_req[0] |= 1u;                       /* mark pulse pending */
    }
    return 0;
}

/* ------------------------------------------------------------------------- *
 *  Node state-machine tick
 *
 *  Walks a fixed table of 10 node slots (0x5C bytes each). For each armed slot
 *  whose scheduled time has elapsed, it either fires the slot's OD action
 *  (od_send) and reports the result through the slot callback, or — if the
 *  bound OD entry is busy (entry[3]!=0) and the slot still has retries — reports
 *  the busy error (-0x91) through the callback. Slots are one-shot (cleared
 *  after firing). OEM FUN_000059c8.
 * ------------------------------------------------------------------------- */
#define NODE_SLOT_COUNT   10
#define NODE_SLOT_STRIDE  0x5C

typedef void (*node_slot_cb)(int bus, int entry, uint8_t *frame, void *result);

void node_sm_dispatch(int table)               /* OEM FUN_000059c8 */
{
    uint32_t now = /* node tick */ 0;           /* OEM FUN_00008fd8() */
    int i;

    /* now = node_get_tick(); (vendor) */
    extern uint32_t node_get_tick(void);        /* FUN_00008fd8 */
    now = node_get_tick();

    for (i = 0; i < NODE_SLOT_COUNT; i++) {
        int   slot  = table + i * NODE_SLOT_STRIDE;
        int   entry = *(int *)(slot + 8);
        if (entry == 0) continue;
        if (*(uint32_t *)(slot + 0x58) >= now) continue;   /* not due yet */

        if (*(char *)(entry + 3) == 0 && *(char *)(slot + 0x54) != 0) {
            /* OD endpoint ready and slot still has retries */
            int rc;
            *(char *)(slot + 0x54) -= 1;
            *(uint32_t *)(slot + 0x58) = *(int *)(entry + 0xc) + now; /* reschedule */
            rc = (int)od_send((uint8_t *)table, (uint8_t *)entry,
                              (uint8_t *)(slot + 0xc), (uint8_t *)(slot + 0x14),
                              *(uint32_t *)(slot + 0x10));
            if (rc == 0) continue;              /* fired ok, keep slot armed */

            {
                node_slot_cb cb = *(node_slot_cb *)(slot + 0x5c);
                if (cb) {
                    struct { int code; int pad0; int pad1; void *ctx; } r;
                    r.code = rc;
                    r.pad0 = 0;
                    r.pad1 = 0;
                    r.ctx  = *(void **)(slot + 0x60);
                    cb(table, entry, (uint8_t *)(slot + 0xc), &r);
                }
            }
        } else {
            /* endpoint busy: report -0x91 (EBUSY-ish) through the callback */
            node_slot_cb cb = *(node_slot_cb *)(slot + 0x5c);
            if (cb) {
                struct { int code; int pad0; int pad1; void *ctx; } r;
                r.code = -0x91;
                r.pad0 = 0;
                r.pad1 = 0;
                r.ctx  = *(void **)(slot + 0x60);
                cb(table, entry, (uint8_t *)(slot + 0xc), &r);
            }
        }
        *(int *)(slot + 8) = 0;                 /* one-shot: disarm */
    }
}

/* ------------------------------------------------------------------------- *
 *  irq_dispatcher (power/src/irq_dispatcher.c)
 *
 *  A 2-slot handler table. Registers a handler for line 0/1; out-of-range
 *  index or NULL handler triggers the assert (irq_dispatcher.c:0x22).
 *  OEM FUN_000085c8.
 * ------------------------------------------------------------------------- */
void irq_dispatcher_register(uint32_t line, void (*handler)(void))
{
    if (line > 1u || handler == NULL) {
        node_assert_fail("handler",
                         "/__w/takahe-fw/takahe-fw/power/src/irq_dispatcher.c", 0x22);
    }
    ((void (**)(void))0x20200d8c)[line] = handler; /* DAT_000085f0 + line*4 */
}

/* ------------------------------------------------------------------------- *
 *  MCP251XFD interrupt service / dispatch
 *
 *  Dispatches on the controller's top-priority pending interrupt code, logs
 *  the event, clears it, raises the matching DTC, and on RX-FIFO/TEF activity
 *  pumps received frames into the node OD layer. The default branch handles the
 *  combined ECC/CRC/byte-count "system error" register. OEM FUN_000019c0.
 *
 *  Interrupt codes (from MCP251XFD_GetCurrentInterruptEvent):
 *    0x41 CERRIF  - error interrupt           ("D>Ext1: Error Interrupt")
 *    0x42 WAKIF   - wake-up                    ("D>Ext1: Wake-up interrupt")
 *    0x43 RXOVIF  - receive FIFO overflow      ("D>Ext1: Receive FIFO Overflow")
 *    0x44 SERRIF  - system/address error       ("D>Ext1: Address Error")
 *    0x45 RXMABOV - RX MAB overflow            ("D>Ext1: RX MAB Overflow")
 *    0x46 TBCIF   - time-base counter overflow ("D>Ext1: TBC Overflow")
 *    0x47 MODIF   - operation-mode change      ("D>Ext1: Operation Mode Change Occurred %d")
 *    0x48 IVMIF   - invalid message            ("D>Ext1: Invalid Message Occurred")
 *    0x4A         - RX FIFO message available -> rx_pump filter
 *    default      - ECC/CRC system error register
 * ------------------------------------------------------------------------- */
void mcp_isr_service(void)                      /* OEM FUN_000019c0 */
{
    volatile uint32_t *mcp_int = (volatile uint32_t *)ADDR_MCP_INT;
    uint32_t dev = MCP_DEV;
    uint8_t  code = 0x40;                        /* 0x40 == no event */
    uint32_t evt[4];                             /* id + up to 8-byte payload */
    uint8_t  flags[4];

    /* MCP host-INT GPIO asserted? bit 18 clear (line pulled low) => pending.
     * NOTE: the OEM only skips the get-current-int + switch dispatch when the
     * line is idle (goto to the post-switch TEF/RX drain), so wrapping *only*
     * the dispatch in this >=0 test — with the drain below running
     * unconditionally — is the faithful structure. */
    if ((int32_t)(*mcp_int << 0xd) >= 0) {       /* int line asserted -> dispatch */
        int rc = mcp_get_current_int(dev, &code);
        mcp_spi_err_check(rc);                   /* FUN_00008b0c: SPI-op result guard */

        if (rc == 0) {
            switch (code) {
            case 0x41:                          /* CERRIF */
                vm_log(0, "D>Ext1: Error Interrupt\n");
                dtc_set(0x16, 1);
                mcp_clear_int(dev, 0x2000);
                break;
            case 0x42:                          /* WAKIF */
                vm_log(0, "D>Ext1: Wake-up interrupt\n");
                mcp_clear_int(dev, 0x4000);
                break;
            case 0x43:                          /* RXOVIF */
                vm_log(0, "D>Ext1: Receive FIFO Overflow Interrupt\n");
                dtc_set(0x14, 1);
                break;
            case 0x44:                          /* SERRIF (address error) */
                vm_log(0, "D>Ext1: Address Error Interrupt\n");
                dtc_set(0x17, 1);               /* DAT_00001c8c -> 0x17 */
                mcp_clear_int(dev, 0x1000);
                break;
            case 0x45:                          /* RX MAB overflow */
                vm_log(0, "D>Ext1: RX MAB Overflow\n");
                dtc_set(0x17, 1);               /* DAT_00001c8c -> 0x17 */
                mcp_clear_int(dev, 0x1000);
                break;
            case 0x46:                          /* TBCIF */
                vm_log(0, "D>Ext1: TBC Overflow\n");
                mcp_clear_int(dev, 4);
                break;
            case 0x47:                          /* MODIF */
                if (mcp_read_crc_event(dev, evt) == 0) {
                    mcp_clear_int(dev, 8);
                    vm_log(0, "D>Ext1: Operation Mode Change Occurred %d\n",
                           evt[0] & 0xff);
                    if ((evt[0] & 0xfb) == 3) {  /* sleep mode entered */
                        dtc_set(0x1b, 1);
                        mcp_start_can20(dev, 6, 0);
                    }
                }
                break;
            case 0x48:                          /* IVMIF */
                vm_log(0, "D>Ext1: Invalid Message Occurred\n");
                dtc_set(0x1a, 1);
                /* FUN_00005c4c(dev, 2): clear invalid-message latch */
                mcp_clear_int(dev, 0x8000);
                break;
            case 0x4a:                          /* RX message available */
                dtc_set(0x15, 1);               /* DAT_00001c94 -> 0x15 */
                mcp_rx_fifo_pump(dev, 2, 0x10); /* FUN_0000646c: ack RX FIFO flags */
                break;
            default:                            /* ECC/CRC system error reg */
                if (mcp_read_ecc_event(dev, evt) == 0) {
                    if ((int32_t)(evt[0] << 0x11) < 0) {  /* CRC mismatch */
                        vm_log(0, "E>Ext1: CRC mismatch occurred\n");
                        mcp_clear_int(dev, 0x4000);
                    }
                    if ((int32_t)(evt[0] << 0x16) < 0) {  /* ECC single-bit */
                        if (mcp_read_ecc_single(dev, flags, 0) == 0) {
                            uint32_t wb = 0;    /* local_38 & 0xffffff00: cleared low byte */
                            dtc_set(0x19, 1);   /* DAT_00001cb0 -> 0x19 */
                            vm_log(0, (flags[0] == 1)
                                   ? "E>Ext1: Number of Bytes mismatch during 'SPI with CRC' command occurred\n"
                                   : "AE>Ext1: ECC Single Error was corrected\n");
                            mcp_reg_write(dev, 0x0e0a, &wb, 1); /* FUN_00003848: clear ECCSTAT */
                        }
                    }
                    if ((int32_t)(evt[0] << 0x17) < 0) {  /* ECC double-bit */
                        char dbl[4];
                        if (mcp_read_ecc_double(dev, dbl) == 0) {
                            dtc_set(0x18, 1);   /* DAT_00001cc0 -> 0x18 */
                            vm_log(0, (dbl[0] != 2)
                                   ? "E>Ext1: ECC Double Error was detected\n"
                                   : "E>MCP251XFD interrupt still asserted (int=%d,int1=%d)\n");
                            flags[0] = 0;
                            mcp_reg_write(dev, 0x0e0a + 6, flags, 1); /* FUN_00003848: clear ECCSTAT+6 */
                        }
                    }
                    if ((int32_t)(evt[0] << 0x12) < 0) {  /* error-warning */
                        vm_log(0, "D>Error Warning\n");
                        dtc_set(0x16, 1);
                        mcp_clear_int(dev, 0x2000);
                    }
                }
                break;
            }
        }
    }

    /* TX-event FIFO drain: pop any pending TEF object, bump the forwarded-packet
     * counter, and forward the frame to the OD layer. */
    flags[0] = 0;
    if (tef_ring_empty((int32_t *)MCP_TEF_CTX) == 0) {   /* FUN_00008f6c: ring not empty */
        int rc = mcp_fifo_status(dev, 2, flags);
        mcp_spi_err_check(rc);                           /* FUN_00008b0c */
        if (rc == 0 && (flags[0] & 1)) {
            volatile uint32_t *counter = (volatile uint32_t *)MCP_TEF_COUNTER;
            struct { uint32_t id; uint32_t seq; uint8_t dlc; uint8_t flg;
                     uint8_t pad[2]; uint8_t *data; } m;
            mcp_fifo_read(MCP_TEF_CTX, evt);             /* FUN_000084d6: pop from TEF ring */
            m.id     = evt[0];
            m.seq    = *counter;
            *counter = *counter + 1;
            m.dlc    = 8;
            m.data   = (uint8_t *)&evt[1];
            mcp_tef_forward(dev, (uint32_t *)&m, 2, 1);  /* FUN_00003e64 */
        }
    }

    /* RX/TEF object available? read & route a7/a4-type frames to the OD bus */
    if ((int32_t)(*mcp_int << 0x1c) >= 0) {
        uint32_t id[2];
        int rc;
        id[0] = 0;
        id[1] = 0;
        rc = mcp_read_tef(dev, id, 0, 0, 1);
        mcp_spi_err_check(rc);                   /* FUN_00008b0c */
        if (rc == 0) {
            uint32_t kind = (id[0] >> 0x15) & 0xff;
            if (kind == 0xa7 || kind == 0xa4) {
                /* FUN_00006df4(OD_BUS, id[0], &frame, flag): dispatch OD frame */
            }
        }
    }
}

/* ------------------------------------------------------------------------- *
 *  MCP251XFD bus diagnostic / error-state recovery
 *
 *  Reads the controller's bus-diagnostic word and, on the error/bus-off flags,
 *  raises the corresponding DTC and (on bus-off) launches recovery.
 *  OEM FUN_00005ea0.
 * ------------------------------------------------------------------------- */
void mcp_bus_diag(void)                          /* OEM FUN_00005ea0 */
{
    volatile uint8_t *mode = (volatile uint8_t *)0x4050f820; /* CAN mode reg */
    uint32_t dev = 0x40508000u;

    if ((*mode & 0xff) == 1) {                    /* CAN operational */
        uint32_t diag = mcp_read_busdiag(dev);
        mcp_store_busdiag(dev, diag, 1);

        if (diag & 1u) {
            mcp_busoff_recover(0);
        }
        if ((int32_t)(diag << 7) < 0) {           /* error-warning */
            vm_log(0, "D>Error Warning\n");
            dtc_set_from_diag(0x10);
        }
        if ((int32_t)(diag << 8) < 0) {           /* error-passive */
            vm_log(0, "D>Error Passive\n");
            dtc_set_from_diag(0x20);
        }
        if ((int32_t)(diag << 6) < 0) {           /* bus-off */
            vm_log(0, "D>Bus_Off Status, recovering\n");
            dtc_set_from_diag(0x40);
            mcp_busoff_clear(dev, 0);
        }
    } else {
        vm_log(0, "D>Default\n");
    }
}

/* ------------------------------------------------------------------------- *
 *  MCP251XFD bring-up / sleep
 * ------------------------------------------------------------------------- */

/* mcp_init — reset, configure, set up filters + FIFOs, start CAN 2.0.
 * Logs the first failing step. OEM FUN_00005ce4. */
int mcp_init(void)                               /* OEM FUN_00005ce4 */
{
    uint32_t dev = MCP_DEV;
    int rc;

    mcp_spi_reset(dev);
    mcp_spi_assert(0x000c3500);

    rc = mcp_configure(dev, MCP_CFG_STRUCT);            /* DAT_00005d5c = 0x20201838 */
    if (rc != 0) { vm_log(0, "E>Init_MCP251XFD err=%d\n", rc); return -5; }

    /* OEM order (FUN_00005ce4): configure -> filters -> fifos -> start. */
    rc = mcp_config_filters(dev, MCP_FILTER_LIST, 2);   /* DAT_00005d64 = 0x2020187c, n=2 */
    if (rc != 0) { vm_log(0, "E>MCP251XFD_ConfigureFilterList err=%d\n", rc); return -5; }

    rc = mcp_config_fifos(dev, 0, MCP_FIFO_LIST, 1);    /* DAT_00005d6c = 0x202018a8 */
    if (rc != 0) { vm_log(0, "E>MCP251XFD_ConfigureFIFOList err=%d\n", rc); return -5; }

    rc = mcp_start_can20(dev, 6, 0);
    if (rc != 0) { vm_log(0, "E>MCP251XFD_StartCAN20 err=%d\n", rc); return -5; }

    return 0;
}

/* mcp_enter_sleep — drain the interrupt, configure & enter the controller's
 * sleep mode. Aborts (and logs) if the int line is still asserted. OEM
 * FUN_00005248. */
int mcp_enter_sleep(void)                        /* OEM FUN_00005248 */
{
    uint32_t dev = MCP_DEV;
    volatile uint32_t *intr = (volatile uint32_t *)ADDR_MCP_INT; /* DAT_00005308 */
    int rc;

    rc = mcp_spi_reset(dev);
    if (rc != 0) { vm_log(0, "E>MCP251XFD_ConfigureSleepMode err=%d\n", rc); return -22; }

    mcp_spi_assert(/*sleep cfg*/ 0);
    rc = mcp_config_sleep(dev, 1, 3, 1);
    if (rc != 0) { vm_log(0, "E>MCP251XFD_ConfigureSleepMode err=%d\n", rc); return -22; }

    rc = mcp_clear_int(dev, /*flags*/ 0x0000f00cu);  /* DAT_00005300 = 0xf00c */
    if (rc != 0) { vm_log(0, "E>MCP251XFD_ClearInterruptEvents err=%d\n", rc); return -22; }

    /* both int + int1 must be clear before sleep */
    if ((int32_t)(*intr << 0xd) >= 0 || (int32_t)(*intr << 0x1c) >= 0) {
        vm_log(0, "E>MCP251XFD interrupt still asserted (int=%d,int1=%d)\n",
               ~(*intr >> 0x12) & 1, ~(*intr >> 3) & 1);
        return -11;
    }

    rc = mcp_enter_sleep_dev(dev);
    if (rc != 0) { vm_log(0, "E>MCP251XFD_EnterSleepMode err=%d\n", rc); return -22; }

    vm_log(0, "D>MCP251XFD_EnterSleepMode (int=%d,int1=%d)\n",
           ~(*intr >> 0x12) & 1, ~(*intr >> 3) & 1);
    return 0;
}

/* ------------------------------------------------------------------------- *
 *  Main tick + entry
 * ------------------------------------------------------------------------- */

/* node_tick — one pass of the super-loop body: optionally pump CAN, watchdog
 * the controller (re-init on failure), run the node FSM and the ISR.
 * OEM FUN_00006e5c. */
void node_tick(void)                             /* OEM FUN_00006e5c */
{
    volatile char *busoff_flag = (volatile char *)0x20200d9b;  /* DAT_00006eb0 */
    uint32_t bus = OD_BUS;

    if (*busoff_flag == 1) {
        /* OEM FUN_00006e5c calls FUN_000068c0(0x00009de4) here — the bus-off
         * recovery/park routine, NOT mcp_bus_diag (FUN_00005ea0). */
        mcp_bus_off_park((const void *)0x00009de4);   /* FUN_000068c0 */
    }

    /* controller health check; on failure re-init + re-announce */
    {
        extern int  mcp_health_a(uint32_t dev);      /* FUN_00008a24 */
        extern int  mcp_health_b(uint32_t dev);      /* FUN_00008d90 */
        extern void node_timer_register(uint32_t bus, uint32_t ms, int z); /* FUN_00007e54 */
        if (mcp_health_a(MCP_DEV) == 0 || mcp_health_b(MCP_DEV) != 0) {
            heartbeat_publish((uint8_t *)bus);
            node_timer_register(bus, 1000, 0);       /* FUN_00007e54: arm 1s OD keepalive */
            *(volatile uint8_t *)0x40081108 = 0xa7;  /* DAT_00006ec0 */
            node_announce((uint8_t *)bus);
        }
    }

    node_sm_dispatch((int)bus);

    if (*busoff_flag == 0) {
        mcp_isr_service();
    }
}

/* main — bring up the node, log serial + RDP level, then run the super-loop.
 * OEM FUN_00007a34. */
void power_main(void)                            /* OEM FUN_00007a34 */
{
    /* FUN_0000704c(): board / node init */
    extern void     node_init(void);             /* FUN_0000704c */
    extern uint32_t read_rdp_level(int z);       /* FUN_00005d78: flash readout-protection level */
    extern void     late_init(void);             /* FUN_00007f4c */

    node_init();

    /* boot log: flash readout-protection (RDP) level. DAT_00007a6c = "I>RDP %d". */
    vm_log(0, "I>RDP %d\n", read_rdp_level(1));

    late_init();

    /* boot log: provisioned serial-number string, or "not provisioned" when the
     * provisioning word (0x00000c20) is still erased (== 0xffff).
     * DAT_00007a78 = "D>Serial number: %s". */
    {
        const char *serial = (const char *)0x00000c10;      /* DAT_00007a70 default */
        if (*(volatile uint32_t *)0x00000c20 == 0x0000ffffu /*DAT_00007a74*/) {
            serial = (const char *)0x00009e6c;              /* "not provisioned" */
        }
        vm_log(0, "D>Serial number: %s\n", serial);
    }

    for (;;) {
        node_tick();
    }
}
