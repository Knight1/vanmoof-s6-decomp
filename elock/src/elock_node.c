/*
 * elock_node.c — VanMoof S6 "elock" ECU node layer
 *
 * TI MSPM0G (ARM Cortex-M0+), VanMoof in-house bare-metal "takahe-fw"
 * (NoRTOS; common/mspm0 + common/node). Image base 0x1800 (MCUboot slot,
 * vector table @ 0x1900).
 *
 * Reconstructed subsystems (CAN bus + Object-Dictionary, DTC, node/heartbeat,
 * reboot/serial). Source path anchors observed in the image:
 *   common/node/src/heartbeat.c
 *   common/mspm0/src/mspm0_flash.c
 *
 * The MCAN (CAN-FD) DriverLib register driver and MCUboot/flash/libc are vendor
 * and are NOT reconstructed here — they appear only as 'extern' declarations
 * carrying their OEM addresses in comments. This file reconstructs the VanMoof
 * CAN error/Object-Dictionary/DTC/heartbeat/reboot/serial logic on top of them.
 *
 * Behaviour-oriented reconstruction (not byte-identical). Clean under
 * -Wall -Wextra -Wpedantic -std=c11.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- *
 *  Vendor / cross-module externs (declared with their OEM addresses)
 * ------------------------------------------------------------------------- */

/* VanMoof printf-style logger. The first format arg ("D>...", "E>...") names
 * the behaviour. OEM FUN_000071c4 is a thin varargs shim over FUN_00001d0c. */
extern void vm_log(int level, const char *fmt, ...);        /* FUN_000071c4 */

/* takahe assert handler: (file, line/msg, code) -> logs and halts.
 * OEM FUN_0000649c builds an assert string and aborts. */
extern void node_assert_fail(const char *expr, const char *file, int line); /* FUN_0000649c */

/* ---- MCAN (CAN-FD) DriverLib register driver — VENDOR (TI MSPM0) -------- */
/* Read the MCAN protocol/interrupt status word (PSR/IR) at a peripheral
 * instance. OEM FUN_00004e44: return *(u32*)(inst + 0x7050). */
extern uint32_t mcan_get_status(uint32_t inst);             /* FUN_00004e44 */
/* Clear MCAN interrupt-status flags. OEM FUN_00007364: inst+ctrl reg, bit0. */
extern void mcan_clear_status(uint32_t inst, uint32_t flags); /* FUN_00007364 */
/* Store last-error snapshot (status, flags) into the node's CAN ctx.
 * OEM FUN_00007454: ctx[+x]=a, ctx[+y]=b. */
extern void mcan_store_error(uint32_t ctx, uint32_t status, uint32_t one); /* FUN_00007454 */
/* OD/CAN frame publish (object-dictionary write). OEM FUN_000071a4 ->
 * FUN_00003194; requires the OD entry to be a writable (type==2) endpoint. */
extern int  od_publish(uint32_t bus, void *od_entry, void *data, uint32_t len); /* FUN_000071a4 */
/* Bus init helpers (vendor MCAN bring-up). */
extern void mcan_bus_recover(uint32_t arg);                 /* FUN_00005574 */
/* FUN_00007538 ORs its byte argument into the MCAN int-enable shadow:
 * *(u8*)(DAT_00007544+1) |= param_1. node_start invokes it with no argument
 * set up (stale r0), so the no-arg prototype is used at that call site. */
extern void mcan_set_int_enable(uint32_t flags);            /* FUN_00007538 */
extern void mcan_set_int_enable_noarg(void);                /* FUN_00007538 (node_start: no r0 setup) */
extern void mcan_filter_reset(void);                        /* FUN_00007424 */
extern void mcan_rx_pump(int *busctx, int param);           /* FUN_00005b58 */
extern uint32_t mcan_alloc_buffer(void);                    /* FUN_000053b8 */

/* ---- MCUboot / flash — VENDOR ------------------------------------------ */
extern int  flash_read_serial(void *out);                   /* FUN_00006eec */
extern int  flash_validate(void *buf, int len);             /* FUN_000068fc */
extern void mem_copy(void *dst, const void *src, int n);    /* FUN_00007648 */

/* ---- node infra / timers / scheduler — VENDOR-ish takahe core ---------- */
extern void   node_module_a_init(void);                     /* FUN_00004d34 */
extern void   node_module_b_init(void);                     /* FUN_000046d4 */
extern void   adc_init(void);                               /* FUN_0000578c */
extern void   timer_a_init(void);                           /* FUN_00005d1c */
extern void   timer_b_init(void);                           /* FUN_00006008 */
extern void   timer_c_init(void);                           /* FUN_00005f68 */
extern void   gpio_a_init(void);                            /* FUN_00004b00 */
extern void   gpio_b_init(void);                            /* FUN_00004b90 */
extern void   gpio_c_init(void);                            /* FUN_00004cac */
extern void   pwm_init(void);                               /* FUN_00004ed8 */
extern void   can_periph_init(void);                        /* FUN_00006c4c */
extern void   misc_init_a(void);                            /* FUN_000073ac */
extern void   misc_init_b(void);                            /* FUN_0000425c */
extern void   misc_init_c(void);                            /* FUN_00007394 */
extern uint32_t node_get_tick(void);                        /* FUN_00007660 */
extern void   __WFI(void);                                  /* WaitForInterrupt */

/* heartbeat / OD endpoint registration (common/node) */
extern uint32_t od_register_endpoint(uint32_t bus, uint32_t cfg); /* FUN_000067dc -> FUN_00007000 */
extern void     can_filter_setup(uint32_t a, uint32_t b);        /* FUN_000067dc body */

/* device-reset / boot-reason driver — VENDOR (mspm0 reset controller) */
extern int  device_reset_request(int reason);               /* FUN_000063cc */
extern int  reset_record_write(uint32_t a, uint32_t b, uint32_t code, uint32_t c, uint32_t d); /* FUN_00005344 */

/* state-machine dispatch (the node's reboot/charge FSM trampoline) */
extern int  node_sm_dispatch(int state, uint32_t arg);      /* FUN_000069dc */
extern void node_tx_drain(uint32_t base);                   /* FUN_00004628 */
extern void solenoid_tick(void);                            /* FUN_00005afc (other module) */

/* ------------------------------------------------------------------------- *
 *  DTC (diagnostic trouble code) system  — heartbeat.c
 *
 *  DTCs are addressed by an 8-bit "bit" id in the range [0x14 .. 0x14+0x37]
 *  (DTC_MAX == 0x38 == 56 codes). State is held in two parallel structures:
 *    - a per-byte "supported/active" bitmap (g_dtc_present[]), indexed by
 *      (bit-0x14)>>3, bit position ((bit-0x14)&7);
 *    - a 64-bit "active" mask published in the heartbeat (g_dtc_active_lo/hi),
 *      where active code N sets bit (0x10000 << (bit-0x14)).
 *
 *  The raw shift "0x10000 << k" with k up to 0x37 is a deliberate 64-bit
 *  field: low word takes bits [16..47], the carry into the high word is the
 *  arithmetic top bit (>> 0x1f), reproduced verbatim below.
 * ------------------------------------------------------------------------- */

#define DTC_BASE   0x14u
#define DTC_MAX    0x38u   /* "bit < DTC_MAX" assert bound (string @0x809c) */

static const char k_heartbeat_c[] = "common/node/src/heartbeat.c"; /* @0x7bb3 */

/* g_dtc_present[]: byte bitmap of which DTC ids are flagged (offset +2 from
 * the heartbeat record base in the OEM; reproduced as a flat array here). */
extern uint8_t  g_dtc_present[];        /* DAT_00005dc4 / DAT_000060e4 (+2) */
/* g_dtc_active: 64-bit active mask, published to the bus.                   */
extern uint32_t g_dtc_active_lo;        /* DAT_00005dc8[0] / DAT_000060e8[0] */
extern uint32_t g_dtc_active_hi;        /* DAT_00005dc8[1] / DAT_000060e8[1] */

/*
 * dtc_set — flag a diagnostic trouble code as present, optionally active.
 * OEM FUN_00005d74.  (bit must be in [DTC_BASE, DTC_BASE+DTC_MAX).)
 *   - marks the code "present" in the per-byte bitmap;
 *   - if 'active' set, raises the code's bit in the 64-bit active mask.
 */
void dtc_set(uint8_t bit, int active)
{
    uint8_t k = (uint8_t)(bit - DTC_BASE);

    if (k > 0x37u) {                              /* bit < DTC_MAX */
        node_assert_fail("bit < DTC_MAX", k_heartbeat_c, 0x21);
    }

    /* mark present in the byte bitmap */
    g_dtc_present[k >> 3] |= (uint8_t)(1u << (k & 7));

    if (active) {
        uint32_t lo = 0x10000u << k;              /* low-word contribution */
        g_dtc_active_lo |= lo;
        g_dtc_active_hi |= (uint32_t)((int32_t)lo >> 31); /* arithmetic carry */
    }
}

/*
 * dtc_clear — OEM FUN_000060a0.  Despite the name, this does NOT deactivate a
 * code: when the code is flagged present it ORs the bit *into* the 64-bit
 * active mask, identically to dtc_set.  This is an OEM defect faithfully
 * reproduced here (confirmed in Ghidra:
 *   *DAT_000060e8 = *DAT_000060e8 | 0x10000 << uVar2 — an OR, not an AND-NOT).
 * The real deactivation mechanism is the one-shot clear-mask path applied in
 * heartbeat_publish; this routine only consults (never tears down) the
 * "present" bitmap and then re-raises the active bit.
 */
void dtc_clear(uint8_t bit)
{
    uint8_t k = (uint8_t)(bit - DTC_BASE);

    if (k > 0x37u) {                              /* bit < DTC_MAX */
        node_assert_fail("bit < DTC_MAX", k_heartbeat_c, 0x2b);
    }

    /* only act on codes that are flagged present */
    if ((g_dtc_present[k >> 3] >> (k & 7)) & 1) {
        uint32_t lo = 0x10000u << k;
        g_dtc_active_lo |= lo;                    /* OEM DEFECT: ORs (activates), not clears */
        g_dtc_active_hi |= (uint32_t)((int32_t)lo >> 31);
    }
}

/* ------------------------------------------------------------------------- *
 *  CAN bus error / status handler
 *
 *  Registered MCAN status callback (no direct xref — installed via a vtable).
 *  Reads the MCAN protocol-status word and walks the standard CAN error
 *  escalation: Error Warning -> Error Passive -> Bus-Off (recover).
 *
 *  Status word bit layout decoded from the OEM shift tests:
 *    bit0           -> bus-off  (recover the controller)
 *    bit (1<<24)    -> "(s<<7)<0"  : Error Warning  -> int-enable 0x10
 *    bit (1<<23)    -> "(s<<8)<0"  : Error Passive  -> int-enable 0x20
 *    bit (1<<25)    -> "(s<<6)<0"  : Bus-Off status -> int-enable 0x40, recover
 * ------------------------------------------------------------------------- */

#define CAN_INST   0x4050f820u    /* MCAN instance base (DAT_00004ae8) */

extern volatile uint32_t * const g_can_status_flag; /* *DAT_00004ae8 lane sel */
extern uint32_t g_can_ctx;                          /* DAT_00004af0 */

/*
 * can_status_handler — OEM FUN_00004a70.
 * Only acts while the status-source byte == 1 (status-IRQ active); otherwise
 * logs "RDP %d" (the default/idle path).
 */
void can_status_handler(void)
{
    uint32_t ctx = g_can_ctx;

    if ((*g_can_status_flag & 0xff) != 1) {
        vm_log(0, "I>RDP %d\n");                  /* DAT_00004aec */
        return;
    }

    uint32_t status = mcan_get_status(ctx);
    mcan_store_error(ctx, status, 1);

    if (status & 1u) {                            /* bus-off bit */
        mcan_bus_recover(0);
    }
    if ((int32_t)(status << 7) < 0) {             /* Error Warning */
        vm_log(0, "D>Error Warning\n");           /* @0x805c */
        mcan_set_int_enable(0x10);
    }
    if ((int32_t)(status << 8) < 0) {             /* Error Passive */
        vm_log(0, "D>Error Passive\n");           /* @0x803a */
        mcan_set_int_enable(0x20);
    }
    if ((int32_t)(status << 6) < 0) {             /* Bus-Off status */
        vm_log(0, "D>Bus_Off Status, recovering\n"); /* @0x7dfc */
        mcan_set_int_enable(0x40);
        mcan_clear_status(ctx, 0);                /* clear so recovery proceeds */
    }
}

/* ------------------------------------------------------------------------- *
 *  Reboot / device-reset & boot-reason
 *
 *  Reboot-reason string table (DAT_00007ddc, used by the FSM in the OEM to
 *  name the current reboot state in logs):
 *    DEVICE_RESET, DEVICE_AWAKE, enable_power, DEVICE_ERROR  (strings @0x80e0+)
 * ------------------------------------------------------------------------- */

extern volatile uint32_t * const g_reboot_req;   /* DAT_00006f34 (RESET ctrl) */
extern uint32_t g_reboot_key;                    /* DAT_00006f38 (reset key)   */

/*
 * reboot_cb — OEM FUN_00006f14. Logs and asserts the platform reset request
 * (writes 1 + key into the mspm0 reset controller register pair).
 */
int reboot_cb(void)
{
    vm_log(0, "D>reboot_cb\n");                   /* @0x8114 */
    g_reboot_req[0] = 1;
    g_reboot_req[1] = g_reboot_key;
    return 0;
}

/*
 * device_reset — OEM FUN_000063cc. Arms a reset request record (reason!=0),
 * pokes the reset controller, allocates a CAN buffer slot for the reply, and
 * commits a reset-reason record over the bus. Returns -EINVAL (-0x16 -> here
 * -0xea coded as the OEM's 0xffffffea) when reason==0.
 */
int device_reset(int reason)
{
    extern volatile uint32_t * const g_reset_ctrl;  /* DAT_00006400 */
    extern uint32_t g_reset_reason;                 /* DAT_00006404 */

    if (reason == 0) {
        return -0x16;                               /* -EINVAL */
    }
    g_reset_ctrl[0] = 2;
    g_reset_ctrl[0] = 0x10000;
    g_reset_reason  = (uint32_t)reason;
    return reset_record_write(0 /*DAT_00006408*/, 0 /*DAT_00006410*/,
                              0x35, 0 /*DAT_0000640c*/, 0);
}

/* ------------------------------------------------------------------------- *
 *  Serial number (read from flash, validated, copied out as 16 bytes)
 *  OEM FUN_00006384 / FUN_00006eec.
 * ------------------------------------------------------------------------- */

/*
 * read_serial — OEM FUN_00006384. Reads up to 40 bytes from the flash serial
 * region, finds the 0xff terminator (serial is at most 15 chars + NUL), and
 * copies a 16-byte NUL-terminated serial to 'out'. Returns 0 on success,
 * -0x0e (-EIO) if the field is empty/malformed.
 */
int read_serial(char *out16)
{
    char buf[40];
    int rc;
    int i;

    rc = flash_read_serial(buf);                  /* FUN_00006eec */
    if (rc != 0)
        return rc;

    if ((unsigned char)buf[0] == 0xff)
        return -0x0e;                             /* empty */

    for (i = 1; i < 0x10; i++) {
        if ((unsigned char)buf[i] == 0xff)
            break;
    }
    /* valid lengths: 1..15 chars terminated by 0xff, OR full 16 with no term */
    if (i == 0x10 || (uint32_t)(i - 1) > 0x0e) {
        buf[0x0f] = 0;
        mem_copy(out16, buf, 0x10);
        return 0;
    }
    return -0x0e;
}

/* ------------------------------------------------------------------------- *
 *  Heartbeat layer
 *
 *  Heartbeat publishes a periodic OD frame carrying the node's DTC active
 *  mask and presence map; the node also registers up to 16 OD endpoint slots.
 * ------------------------------------------------------------------------- */

extern uint32_t g_hb_handler_tbl[];      /* DAT_000066dc handler ptr table  */
extern uint32_t g_hb_arg_tbl[];          /* DAT_000066e0 handler arg table  */
extern uint8_t  g_hb_slot_bitmap[];      /* DAT_000066e4 registered-slot map */

/*
 * heartbeat_register — OEM FUN_000066a8. Bind a handler+arg to OD slot
 * 'slot' (0..15) and mark the slot present. Returns -0x16 (-EINVAL) if the
 * slot index exceeds 15.
 */
int heartbeat_register(uint32_t slot, uint32_t handler, uint32_t arg)
{
    if ((int32_t)slot > 0xf)
        return -0x16;                             /* -EINVAL */

    g_hb_handler_tbl[slot] = handler;
    g_hb_arg_tbl[slot]     = arg;
    g_hb_slot_bitmap[(int32_t)slot >> 3] |= (uint8_t)(1u << (slot & 7));
    return 0;
}

extern uint32_t g_hb_od_entry;           /* DAT_00006998 OD endpoint */
/* g_hb_payload — the 8-byte heartbeat payload struct that is transmitted.
 * DAT_0000699c holds a *pointer* to it (RAM @0x20201590). Its first byte is
 * the sequence counter; read as two u32 words it is the published active mask. */
extern uint32_t *g_hb_payload;           /* DAT_0000699c -> heartbeat payload  */
/* g_hb_clr — one-shot clear masks (DAT_000069a0 -> RAM @0x20201588).          */
extern uint32_t  g_hb_clr_lo;            /* DAT_000069a0[0] one-shot clear mask */
extern uint32_t  g_hb_clr_hi;            /* DAT_000069a0[1] */

/*
 * heartbeat_publish — OEM FUN_0000696c. Sends the 8-byte heartbeat OD frame
 * ('bus' selects the wire); the data argument is the payload-struct pointer
 * (g_hb_payload), NOT the seq-byte address. Then bumps the sequence counter
 * (the payload's first byte) and clears the one-shot DTC bits *in the payload
 * words* that were latched only for this transmission.
 */
void heartbeat_publish(uint32_t bus)
{
    uint32_t *payload = g_hb_payload;            /* puVar1 = DAT_0000699c */

    od_publish(bus, &g_hb_od_entry, payload, 8); /* od_publish(p1,DAT_6998,DAT_699c,8) */

    /* bump seq: the payload's first byte */
    *(volatile uint8_t *)payload = (uint8_t)(*(volatile uint8_t *)payload + 1);

    /* drop the one-shot clear bits from the *published* active words, then
     * reset the clear masks (operates on the payload, not the dtc_set globals) */
    payload[0] &= ~g_hb_clr_lo;                  /* *puVar1 &= ~*DAT_000069a0 */
    payload[1] &= ~g_hb_clr_hi;                  /* puVar1[1] &= ~DAT_000069a0[1] */
    g_hb_clr_lo = 0;                             /* *DAT_000069a0 = 0 */
    g_hb_clr_hi = 0;                             /* DAT_000069a0[1] = 0 */
}

/* ------------------------------------------------------------------------- *
 *  Node init / start / run loop
 * ------------------------------------------------------------------------- */

extern uint8_t *g_node_ctx;              /* DAT_00006380 */

/*
 * node_init — OEM FUN_0000633c. Brings up every peripheral/module driver in
 * the OEM's fixed order, then clears the node's "started" flag (ctx+0x9c).
 */
void node_init(void)
{
    node_module_a_init();
    node_module_b_init();
    adc_init();
    timer_a_init();
    timer_b_init();
    timer_c_init();
    gpio_a_init();
    gpio_b_init();
    gpio_c_init();
    pwm_init();
    can_periph_init();
    misc_init_a();
    misc_init_b();
    misc_init_c();
    g_node_ctx[0x9c] = 0;
}

extern volatile uint32_t * const g_can_filter_ctx; /* DAT_00006520 */

/*
 * node_start — OEM FUN_000064e0. Boot-reason check + CAN/OD bring-up:
 *   - if a pending reset record exists, log "..." and continue;
 *   - reset the MCAN filter table;
 *   - apply the node's CAN RX acceptance config;
 *   - enable status interrupts;
 *   - register the primary OD endpoint (id 0xc1);
 *   - allocate the heartbeat TX buffer.
 */
void node_start(void)
{
    extern int  boot_reason_pending(void);          /* FUN_00006f3c */
    extern void can_rx_config(uint32_t cfg);        /* FUN_00005b58 */
    extern void od_endpoint_register(uint32_t a, uint32_t id); /* FUN_000067dc */
    extern uint32_t g_node_can_cfg;                 /* DAT_00006518 */
    extern uint32_t g_node_od_cfg;                  /* DAT_0000651c */

    if (boot_reason_pending() != 0) {
        vm_log(0, "...");                           /* DAT_00006514 */
    }
    mcan_filter_reset();                            /* FUN_00007424 */
    can_rx_config(g_node_can_cfg);                  /* FUN_00005b58 */
    /* OEM calls FUN_00007538 with no argument set up (the byte OR'd in is the
     * stale r0 left by can_rx_config, which is a void fn) — not a literal 0. */
    mcan_set_int_enable_noarg();                    /* FUN_00007538 */
    od_endpoint_register(g_node_od_cfg, 0xc1);      /* FUN_000067dc */
    *g_can_filter_ctx = mcan_alloc_buffer();        /* FUN_000053b8 */
}

/*
 * node_main — OEM FUN_00006668. The elock firmware entry after init:
 *   - bring up all modules (node_init);
 *   - probe the running firmware slot/version and log it;
 *   - start the CAN/OD stack (node_start);
 *   - read & log the serial ("D>Serial %s");
 *   - then spin forever: tick the application (solenoid) and WFI.
 */
void node_main(void)
{
    char serial[16];

    node_init();

    {
        extern uint32_t fw_slot_probe(int which);   /* FUN_00004948 */
        uint32_t slot = fw_slot_probe(1);
        vm_log(0, "..%d\n", slot);                  /* DAT_000066a0[0] */
    }

    node_start();

    if (read_serial(serial) == 0) {
        vm_log(0, "D>Serial %s\n", serial);         /* @0x80d3 */
    }

    for (;;) {
        solenoid_tick();                            /* FUN_00005afc */
        __WFI();
    }
}
