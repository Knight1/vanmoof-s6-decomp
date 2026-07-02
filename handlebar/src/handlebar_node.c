/*
 * VanMoof S6 handlebar ECU - CAN/OD node layer + OTA self-update
 * Target: TI MSPM0G (ARM Cortex-M0+, no FPU), takahe-fw (NoRTOS).
 * Image base 0x1800 (MCUboot slot; vector table 0x1900).
 *
 * Reconstructed from Ghidra program "handlebar.bin". Addresses in the
 * OEM-addr comments are the load addresses with the image at base 0x1800.
 *
 * This file reconstructs the VanMoof-authored node/CAN/OD/DTC/heartbeat and
 * the sys_image_* OTA self-updater. Vendor code (TI MSPM0 DriverLib register
 * I/O, the MCAN/MCP251xFD CAN driver, MCUboot/sys_image services, libc and
 * the printf-style logger) is NOT reconstructed; each such call is declared as
 * a local `extern` with its OEM address in a comment.
 *
 * Cortex-M0+ has no FPU; integer math only. C11, -Wall -Wextra -Wpedantic.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- */
/* Vendor / runtime functions - declared, not reconstructed.                 */
/* ------------------------------------------------------------------------- */

/* printf-style logger; fmt strings carry "D>"/"E>" severity prefix.
 * OEM 0x6dec is a varargs trampoline into the real vfprintf-style sink at
 * 0x19c0. We model it with a fixed-arg extern (calls are all <=3 args). */
extern void vm_log(int chan, const char *fmt, ...); /* OEM 0x6dec -> 0x19c0 */

/* TI MSPM0 flash DriverLib (vendor). */
extern void   flash_cmd_exec(uint32_t flashctl, uint32_t addr, uint32_t mode);     /* OEM 0x3e70 */
extern void   flash_program64(uint32_t flashctl, uint32_t addr, uint32_t cmd);     /* OEM 0x6f5c */
extern void   flash_write_words(uint32_t flashctl, uint32_t addr,
                                const void *src, uint32_t n, uint32_t mode);        /* OEM 0x4cdc */
extern int    flash_program_word(uint32_t flashctl, uint32_t addr);                /* OEM 0x6f44 */
extern void   flash_set_data(uint32_t flashctl, uint32_t addr, void *p);           /* OEM 0x696c */

/* MCUboot / sys_image image-management services (vendor). */
extern int    sys_image_open(int slot, void *desc);              /* OEM 0x6dac */
extern int    sys_image_validate(int slot, uint32_t len, int *out);/* OEM 0x5e94 (via 0x43ec) */
extern int    sys_image_gate(void);                              /* OEM 0x7258 : update gate (stub -> 0) */
extern int    sys_image_prep(void);                              /* OEM 0x4b44 : stage/verify prep       */

/* libc-ish helpers (vendor / toolchain). */
extern void  *vm_memcpy(void *dst, const void *src, uint32_t n);  /* OEM 0x7228 */
extern void  *vm_memset(void *dst, int c, uint32_t n);           /* OEM 0x71a8 */
extern void   vm_memset3(void *dst, int c, uint32_t n);          /* OEM 0x7228 dup (3-arg) */

/* CAN driver send hook is reached via a function pointer at node[+4]. */

/* Scheduler / time / IRQ primitives (vendor, NoRTOS port). */
extern uint32_t tick_ms(void);          /* OEM 0x7248 */
extern uint32_t tick_ms2(void);         /* OEM 0x7238 */
extern uint32_t uptime_ticks(void);     /* OEM 0x71c0 / 0x71c8 */
extern void     critical_enter(uint32_t lock);  /* OEM 0x71e4 */
extern void     irq_disable(void);              /* OEM disableIRQinterrupts */
extern void     irq_enable(void);               /* OEM enableIRQinterrupts */
extern void     wait_for_interrupt(void);       /* OEM WaitForInterrupt */

/* ------------------------------------------------------------------------- */
/* Return / error codes (negative errno-style, observed in the image).       */
/* ------------------------------------------------------------------------- */
#define NODE_OK            0
#define E_IO             (-5)    /* 0xfffffffb -> -5  (image open / xfer)     */
#define E_INVAL          (-22)   /* 0xffffffea -> -22                         */
#define E_BADCRC         (-34)   /* 0xffffffde -> -34 (Image CRC failed)      */
#define E_NODEV          (-14)   /* 0xfffffff2 -> -14 (validate/size failed)  */
#define E_NOENT          (-2)    /* 0xfffffffe -> -2  (no OD endpoint)        */
#define E_OVERFLOW       (-12)   /* 0xfffffff4 -> -12 (multi-frame overflow)  */
#define E_AGAIN          (-145)  /* 0xffffff6f -> -145 (xfer timeout, 0x91)   */

/* sys_image image header magic / trailer constants (compared in 0x4990). */
extern const uint32_t IMG_HDR_MAGIC;   /* OEM DAT_0x4a1c */
extern const uint32_t IMG_TLV_MAGIC;   /* OEM DAT_0x4a20 */

/* Flash page geometry. */
#define FLASH_PAGE_SIZE   0x400u   /* 1 KiB MSPM0 sector; addr&0x3ff==0 req'd */

/* ------------------------------------------------------------------------- */
/* Diagnostic Trouble Code (DTC) flags.                                       */
/* The node maintains a 16-bit DTC bitfield in the heartbeat OD object; the   */
/* low byte is the node-status byte, the high byte (offset +1) carries DTCs.  */
/* ------------------------------------------------------------------------- */
extern volatile uint8_t *g_dtc_byte;   /* OEM DAT_0x7104 + 1, DAT_0x70f4 + 1 */

#define DTC_GENERIC      0x01u   /* set on a failed transaction / SM error    */
#define DTC_ERR_PASSIVE  0x10u   /* CAN controller Error-Passive              */
#define DTC_ERR_WARNING  0x20u   /* CAN controller Error-Warning              */
#define DTC_BUS_OFF      0x40u   /* CAN controller Bus-Off                    */

/* OEM 0x70f8 : set DTC bit(s). */
void dtc_set(uint8_t bits)
{
    *g_dtc_byte = (uint8_t)(*g_dtc_byte | bits);
}

/* OEM 0x70e8 : clear DTC bit(s). */
void dtc_clear(uint8_t bits)
{
    *g_dtc_byte = (uint8_t)(*g_dtc_byte & ~bits);
}

/* OEM 0x70e8 used with 0xff in the SM-error path -> clear all DTCs. */
#define dtc_clear_all() dtc_clear(0xffu)

/* ------------------------------------------------------------------------- */
/* CAN controller status register accessors (TI MCAN, vendor-mapped).         */
/* ------------------------------------------------------------------------- */
extern volatile uint32_t * const g_can_present;   /* OEM DAT_0x4a9c: !=1 -> "Default" */
extern volatile uint8_t  * const g_can_node;      /* OEM DAT_0x4aa4: CAN node base    */
extern const uint32_t      CAN_PSR_OFF;           /* OEM DAT_0x71a4: PSR reg offset   */
extern const uint32_t      CAN_STSAV_OFF1;        /* OEM DAT_0x7010                   */
extern const uint32_t      CAN_STSAV_OFF2;        /* OEM DAT_0x7014                   */
extern const uint32_t      CAN_CCCR_OFF;          /* OEM DAT_0x6f88: CCCR offset      */

/* OEM 0x719c : read CAN protocol-status register. */
static uint32_t can_read_psr(uint32_t can_node)
{
    return *(volatile uint32_t *)(can_node + CAN_PSR_OFF);
}

/* OEM 0x7004 : stash last-error words. */
static void can_save_status(uint32_t can_node, uint32_t a, uint32_t b)
{
    *(volatile uint32_t *)(can_node + CAN_STSAV_OFF1) = a;
    *(volatile uint32_t *)(can_node + CAN_STSAV_OFF2) = b;
}

/* OEM 0x6f74 : set/clear CCCR.INIT (request bus-off recovery). */
static void can_set_init(uint32_t can_node, uint32_t init)
{
    volatile uint32_t *r = (volatile uint32_t *)(can_node + CAN_CCCR_OFF);
    *r = (*r & 0xfffffffeu) | (init & 1u);
}

extern void can_drain_rx(int arg);   /* OEM 0x5270 : drain RX FIFO -> dispatch */

/*
 * OEM 0x4a24 : CAN protocol-status / error poll.
 * Reads PSR; saves it; on Bus-Off drains the RX FIFO and re-arms INIT for
 * recovery; raises the matching DTC for Error-Passive / Error-Warning / Bus-Off.
 *
 * PSR bit layout exercised here (TI MCAN PSR):
 *   (psr & 1)        -> bus-off pending work / RX drain trigger
 *   bit (psr<<7 <0)  -> bit24 : Error-Passive  (EP)
 *   bit (psr<<8 <0)  -> bit23 : Error-Warning  (EW)
 *   bit (psr<<6 <0)  -> bit25 : Bus-Off        (BO)
 */
void can_status_poll(void)
{
    uint32_t can_node = (uint32_t)g_can_node;
    uint32_t psr;

    if ((*g_can_present & 0xff) != 1) {
        vm_log(0, "D>Default\n");                 /* OEM str 0x7cba */
        return;
    }

    psr = can_read_psr(can_node);
    can_save_status(can_node, psr, 1);

    if ((psr & 1u) != 0)
        can_drain_rx(0);

    if ((int)(psr << 7) < 0) {                    /* Error Passive (bit24)    */
        vm_log(0, "D>Error Passive\n");           /* OEM str 0x7c23 */
        dtc_set(DTC_ERR_PASSIVE);
    }
    if ((int)(psr << 8) < 0) {                    /* Error Warning (bit23)    */
        vm_log(0, "D>Error Warning\n");           /* OEM str 0x7c56 */
        dtc_set(DTC_ERR_WARNING);
    }
    if ((int)(psr << 6) < 0) {                    /* Bus-Off (bit25)          */
        vm_log(0, "D>Bus_Off Status, recovering\n"); /* OEM str 0x7aa6 */
        dtc_set(DTC_BUS_OFF);
        can_set_init(can_node, 0);                /* clear INIT -> recover    */
    }
}

/* ------------------------------------------------------------------------- */
/* Object-Dictionary CAN address encoding + publish.                          */
/*                                                                            */
/* A VanMoof OD endpoint descriptor (18 bytes, the entry walked in od_rx):    */
/*   +0  u8  node_id                                                          */
/*   +1  u8  index_lo / mux                                                   */
/*   +2  u8  index_hi                                                         */
/*   +3  u8  flags (0 -> "this node owns it")                                 */
/*   +4  u8  kind  (0 RX, 1 publish/heartbeat, 2 block-xfer)                  */
/*   +8  u32 length (>8 -> multi-frame)                                       */
/*   +0xc u32 period_ticks                                                    */
/*   +0x14 code* handler                                                      */
/*                                                                            */
/* The 29-bit extended CAN ID packs node/index/subindex; od_publish builds it */
/* and pushes the payload via the driver send hook at node[+4], splitting     */
/* payloads >8 bytes into consecutive frames with a rolling sub-index nibble. */
/* ------------------------------------------------------------------------- */

/* node object: byte[0]=node_id, [4]=code* send(node,id,payload,len). */
typedef int (*can_send_fn)(void *node, uint32_t can_id, const void *payload, uint32_t len);
/* single-frame send: OEM omits len, calling the hook with only 3 args. */
typedef int (*can_send3_fn)(void *node, uint32_t can_id, const void *payload);

/*
 * OEM 0x3028 : od_publish.
 * param: node, ep descriptor (or override ep `ovr`), payload, len.
 * Returns driver send result (0 = ok).
 */
int od_publish(uint8_t *node, uint8_t *ep, uint8_t *ovr, uint32_t payload, uint32_t len)
{
    can_send_fn send = *(can_send_fn *)(node + 4);
    uint32_t sub_step;   /* sub-index increment field (held in id low bits)   */
    uint32_t id;

    /* kind==2 (block-xfer) keeps sub-index at 0; otherwise, when the
     * endpoint is "owned" (flags==0) seed sub-index field with 0x10. */
    if (ep[4] == 2)
        sub_step = 0;
    else
        sub_step = (ep[3] == 0) ? 0x10u : 0u;

    if (len < 9) {
        can_send3_fn send1 = *(can_send3_fn *)(node + 4);   /* OEM: 3-arg call, len omitted */
        uint8_t *e = (ovr != NULL) ? ovr : ep;
        uint32_t index = (uint32_t)e[1] * 0x100u + e[0];
        uint32_t node_id = e[2];
        if (index + node_id * 0x10000u < 0x10000u)
            node_id = node[0];
        id = ((node_id << 5) |
              ((uint32_t)e[0] * 0x200000u + ((index * 0x20u) & 0x1fe000u))) + sub_step;
        return send1(node, id, (const void *)(uintptr_t)payload);
    }

    /* len >= 9 : split into frames of <=8 bytes, advancing the sub-index. */
    {
        uint8_t *e = (ovr != NULL) ? ovr : ep;
        uint32_t off = 0;
        do {
            uint32_t index = (uint32_t)e[1] * 0x100u + e[0];
            uint32_t node_id = e[2];
            uint32_t chunk;
            uint32_t mask, step;
            int rc;

            if (index + node_id * 0x10000u < 0x10000u)
                node_id = node[0];

            chunk = len - off;
            if (chunk > 7u)
                chunk = 8u;

            id = ((node_id << 5) |
                  ((uint32_t)e[0] * 0x200000u + ((index * 0x20u) & 0x1fe000u))) + sub_step;
            rc = send(node, id, (const void *)(uintptr_t)(payload + off), chunk);
            if (rc != 0)
                return rc;

            /* advance the rolling sub-index: 4-bit field for block-xfer,
             * 3-bit field otherwise. */
            if (ep[4] == 2) { mask = 0xfu; step = 0xfffffff0u; }
            else            { mask = 0x7u; step = 0xfffffff8u; }
            off += chunk;
            sub_step = (step & sub_step) | (((sub_step + 1) & mask));
        } while (off < len);
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* OD RX dispatch.                                                            */
/*                                                                            */
/* od_rx() decodes the 29-bit ID into (node, index, subindex), finds the      */
/* matching pending multi-frame slot (10 slots x 0x5c bytes at node+8) or, if  */
/* none, the matching endpoint in the static endpoint table, reassembles      */
/* multi-frame transfers, then invokes the endpoint handler. kind==1 endpoints */
/* auto-reply via od_publish.                                                  */
/* ------------------------------------------------------------------------- */
extern uint8_t * const g_ep_table;        /* OEM DAT_0x2164 : endpoint table  */
extern uint8_t * const g_ep_table_end;    /* OEM DAT_0x2160 : table end        */

#define NODE_NSLOTS   10
#define SLOT_SIZE     0x5c
#define EP_SIZE       0x18

/*
 * OEM 0x1eec : od_rx (CAN frame -> OD dispatch).
 * node      : node object base
 * can_id    : 29-bit extended id of the received frame
 * data      : up to 8 payload bytes
 * dlc       : payload length
 */
int od_rx(uint8_t *node, uint32_t can_id, uint8_t *data, int dlc)
{
    uint8_t hdr[3];
    uint8_t *slot = NULL;     /* matching multi-frame reassembly slot          */
    uint8_t *ep;
    int is_new;               /* endpoint matched fresh (no in-flight slot)    */
    uint32_t node_id  = (can_id >> 0x15) & 0xff;
    uint32_t index    = (can_id >> 0x0d) & 0xff;
    uint32_t subindex = (can_id >> 5)    & 0xff;
    uint32_t lo, hi;
    int i;

    hdr[0] = (uint8_t)(can_id >> 0x15);
    hdr[1] = (uint8_t)(can_id >> 0x0d);
    hdr[2] = (uint8_t)(can_id >> 5);

    /* 1) look for an in-flight reassembly slot keyed by (node,index,subidx). */
    {
        uint8_t *p = node + 8;
        for (i = NODE_NSLOTS; i != 0; --i, p += SLOT_SIZE) {
            uint8_t *cur_ep = *(uint8_t **)p;
            if (cur_ep != NULL && (uint32_t)p[6] == subindex &&
                p[5] == index && p[4] == node_id) {
                slot = p;
                is_new = 0;
                ep = cur_ep;
                goto matched;
            }
        }
    }

    /* 2) otherwise scan the static endpoint table for a node/index match. */
    {
        uint8_t *p = g_ep_table;
        ep = NULL;
        while (p < g_ep_table_end) {
            if (p[1] == index &&
                (p[0] == node_id || (p[0] == 0 && node[0] == node_id))) {
                ep = p;
                break;
            }
            p += EP_SIZE;
        }
        if (ep == NULL)
            return E_NOENT;
        is_new = 1;
        slot = NULL;
    }

matched:
    lo = (uint32_t)data[3] * 0x1000000u + data[2] * 0x10000u + data[1] * 0x100u + data[0];
    hi = (uint32_t)data[7] * 0x1000000u + data[6] * 0x10000u + data[5] * 0x100u + data[4];
    (void)lo; (void)hi;

    /* publish-kind endpoint (kind==1, owned) with a result callback: invoke
     * the per-slot completion callback then free the slot. */
    if (ep[4] == 1 && ep[3] == 0) {
        uint8_t *p = node;
        for (i = NODE_NSLOTS; i != 0; --i, p += SLOT_SIZE) {
            if (*(uint8_t **)(p + 8) == ep) {
                {
                    void (*h)(uint8_t *, uint8_t *, uint8_t *, void *) =
                        (void (*)(uint8_t *, uint8_t *, uint8_t *, void *))(uintptr_t)
                        (*(void **)(p + 0x5c) ? *(void **)(p + 0x5c)
                                             : *(void **)(ep + 0x14));
                    if (h != NULL)
                        h(node, ep, hdr, &slot);
                }
                vm_memset(p + 8, 0, 4);
                return NODE_OK;
            }
        }
        return E_NOENT;
    }

    /* RTR / remote-request (bit set in id) on an RX endpoint: hand the read
     * request straight to the endpoint handler. */
    if ((int)(can_id << 0x1b) < 0 && ep[4] == 0) {
        void (*h)(uint8_t *, uint8_t *, uint8_t *, void *) =
            (void (*)(uint8_t *, uint8_t *, uint8_t *, void *))(uintptr_t)*(void **)(ep + 0x14);
        if (h != NULL)
            h(node, ep, hdr, &data);
        return NODE_OK;
    }

    /* multi-frame object (declared length > 8): reassemble. */
    if (*(uint32_t *)(ep + 8) > 8u) {
        if (is_new) {
            /* allocate a free slot. */
            uint8_t *p = node + 8;
            slot = NULL;
            for (i = NODE_NSLOTS; i != 0; --i, p += SLOT_SIZE)
                if (*(int *)p == 0)
                    slot = p;
            if (slot == NULL)
                return E_OVERFLOW;

            vm_memset(slot + 4, 0, 0x58);
            *(uint8_t **)slot = ep;
            slot[0x4c] = ep[0x10];
            *(uint32_t *)(slot + 0x50) = *(uint32_t *)(ep + 0xc) + tick_ms();
            vm_memcpy(slot + 4, hdr, 3);
        } else if (slot == NULL) {
            return E_OVERFLOW;
        }

        if ((uint32_t)(*(int *)(slot + 8) + dlc) > 0x40u)
            return E_OVERFLOW;

        /* copy payload at the frame's byte offset (block-xfer carries 0x78
         * stride, plain multi-frame 0x38, scaled by the 3-bit subindex). */
        {
            uint32_t stride = (ep[4] == 2) ? 0x78u : 0x38u;
            vm_memcpy(slot + (stride & (can_id << 3)) + 0xc, data, (uint32_t)dlc);
        }
        *(int *)(slot + 8) += dlc;
        if (*(int *)(slot + 8) != *(int *)(ep + 8))
            return NODE_OK;   /* more frames to come */

        /* complete: invoke handler. */
        {
            void *payload = slot + 0xc;
            int (*h)(uint8_t *, uint8_t *, uint8_t *, void **) =
                (int (*)(uint8_t *, uint8_t *, uint8_t *, void **))(uintptr_t)
                (*(void **)(slot + 0x54) ? *(void **)(slot + 0x54)
                                        : *(void **)(ep + 0x14));
            int rc = 0;
            (void)payload;
            if (h != NULL)
                rc = h(node, ep, hdr, &payload);
            vm_memset(slot, 0, 4);
            if (rc != 0)
                return NODE_OK;
        }
        if (ep[4] == 1)
            od_publish(node, ep, hdr, 0, 0);
        return NODE_OK;
    }

    /* single-frame: subindex must be frame-aligned. */
    if ((can_id & 7u) != 0)
        return E_INVAL;

    {
        int rc;
        void (*sh)(uint8_t *, uint8_t *, uint8_t *, uint8_t **);
        if (is_new || *(void **)(slot + 0x54) == NULL) {
            void *h = *(void **)(ep + 0x14);
            rc = (h != NULL) ? ((int (*)(uint8_t *, uint8_t *, uint8_t *, uint8_t **))(uintptr_t)h)
                               (node, ep, hdr, &data) : 0;
            if (!is_new)
                vm_memset(slot, 0, 4);
        } else {
            sh = (void (*)(uint8_t *, uint8_t *, uint8_t *, uint8_t **))(uintptr_t)*(void **)(slot + 0x54);
            rc = ((int (*)(uint8_t *, uint8_t *, uint8_t *, uint8_t **))(uintptr_t)sh)
                 (node, ep, hdr, &data);
            vm_memset(slot, 0, 4);
        }
        if (rc != 0)
            return NODE_OK;
    }
    if (ep[4] == 1)
        od_publish(node, ep, hdr, 0, 0);
    return NODE_OK;
}

/* ------------------------------------------------------------------------- */
/* Heartbeat.                                                                  */
/*                                                                            */
/* The main-loop tick publishes an 8-byte heartbeat OD frame at a fixed       */
/* period; byte 0 is a rolling sequence counter; on first arm the node-status */
/* byte is set to 0xa7. Latched DTC bits are cleared after publish.           */
/* ------------------------------------------------------------------------- */
extern uint8_t  *g_hb_buf;        /* OEM DAT_0x6608 : heartbeat payload buf    */
extern uint32_t  g_hb_ep;         /* OEM DAT_0x6604 : heartbeat endpoint        */
extern uint32_t *g_hb_clear_mask; /* OEM DAT_0x660c : [0],[1] dtc clear masks   */
extern void od_send_buf(uint32_t ep, uint32_t which, void *buf, uint32_t len); /* OEM 0x6dcc */

#define HB_PERIOD_TICKS_DAT  0x0  /* OEM DAT_0x4dc8: heartbeat period (ticks)  */
#define NODE_STATUS_ALIVE    0xa7 /* node-status byte stamped on (re)arm        */

/* OEM 0x65d8 : publish heartbeat frame, bump seq, clear latched DTCs. */
void heartbeat_publish(uint32_t ep)
{
    uint32_t *buf  = (uint32_t *)g_hb_buf;
    uint32_t *clr  = g_hb_clear_mask;
    uint32_t  clr1 = clr[1];

    od_send_buf(ep, g_hb_ep, g_hb_buf, 8);
    *(uint8_t *)buf = (uint8_t)(*(uint8_t *)buf + 1);   /* seq++ */

    buf[0] &= ~clr[0];
    buf[1] &= ~clr1;
    clr[0]  = 0;
    clr[1]  = 0;
}

/* ------------------------------------------------------------------------- */
/* Main-loop tick (node service).                                             */
/* ------------------------------------------------------------------------- */
extern uint8_t  *g_reboot_req;    /* OEM DAT_0x4dbc : pending self-update flag  */
extern void     *g_reboot_ctx;    /* OEM DAT_0x4dc0 : reboot/flash context      */
extern int      *g_hb_last;       /* OEM DAT_0x4dc4 : last heartbeat timestamp  */
extern uint32_t  g_hb_period;     /* OEM DAT_0x4dc8 : heartbeat period (ticks)  */
extern uint32_t  g_hb_node;       /* OEM DAT_0x4dcc : heartbeat node object     */
extern uint8_t  *g_node_status;   /* OEM DAT_0x4dd0 : node-status byte          */
extern uint8_t  *g_led_ctx_r;     /* OEM DAT_0x4dd4 : right LED-ring context    */
extern uint8_t  *g_led_ctx_l;     /* OEM DAT_0x4dd8 : left LED-ring context     */

extern int  sys_image_apply(void *ctx);   /* OEM 0x4020 : flash+reboot         */
extern void node_sm_service(uint32_t node);/* OEM 0x44a0 : transaction service  */
extern int  led_ring_service(uint8_t *ctx);/* OEM 0x2168 : LED-ring/button anim */

/*
 * OEM 0x4d5c : node_tick (called once per main-loop iteration).
 *  - if a self-update was requested, apply it (reboots; never returns on success);
 *  - publish the heartbeat when its period has elapsed (and stamp status 0xa7);
 *  - service in-flight OD transactions and the LED-ring animations.
 */
void node_tick(void)
{
    if (*g_reboot_req == 1) {
        sys_image_apply(g_reboot_ctx);   /* erase/flash/reboot path */
        dtc_clear_all();                 /* OEM 0x70e8(0xff)         */
        dtc_set(DTC_GENERIC);            /* OEM 0x70f8(1)            */
        *g_reboot_req = 0;
    }

    {
        int due = 1;
        if (*g_hb_last >= 0) {
            uint32_t now = uptime_ticks();
            if (*g_hb_last >= 0 &&
                (uint32_t)(now - (uint32_t)*g_hb_last) < g_hb_period)
                due = 0;
        }
        if (due) {
            *g_hb_last = (int)uptime_ticks();
            heartbeat_publish(g_hb_node);
            *g_node_status = NODE_STATUS_ALIVE;   /* 0xa7 */
        }
    }

    node_sm_service(g_hb_node);
    led_ring_service(g_led_ctx_r);
    led_ring_service(g_led_ctx_l);
}

/* ------------------------------------------------------------------------- */
/* Node transaction service (pending-request loop).                           */
/*                                                                            */
/* 10 slots of 0x5c bytes; each slot tracks a pending request with a deadline */
/* (+0x58), a retry counter (+0x54), an endpoint pointer (+8) and a result    */
/* callback (+0x5c). When due, od_publish is invoked; on success it is left   */
/* in flight, otherwise the result callback fires with the error and the slot */
/* is freed. An expired/exhausted slot reports E_AGAIN (-0x91).               */
/* ------------------------------------------------------------------------- */

/* OEM 0x44a0 : node_sm_service. (Reconstruction of the dispatch loop.) */
void node_sm_dispatch(uint8_t *base)
{
    uint32_t now = tick_ms();
    int i;
    uint8_t *slot = base;

    for (i = NODE_NSLOTS; i != 0; --i, slot += SLOT_SIZE) {
        uint8_t *ep = *(uint8_t **)(slot + 8);
        if (ep == NULL || *(uint32_t *)(slot + 0x58) >= now)
            continue;

        if (ep[3] == 0 && slot[0x54] != 0) {
            int rc;
            slot[0x54]--;                                  /* retry-- */
            *(uint32_t *)(slot + 0x58) = *(uint32_t *)(ep + 0xc) + now;
            rc = od_publish(base, ep, slot + 0xc,
                            (uint32_t)(uintptr_t)(slot + 0x14),   /* payload = &slot[0x14] */
                            *(uint32_t *)(slot + 0x10));          /* len     = slot[0x10]   */
            if (rc == 0)
                continue;                                  /* still in flight */
            {
                void (*cb)(uint8_t *, uint8_t *, uint8_t *, void *) =
                    (void (*)(uint8_t *, uint8_t *, uint8_t *, void *))(uintptr_t)*(void **)(slot + 0x5c);
                if (cb != NULL) {
                    uint8_t args[8] = {0};
                    cb(base, *(uint8_t **)(slot + 8), slot + 0xc, args);
                }
            }
        } else {
            void (*cb)(uint8_t *, uint8_t *, uint8_t *, void *) =
                (void (*)(uint8_t *, uint8_t *, uint8_t *, void *))(uintptr_t)*(void **)(slot + 0x5c);
            if (cb != NULL) {
                uint8_t args[8] = {0};
                /* report -0x91 (E_AGAIN: deadline expired / no retries left) */
                args[0] = (uint8_t)(E_AGAIN & 0xff);
                cb(base, ep, slot + 0xc, args);
            }
        }
        *(uint32_t *)(slot + 8) = 0;   /* free slot */
    }
}

/* ------------------------------------------------------------------------- */
/* CAN filter / mailbox setup.                                                */
/*                                                                            */
/* node_can_init() programs 4 RX acceptance filters (mailboxes 1..4) with the */
/* node's base extended ID and per-mailbox accept masks, registers each with  */
/* the driver, and enables RX. (TI MCAN register programming is vendor; the   */
/* accept-mask layout is VanMoof's.)                                          */
/* ------------------------------------------------------------------------- */
extern uint8_t  *g_can_filters;   /* OEM DAT_0x4328 : filter array base        */
extern uint32_t  g_can_node_id;   /* OEM DAT_0x432c : this node's base id       */
extern uint8_t  *g_can_rx_en1;    /* OEM DAT_0x4330 : RX enable reg 1           */
extern uint8_t  *g_can_rx_en2;    /* OEM DAT_0x4334 : RX enable reg 2           */
extern uint32_t  can_alloc_mailbox(void);          /* OEM 0x5048 */
extern void      can_register_mailbox(uint32_t mb, void *filt); /* OEM 0x71d8 */

/* OEM 0x4284 : node_can_init. */
void node_can_init(void)
{
    /* The four acceptance masks observed in the image. */
    static const uint32_t accept_mask[4] = {
        0x4000000u, 0x1000000u, 0x8000000u, 0x2000000u
    };
    uint8_t *f = g_can_filters;
    int k;

    for (k = 0; k < 4; ++k) {
        uint8_t *e = f + k * 0x20;
        uint32_t mb;

        e[0]                       = (uint8_t)(k + 1);     /* filter index 1..4 */
        *(uint32_t *)(e + 4)       = g_can_node_id;
        *(uint32_t *)(e + 8)       = accept_mask[k];
        e[0x10]                    = 0;
        *(uint32_t *)(e + 0x14)    = 0;
        *(uint16_t *)(e + 0x18)    = 1;
        mb = can_alloc_mailbox();
        *(uint32_t *)(e + 0x1c)    = mb;
        can_register_mailbox(mb, e);
    }

    *g_can_rx_en1 = 2;
    *g_can_rx_en2 = 2;
}

/* ------------------------------------------------------------------------- */
/* Serial-number provisioning.                                                */
/*                                                                            */
/* On boot, the stored 96-byte (0x60) serial record is compared against the   */
/* default; if they differ it is (re)written to the dedicated flash sector    */
/* together with a 0x16-word provisioning blob. The serial is also logged.    */
/* ------------------------------------------------------------------------- */
extern void    *g_serial_stored;   /* OEM DAT_0x4974 / 0x4978 : stored serial   */
extern uint32_t g_serial_state[];  /* OEM DAT_0x497c : provisioning state        */
extern uint32_t g_flash_ctl;       /* OEM DAT_0x4984 : flash controller base     */
extern volatile uint32_t *g_flash_sts; /* OEM DAT_0x4980 : flash status reg       */
extern uint32_t g_serial_sector;   /* OEM DAT_0x4974 : serial flash address       */
extern void    *g_prov_blob_src;   /* OEM DAT_0x4988 : provisioning blob RAM source  */
extern uint32_t g_prov_blob_dst;   /* OEM DAT_0x498c : provisioning blob flash dest   */

#define SERIAL_LEN  0x60   /* 96-byte serial record; loop bound 0x5f compared  */

/*
 * OEM 0x48fc : serial_provision.
 * commit!=0 : compare stored serial to default; if mismatched, erase the
 * serial sector and (re)write the serial record + provisioning blob.
 * Returns 0 if already provisioned, 1 if it (re)wrote, -0x30 if commit==0.
 */
int serial_provision(int commit)
{
    uint32_t *state = g_serial_state;
    uint32_t  sector = g_serial_sector;
    const char *stored  = (const char *)g_serial_stored;     /* DAT_0x4978 */
    const char *defaultv = (const char *)sector;             /* DAT_0x4974 */
    int i;

    if (commit == 0)
        return -0x30;

    /* OEM do-while compares indices 0..0x5f inclusive (96 bytes); the compare
     * pointer is left at the last-compared index for the post-loop check. */
    i = 0;
    for (;;) {
        if (stored[i] != defaultv[i])
            break;
        if (i == 0x5f)
            break;
        ++i;
    }
    if (stored[i] == defaultv[i])
        return 0;   /* already provisioned / matches */

    /* mismatch -> commit a fresh serial record. */
    state[1] = 5;
    state[0] = 1;
    while ((int)(*g_flash_sts << 0x1d) < 0)
        ;   /* wait flash idle */
    flash_cmd_exec(g_flash_ctl, sector, FLASH_PAGE_SIZE);    /* erase */
    flash_program64(g_flash_ctl, sector, 0x40);
    flash_write_words(g_flash_ctl, sector, g_serial_stored, 0x18, FLASH_PAGE_SIZE);
    flash_write_words(g_flash_ctl, g_prov_blob_dst, g_prov_blob_src, 0x16, FLASH_PAGE_SIZE);
    return 1;
}

/* ------------------------------------------------------------------------- */
/* OTA self-update.                                                           */
/*                                                                            */
/* sys_image_* services validate the staged image (header magic, length,      */
/* CRC) and stage the apply; the node erases the destination pages, copies the */
/* image, then reboots into it. The endpoint-driven entry point (od_apply)    */
/* runs the validate/size/CRC/allow chain and replies on the CAN bus.         */
/* ------------------------------------------------------------------------- */

/* OEM 0x4864 : erase a run of flash pages and confirm each erase.
 * slot   : sys_image slot index
 * off    : byte offset within slot
 * count  : page-aligned byte count (multiple of FLASH_PAGE_SIZE asserted)
 * Returns 0 ok, -0x16 (E_INVAL) on range error, -0xe (E_NODEV) on erase fail. */
extern uint32_t g_img_slots;     /* OEM DAT_0x48f0 : {base,size} per slot       */
extern uint32_t g_img_flashctl;  /* OEM DAT_0x48f8 : flash controller            */
extern volatile uint32_t *g_img_flashsts; /* OEM DAT_0x48f4 : flash status        */
extern uint32_t g_page_stride;   /* OEM DAT_0x48e4 : (page-1) stride             */
extern uint32_t g_assert_file;   /* OEM DAT_0x48e8 */
extern uint32_t g_assert_line;   /* OEM DAT_0x48ec */
extern void node_assert(uint32_t file, uint32_t line, uint32_t lineno); /* OEM 0x60cc */

int sys_image_erase_pages(int slot, uint32_t off, uint32_t count)
{
    uint32_t base, limit, p;

    if ((off & (FLASH_PAGE_SIZE - 1)) != 0)
        node_assert(g_assert_file, g_assert_line, 0x34);

    limit = *(uint32_t *)(g_img_slots + slot * 8 + 4);
    if (off + count > limit)
        return E_INVAL;

    if (count == 0)
        return NODE_OK;

    base = *(uint32_t *)(g_img_slots + slot * 8);
    p = 0;
    do {
        uint32_t addr = base + off + p;
        flash_cmd_exec(g_img_flashctl, addr, 0x200);
        flash_program64(g_img_flashctl, addr, 0x40);
        while ((*g_img_flashsts & 1u) == 0)
            ;
        if ((int)(*g_img_flashsts << 0x1e) >= 0)   /* erase status bit clear */
            return E_NODEV;
        p += g_page_stride + 1;
    } while (p < count);

    return NODE_OK;
}

/* OEM 0x45f4 : erase the destination page range for a staged image.
 * The page descriptor (start page, page count) is passed in r3 as a pointer to
 * a pointer-to-descriptor (`descp`; OEM `in_r3`, `pd = *descp`). Requires
 * sys_image_open + the two gates (sys_image_gate, sys_image_prep) to succeed,
 * then erases each page; logs "failed to erase page %d (err=%d)" on failure and
 * records the erased window. */
extern int *g_erase_win_start;   /* OEM DAT_0x468c */
extern int *g_erase_win_end;     /* OEM DAT_0x4690 */

int sys_image_erase_range(uint8_t **descp)   /* descp arrives in r3 */
{
    uint32_t open_desc[2];      /* sys_image_open output; [1] = slot_off (local_20) */
    uint8_t *pd = *descp;       /* staged-image page descriptor (OEM pbVar5 = *in_r3) */
    int slot_off;
    uint32_t start, cursor, npages;
    int rc;

    rc = sys_image_open(2, open_desc);          /* OEM 0x6dac */
    if (rc != 0 ||
        (rc = sys_image_gate()) != 0 ||         /* OEM 0x7258 */
        (rc = sys_image_prep()) != 0)           /* OEM 0x4b44 */
        return E_NODEV;                         /* 0xfffffff2 */

    slot_off = (int)open_desc[1];               /* local_20 : 2nd word from open */

    start  = (uint32_t)pd[1] * 0x100u + pd[0];  /* descriptor word 0 : first page */
    npages = (uint32_t)pd[3] * 0x100u + pd[2];  /* descriptor word 1 : page count */
    cursor = start;

    if (npages != 0) {
        do {
            /* OEM passes slot_off as the byte count (r2 = local_20), erasing
             * one page (slot_off bytes) at offset slot_off*cursor. */
            rc = sys_image_erase_pages(2, (uint32_t)slot_off * cursor,
                                       (uint32_t)slot_off);
            if (rc != 0) {
                vm_log(0, "E>failed to erase page %d (err=%d)\n", cursor, rc); /* 0x7978 */
                return E_NODEV;
            }
            cursor++;
            start  = (uint32_t)pd[1] * 0x100u + pd[0];
            npages = (uint32_t)pd[3] * 0x100u + pd[2];
        } while (cursor < npages + start);
    }

    *g_erase_win_start = (int16_t)start * (int16_t)slot_off;
    *g_erase_win_end   = (int16_t)slot_off * ((int16_t)npages + (int16_t)start);
    return NODE_OK;
}

extern int  sys_image_allow_update(uint32_t crc);   /* OEM 0x4ddc */
extern int  sys_image_size(int *out_len);           /* OEM 0x4990 */
extern void od_reply(uint8_t *node, uint8_t *ep, uint8_t *hdr, void *result, int len); /* OEM 0x7118 */

/*
 * OEM 0x43ec : od_apply (image-update OD endpoint handler).
 *  - validate the staged image (sys_image_validate);
 *  - read its declared size (sys_image_size);
 *  - re-validate / CRC the destination against the request CRC;
 *  - if the CRC matches, allow the update (sys_image_allow_update), arming the
 *    self-update that node_tick() applies on the next loop;
 *  - reply on the bus with the resulting status.
 */
void od_apply(uint8_t *node, uint8_t *ep, uint8_t *hdr, uint32_t **req)
{
    int status = 0;
    int req_crc = (int)**req;         /* OEM *(int *)*param_4 : CRC via double deref */
    int rc;

    rc = sys_image_gate();            /* OEM 0x7258 : update gate (!=0 -> E_IO) */
    if (rc != 0) {
        status = E_IO;                /* -5 */
        goto reply;
    }

    rc = sys_image_validate(/*slot*/2, 0, NULL);   /* OEM 0x2cdc wrapper */
    if (rc != 0) {
        vm_log(0, "E>sys_image_validate failed ret=%d\n", rc);   /* 0x799c */
        status = E_NODEV;             /* -0xe */
        goto reply;
    }

    {
        int img_len = 0;
        rc = sys_image_size(&img_len);
        if (rc != 0) {
            vm_log(0, "E>sys_image_size failed ret=%d\n", rc);   /* 0x7a68 */
            status = E_NODEV;         /* -0xe */
            goto reply;
        }

        {
            int computed_crc = 0;
            rc = sys_image_validate(0, (uint32_t)img_len, &computed_crc); /* 0x5e94 */
            if (rc == 0 && computed_crc == req_crc) {
                rc = sys_image_allow_update((uint32_t)req_crc);   /* 0x4ddc */
                if (rc != 0) {
                    vm_log(0, "E>sys_image_allow_update failed ret=%d\n", rc); /* 0x794f */
                    status = rc;
                }
            } else {
                vm_log(0, "E>Image CRC failed %u vs %u\n",
                       (unsigned)computed_crc, (unsigned)req_crc);  /* 0x7ae1 */
                status = E_BADCRC;    /* -0x22 */
            }
        }
    }

reply:
    od_reply(node, ep, hdr, &status, 1);
}

/* ------------------------------------------------------------------------- */
/* Main / NoRTOS super-loop.                                                  */
/* ------------------------------------------------------------------------- */
extern uint32_t  g_main_lock;      /* OEM DAT_0x5540 */
extern void      board_init(void); /* OEM 0x6088 : peripheral bring-up          */
extern void      node_init(void);  /* OEM 0x6250 : OD / endpoint bring-up        */
extern volatile uint32_t *g_clk_reg; /* OEM DAT_0x5548 */
extern const uint32_t g_boot_token;  /* OEM DAT_0x5550 : compared to 0xc20 word  */
extern const uint32_t g_clk_alt;     /* OEM DAT_0x554c */

/* OEM 0x54f0 : main. */
void node_main(void)
{
    uint32_t v;

    critical_enter(g_main_lock);
    board_init();                                         /* OEM 0x6088 */

    v = (uint32_t)serial_provision(1);                    /* OEM 0x48fc(1) */
    vm_log(0, "D>Serial number: %s\n", (const char *)(uintptr_t)v); /* 0x7bae */

    *g_clk_reg &= 0xfffdffffu;

    v = 0xc10;
    if (*(volatile uint32_t *)0x00000c20 == g_boot_token)
        v = g_clk_alt;
    vm_log(0, "D>%u\n", v);

    node_init();                                          /* OEM 0x6250 */
    node_can_init();                                      /* OEM 0x4284 */

    for (;;) {
        node_tick();                                      /* OEM 0x4d5c */
        wait_for_interrupt();
    }
}
