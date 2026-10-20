/*
 * can_od.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * SHARED LPC-trio core: this file is byte-for-byte the same reconstruction as
 * frontlight/src/can_od.c. Verified by cross-program diff of can_od_rx_dispatch
 * (frontlight 0x11e0 vs rearlight 0x1050 = functionally identical; the only diffs
 * are compiler addressing-mode choices) and byte-identical prologues for the rest.
 * The rearlight OEM addresses differ from the inline (frontlight) comments below:
 *     can_od_rx_dispatch  0x1050   (frontlight 0x11e0)
 *     can_isr             0x1670   (frontlight 0x176c)
 *     can_frame_encode    0x2fa0   (frontlight 0x33fc)
 * The `vm` protocol, structs, and behaviour are identical; see the frontlight
 * copy for the full commentary. Sonnet-verified there (0 findings on can_isr /
 * can_frame_encode; 4 HIGH+1 MED fixed on can_od_rx_dispatch's od_slot layout).
 *
 * The VanMoof `vm` CAN Object-Dictionary RX core. A received CAN frame's 29-bit
 * extended ID encodes an OD address (node/class . object . subindex); this
 * dispatcher decodes it, matches a registered OD object, reassembles multi-frame
 * payloads into a per-object slot, and invokes the object's handler when the
 * message is complete. Same wire protocol as ble/modem (see docs/progress.md).
 *
 *   can_od_rx_dispatch  @ 0x11e0   (event 0x1848 = bus error, 0x183d = RX)
 *
 * 29-bit ID -> OD address bit-layout:
 *   id[28:21] = addrA (node/class)   id[20:13] = addrB (object)
 *   id[12: 5] = addrC (subindex)     id[ 4: 0] = frame seq / flags
 *
 * Behaviour-oriented reconstruction from the struct-typed Ghidra decompile
 * (image base 0x0, raw LPC). Not byte-identical. The M_CAN driver, memcpy/memset
 * and can_frame_encode are externs.
 *
 * NOTE (to verify): the reassembly-slot callback fields (cb / cb_arg) sit at the
 * slot tail; the decompiler indexes them from the obj-field pointer in a way that
 * overlaps the 0x5c slot stride. Offsets marked "(*)" below need a disassembly
 * check to pin exactly. The control flow / OD-address decode / accumulation are
 * confirmed against the struct-typed decompile.
 */

#include <stdint.h>
#include <stddef.h>

/* OD object handler / slot completion callback: (slots, reg, addr, &pdata) -> rc */
struct od_reg;
typedef int (*od_handler_t)(void *slots, struct od_reg *reg, void *addr, void *pdata);

/* ---- registered OD object (0x18 B), list [g_od_regs .. g_od_regs_end) ------ */
struct od_reg {
    uint8_t  addrA;        /* +0x00 node/class                                  */
    uint8_t  addrB;        /* +0x01 object                                      */
    uint8_t  pad02;
    uint8_t  flag3;        /* +0x03 */
    uint8_t  mode;         /* +0x04 0 = accumulate, 1 = single-frame, 2 = multi */
    uint8_t  pad05[3];
    uint32_t exp_len;      /* +0x08 total expected payload length               */
    uint32_t timeout;      /* +0x0c reassembly timeout (added to now for slot)  */
    uint8_t  init_val;     /* +0x10 */
    uint8_t  pad11[3];
    od_handler_t handler;  /* +0x14 */
};

/* ---- per-object reassembly slot (0x5c B stride, 10 slots) ------------------
 * The slot is exactly 0x5c and buf occupies +0x14..+0x54 (0x40 B), so there is
 * NO in-slot completion callback. The OEM stores slot i's completion callback +
 * arg in the FIRST TWO WORDS of the NEXT slot (slot i base +0x5c / +0x60), which
 * alias slot[i+1]'s node/send words. Access via SLOT_CB / SLOT_CB_ARG below. */
struct od_slot {
    uint8_t  node;         /* +0x00 own node/class byte (base of the TX addr)   */
    uint8_t  hdr0_hi[3];
    /* +0x04: low-level "send one CAN frame" fn: (slots, id, payload_ptr, len)
     *        returns 0 to continue, nonzero to abort the burst.                */
    int    (*send)(struct od_slot *slots, uint32_t id, int payload, unsigned len);
    struct od_reg *obj;    /* +0x08 registered object (NULL = free slot)        */
    uint16_t addr_lo;      /* +0x0c addrA | addrB<<8                            */
    uint8_t  addrC;        /* +0x0e */
    uint8_t  pad0f;
    uint32_t accum_len;    /* +0x10 bytes reassembled so far                    */
    uint8_t  buf[0x40];    /* +0x14 payload accumulation (64 B, up to SLOT_BUFCAP) */
    uint8_t  init_val;     /* +0x54 */
    uint8_t  pad55[3];
    uint32_t deadline;     /* +0x58 */
};                         /* sizeof = 0x5c */

/* slot i's completion callback + arg live at slot_i + 0x5c / +0x60 (= the first
 * two words of slot[i+1]). */
#define SLOT_CB(sp)     (*(od_handler_t *)((uint8_t *)(sp) + 0x5c))
#define SLOT_CB_ARG(sp) (*(uint32_t *)((uint8_t *)(sp) + 0x60))

/* ---- externs ------------------------------------------------------------- */
extern void vm_memcpy(void *dst, const void *src, unsigned n);       /* 0x3822 */
extern void vm_memset(void *dst, int v, unsigned n);                 /* 0x383c */
void can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                      uint8_t *addr, int base, unsigned total);      /* 0x33fc */

/* M_CAN RX element (DAT_0000149c): [0]=R0 (XTD/RTR/29-bit ID), byte6=DLC nibble,
 * [2]=pointer to the payload bytes. */
extern uint32_t *g_can_rx;        /* DAT_0000149c */
extern uint8_t   g_bus_err;       /* DAT_000014ac + 1 (error-latch byte)        */
extern struct od_reg *g_od_regs;      /* DAT_000014a0 (list start)              */
extern struct od_reg *g_od_regs_end;  /* DAT_000014a4 (list end)                */
extern uint32_t *g_now;           /* DAT_000014a8 (tick source)                 */

#define NUM_SLOTS   10
#define SLOT_BUFCAP 0x40

/* -------------------------------------------------------------------------
 * can_od_rx_dispatch  --  0x11e0
 * ------------------------------------------------------------------------- */
void can_od_rx_dispatch(int can_regs, int rx_ctx, int event, int flags,
                        struct od_slot *slots)
{
    uint32_t *rx = g_can_rx;
    uint32_t  id;
    unsigned  addrA, addrB, addrC, dlc;
    struct od_reg  *reg;
    struct od_slot *slot = NULL;
    uint8_t   addr[4];        /* {addrA, addrB, addrC, seq/flags} for handlers */
    uint8_t   data8[8];
    uint8_t  *pdata;
    int       i;

    if (event != 0x183d) {
        /* ---- 0x1848: bus error/status ---- */
        if (event != 0x1848)
            return;
        if ((flags << 7) < 0) g_bus_err |= 0x10;   /* bit 24 */
        if ((flags << 8) < 0) g_bus_err |= 0x20;   /* bit 23 */
        if ((flags << 6) >= 0)                      /* bit 25 clear -> done */
            return;
        g_bus_err |= 0x40;
        *(volatile uint32_t *)(can_regs + 0x18) &= ~1u;         /* disable */
        while ((int)(*(volatile uint32_t *)(can_regs + 0x18) << 0x1f) < 0)
            ;                                                    /* wait busy clear */
        return;
    }

    /* ---- 0x183d: message received ---- */
    id    = rx[0];
    pdata = (uint8_t *)(uintptr_t)rx[2];
    addrA = (id & 0x1fffffff) >> 0x15;   /* id[28:21] */
    addrB = (id & 0x1fffff)   >> 0x0d;   /* id[20:13] */
    addrC = (id & 0x1fff)     >> 0x05;   /* id[12: 5] */
    dlc   = ((uint8_t *)rx)[6] & 0xf;
    addr[0] = (uint8_t)addrA;
    addr[1] = (uint8_t)addrB;
    addr[2] = (uint8_t)addrC;
    /* addr[3] left as-is (seq/flags scratch, OEM keeps the prior high byte) */

    /* Phase 1: an in-progress reassembly slot matching (addrA,addrB,addrC)? */
    reg = NULL;
    for (i = 0; i < NUM_SLOTS; i++) {
        if (slots[i].obj != NULL &&
            slots[i].addrC == addrC &&
            (slots[i].addr_lo >> 8) == addrB &&
            (slots[i].addr_lo & 0xff) == addrA) {
            reg  = slots[i].obj;
            slot = &slots[i];
            if (reg != NULL)
                goto matched;
            goto rearm;
        }
    }

    /* Phase 2: search the registered-object list for (addrA,addrB) */
    for (reg = g_od_regs; reg < g_od_regs_end; reg++) {
        if (reg->addrB != addrB)
            continue;
        if (reg->addrA == addrA) {           /* exact match */
            slot = NULL;
            goto matched;
        }
        if (reg->addrA == 0 &&               /* wildcard node, match on own node */
            slots[0].node == addrA) {
            slot = NULL;
            goto matched;
        }
    }
    goto rearm;                              /* no handler for this OD address */

matched:
    vm_memcpy(data8, pdata, 8);
    pdata = data8;

    if (reg->mode == 1 && reg->flag3 == 0) {
        /* single-frame event: fire the handler, then release its slot */
        vm_memset(&pdata, 0, 0x10);
        for (i = 0; i < NUM_SLOTS; i++) {
            if (slots[i].obj == reg) {
                od_handler_t cb = SLOT_CB(&slots[i]) ? SLOT_CB(&slots[i]) : reg->handler;
                if (cb)
                    cb(slots, reg, addr, &pdata);
                slots[i].obj = NULL;
                break;
            }
        }
        goto rearm;
    }

    if (reg->mode == 0 && (int)(id << 0x1b) < 0) {
        /* immediate single delivery (bit 4 of id set) */
        if (reg->handler)
            reg->handler(slots, reg, addr, &pdata);
        goto rearm;
    }

    if (reg->exp_len < 9) {
        /* short object: one frame carries the whole payload */
        if ((id & 7) != 0)
            goto rearm;
        if (slot != NULL && SLOT_CB(slot) != NULL) {
            /* deliver via the slot callback, THEN release the slot */
            int rc = SLOT_CB(slot)(slots, reg, addr, &pdata);
            slot->obj = NULL;
            if (rc != 0)
                goto rearm;
        } else if (reg->handler != NULL) {
            int rc = reg->handler(slots, reg, addr, &pdata);
            if (slot != NULL)
                slot->obj = NULL;
            if (rc != 0)
                goto rearm;
        } else if (slot != NULL) {
            slot->obj = NULL;
        }
    } else {
        /* long object: accumulate frames into a slot until exp_len reached */
        if (slot == NULL) {
            for (i = 0; i < NUM_SLOTS; i++)
                if (slots[i].obj == NULL)
                    slot = &slots[i];
            if (slot == NULL)
                goto rearm;
            /* OEM clears from slot+8: preserves the slot's own node/send words
             * and zeroes 0x5c bytes (through the next slot's cb/cb_arg words). */
            vm_memset((uint8_t *)slot + 8, 0, 0x5c);
            slot->obj      = reg;
            slot->init_val = reg->init_val;
            slot->deadline = reg->timeout + *g_now;
            slot->addr_lo  = (uint16_t)(addr[0] | (addr[1] << 8));
            slot->addrC    = addr[2];
        }
        if ((int)(slot->accum_len + dlc) > SLOT_BUFCAP)
            goto rearm;
        {
            unsigned seq = (reg->mode == 2) ? (id & 0xf) : (id & 7);
            vm_memcpy(slot->buf + seq * 8, pdata, dlc);
        }
        slot->accum_len += dlc;
        if (slot->accum_len != reg->exp_len)
            goto rearm;                      /* more frames to come */

        pdata = slot->buf;
        {
            od_handler_t cb = SLOT_CB(slot) ? SLOT_CB(slot) : reg->handler;
            if (cb == NULL) {
                slot->obj = NULL;
            } else {
                int rc = cb(slots, reg, addr, &pdata);
                slot->obj = NULL;
                if (rc != 0)
                    goto rearm;
            }
        }
    }

    if (reg->mode == 1)                       /* single-mode: send the ack frame */
        can_frame_encode(slots, reg, addr, 0, 0);

rearm:
    /* re-arm the RX path for the next message */
    if (*(volatile uint8_t *)(rx_ctx + 0x14c) == 0) {
        *(volatile uint8_t *)(rx_ctx + 0x14c) = 5;
        *(uint32_t **)(rx_ctx + 0x108) = g_can_rx;
        *(volatile uint32_t *)(can_regs + 0x5c) |= 1;
        *(volatile uint32_t *)(can_regs + 0x58) &= ~1u;
        *(volatile uint32_t *)(can_regs + 0x54) |= 1;
    }
}

/* -------------------------------------------------------------------------
 * can_isr  --  0x176c
 *
 * Bosch M_CAN controller ISR. Drains the interrupt register, and for each
 * pending source: handles it against the M_CAN registers (RX FIFO read into the
 * driver's RX element, TX-complete cleanup, error latch), maps it to a VanMoof
 * event code, and dispatches to the registered OD callback (ctx[0]) as
 * cb(can_regs, ctx, event, ack). The event code is what can_od_rx_dispatch
 * decodes (0x183d = RXF0 message, 0x1842 = RXF1, 0x1839 = TX complete,
 * 0x1848 = bus error, 0x1840/0x1849 = status).
 *
 * M_CAN register offsets (standard IP; the driver adds an MRAM base ptr @+0x200):
 *   IR 0x50, IE 0x54, RXF0C 0xa0/S 0xa4/A 0xa8, RXF1C 0xb0/S 0xb4/A 0xb8,
 *   RXESC 0xbc, TXBC 0xc0, TXBCR 0xd4, TXBTIE 0xd8, TXBTO 0xe0.
 * Driver context (ctx, uint32 words): [0]=event cb, [1]=cb arg, [i+2]/byte+0x10c
 *   = per-TX-buffer state, [0x42]=RX element ptr (@+0x108), byte+0x14c = rx flag.
 * MMIO is reproduced verbatim; the M_CAN bit layout is the standard IP, the
 * event-code mapping + dispatch is the VanMoof glue.
 * ------------------------------------------------------------------------- */
#define R(off) (*(volatile uint32_t *)(can_regs + (off)))

/* decode an M_CAN element-size code to its element length in 32-bit words
 * (2 header words + data words). */
static unsigned mcan_elem_words(unsigned code)
{
    return (code < 5) ? code + 4 : code * 4 - 10;
}

void can_isr(int can_regs, uint32_t *ctx, int arg)
{
    uint32_t ir = R(0x50);
    (void)arg;

    for (;;) {
        uint32_t event, ack;
        uint32_t errbits = ir & 0x3800000;      /* bus-off / passive / warning */

        if (errbits != 0) {
            event = 0x1848;
            ack   = errbits;
        } else if ((int)(ir << 0x16) < 0) {     /* bit 9: TC (transmission complete) */
            unsigned ntx = (R(0xc0) & 0x3fffff) >> 0x10;   /* TXBC.NDTB */
            for (unsigned i = 0; (i & 0xff) < ntx; i++) {
                uint32_t m = 1u << (i & 0xff);
                if (((R(0xd8) & m) >> (i & 0xff)) != 0 &&                 /* TXBTIE */
                    (int)((R(0xe0) >> (i & 0xff)) << 0x1f) < 0) {         /* TXBTO */
                    R(0xe0) &= ~m;
                    R(0xd4)  = m;                                          /* clear */
                    ctx[i + 2] = 0;
                    *((uint8_t *)ctx + i + 0x10c) = 0;
                }
            }
            event = 0x1839;
            ack   = 0x200;
        } else if ((ir & 1) != 0) {             /* bit 0: RX FIFO 0 new message */
            uint32_t *elem = (uint32_t *)(uintptr_t)ctx[0x42];
            if ((R(0xa4) & 0x7f) != 0) {                          /* RXF0S fill level */
                unsigned ew = mcan_elem_words(R(0xbc) & 7);       /* RXESC.F0DS */
                int addr = (R(0xa0) & 0xfffc) + *(int *)(can_regs + 0x200)
                           + (int)((R(0xa4) & 0x3fff) >> 8) * (int)ew * 4;
                vm_memcpy(elem, (void *)(uintptr_t)addr, 8);
                elem[2] = (uint32_t)(addr + 8);
                R(0xa8) = (R(0xa4) & 0x3fff) >> 8;                /* RXF0A ack */
            }
            event = 0x183d;
            ack   = 1;
            R(0x54) &= ~1u;                                       /* IE clear RF0N */
            ctx[0x42] = 0;
            *((uint8_t *)ctx + 0x14c) = 0;
        } else if ((int)(ir << 0x1c) < 0) {     /* bit 3 */
            event = 0x1840;
            ack   = 8;
        } else if ((int)(ir << 0x1b) < 0) {     /* bit 4: RX FIFO 1 new message */
            uint32_t *elem = (uint32_t *)(uintptr_t)ctx[0x42];
            if ((R(0xb4) & 0x7f) != 0) {                          /* RXF1S fill level */
                unsigned ew = mcan_elem_words((R(0xbc) & 0x7f) >> 4);  /* RXESC.F1DS */
                int addr = (R(0xb0) & 0xfffc) + *(int *)(can_regs + 0x200)
                           + (int)((R(0xb4) & 0x3fff) >> 8) * (int)ew * 4;
                vm_memcpy(elem, (void *)(uintptr_t)addr, 8);
                elem[2] = (uint32_t)(addr + 8);
                R(0xb8) = (R(0xb4) & 0x3fff) >> 8;                /* RXF1A ack */
            }
            event = 0x1842;
            ack   = 0x10;
            R(0x54) &= ~0x10u;                                    /* IE clear RF1N */
            ctx[0x42] = 0;
            *((uint8_t *)ctx + 0x14c) = 0;
        } else if ((int)(ir << 0x18) < 0) {     /* bit 7 */
            event = 0x1840;
            ack   = 0x80;
        } else {
            event = 0x1849;
            ack   = 0xfc7ffd66u & ir;           /* DAT_00001910 */
        }

        {
            void (*cb)(int, uint32_t *, uint32_t, uint32_t) =
                (void (*)(int, uint32_t *, uint32_t, uint32_t))(uintptr_t)ctx[0];
            R(0x50) = ack;                       /* ack the handled source(s) in IR */
            if (cb != NULL)
                cb(can_regs, ctx, event, ack);
        }

        ir = R(0x50);
        if (ir == 0)
            return;
    }
}
#undef R

/* -------------------------------------------------------------------------
 * can_frame_encode  --  0x33fc
 *
 * TX side of the vm CAN/OD protocol: encode an OD object's payload into one or
 * more 29-bit-ID CAN frames and hand each to the low-level sender (slots->send).
 *
 * The 29-bit ID is assembled from the OD address (same layout the RX path
 * decodes):
 *   id = addrA<<0x15 | addrB<<0x0d | addrC<<5 | last_flag<<4 | seq
 * where addrA/addrB/addrC come from `addr` (when non-NULL) else from the
 * registered object, addrC falls back to this node's own byte (slots->node) when
 * the object's subindex byte is 0, and `last_flag` is set for a single/final
 * frame (mode!=2 && flag3==0).
 *
 *   base  = pointer/handle to the payload (passed opaque to send)
 *   total = payload length in bytes
 *
 * total<9 : one frame carries the whole payload.
 * total>=9: multi-frame burst of <=8-byte chunks; seq increments and wraps
 *           (mask 0xf for mode 2, else 0x7); aborts if send returns nonzero.
 * ------------------------------------------------------------------------- */
void can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                      uint8_t *addr, int base, unsigned total)
{
    unsigned last_flag = (reg->mode == 2) ? 0u : (unsigned)(reg->flag3 == 0);
    uint8_t  a, b, c;
    unsigned addrC;

    /* select the OD address bytes */
    #define LOAD_ADDR()  do {                            \
        if (addr == NULL) { a = reg->addrA; b = reg->addrB; c = reg->pad02; } \
        else              { a = addr[0];    b = addr[1];    c = addr[2];   } \
        addrC = c ? (unsigned)c : (unsigned)slots->node;  \
    } while (0)

    if (total < 9) {
        LOAD_ADDR();
        slots->send(slots,
                    addrC << 5 | last_flag << 4 | (unsigned)b << 0x0d | (unsigned)a << 0x15,
                    base, total);
        return;
    }

    {
        unsigned off = 0;
        unsigned acc = 0;         /* running seq accumulator (uVar8)          */
        do {
            unsigned lowbits = acc | last_flag << 4;   /* seq | last_flag@bit4 */
            unsigned chunk = total - off;
            if (chunk > 7)
                chunk = 8;
            LOAD_ADDR();
            if (slots->send(slots,
                            lowbits | (unsigned)b << 0x0d | (unsigned)a << 0x15 | addrC << 5,
                            base + off, chunk) != 0)
                return;
            off += chunk;
            lowbits += 1;
            /* mode 2 wraps seq mod 16; else keep acc's high bits, seq mod 8 */
            acc = (reg->mode == 2) ? (lowbits & 0xf)
                                   : ((acc & 0xe8) | (lowbits & 7));
        } while (off < total);
    }
    #undef LOAD_ADDR
}
