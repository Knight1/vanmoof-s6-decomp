/*
 * can_rx.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * vm CAN/OD core of this framework revision. The FDCAN1 interrupt
 * (fdcan1_it0_isr @ 0x8006d14) is ST's HAL_FDCAN_IRQHandler (vendor) with two
 * VanMoof callbacks inlined; those callbacks are reconstructed here as
 * separate functions (the OEM has them inline, so they have no addresses of
 * their own):
 *
 *   od_rx_frame        RX FIFO0 callback body, once per received frame
 *                      (inside 0x8006d14, after HAL_FDCAN_GetRxMessage)
 *   can_error_status   error-status callback body (inside 0x8006d14)
 *   can_frame_encode   @ 0x800ab60  TX encoder (same protocol as the LPC
 *                      frontlight/src/can_od.c, separately compiled)
 *
 * Same wire protocol as the LPC trio: 29-bit id = A<<21 | B<<13 | C<<5 |
 * last<<4 | seq; request slots (10 x 0x5c) are matched first, then the flash
 * OD table (0x0800ccb0..0x0800cef0). Differences seen here: after a mode-1
 * (write) object is handled, an empty frame is sent back on the same address
 * (write acknowledge), and CAN error flags land in heartbeat-payload byte 1.
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the Ghidra decompile, key paths checked against the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_payload {
    uint8_t  *data;              /* +0 */
    uint32_t  len;               /* +4 */
    uint32_t  rsvd;              /* +8 */
    uint32_t  cb_arg;            /* +c */
};

struct od_reg {                  /* 24-B flash record */
    uint8_t  addrA, addrB, addrC, flag3;   /* od id, little-endian bytes */
    uint8_t  mode;               /* +4: 0 read responder, 1 write, 2 notify */
    uint8_t  pad5[3];
    uint32_t exp_len;            /* +8  */
    uint32_t timeout;            /* +c  */
    uint32_t retries;            /* +10 */
    int    (*handler)(void *slots, struct od_reg *reg, uint8_t *addr,
                      struct od_payload *p);   /* +14 */
};
typedef int (*od_cb_t)(void *slots, struct od_reg *reg, uint8_t *addr,
                       struct od_payload *p);

/* request slot, seen from &slot.obj (slot base + 8), stride 0x5c */
struct od_req {
    struct od_reg *obj;          /* +0x00 */
    uint8_t  addr[3];            /* +0x04 */
    uint8_t  pad7;
    uint32_t total;              /* +0x08 */
    uint8_t  buf[0x40];          /* +0x0c */
    uint8_t  retries;            /* +0x4c */
    uint8_t  pad4d[3];
    uint32_t deadline;           /* +0x50 */
    od_cb_t  cb;                 /* +0x54 */
    uint32_t cb_arg;             /* +0x58 */
};

/* slot array: byte 0 = own node byte, slots at +8 + i*0x5c; +4 = send fn */
struct can_slots {
    uint8_t  node;
    uint8_t  pad[3];
    int    (*send)(struct can_slots *s, uint32_t id, int data, unsigned len);
};

extern struct can_slots *g_slots;           /* *0x200009dc (= 0x20000a14) */
extern struct od_reg     g_od_regs[];       /* 0x0800ccb0 */
extern struct od_reg     g_od_regs_end[];   /* 0x0800cef0 */
extern volatile uint8_t  g_hb_payload[8];   /* 0x20000700 ([1] = node status flags) */
extern struct od_req    *od_slot_alloc(void *slots, const struct od_reg *rec); /* 0x80062f8 */
extern void *vm_memset(void *dst, int c, size_t n);              /* 0x800b1f6 */
extern void *vm_memcpy(void *dst, const void *src, size_t n);    /* 0x800b1ba */

#define SLOT(s, i)  ((struct od_req *)((uint8_t *)(s) + 8 + (i) * 0x5c))

/* -------------------------------------------------------------------------
 * can_frame_encode  --  0x800ab60
 *   Returns the send() rc (0 = all frames queued).
 * ------------------------------------------------------------------------- */
int can_frame_encode(struct can_slots *slots, struct od_reg *reg, uint8_t *addr,
                     int base, unsigned total)
{
    unsigned last = (reg->mode == 2) ? 0u : (unsigned)(reg->flag3 == 0);
    unsigned a, b, c, seq = 0, off = 0;
    int rc;

    if (total < 9) {
        c = slots->node;
        if (addr == NULL) { a = reg->addrA; b = reg->addrB; if (reg->addrC) c = reg->addrC; }
        else              { a = addr[0];    b = addr[1];    if (addr[2])    c = addr[2]; }
        return slots->send(slots, c << 5 | last << 4 | b << 13 | a << 21, base, total);
    }

    do {
        unsigned lowbits, chunk;

        c = slots->node;
        if (addr == NULL) { a = reg->addrA; b = reg->addrB; if (reg->addrC) c = reg->addrC; }
        else              { a = addr[0];    b = addr[1];    if (addr[2])    c = addr[2]; }
        lowbits = seq | last << 4;
        chunk = total - off;
        if (chunk > 7)
            chunk = 8;
        rc = slots->send(slots, lowbits | b << 13 | a << 21 | c << 5, base + (int)off, chunk);
        if (rc != 0)
            return rc;
        off += chunk;
        lowbits += 1;
        seq = (reg->mode == 2) ? (lowbits & 0xf) : ((seq & 0xe8) | (lowbits & 7));
    } while (off < total);
    return rc;
}

/* -------------------------------------------------------------------------
 * od_rx_frame  --  (inline in 0x8006d14)
 *   id = 29-bit extended id, len = DLC (classic CAN), data = frame payload.
 * ------------------------------------------------------------------------- */
void od_rx_frame(uint32_t id, unsigned len, const uint8_t *data)
{
    struct can_slots *slots = g_slots;
    struct od_req *s = NULL;
    struct od_reg *reg = NULL;
    struct od_payload pl;
    uint8_t addr[4];
    uint8_t copy[8];
    unsigned a = id >> 21, b = (id & 0x1fffff) >> 13, c = (id & 0x1fff) >> 5;
    int i, rc = 0;

    addr[0] = (uint8_t)a;
    addr[1] = (uint8_t)b;
    addr[2] = (uint8_t)c;
    addr[3] = 0;

    /* 1) a pending request slot for this exact address */
    for (i = 0; i != 10; i++) {
        struct od_req *r = SLOT(slots, i);
        if (r->obj != NULL && r->addr[2] == c && r->addr[1] == b && r->addr[0] == a) {
            s = r;
            reg = r->obj;
            break;
        }
    }

    /* 2) otherwise the OD table (node byte 0 = "this node") */
    if (reg == NULL) {
        for (reg = g_od_regs; reg < g_od_regs_end; reg++) {
            if (reg->addrB != b)
                continue;
            if (reg->addrA == a)
                break;
            if (reg->addrA == 0 && slots->node == a)
                break;
        }
        if (reg >= g_od_regs_end)
            return;
    }

    vm_memcpy(copy, data, 8);

    /* answer to one of our own write requests to a remote object */
    if (reg->mode == 1 && reg->flag3 == 0) {
        vm_memset(&pl, 0, sizeof pl);
        for (i = 0; i != 10; i++) {
            struct od_req *r = SLOT(slots, i);
            if (r->obj == reg) {
                od_cb_t cb = r->cb ? r->cb : reg->handler;
                if (cb != NULL)
                    cb(slots, reg, addr, &pl);
                r->obj = NULL;
                break;
            }
        }
        return;
    }

    pl.data = copy;
    pl.len = len;
    pl.rsvd = 0;
    pl.cb_arg = 0;

    /* read request (last-frame flag) to one of our read responders */
    if (reg->mode == 0 && (id & 0x10u) != 0) {
        if (reg->handler != NULL)
            reg->handler(slots, reg, addr, &pl);
        return;
    }

    if (reg->exp_len < 9) {                       /* single-frame object */
        if ((id & 7u) != 0)
            return;
        if (s != NULL && s->cb != NULL) {
            pl.cb_arg = s->cb_arg;
            rc = s->cb(slots, reg, addr, &pl);
            s->obj = NULL;
        } else if (reg->handler != NULL) {
            rc = reg->handler(slots, reg, addr, &pl);
            if (s != NULL)
                s->obj = NULL;
        } else if (s != NULL) {
            s->obj = NULL;
        }
        if (rc != 0)
            return;
    } else {                                      /* multi-frame reassembly */
        unsigned seq;
        od_cb_t cb;

        if (s == NULL) {
            s = od_slot_alloc(slots, reg);
            if (s == NULL)
                return;
            s->addr[0] = addr[0];
            s->addr[1] = addr[1];
            s->addr[2] = addr[2];
        }
        if (s->total + len > 0x40)
            return;
        seq = (reg->mode == 2) ? (id & 0xfu) : (id & 7u);
        vm_memcpy(&s->buf[seq * 8], data, len);
        s->total += len;
        if (s->total != reg->exp_len)
            return;

        pl.data = s->buf;
        pl.len = s->total;
        pl.cb_arg = s->cb_arg;
        cb = s->cb ? s->cb : reg->handler;
        if (cb != NULL) {
            rc = cb(slots, reg, addr, &pl);
            s->obj = NULL;
            if (rc != 0)
                return;
        } else {
            s->obj = NULL;
        }
    }

    if (reg->mode == 1)                           /* acknowledge a write */
        can_frame_encode(slots, reg, addr, 0, 0);
}

/* -------------------------------------------------------------------------
 * can_error_status  --  (inline in 0x8006d14)
 *   ir_err = FDCAN IR & IE & (EW|EP|BO). Flags go to heartbeat byte 1; on
 *   bus-off INIT is cleared so the controller restarts.
 * ------------------------------------------------------------------------- */
void can_error_status(volatile uint32_t *fdcan, uint32_t ir_err)
{
    fdcan[0x50 / 4] = ir_err;                     /* IR: clear */
    if (ir_err & (1u << 18))                      /* EW */
        g_hb_payload[1] |= 0x10;
    if (ir_err & (1u << 17))                      /* EP */
        g_hb_payload[1] |= 0x20;
    if (ir_err & (1u << 19)) {                    /* BO */
        g_hb_payload[1] |= 0x40;
        fdcan[0x18 / 4] &= ~1u;                   /* CCCR.INIT = 0 */
    }
}
