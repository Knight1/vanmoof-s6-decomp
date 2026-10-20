/*
 * od_handlers.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * Rear-light OD object read-responders: registered as the `handler` for specific
 * vm CAN/OD objects, each reads light state / config / a stored record and replies
 * with a CAN/OD response via can_frame_encode (can_od.c). This is the rearlight-
 * specific app layer (frontlight has its own, different set); the shared vm CAN/OD
 * + LED core is reused verbatim (can_od.c, led.c).
 *
 *   od_read_blob_responder @ 0x07f0  read 0x40-B stored record -> reply 0x10 B
 *   od_report_13           @ 0x3102  getter -> reply 13 B
 *   od_report_status       @ 0x321a  light state -> {0x56, bswap16(v), ...} reply 7 B
 *   od_report_state        @ 0x0dd4  light state -> {mode, value, ...} reply 0x10 B
 *   od_report_config       @ 0x326a  config -> {v, sum/v} reply 4 B
 *   od_report_scaled       @ 0x32e4  config + scale (0xffff = passthrough) reply 4 B
 *
 * The OD registration (which OD address -> which handler) is RAM-resident (past
 * the flash image), so the address<->handler map is not statically readable; these
 * are the leaf responders. Storage/state accessors are vendor/framework externs.
 * Behaviour-oriented reconstruction from the Ghidra decompile (image base 0x0).
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;

/* ---- vm CAN/OD TX (can_od.c) --------------------------------------------- */
extern int can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                            uint8_t *addr, int base, unsigned total);   /* 0x2fa0 */

/* ---- storage + light-state accessors (vendor/framework) ------------------ */
extern int  storage_ensure_ready(void);                                /* 0x0774 (0=ready) */
extern int  storage_read(void *dev, void *dst, int a, int b);          /* 0x04a4 (0=ok)    */
extern void *g_store_blob;    /* DAT_00000830 */

/* light_state_get(sel, out): fetch a subsystem state block; 0 on success.
 * validated variant checks a magic tag. */
extern int  light_state_get(int sel, void *out);                       /* 0x0d6c */
extern int  light_state_get_validated(void *out);                      /* 0x0d9c */
extern int  report13_get(void *out);                                   /* 0x07a4 */
extern int  scaled_prepare(int scaled, int base, void *io);            /* 0x1564 */
extern int  scaled_ready(void);                                        /* 0x1320 */

extern uint32_t g_state_tag;   /* DAT_00000e14 (constant packed into od_report_state) */

/* -------------------------------------------------------------------------
 * od_read_blob_responder  --  0x07f0
 *   Read a 0x40-B stored record, reply its first 0x10 bytes. (Same shape as the
 *   frontlight responder.)
 * ------------------------------------------------------------------------- */
int od_read_blob_responder(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    uint8_t rec[0x10];

    if (storage_ensure_ready() != 0)
        return -0x5;
    if (storage_read(g_store_blob, rec, 0x40, 0x10) != 0)
        return -0xe;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0x10);
}

/* -------------------------------------------------------------------------
 * od_report_13  --  0x3102
 *   Fetch a 13-byte report record and reply it.
 * ------------------------------------------------------------------------- */
void od_report_13(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    uint8_t rec[0x10];
    if (report13_get(rec) == 0)
        can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0xd);
}

/* -------------------------------------------------------------------------
 * od_report_status  --  0x321a
 *   Light state -> a 7-byte status record: {0x56, bswap16(state[+4]), 8,1,8,0}.
 * ------------------------------------------------------------------------- */
int od_report_status(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    int st;
    if (light_state_get_validated(&st) != 0)
        return -0x16;
    {
        uint16_t v = *(uint16_t *)(st + 4);
        struct __attribute__((packed)) {
            uint8_t  tag;      /* 0x56 */
            uint16_t val;      /* byte-swapped state word */
            uint8_t  a, b, c, d;
        } rec;
        rec.tag = 0x56;
        rec.val = (uint16_t)((v << 8) | (v >> 8));
        rec.a = 8; rec.b = 1; rec.c = 8; rec.d = 0;
        return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&rec, 7);
    }
}

/* -------------------------------------------------------------------------
 * od_report_state  --  0x0dd4
 *   Light state -> a 0x10-B record: {state[+4], state[+0x10], g_state_tag, 0x136e}.
 * ------------------------------------------------------------------------- */
int od_report_state(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    int st;
    if (light_state_get_validated(&st) != 0)
        return -0x16;
    {
        uint32_t rec[4];
        rec[0] = *(uint32_t *)(st + 4);
        rec[1] = *(uint32_t *)(st + 0x10);
        rec[2] = g_state_tag;
        rec[3] = 0x136e;
        return can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0x10);
    }
}

/* -------------------------------------------------------------------------
 * od_report_config  --  0x326a
 *   Config (light_state_get sel 2) -> {v:u16, (sum/v):u16} 4-B reply.
 * ------------------------------------------------------------------------- */
int od_report_config(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    struct { uint8_t raw[4]; uint32_t v, sum; } s;
    if (light_state_get(2, s.raw) != 0)
        return -0xe;
    {
        struct { uint16_t v; uint16_t avg; } rec;
        rec.v   = (uint16_t)s.v;
        rec.avg = (uint16_t)(s.sum / s.v);
        return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&rec, 4);
    }
}

/* -------------------------------------------------------------------------
 * od_report_scaled  --  0x32e4
 *   Config + a scale factor from the request (addr word). 0xffff = passthrough
 *   of the base value; else multiply. Replies a computed 4-B value.
 * ------------------------------------------------------------------------- */
int od_report_scaled(struct od_slot *slots, struct od_reg *reg, uint8_t *addr,
                     uint8_t **req)
{
    uint16_t factor = *(uint16_t *)*req;
    /* light_state_get(2, buf) fills 12 B: [0..4) unused here, base@+4, extra@+8
     * (OEM auStack_28 / local_24 / iStack_20). */
    uint8_t  buf[12];
    int      out = 0;
    int      base, extra, computed, base_arg;

    if (scaled_ready() != 0 || light_state_get(2, buf) != 0)
        return -0xe;

    base  = *(int32_t *)(buf + 4);
    extra = *(int32_t *)(buf + 8);
    if (factor == 0xffff) {              /* passthrough: scale=0, use extra */
        computed = 0;
        base_arg = extra;
    } else {
        computed = base * (int)(unsigned)factor;
        base_arg = base;
    }
    if (scaled_prepare(computed, base_arg, &out) != 0)
        return -0x16;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&out, 4);
}
