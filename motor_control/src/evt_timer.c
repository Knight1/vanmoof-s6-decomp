/*
 * evt_timer.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * One-shot / periodic event timers kept as a delta list (each entry's
 * `remaining` is relative to its predecessor) over one hardware timer (TIM2),
 * driven through a small HAL vtable. Also the OD send helpers of this
 * framework revision.
 *
 *   evt_timer_insert   @ 0x8005658
 *   evt_timer_arm      @ 0x80056c0
 *   evt_timer_restart  @ 0x80056f8  disarm; if active re-arm for ms*1000+100000
 *                                   ticks with assist_timeout_cb
 *   tim2_isr           @ 0x8006cd4  head expired: pop, reload periodic, call cb
 *   od_publish         @ 0x80058e0  encode only notify (mode 2) objects
 *   od_slot_alloc      @ 0x80062f8  LAST free of 10 request slots
 *   od_request         @ 0x8006334
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- event timers --------------------------------------------------------- */
struct evt_timer;
typedef void (*evt_cb_t)(struct evt_timer *t);

struct evt_timer {
    uint8_t  armed;               /* +0x00 */
    uint8_t  pad[3];
    uint32_t remaining;           /* +0x04 delta to the previous entry */
    uint32_t period;              /* +0x08 reload (0 = one-shot)       */
    struct evt_timer *next;       /* +0x0c */
    uint32_t rsvd;                /* +0x10 */
    evt_cb_t cb;                  /* +0x14 */
};

struct evt_hal {                  /* g_evt (0x2000065c) */
    struct evt_timer *head;                           /* +0x00 */
    void   *ctx;                                      /* +0x04 */
    void  (*start)(void *ctx, uint32_t ticks);        /* +0x08 */
    void  (*restart)(void *ctx, uint32_t ticks);      /* +0x0c */
    void  (*stop)(void *ctx);                         /* +0x10 */
    uint32_t (*remaining)(void *ctx);                 /* +0x14 ticks until head fires */
    void  (*unlock)(void *ctx);                       /* +0x18 */
    void  (*lock)(void *ctx);                         /* +0x1c */
    int   (*irq_check)(void *ctx);                    /* +0x20 pending + clear */
};
extern struct evt_hal g_evt;      /* 0x2000065c */

extern void assist_timeout_cb(struct evt_timer *t);   /* 0x8005b9c */

/* -------------------------------------------------------------------------
 * evt_timer_insert  --  0x8005658
 * ------------------------------------------------------------------------- */
void evt_timer_insert(struct evt_timer *t)
{
    struct evt_timer *p, *n;
    uint32_t hw;

    t->next = NULL;
    if (g_evt.head == NULL) {
        g_evt.head = t;
        g_evt.start(g_evt.ctx, t->remaining);
        return;
    }

    hw = g_evt.remaining(g_evt.ctx);
    if (hw > t->remaining) {                     /* new head */
        p = g_evt.head;
        g_evt.head = t;
        p->remaining = hw - t->remaining;
        t->next = p;
        g_evt.restart(g_evt.ctx, t->remaining);
        return;
    }

    t->remaining -= hw;
    p = g_evt.head;
    for (;;) {
        n = p->next;
        if (n == NULL || t->remaining < n->remaining)
            break;
        t->remaining -= n->remaining;
        p = n;
    }
    t->next = n;
    p->next = t;
    if (t->next != NULL)
        t->next->remaining -= t->remaining;
}

/* -------------------------------------------------------------------------
 * evt_timer_arm  --  0x80056c0
 * ------------------------------------------------------------------------- */
void evt_timer_arm(struct evt_timer *t, uint32_t ticks, evt_cb_t cb, int periodic)
{
    t->remaining = ticks;
    t->period = periodic ? ticks : 0;
    t->cb = cb;
    t->rsvd = 0;
    g_evt.lock(g_evt.ctx);
    evt_timer_insert(t);
    t->armed = 1;
    g_evt.unlock(g_evt.ctx);
}

/* -------------------------------------------------------------------------
 * evt_timer_restart  --  0x80056f8
 *   Unlink if armed (a timer not found in the list stays flagged armed), then
 *   re-arm when active.
 * ------------------------------------------------------------------------- */
void evt_timer_restart(struct evt_timer *t, int active, unsigned ms)
{
    if (t->armed) {
        g_evt.lock(g_evt.ctx);
        if (t == g_evt.head) {
            g_evt.head = t->next;
            if (g_evt.head != NULL) {
                uint32_t r = g_evt.remaining(g_evt.ctx) + g_evt.head->remaining;
                g_evt.head->remaining = r;
                g_evt.restart(g_evt.ctx, r);
            } else {
                g_evt.stop(g_evt.ctx);
                g_evt.irq_check(g_evt.ctx);
            }
            t->armed = 0;
        } else {
            struct evt_timer *p = g_evt.head, *n;
            for (;;) {
                n = p->next;
                if (n == NULL)
                    goto unlock;
                if (n == t)
                    break;
                p = n;
            }
            if (t->next != NULL)
                t->next->remaining += t->remaining;
            p->next = t->next;
            t->armed = 0;
        }
unlock:
        g_evt.unlock(g_evt.ctx);
    }

    if (active)
        evt_timer_arm(t, ms * 1000u + 100000u, assist_timeout_cb, 0);
}

/* -------------------------------------------------------------------------
 * tim2_isr  --  0x8006cd4   (vector IRQ28)
 * ------------------------------------------------------------------------- */
void tim2_isr(void)
{
    struct evt_timer *t;

    if (g_evt.irq_check(g_evt.ctx) == 0)
        return;

    t = g_evt.head;
    g_evt.head = t->next;
    if (g_evt.head != NULL)
        g_evt.start(g_evt.ctx, g_evt.head->remaining);

    if (t->period != 0) {
        t->remaining = t->period;
        evt_timer_insert(t);
    } else {
        t->armed = 0;
    }
    if (t->cb != NULL)
        t->cb(t);
}

/* ---- OD send helpers ------------------------------------------------------ */
struct od_slot;
struct od_reg;
struct od_payload;
typedef int (*od_done_cb_t)(struct od_slot *, struct od_reg *, void *, struct od_payload *);

extern int  can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);   /* 0x800ab60 */
extern void *vm_memset(void *dst, int c, size_t n);                      /* 0x800b1f6 */
extern void *vm_memcpy(void *dst, const void *src, size_t n);            /* 0x800b1ba */
extern uint8_t g_can_slots_mem[];      /* 0x20000a14 (struct od_slot[10] + header) */
#define g_can_slots ((struct od_slot *)g_can_slots_mem)
extern volatile uint32_t g_ms_now;     /* 0x200009d8 */

#define OD_REG_MODE(r)     (((const uint8_t *)(r))[4])
#define OD_REG_TIMEOUT(r)  (((const uint32_t *)(r))[3])
#define OD_REG_RETRIES(r)  (((const uint8_t *)(r))[0x10])

/* request slot as returned by od_slot_alloc (= &slot.obj, 0x5c stride) */
struct od_req {
    const struct od_reg *obj;  /* +0x00 */
    uint8_t  addr[3];          /* +0x04 */
    uint8_t  pad7;
    uint32_t total;            /* +0x08 */
    uint8_t  buf[0x40];        /* +0x0c */
    uint8_t  retries;          /* +0x4c */
    uint8_t  pad4d[3];
    uint32_t deadline;         /* +0x50 */
    od_done_cb_t cb;           /* +0x54 */
    uint32_t cb_arg;           /* +0x58 */
};

/* -------------------------------------------------------------------------
 * od_publish  --  0x80058e0
 * ------------------------------------------------------------------------- */
void od_publish(const struct od_reg *rec, const void *data, unsigned len)
{
    if (OD_REG_MODE(rec) == 2)
        can_frame_encode(g_can_slots, (struct od_reg *)rec, NULL,
                         (int)(uintptr_t)data, len);
}

/* -------------------------------------------------------------------------
 * od_slot_alloc  --  0x80062f8
 * ------------------------------------------------------------------------- */
struct od_req *od_slot_alloc(uint8_t *slots, const struct od_reg *rec)
{
    struct od_req *r = NULL;
    unsigned off;

    for (off = 8; off != 0x3a0; off += 0x5c)
        if (*(void **)(slots + off) == NULL)
            r = (struct od_req *)(slots + off);      /* last free one wins */

    if (r != NULL) {
        vm_memset(r, 0, 0x5c);
        r->obj = rec;
        r->retries = OD_REG_RETRIES(rec);
        r->deadline = g_ms_now + OD_REG_TIMEOUT(rec);
    }
    return r;
}

/* -------------------------------------------------------------------------
 * od_request  --  0x8006334
 *   Queue a request on `rec` (to `addr` if given, else rec's own address),
 *   completion callback `cb`; the slot is freed again if the send fails.
 * ------------------------------------------------------------------------- */
void od_request(const struct od_reg *rec, const uint8_t *addr, const void *data,
                unsigned len, od_done_cb_t cb)
{
    struct od_req *r = od_slot_alloc(g_can_slots_mem, rec);
    const uint8_t *id = (const uint8_t *)rec;

    if (r == NULL)
        return;

    r->addr[0] = id[0];
    r->addr[1] = id[1];
    r->addr[2] = id[2];
    r->cb_arg = 0;
    r->cb = cb;
    vm_memcpy(r->buf, data, len);
    r->total = len;
    if (addr != NULL) {
        r->addr[0] = addr[0];
        r->addr[1] = addr[1];
        r->addr[2] = addr[2];
    }
    if (can_frame_encode(g_can_slots, (struct od_reg *)r->obj, r->addr,
                         (int)(uintptr_t)r->buf, len) != 0)
        r->obj = NULL;
}
