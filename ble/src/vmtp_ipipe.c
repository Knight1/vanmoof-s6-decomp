/*
 * vmtp_ipipe.c -- VanMoof S6 "ble" (nRF52840 central controller)
 *
 * Inbound command-pipeline ("ipipe") transport for the VanMoof transport
 * protocol (vmtp).  Two routines reconstructed from the OEM image:
 *
 *   ipipe_ctx_init   @ 0x0002e0c8  -- allocate & wire up the ~0x460-byte
 *                                     command-pipeline context, register it
 *                                     with the underlying transport, and on
 *                                     success publish the binding to the
 *                                     post-init state object.
 *   ipipe_dispatch   @ 0x0002e14c  -- per-message entry point: reset the
 *                                     per-call scratch fields, parse the
 *                                     inbound message (0x6e92c), then invoke
 *                                     the registered command handler found at
 *                                     ctx+0x1c -> +0x18.  Logs
 *                                     "ipipe dispatch failed (err=%d)" and
 *                                     returns -32 (-0x20 / -ENOMSG style) when
 *                                     no handler is registered.
 *
 * Behaviour-oriented translation.  Vendor/RTOS/SDK routines are declared as
 * local externs with their OEM address; no vendor code is reconstructed here.
 * Function pointers are cast through uintptr_t.
 *
 * Build: cc -Wall -Wextra -Wpedantic -std=c11 -c vmtp_ipipe.c
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- *
 * Vendor / platform externs (declared, not reconstructed).
 * ------------------------------------------------------------------------- */

/*
 * Zeroing block allocator / fixed-region acquire used to obtain the pipeline
 * context.  Called as fn(pool, 0, size, pool, r3); returns a pointer to a
 * size-byte zero-initialised region.  @ 0x0007b2ba
 */
extern void *vmtp_block_alloc(void *pool, int zero, uint32_t size,
                              void *pool2, uint32_t r3); /* 0x0007b2ba */

/*
 * Register / start the transport binding (binds the rx callbacks installed at
 * binding+0x28 / +0x2c).  Returns 0 on success, negative errno on failure.
 * @ 0x0003e4f0
 */
extern int vmtp_transport_register(void *binding); /* 0x0003e4f0 */

/*
 * Notify that the transport binding is ready (kick the pipeline / signal
 * waiters).  Takes no explicit argument in the OEM ABI.  @ 0x0003e530
 */
extern void vmtp_transport_started(void); /* 0x0003e530 */

/*
 * Parse / feed the inbound message buffer through the framing layer; on the
 * way it populates the scratch fields of the per-call context block
 * (block+0x20 region) and selects the registered handler (block+0x1c).
 * Called as fn(scratch_base, msg, len).  @ 0x0006e92c
 */
extern void vmtp_msg_parse(void *scratch_base, uint32_t msg, uint32_t len); /* 0x0006e92c */

/* VanMoof formatted logger: vm_logf(log_ctx, level, fmt, arg). @ 0x0006efea */
extern void vm_logf(void *log_ctx, int level, const char *fmt, int arg); /* 0x0006efea */

/* ------------------------------------------------------------------------- *
 * Fixed image objects referenced by the two routines (OEM addresses).
 * ------------------------------------------------------------------------- */

/* Pool/arena the context is carved from.            @ 0x2000f8e0 */
#define IPIPE_CTX_POOL      ((void *)(uintptr_t)0x2000f8e0u)
/* Same arena base reused as the per-call dispatch scratch block. */
#define IPIPE_SCRATCH       ((volatile uint8_t *)(uintptr_t)0x2000f8e0u)
/* Transport binding object configured by init.      @ 0x2000fd4c */
#define IPIPE_BINDING       ((volatile uint8_t *)(uintptr_t)0x2000fd4cu)
/* Post-init state object (publishes binding ptr + state). @ 0x2000fd40 */
#define IPIPE_STATE         ((volatile uint32_t *)(uintptr_t)0x2000fd40u)
/* Logging module context.                           @ 0x20003394 */
#define IPIPE_LOG_CTX       ((volatile uint32_t *)(uintptr_t)0x20003394u)

/*
 * Image-resident function pointers wired into the context / binding.  These
 * are platform glue (transport rx path + the per-message command callback);
 * reconstructed only as the bare pointers the OEM stores.
 */
#define IPIPE_CMD_HANDLER   ((void *)(uintptr_t)0x0002e035u) /* -> ctx+0x18  */
#define IPIPE_RX_CB_A       ((void *)(uintptr_t)0x0002e015u) /* -> binding+0x28 */
#define IPIPE_RX_CB_B       ((void *)(uintptr_t)0x0006cf3du) /* -> binding+0x2c */

/* Field offsets within the pipeline context (~0x460 bytes total). */
#define CTX_HANDLER_OBJ     0x18u  /* registered handler object ptr            */
#define CTX_BUF0_PTR        0x20u  /* -> ctx+0x40  (first 0x200-byte buffer)   */
#define CTX_BUF0_LEN        0x3cu  /* 0x200                                    */
#define CTX_BUF0            0x40u
#define CTX_BUF1_PTR        0x240u /* -> ctx+0x260 (second 0x200-byte buffer)  */
#define CTX_BUF1_LEN        0x25cu /* 0x200                                    */
#define CTX_BUF1            0x260u
#define IPIPE_BUF_LEN       0x200u
#define IPIPE_CTX_SIZE      0x460u

/* Field offsets within the transport binding object. */
#define BIND_RX_CB_A        0x28u
#define BIND_RX_CB_B        0x2cu

/*
 * Per-call dispatch scratch sub-block, based at SCRATCH+0x20.  ipipe_dispatch
 * clears the message-parse working fields before handing off to the parser.
 */
#define SCR_BASE            0x20u  /* parser working base                      */
#define SCR_HANDLER         0x1cu  /* selected handler object (set by parser)  */
#define SCR_F24             0x24u
#define SCR_F28             0x28u
#define SCR_F2C             0x2cu
#define SCR_F30             0x30u
#define SCR_F34             0x34u
#define SCR_F38             0x38u

/* Handler object: callback at +0x18, invoked as fn(obj, scratch, scratch+0x20). */
#define HANDLER_FN          0x18u

/* Post-init state object layout: binding ptr at +4, state code at +8. */
#define STATE_BINDING       1u     /* word index 1 (+4) */
#define STATE_CODE          2u     /* word index 2 (+8) */
#define IPIPE_STATE_READY   5u

#define IPIPE_LOG_MASK      7u     /* (log_ctx[0] << 29) != 0  <=>  low 3 bits */
#define IPIPE_LOG_LEVEL     1
#define IPIPE_ENOHANDLER    (-0x20) /* no registered handler */

static const char IPIPE_FMT_INIT_FAIL[] = "unable to initialize transport (err=%d)";
static const char IPIPE_FMT_DISP_FAIL[] = "ipipe dispatch failed (err=%d)";

/* ------------------------------------------------------------------------- *
 * Small store helpers (verbatim MMIO/struct field writes, no abstraction that
 * changes the emitted accesses).
 * ------------------------------------------------------------------------- */

static inline void ctx_store_u32(uint8_t *ctx, uint32_t off, uint32_t v)
{
    *(volatile uint32_t *)(uintptr_t)(ctx + off) = v;
}

static inline void ctx_store_ptr(uint8_t *ctx, uint32_t off, void *p)
{
    *(volatile uintptr_t *)(uintptr_t)(ctx + off) = (uintptr_t)p;
}

/* ------------------------------------------------------------------------- *
 * ipipe_ctx_init  @ 0x0002e0c8
 *
 * Allocate the command-pipeline context, install the command handler and its
 * two 0x200-byte scratch buffers, wire the transport binding's rx callbacks,
 * and register the binding.  On success, publish the binding pointer and the
 * "ready" state code (5) to the post-init state object and signal the
 * transport-started hook.  On failure, log the init error.
 *
 * Returns 0 on success, otherwise the transport register error code.
 * ------------------------------------------------------------------------- */
int ipipe_ctx_init(void)
{
    volatile uint8_t *binding = IPIPE_BINDING;
    uint8_t *ctx;
    int err;

    ctx = (uint8_t *)vmtp_block_alloc(IPIPE_CTX_POOL, 0, IPIPE_CTX_SIZE,
                                      IPIPE_CTX_POOL, 0u);

    /* Registered command handler object. */
    ctx_store_ptr(ctx, CTX_HANDLER_OBJ, IPIPE_CMD_HANDLER);

    /* Two in-context 0x200-byte buffers, each described by {ptr,len}. */
    ctx_store_u32(ctx, CTX_BUF0_LEN, IPIPE_BUF_LEN);
    ctx_store_u32(ctx, CTX_BUF1_LEN, IPIPE_BUF_LEN);
    ctx_store_ptr(ctx, CTX_BUF0_PTR, ctx + CTX_BUF0);
    ctx_store_ptr(ctx, CTX_BUF1_PTR, ctx + CTX_BUF1);

    /* Wire the transport binding's rx callbacks. */
    *(volatile uintptr_t *)(uintptr_t)(binding + BIND_RX_CB_A) = (uintptr_t)IPIPE_RX_CB_A;
    *(volatile uintptr_t *)(uintptr_t)(binding + BIND_RX_CB_B) = (uintptr_t)IPIPE_RX_CB_B;

    err = vmtp_transport_register((void *)binding);
    if (err == 0) {
        /* Publish binding + ready state, then signal start. */
        IPIPE_STATE[STATE_BINDING] = (uint32_t)(uintptr_t)binding;
        IPIPE_STATE[STATE_CODE]    = IPIPE_STATE_READY;
        vmtp_transport_started();
        return 0;
    }

    if ((IPIPE_LOG_CTX[0] & IPIPE_LOG_MASK) != 0u) {
        vm_logf((void *)IPIPE_LOG_CTX, IPIPE_LOG_LEVEL, IPIPE_FMT_INIT_FAIL, err);
    }
    return err;
}

/* ------------------------------------------------------------------------- *
 * ipipe_dispatch  @ 0x0002e14c
 *
 * Per-message dispatch.  Clears the per-call working fields of the dispatch
 * scratch block, runs the framing/parse step (which selects the handler and
 * fills the scratch sub-block at +0x20), then -- if a handler with a non-NULL
 * callback was selected -- invokes it as fn(handler, scratch, scratch+0x20).
 *
 *   param_1 = inbound message buffer
 *   param_2 = message length
 *
 * Returns 0 on success; the handler's error code (logged) on failure; or
 * -0x20 when no handler is registered (also logged).
 * ------------------------------------------------------------------------- */
int ipipe_dispatch(uint32_t msg, uint32_t len)
{
    volatile uint8_t *scr = IPIPE_SCRATCH;
    void *scratch_base = (void *)(uintptr_t)(scr + SCR_BASE);
    void *handler;
    int err;

    /* Reset per-call working fields before parsing. */
    ctx_store_u32((uint8_t *)scr, SCR_F24, 0);
    ctx_store_u32((uint8_t *)scr, SCR_F28, 0);
    ctx_store_u32((uint8_t *)scr, SCR_F2C, 0);
    ctx_store_u32((uint8_t *)scr, SCR_F30, 0);
    ctx_store_u32((uint8_t *)scr, SCR_F34, 0);
    ctx_store_u32((uint8_t *)scr, SCR_F38, 0);

    /* Parse the inbound message; selects handler at scr+0x1c. */
    vmtp_msg_parse(scratch_base, msg, len);

    handler = *(void *const volatile *)(uintptr_t)(scr + SCR_HANDLER);
    if (handler == NULL ||
        *(void *const volatile *)(uintptr_t)((uint8_t *)handler + HANDLER_FN) == NULL) {
        err = IPIPE_ENOHANDLER;
    } else {
        int (*fn)(void *, void *, void *) =
            (int (*)(void *, void *, void *))(uintptr_t)
            *(void *const volatile *)(uintptr_t)((uint8_t *)handler + HANDLER_FN);

        err = fn(handler, (void *)scr, (void *)(uintptr_t)(scr + SCR_BASE));
        if (err == 0) {
            return 0;
        }
    }

    if ((IPIPE_LOG_CTX[0] & IPIPE_LOG_MASK) != 0u) {
        vm_logf((void *)IPIPE_LOG_CTX, IPIPE_LOG_LEVEL, IPIPE_FMT_DISP_FAIL, err);
    }
    return err;
}