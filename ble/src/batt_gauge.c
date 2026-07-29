/*
 * batt_gauge.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Fuel-gauge (TI bq27xxx-class) management driver, over I2C. Recovered by the ble
 * extern-audit: previously declared `extern`, but VanMoof-authored app code that
 * programs the gas gauge — staging data-flash parameters with block checksums,
 * the seal/unseal sequence, committing config, comparing read-back values, and a
 * device-type / reset probe.
 *
 * The gauge object holds an I2C device handle at `+0x04` and a config-snapshot
 * pointer at `+0x10`. Register/bus access (reg_write / i2c_write / the raw reg
 * toggles) is the low-level layer (vendor). `wdt_feed` (GPIO pin 0x148) is the
 * watchdog pat done between slow I2C steps.
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) noted per function. Not byte-identical.
 * Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- low-level gauge bus access ----------------------------------------- */
extern int      reg_write(void *i2c, uint32_t reg, uint32_t val);       /* 0x78afc */
extern int      i2c_write_vec(void *i2c, const void *iov, int n, uint16_t addr); /* 0x78ace */
extern int      reg_cfg(void *i2c, uint8_t addr, uint32_t flags);       /* 0x78a7a */
extern int      reg_toggle(void *i2c, uint8_t addr, uint32_t v);        /* 0x78aae */
extern int      gauge_read_word(void *gauge, uint32_t key, int *out, int len); /* 0x59f68 */
extern void     gauge_read_status(void *gauge, uint32_t *io);           /* 0x5a08c */
extern void     wdt_feed(int pin, int z);                               /* 0x63f14 (via 0x148) */
extern void     k_sleep_ms(int ms);                                     /* 0x63f50 */

/* log modules (gate = first byte & 7). */
extern void     aem_raise(void *m, uint32_t lvl, void *s);              /* 0x6efd8 */
extern uint8_t  g_log_gauge_commit[];   /* 0x59c54 */
extern uint8_t  g_log_gauge_stage[];    /* 0x59f5c */
extern uint8_t  g_log_gauge_cmp[];      /* 0x5a048 */
extern uint8_t  g_log_gauge_unseal[];   /* 0x5a118 */
extern uint8_t  g_log_gauge_poll[];     /* 0x5a150 */
extern uint8_t  g_log_gauge_probe[];    /* 0x5aa04 */
extern uint8_t  g_log_gauge_taper[];    /* 0x5aae4 */
extern void    *g_msg_gauge_commit, *g_msg_gauge_stage_a, *g_msg_gauge_stage_b,
               *g_msg_gauge_cmp, *g_msg_gauge_unseal, *g_msg_gauge_poll,
               *g_msg_gauge_probe, *g_msg_gauge_taper;

/* gauge object layout */
#define G_I2C(g)   (*(void **)((uint8_t *)(g) + 4))     /* i2c device handle */
#define G_ADDR(g)  (*(uint16_t *)((uint8_t *)(g) + 8))  /* i2c bus address   */
#define G_CFG(g)   (*(void **)((uint8_t *)(g) + 0x10))  /* config snapshot   */

static int level_set(const uint8_t *m) { return (m[0] & 7) != 0; }

/* bq data-flash "control block" registers. */
#define BQ_BLOCK_DATA  0x3e
#define BQ_BLOCK_CSUM  0x60

/* -------------------------------------------------------------------------
 * gauge_commit_params -- 0x59c28 : issue the config-update / commit command
 * (register 0x91), pat the watchdog on success.
 * ------------------------------------------------------------------------- */
void gauge_commit_params(void *gauge)
{
    if (reg_write(gauge, 0, 0x91) >= 0) {
        wdt_feed(0x148, 0);
        return;
    }
    if (level_set(g_log_gauge_commit))
        aem_raise(g_log_gauge_commit, 1, g_msg_gauge_commit);
}

/* -------------------------------------------------------------------------
 * gauge_stage_param -- 0x59e50 : write a data-flash value + its block checksum.
 *
 * The value (`len` bytes of `val`, big-endian) is written at the block-data
 * register, then the one's-complement block checksum (with the 4+len length
 * marker) is written to the checksum register — the bq27xxx dataflash update
 * sequence. Returns 0 on success or the negative bus error.
 * ------------------------------------------------------------------------- */
int gauge_stage_param(void *gauge, uint16_t offset, uint32_t val, unsigned len)
{
    struct { void *ptr; uint16_t len; uint8_t r; uint8_t stop; } iov[1];
    uint8_t  blk[8];
    uint8_t  sum = 0;
    unsigned i;
    int rc;

    /* blk[0] = offset marker, then `len` value bytes big-endian at the tail */
    *(uint16_t *)blk = offset;
    for (i = 0; i < len; i++)
        blk[1 + (len - 1 - i)] = (uint8_t)(val >> (i * 8));

    iov[0].ptr = blk; iov[0].len = (uint16_t)(len + 2); iov[0].r = BQ_BLOCK_DATA;
    iov[0].stop = 2;
    rc = i2c_write_vec(G_I2C(gauge), iov, 2, G_ADDR(gauge));
    if (rc < 0) {
        if (level_set(g_log_gauge_stage)) aem_raise(g_log_gauge_stage, 1, g_msg_gauge_stage_a);
        return rc;
    }
    wdt_feed(0x148, 0);

    for (i = 0; i < (len == 1 ? 3u : 4u); i++)
        sum = (uint8_t)(sum + blk[i]);

    blk[0] = (uint8_t)~sum;
    blk[1] = (uint8_t)(len + 4);
    iov[0].len = 2; iov[0].r = BQ_BLOCK_CSUM;
    rc = i2c_write_vec(G_I2C(gauge), iov, 2, G_ADDR(gauge));
    if (rc >= 0) {
        wdt_feed(0x148, 0);
        return 0;
    }
    if (level_set(g_log_gauge_stage)) aem_raise(g_log_gauge_stage, 1, g_msg_gauge_stage_b);
    return rc;
}

/* -------------------------------------------------------------------------
 * gauge_compare_param -- 0x5a01c : read a parameter and report whether it
 * differs from `expected`.
 * ------------------------------------------------------------------------- */
int gauge_compare_param(void *gauge, uint32_t key, int expected, int len)
{
    int got = 0;
    if (gauge_read_word(gauge, key, &got, len) != 0 && level_set(g_log_gauge_cmp))
        aem_raise(g_log_gauge_cmp, 1, g_msg_gauge_cmp);
    return got != expected;
}

/* -------------------------------------------------------------------------
 * gauge_unseal -- 0x5a120 : issue the unseal command (reg 0x90) and poll the
 * status up to 5 times for the "unsealed" (FULL ACCESS) bit.
 * ------------------------------------------------------------------------- */
int gauge_unseal(void *gauge)
{
    uint32_t st = 0;
    int tries = 5;

    if (reg_write(G_I2C(gauge), 0, 0x90) < 0) {
        if (level_set(g_log_gauge_poll)) aem_raise(g_log_gauge_poll, 1, g_msg_gauge_poll);
        return -1;
    }
    wdt_feed(0x148, 0);

    do {
        gauge_read_status(gauge, &st);
        if (((st >> 8) & 4) != 0)         /* status>>8 bit 2 = unsealed/full-access */
            return 0;
        wdt_feed(0x148, 0);
    } while (--tries != 0);

    if (level_set(g_log_gauge_unseal))
        aem_raise(g_log_gauge_unseal, 1, g_msg_gauge_unseal);
    return -0xe;
}

/* -------------------------------------------------------------------------
 * gauge_probe_device_type -- 0x5a988 : reset/probe the gauge via its device
 * vtable (configure the ROM/reset pins, toggle, settle 100 ms, read type).
 * ------------------------------------------------------------------------- */
int gauge_probe_device_type(void *gauge)
{
    void  *dev  = G_I2C(gauge);
    void **hw   = (void **)(*(void ***)dev)[2];     /* device sub-handle */
    uint8_t pin = *(uint8_t *)((uint8_t *)dev + 0xc);
    int (*cfg)(void *, uint8_t, uint32_t, int);

    if (level_set(g_log_gauge_probe) && (g_log_gauge_probe[0] & 7) > 2)
        aem_raise(g_log_gauge_probe, 3, g_msg_gauge_probe);

    cfg = (int (*)(void *, uint8_t, uint32_t, int))(uintptr_t)
          ((void **)(*(void ***)hw)[0])[6];         /* vtable[+0x18] */
    if (cfg == NULL) return -22;

    if (cfg(hw, pin, 0x200000, 0) == 0 &&
        reg_cfg(hw, pin, 0x20000) == 0 &&
        reg_toggle(hw, pin, 1) == 0) {
        k_sleep_ms(100);
        if (reg_toggle(hw, pin, 0) == 0 &&
            reg_cfg(hw, pin, (uint32_t)G_ADDR(gauge) | 0x10000) == 0)
            return 0;
    }
    return -22;                                      /* 0xffffffea */
}

/* -------------------------------------------------------------------------
 * gauge_set_taper -- 0x5aaac : scale the configured taper reference (cfg[+0x2a])
 * by `pct`/100 and write it to register 0x34, caching the result at cfg[+0x26].
 * ------------------------------------------------------------------------- */
int gauge_set_taper(void *gauge, int pct)
{
    uint8_t *cfg = (uint8_t *)G_CFG(gauge);
    uint32_t v = (uint32_t)((*(int16_t *)(cfg + 0x2a) * pct) / 100);
    int rc = reg_write(G_I2C(gauge), 0x34, v & 0xffff);

    if (rc != 0 && level_set(g_log_gauge_taper))
        aem_raise(g_log_gauge_taper, 1, g_msg_gauge_taper);
    *(int16_t *)(cfg + 0x26) = (int16_t)v;
    return rc;
}
