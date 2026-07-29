/*
 * charger_cfg.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Charger-IC configuration driver (SMBus/I2C register programming). Recovered by
 * the ble extern-audit: these functions were previously declared `extern` (as if
 * vendor) but are VanMoof-authored charger-management code. Each `charger_set_*`
 * clamps a caller setpoint (mV / mA) to a per-field window, scales it to the
 * charger register's LSB, and writes a masked register field; the `*_encode`
 * helpers map sentinel setpoints to the 2-bit mode/rate codes.
 *
 * The charger object's I2C device handle is at `+0x04`; register access
 * (reg_write_masked / smbus_block_write) is the low-level bus layer (vendor).
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) noted per function. Not byte-identical.
 * Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- low-level charger bus access (I2C/SMBus register layer) ------------- */
/* Write a masked field of a charger register: (i2c, reg, field_mask, value).
 * Returns 0 on success, negative on bus error. */
extern int  reg_write_masked(void *i2c, uint32_t reg, uint32_t mask, uint32_t v); /* 0x78860 */
/* SMBus block write: (i2c, buf, len, i2c_addr). */
extern int  smbus_block_write(void *i2c, const void *buf, int len, uint16_t addr); /* 0x787c8 */
/* Fatal-assert helper (bad enum value). */
extern void charger_cfg_assert(void *msg);                                       /* 0x6e064 */
extern void *g_msg_bad_mode;                       /* DAT_00058654               */
extern void *g_msg_bad_rate;                       /* DAT_00058680               */

/* The charger object: I2C handle at +0x04, config struct pointer at +0x04->... */
#define CHG_I2C(c)   (*(void **)((uint8_t *)(c) + 4))

/* Per-field clamp windows (OEM rodata constants). Values below `lo` snap to the
 * field's minimum code, above `hi` snap to its maximum code. */
extern const uint32_t g_chg_vlim_lo, g_chg_vlim_hi;   /* 0x58a4c / 0x58a50 */
extern const uint32_t g_chg_iin_lo,  g_chg_iin_hi;    /* 0x58bec / 0x58bf0 */
extern const uint32_t g_chg_ichg_lo, g_chg_ichg_hi;   /* 0x58c30 / 0x58c34 */
extern const uint32_t g_chg_fa_lo,   g_chg_fa_hi;     /* 0x58c74 / 0x58c78 */
extern const uint32_t g_chg_fc_lo,   g_chg_fc_hi;     /* 0x58cb8 / 0x58cbc */
extern const uint32_t g_chg_fe_lo,   g_chg_fe_hi;     /* 0x58d44 / 0x58d48 */
extern const uint32_t g_chg_f10_hi;                   /* 0x58db4 */

/* config-struct field: the caller-max ceiling checked before the voltage write. */
#define CHG_VMAX(c)  (*(uint32_t *)((uint8_t *)CHG_I2C(c) + 0x2c))

/* charger log module (gate = first byte & 7). */
extern uint8_t g_log_charger_cfg[];                   /* 0x5869c */
extern void    aem_raise(void *m, uint32_t lvl, void *s); /* 0x6efd8 */
extern void    wdt_feed(int pin, int z);              /* 0x63f14 (via 0x148) */

/* Clamp `mv`/`ma` into [lo,hi]: below -> `min_code`, above -> `max_code`,
 * otherwise the raw value / 1000 (mV/mA -> the register's mV/mA units). */
static uint32_t clamp_scale(uint32_t v, uint32_t lo, uint32_t hi,
                            uint32_t min_code, uint32_t max_code)
{
    if (v <= lo) return min_code;
    if (v >= hi) return max_code;
    return (v / 1000) & 0xffff;
}
/* OEM returns `rc & (rc>>31)` == rc if the write failed (rc<0), else 0. */
static int wr_result(int rc) { return rc & (rc >> 31); }

/* -------------------------------------------------------------------------
 * charger_mode_encode -- 0x58620 : sentinel charge-mode -> 2-bit code.
 * -300->0, -200->1, -100->2, 0->3; anything else asserts and returns 0.
 * ------------------------------------------------------------------------- */
uint32_t charger_mode_encode(int sentinel)
{
    switch (sentinel) {
    case -300: return 0;
    case -200: return 1;
    case -100: return 2;
    case 0:    return 3;
    default:   charger_cfg_assert(g_msg_bad_mode); return 0;
    }
}

/* -------------------------------------------------------------------------
 * charger_rate_encode -- 0x58658 : percent rate -> 2-bit code.
 * 0->0, 20->1, 40->2, 100->3; else assert.
 * ------------------------------------------------------------------------- */
uint32_t charger_rate_encode(int pct)
{
    switch (pct) {
    case 0:    return 0;
    case 0x14: return 1;   /* 20 */
    case 0x28: return 2;   /* 40 */
    case 100:  return 3;
    default:   charger_cfg_assert(g_msg_bad_rate); return 0;
    }
}

/* -------------------------------------------------------------------------
 * charger_set_charge_voltage -- 0x58a04 : reg 2, field 0xFC0, 80 mV/LSB.
 * Rejected (returns -1) if the request exceeds the config ceiling (+0x2c).
 * ------------------------------------------------------------------------- */
uint32_t charger_set_charge_voltage(void *chg, uint32_t mv)
{
    uint32_t code;
    if (mv > CHG_VMAX(chg)) {
        if ((g_log_charger_cfg[0] & 4) != 0)     /* bit-2 info gate */
            aem_raise(g_log_charger_cfg, 1, (void *)0 /* 0x586a0 */);
        return 0xffffffff;
    }
    code = clamp_scale(mv, g_chg_vlim_lo, g_chg_vlim_hi, 0x50, 0xdc0);
    return (uint32_t)wr_result(reg_write_masked(CHG_I2C(chg), 2, 0xfc0, code / 0x50));
}

/* charger_set_input_current -- 0x58bb0 : reg 6, field 0xFF0, 20 mA/LSB. */
uint32_t charger_set_input_current(void *chg, uint32_t ma)
{
    uint32_t code = clamp_scale(ma, g_chg_iin_lo, g_chg_iin_hi, 100, 0xc80);
    return (uint32_t)wr_result(reg_write_masked(CHG_I2C(chg), 6, 0xff0, code / 0x14));
}

/* charger_set_charge_current -- 0x58bf4 : reg 8, field 0x3FE0, 40 mA/LSB. */
uint32_t charger_set_charge_current(void *chg, uint32_t ma)
{
    uint32_t code = clamp_scale(ma, g_chg_ichg_lo, g_chg_ichg_hi, 0xed8, 0x41a0);
    return (uint32_t)wr_result(reg_write_masked(CHG_I2C(chg), 8, 0x3fe0, code / 0x28));
}

/* charger_set_field_a -- 0x58c38 : reg 0x0A, field 0xFF0, 20-unit/LSB. */
uint32_t charger_set_field_a(void *chg, uint32_t v)
{
    uint32_t code = clamp_scale(v, g_chg_fa_lo, g_chg_fa_hi, 100, 0x960);
    return (uint32_t)wr_result(reg_write_masked(CHG_I2C(chg), 0xa, 0xff0, code / 0x14));
}

/* charger_set_field_c -- 0x58c7c : reg 0x0C, field 0x1FC0, 80-unit/LSB. */
uint32_t charger_set_field_c(void *chg, uint32_t v)
{
    uint32_t code = clamp_scale(v, g_chg_fc_lo, g_chg_fc_hi, 0xf00, 0x2580);
    return (uint32_t)wr_result(reg_write_masked(CHG_I2C(chg), 0xc, 0x1fc0, code / 0x50));
}

/* charger_set_field_e -- 0x58cec : reg 0x0E via a 3-byte SMBus block write. */
uint32_t charger_set_field_e(void *chg, uint32_t v)
{
    uint32_t code = clamp_scale(v, g_chg_fe_lo, g_chg_fe_hi, 0xa00, 0xf00);
    uint32_t scaled = (code / 0x50) << 6;
    uint8_t  buf[3];
    void   **dev = (void **)CHG_I2C(chg);
    buf[0] = 0x0e;
    buf[1] = (uint8_t)scaled;
    buf[2] = (uint8_t)(scaled >> 8);
    return (uint32_t)wr_result(smbus_block_write(dev[0], buf, 3, *(uint16_t *)(dev + 1)));
}

/* charger_set_field_10 -- 0x58d78 : reg 0x10, field 0x1F0, 20-unit/LSB.
 * Values < 21000 clamp to the minimum code (0x14). */
uint32_t charger_set_field_10(void *chg, uint32_t v)
{
    uint32_t code;
    if (v < 21000)                 code = 0x14;
    else if (v > g_chg_f10_hi)     code = 0x26c;
    else                           code = (v / 1000) & 0xffff;
    return (uint32_t)wr_result(reg_write_masked(CHG_I2C(chg), 0x10, 0x1f0, code / 0x14));
}
