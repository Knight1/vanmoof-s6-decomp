/*
 * gate_driver.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * Boot-time configuration of an I2C-attached motor driver companion chip
 * (7-bit address 0x47, write-protect register 0x0B: 0x2D unlocks, 0xDD locks;
 * register 0x80 bit 7 reads 0 when unlocked). The chip is not identified; it
 * is described by its register interface only.
 *
 *   gd_unlock       @ 0x800ad04  returns 0 when unlocked, else rc / bit 7
 *   gd_lock         @ 0x800ad26
 *   gd_configure    inline in main (0x80083e8 .. 0x80085ca)
 *
 * The register transfers (i2c_reg_read 0x8005324, i2c_reg_write 0x800541c)
 * are register-level STM32 I2C state machines with SysTick-based timeouts
 * (return 3 on timeout); kept as externs.
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>

extern int i2c_reg_read(uint8_t reg, uint8_t *val);     /* 0x8005324 */
extern int i2c_reg_write(uint8_t reg, uint8_t val);     /* 0x800541c */
extern volatile uint32_t g_ms_now;                      /* 0x200009d8 */

#define GD_REG_WPROT    0x0b
#define GD_REG_STATUS   0x80
#define GD_UNLOCK_KEY   0x2d
#define GD_LOCK_KEY     0xdd

/* -------------------------------------------------------------------------
 * gd_unlock  --  0x800ad04
 * ------------------------------------------------------------------------- */
int gd_unlock(void)
{
    uint8_t st;
    int rc;

    rc = i2c_reg_write(GD_REG_WPROT, GD_UNLOCK_KEY);
    if (rc != 0)
        return rc;
    rc = i2c_reg_read(GD_REG_STATUS, &st);
    if (rc != 0)
        return rc;
    return st >> 7;
}

/* -------------------------------------------------------------------------
 * gd_lock  --  0x800ad26   (the status read-back result is not used)
 * ------------------------------------------------------------------------- */
int gd_lock(void)
{
    uint8_t st;
    int rc;

    rc = i2c_reg_write(GD_REG_WPROT, GD_LOCK_KEY);
    if (rc != 0)
        return rc;
    return i2c_reg_read(GD_REG_STATUS, &st);
}

/* -------------------------------------------------------------------------
 * gd_configure  --  inline in main (0x80083e8)
 *   Each step stops its block at the first failing transfer; the block's
 *   gd_lock() and the final reg9 write always run.
 * ------------------------------------------------------------------------- */
void gd_configure(void)
{
    uint8_t v = 0;
    uint32_t t0;

    if (gd_unlock() == 0)
        i2c_reg_write(12, 0xff);

    /* block 1 */
    if (i2c_reg_read(1, &v) == 0 && gd_unlock() == 0) {
        v = (uint8_t)((v & ~0x23u) | 0x02u);
        if (i2c_reg_write(1, v) == 0 &&
            i2c_reg_read(8, &v) == 0 &&
            i2c_reg_write(8, (uint8_t)(v | 0x01u)) == 0 &&
            i2c_reg_read(7, &v) == 0)
            i2c_reg_write(7, (uint8_t)(v & 0xfeu));
    }
    gd_lock();

    /* block 2 */
    v = 0;
    if (i2c_reg_read(2, &v) == 0 && gd_unlock() == 0) {
        v = (uint8_t)((v & ~0x0cu) | 0x04u);
        if (i2c_reg_write(2, v) == 0 &&
            i2c_reg_read(8, &v) == 0)
            i2c_reg_write(8, (uint8_t)(v | 0x04u));
    }
    gd_lock();
    i2c_reg_write(9, 0xff);

    /* settle: wait for the ms counter to advance by more than 2 */
    t0 = g_ms_now;
    while ((uint32_t)(g_ms_now - t0) <= 2)
        ;
}
