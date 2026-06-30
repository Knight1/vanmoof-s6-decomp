/*
 * battery_charger.c — VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Reconstruction of the charger (BQ25xxx-class) configuration / current-control
 * path and the battery fuel-gauge (BQ27xxx / TI Impedance Track) bring-up path,
 * plus the two Application-Event-Manager publishers the charger driver uses to
 * announce "charger detected" and "charger status" events.
 *
 * Behaviour-oriented (NOT byte-identical). OEM addresses are noted per function.
 * Compilable standalone with only <stdint.h> + <stddef.h>; every vendor / SDK /
 * RTOS symbol is declared extern below with its OEM address.
 *
 * The hardware-config blob ('param_2' in charger_write_config_registers) is a
 * flat array of 32-bit fields (one per configurable charger setting). The OEM
 * code reads it as a 'undefined4 *', and many fields are accessed at byte
 * offsets that fall *inside* those 32-bit slots — i.e. the producer packs both a
 * full 32-bit value and several sentinel-encoded enum bytes into the structure.
 * We model it as a raw byte buffer + offset accessors to stay faithful to the
 * decompiler's mixed word/byte access without inventing a struct layout.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- */
/* Vendor / SDK / RTOS externs (declared, never reconstructed)               */
/* ------------------------------------------------------------------------- */

/* I2C register write helpers (charger / gauge transport layer). */
extern int   reg_write_u8 (void *dev, uint32_t reg, uint32_t val);                 /* 0x787ee  (FUN_000787ee) */
extern int   reg_write_masked(void *dev, uint32_t reg, uint32_t mask, uint32_t v); /* 0x78860  (FUN_00078860) */
extern int   reg_set_bit  (void *dev, uint32_t reg, uint32_t bit);                 /* 0x788b0  (FUN_000788b0) */
extern int   reg_write_u16(void *dev, uint32_t reg, uint32_t val);                 /* 0x78afc  (FUN_00078afc) */
extern int   reg_read_u16 (void *dev, uint32_t reg, void *out);                    /* 0x78b3a  (FUN_00078b3a) */
extern int   gpio_pin_configure_raw(void *dev, uint32_t pin, uint32_t flags);      /* 0x78a7a  (FUN_00078a7a) */

/* Charger sub-field encoders used by charger_write_config_registers. */
extern int   charger_cfg_set_field_58a04(void *self, uint32_t v); /* 0x58a04 */
extern int   charger_cfg_set_field_58bf4(void *self, uint32_t v); /* 0x58bf4 */
extern int   charger_cfg_set_field_58c38(void *self, uint32_t v); /* 0x58c38 */
extern int   charger_cfg_set_field_58c7c(void *self, uint32_t v); /* 0x58c7c */
extern int   charger_cfg_set_field_58bb0(void *self, uint32_t v); /* 0x58bb0 */
extern int   charger_cfg_set_field_58cec(void *self, uint32_t v); /* 0x58cec */
extern int   charger_cfg_set_field_58d78(void *self, uint32_t v); /* 0x58d78 */
extern uint8_t charger_enc_2bit_58620(uint32_t sentinel);        /* 0x58620 */
extern uint8_t charger_enc_2bit_58658(uint32_t sentinel);        /* 0x58658 */

/* Gauge config-compare / writeback helpers. */
extern int   gauge_compare_param (void *self, uint32_t key, int val, int len);     /* 0x5a01c  (FUN_0005a01c) */
extern int   gauge_stage_param   (void *dev, uint32_t key, int val, int len);      /* 0x59e50  (FUN_00059e50) */
extern int   gauge_commit_params (void *dev);                                      /* 0x59c28  (FUN_00059c28) */
extern int   gauge_unseal        (void *self);                                     /* 0x5a120  (FUN_0005a120) */
extern int   gauge_read_device_type(void *self);                                   /* 0x5a988  (FUN_0005a988) */
extern void  gauge_apply_extra   (void *self);                                     /* 0x5aa3c  (FUN_0005aa3c) */
extern int   gauge_set_misc      (void *self, uint8_t v);                          /* 0x5aaac  (FUN_0005aaac) */

/* Bus / device readiness + delay. */
extern int   device_is_ready (void *dev);          /* 0x7a4bc  (FUN_0007a4bc) */
extern void  k_busy_wait_us  (uint32_t us, int x); /* 0x63f14  (thunk_FUN_00063f14) */

/* Application Event Manager (Zephyr AEM) + small helpers. */
extern void *aem_event_alloc (int chan, int id, int sz, int flags); /* 0x77cfc  (FUN_00077cfc) */
extern void  aem_event_submit(void *evt);                           /* 0x55564  (FUN_00055564) */
extern int   aem_notify       (void *handle, uint32_t id, void *data, int len); /* 0x79b92 (FUN_00079b92) */

/* CAN / OD plumbing (charger_identify). */
extern int   od_compare_serial(void *buf, void *expected, int len); /* 0x7b438  (FUN_0007b438) */
extern void  od_format_id     (void *dst, const void *fmt, char lo, int hi); /* 0x67450 (FUN_00067450) */
extern void  evt_blob_zero    (void *p, int v, int n);              /* 0x7b2ba  (FUN_0007b2ba) */
extern void  evt_blob_set_dev (void *p, uint32_t dev);             /* 0x7b3dc  (FUN_0007b3dc) */
extern uint16_t crc16_calc    (void *p);                            /* 0x1f76c  (FUN_0001f76c) */

/* Power-state coordination (charger_update_charge_current). */
extern int   ps_power_state_get  (void);   /* power state machine accessor */
extern int   ps_power_off_request(int reason);

/* Structured logging (Zephyr LOG backend wrappers). */
extern void  vm_logf       (volatile void *mod, int level, const void *fmt, ...);  /* 0x6effe (FUN_0006effe) */
extern void  vm_log_simple (volatile void *mod, int level, const void *fmt, ...);  /* 0x6efd8 (thunk_FUN_0006efd8) */
extern void  vm_log_assert (const void *msg);                            /* 0x6e064 (FUN_0006e064) */
extern void  vm_log_struct (volatile void *mod, uint32_t kind, void *rec, int x); /* 0x364f0 (FUN_000364f0) */

/* Per-module log-control words ('& 7' is the compiled-in level threshold). */
extern volatile uint32_t *g_log_charger;  /* 0x2b1fc / 0x2aadc / 0x2ab84 / 0x593ec / 0x5869c */
extern volatile uint32_t *g_log_gauge;    /* 0x5ac90 / 0x5a900 / 0x5aaa4 */

/* Assorted const data refs / format strings referenced via DAT_*. */
extern const void *g_str_blob;            /* generic placeholder for log fmt/string DATs */

/* Charger detected-event ID table (DAT_0002aae8): array of {id; serial_ptr; ...}
 * stride 0xc, [0]=2000mA charger, [1]=5000mA charger. */
extern const uint8_t g_charger_id_table[]; /* 0x2aae8 */

/* Module/instance singletons captured by the OEM (DAT_*): the gauge driver
 * 'self', the charger driver instance, AEM handle table, etc. */
extern void *g_charger_self;   /* DAT_0002b1f8 etc. */
extern void *g_charger_state;  /* DAT_0002b1f4 (charger_update_charge_current state) */
extern void *g_aem_handles;    /* DAT_0002abbc */

/* ------------------------------------------------------------------------- */
/* VanMoof current-threshold constants (read verbatim from .rodata)          */
/* ------------------------------------------------------------------------- */

#define FCC_THRESHOLD_LO     3500999u   /* DAT_00058ba8 — below => default 0xdac */
#define FCC_THRESHOLD_HI     4800000u   /* DAT_00058bac — at/above => cap 0x12c0 */
#define DISCHG_LIMIT_HI      619999u    /* DAT_00058df4 — above => cap 0x26c    */

/* charger config-blob byte-offset accessors (param_2 viewed as bytes). */
#define CFG_B(buf, off)   (((const uint8_t  *)(buf))[(off)])
#define CFG_W(buf, widx)  (((const uint32_t *)(buf))[(widx)])

/* ------------------------------------------------------------------------- */
/* charger_set_fast_charge_current @ 0x58b5c                                 */
/*                                                                            */
/* Clamp a requested fast-charge current (microamps) to the configured max,  */
/* map it to the charger's ICHG register units, and program register 4       */
/* (mask 0xff8). Returns 0 on success or the negative driver error.          */
/* ------------------------------------------------------------------------- */
int charger_set_fast_charge_current(void *self, uint32_t req_ua)
{
    /* self+4 -> driver instance; instance+0x28 -> configured current ceiling. */
    void *dev = *(void **)((uint8_t *)self + 4);
    uint32_t cfg_max = *(uint32_t *)((uint8_t *)dev + 0x28);
    uint32_t code;
    int ret;

    if (cfg_max < req_ua) {
        /* OEM guard '*DAT << 0x1d != 0' is identical to '(*DAT & 7) != 0' for
         * a u32 (only bits[2:0] survive the 29-bit shift). */
        if ((*g_log_charger & 7) != 0)
            vm_log_simple(g_log_charger, 1, g_str_blob /* "current exceeds max" */);
        return -1;
    }

    if (req_ua > FCC_THRESHOLD_LO) {
        if (req_ua < FCC_THRESHOLD_HI)
            code = (req_ua / 1000u) & 0xffffu;
        else
            code = 0x12c0u;                  /* hard ceiling */
    } else {
        code = 0xdacu;                       /* floor / default */
    }

    /* Program ICHG: register units are (mA)/10. */
    ret = (int)reg_write_masked(dev, 4, 0xff8, code / 10u);
    /* OEM: 'uVar1 & (int)uVar1 >> 0x1f' — pass through only negative errors. */
    return ret & (ret >> 31);
}

/* ------------------------------------------------------------------------- */
/* charger_set_discharge_current_limit @ 0x58db8                             */
/*                                                                            */
/* Clamp the system discharge-current limit (microamps) and program register */
/* 0x12 (mask 0x1f8). Units are (mA)/10 like ICHG. Floor 10, cap 0x26c.      */
/* ------------------------------------------------------------------------- */
int charger_set_discharge_current_limit(void *self, uint32_t req_ua)
{
    void *dev = *(void **)((uint8_t *)self + 4);
    uint32_t code;
    int ret;

    if (req_ua < 11000u)
        code = 10;
    else if (req_ua > DISCHG_LIMIT_HI)
        code = 0x26c;
    else
        code = (req_ua / 1000u) & 0xffffu;

    ret = (int)reg_write_masked(dev, 0x12, 0x1f8, code / 10u);
    return ret & (ret >> 31);
}

/* ------------------------------------------------------------------------- */
/* charger_update_charge_current @ 0x2b100                                   */
/*                                                                            */
/* React to a charger-presence/level code (param_2 & 0xff): pick a discharge */
/* current limit (8000 / 400 mA -> *1000 uA), reprogram it if changed, emit  */
/* the appropriate log/struct events, and on "removed" (code 0) optionally   */
/* request a power-off. Stores the last code in state+1.                     */
/* ------------------------------------------------------------------------- */
void charger_update_charge_current(void *charger_dev, uint32_t code)
{
    uint8_t *st = (uint8_t *)g_charger_state;   /* DAT_0002b1f4 */
    int target_ma;
    void *fmt __attribute__((unused));

    (void)charger_dev;

    if ((code & 0xff) != 0) {
        /* st[2]==0 (not throttled) AND power-state==3 => use stored hi limit
         * (st+8), else fall back to 400 mA. */
        if (st[2] == 0 && ps_power_state_get() == 3)
            target_ma = *(int *)(st + 8);
        else
            target_ma = 400;

        if (*(int *)(st + 4) != target_ma) {
            charger_set_discharge_current_limit(g_charger_self,
                                                (uint32_t)target_ma * 1000u);
            if ((*g_log_charger & 7) > 2)
                vm_logf(g_log_charger, 3, g_str_blob /* "discharge limit=%d" */,
                        target_ma);
            *(int *)(st + 4) = target_ma;
        }
    }

    /* Pick struct-event variant by throttle flag (st[2]). */
    fmt = (void *)g_str_blob;          /* DAT_0002b204 (normal) */
    if (st[2] != 0)
        fmt = (void *)g_str_blob;      /* DAT_0002b208 (throttled) */

    switch (code) {
    case 0:   /* charger removed */
        if ((*g_log_charger & 7) > 2)
            vm_log_simple(g_log_charger, 3, g_str_blob /* "charger removed" */);
        if (st[3] != 0) {
            ps_power_off_request(1);
            st[3] = 0;
        }
        break;
    case 1:   /* detected, no negotiation log unless verbose */
        if ((*g_log_charger & 7) > 2) {
            /* emits struct event 0x1cc0, see below */
            struct { void *fmt; void *p2; void *p3; uint16_t k; } rec;
            rec.k   = 0x200;
            rec.fmt = (void *)g_str_blob;   /* DAT_0002b214 */
            vm_log_struct(g_log_charger, 0x1cc0, &rec, 0);
        }
        break;
    case 2:
    case 3:
        if ((*g_log_charger & 7) > 2) {
            struct { void *fmt; void *p2; void *p3; uint16_t k; } rec;
            rec.k   = 0x200;
            rec.fmt = (void *)g_str_blob;   /* DAT_0002b214 */
            vm_log_struct(g_log_charger, 0x1cc0, &rec, 0);
        }
        break;
    default:
        break;
    }

    st[1] = (uint8_t)code;   /* remember last code */
}

/* ------------------------------------------------------------------------- */
/* charger_write_config_registers @ 0x590cc                                  */
/*                                                                            */
/* Push the full charger configuration blob (param_2) into the device. First */
/* the six sub-field encoders + the FCC / discharge limits run; then a long  */
/* sequence of sentinel-decoded enum bytes is packed into charger registers  */
/* 0x14..0x1c. Every sentinel value is validated; an unexpected value logs   */
/* an assert (vm_log_assert) and falls through to the safe default. Any I2C  */
/* write error aborts with a logged message and returns the negative code.   */
/*                                                                            */
/* Returns 0 on success, the negative driver error, or -1 on a bad PROFILE   */
/* sentinel at offset 0x26.                                                   */
/* ------------------------------------------------------------------------- */
int charger_write_config_registers(void *self, const void *cfg)
{
    const uint8_t *b = (const uint8_t *)cfg;
    void *dev = *(void **)((uint8_t *)self + 4);
    uint8_t r;          /* register 0x14 accumulator */
    uint8_t r17, r18, r19, r15, r1a, r1b, r1c;
    int t, t2;
    int ret;

    /* --- Sub-field encoders (each programs its own register set). ---
     * OEM passes 'self' (param_1) to every higher-level encoder; only the
     * reg_write_* / reg_set_bit primitives take the extracted 'dev'. */
    if ((ret = charger_set_fast_charge_current(self, CFG_W(b, 0))) < 0) return ret;
    if ((ret = charger_cfg_set_field_58a04(self, CFG_W(b, 1)))     < 0) return ret;
    if ((ret = charger_cfg_set_field_58bf4(self, CFG_W(b, 2)))     < 0) return ret;
    if ((ret = charger_cfg_set_field_58c38(self, CFG_W(b, 5)))     < 0) return ret;
    if ((ret = charger_cfg_set_field_58c7c(self, CFG_W(b, 4)))     < 0) return ret;
    if ((ret = charger_cfg_set_field_58bb0(self, CFG_W(b, 3)))     < 0) return ret;
    if ((ret = charger_cfg_set_field_58cec(self, CFG_W(b, 6)))     < 0) return ret;
    if ((ret = charger_cfg_set_field_58d78(self, CFG_W(b, 7)))     < 0) return ret;
    if ((ret = charger_set_discharge_current_limit(self, CFG_W(b, 8))) < 0) return ret;

    /* --- Register 0x14: a couple of bool bits + PROFILE sentinel (0x26). - */
    r = (uint8_t)((CFG_B(b, 0x25) << 6) | (CFG_B(b, 0x24) << 7));

    if (CFG_B(b, 0x26) == 0x14) {
        /* ok, leave bit5 clear */
    } else if (CFG_B(b, 0x26) == 0x50) {
        r |= 0x20;
    } else {
        if ((*g_log_charger & 7) != 0)
            vm_log_simple(g_log_charger, 1, g_str_blob /* "invalid profile" */);
        return -1;
    }

    /* WATCHDOG sentinel (0x27) -> 2-bit field shifted into bit3. */
    {
        uint8_t wd = CFG_B(b, 0x27);
        uint8_t code;
        if (wd == 0x23)      code = 2;
        else if (wd < 0x24)  { if (wd == 0) code = 0;
                               else if (wd == 0x11) code = 1;
                               else { vm_log_assert(g_str_blob); code = 0; } }
        else if (wd == 0x34) code = 3;
        else { vm_log_assert(g_str_blob); code = 0; }

        r |= (uint8_t)((CFG_B(b, 0x29) << 1) | (CFG_B(b, 0x28) << 2) | (code << 3));
    }

    /* ENABLE sentinel (0x2a): 0x64 -> bit0 clear, 0xc8 -> bit0 set, else err. */
    if (CFG_B(b, 0x2a) != 0x64) {
        if (CFG_B(b, 0x2a) != 0xc8) {            /* (signed -0x38) */
            if ((*g_log_charger & 7) != 0)
                vm_log_simple(g_log_charger, 1, g_str_blob);
            return -1;
        }
        r |= 1;
    }

    if ((ret = reg_write_u8(dev, 0x14, r)) < 0) {
        if ((*g_log_charger & 7) != 0)
            vm_log_simple(g_log_charger, 1, g_str_blob /* "reg 0x14 write fail" */);
        return ret;
    }

    /* Optional reg 0x16 bit7 set (gated by flag at 0x2b). */
    if (CFG_B(b, 0x2b) != 0) {
        if ((ret = reg_set_bit(dev, 0x16, 0x80)) < 0) {
            if ((*g_log_charger & 7) != 0)
                vm_log_simple(g_log_charger, 1, g_str_blob);
            return ret;
        }
    }

    /* --- Register 0x17: VINDPM-ish sentinels at 0x2c/0x2d/0x2e/0x2f. --- */
    if (CFG_B(b, 0x2c) == 0x3c)        r17 = 0;        /* '<' */
    else if (CFG_B(b, 0x2c) == 0x78)   r17 = 0x40;     /* 'x' */
    else { if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob); return -1; }

    if (CFG_B(b, 0x2d) == 0)           t = 0;
    else if (CFG_B(b, 0x2d) == 0x0a)   t = 2;
    else if (CFG_B(b, 0x2d) == 0xf6)   t = 1;          /* (signed -10) */
    else { vm_log_assert(g_str_blob); t = 0; }

    if (CFG_B(b, 0x2e) == 's')         t2 = 3;
    else if (CFG_B(b, 0x2e) == 'w')    t2 = 0;
    else if (CFG_B(b, 0x2e) == 'n')    t2 = 1;
    else { vm_log_assert(g_str_blob); t2 = 0; }

    r17 |= (uint8_t)((t << 4) | (t2 << 2));

    if (CFG_B(b, 0x2f) == 0x06)        { /* bit0 clear */ }
    else if (CFG_B(b, 0x2f) == 0x12)   r17 |= 1;
    else { if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob); return -1; }

    if ((ret = reg_write_u8(dev, 0x17, r17)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    /* --- Register 0x18: four bool bits at 0x30/0x31/0x32/0x33. --- */
    r18 = (uint8_t)((CFG_B(b, 0x30) << 6) | (CFG_B(b, 0x31) << 5) |
                    (CFG_B(b, 0x32) << 4) | (CFG_B(b, 0x33) << 3));
    if ((ret = reg_write_u8(dev, 0x18, r18)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    /* --- Register 0x19: two 2-bit enum sentinels at 0x34 / 0x38 + bits. --- */
    {
        uint8_t f34, f38;
        switch (CFG_B(b, 0x34)) {
        case 1:  f34 = 0; break;
        case 3:  f34 = 1; break;
        case 6:  f34 = 2; break;
        case 0xc:f34 = 3; break;
        default: vm_log_assert(g_str_blob); f34 = 0; break;
        }
        switch (CFG_B(b, 0x38)) {
        case 2:  f38 = 1; break;
        case 1:  f38 = 0; break;
        case 4:  f38 = 2; break;
        case 6:  f38 = 3; break;
        default: vm_log_assert(g_str_blob); f38 = 0; break;
        }
        r19 = (uint8_t)(f38 |
                        (CFG_B(b, 0x35) << 5) | (CFG_B(b, 0x36) << 4) |
                        (CFG_B(b, 0x37) << 2) | (f34 << 6));
    }
    if ((ret = reg_write_u8(dev, 0x19, r19)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    /* --- Register 0x15: two sentinels at 0x3c / 0x3d. --- */
    if (CFG_B(b, 0x3c) == 0x96)        /* (signed -0x6a) */
        r15 = (uint8_t)((CFG_B(b, 0x3a) << 3) | (CFG_B(b, 0x3b) << 2) | (CFG_B(b, 0x39) << 7));
    else if (CFG_B(b, 0x3c) == 0x28)   r15 = 2;
    else { if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob); return -1; }

    if (CFG_B(b, 0x3d) == 0x0e)        { /* keep */ }
    else if (CFG_B(b, 0x3d) == 0x1c)   r15 = 1;
    else { if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob); return -1; }

    if ((ret = reg_write_u8(dev, 0x15, r15)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    /* --- Register 0x1a: bool 0x3e, TS sentinel (word 0x10), flag (word 0x11),
     *     plus two 2-bit encoders (words 0x12 / 0x13 via 0x58658). --- */
    {
        uint8_t b3e = CFG_B(b, 0x3e);
        int sel = (int)CFG_W(b, 0x10);
        uint8_t cVar9;
        uint8_t hi, lo;

        if (sel == 0x3c)       cVar9 = 1;
        else if (sel == 0x37)  cVar9 = 0;
        else if (sel == 0x41)  cVar9 = 2;
        else if (sel == 0)     cVar9 = 3;
        else { vm_log_assert(g_str_blob); cVar9 = 0; }

        r1a = (uint8_t)((b3e << 7) | (cVar9 << 5));

        if ((int)CFG_W(b, 0x11) == -0x14) {        /* 0xffffffec */
            /* keep bit4 clear */
        } else if ((int)CFG_W(b, 0x11) == -10) {   /* 0xfffffff6 */
            r1a |= 0x10;
        } else {
            if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
            return -1;
        }

        hi = charger_enc_2bit_58658(CFG_W(b, 0x12));
        lo = charger_enc_2bit_58658(CFG_W(b, 0x13));
        r1a |= (uint8_t)(((hi & 3) << 2) | (lo & 3));
    }
    if ((ret = reg_write_u8(dev, 0x1a, r1a)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    /* --- Register 0x1b: 3-bit fields (words 0x14 / 0x15) + 2-bit enc 0x16. - */
    {
        uint32_t hi3 = CFG_W(b, 0x14) & 7;
        uint32_t lo3 = CFG_W(b, 0x15) & 7;
        uint8_t  enc = charger_enc_2bit_58620(CFG_W(b, 0x16));
        r1b = (uint8_t)((enc & 3) | (lo3 << 2) | (hi3 << 5));
    }
    if ((ret = reg_write_u8(dev, 0x1b, r1b)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    /* --- Register 0x1c: bool (word 0x17), 2-bit enc 0x18, two 2-bit enc
     *     0x19 / 0x1a (via 0x58658). --- */
    {
        uint8_t b17 = (uint8_t)CFG_B(b, 0x17 * 4);  /* OEM: *(char*)(param_2 + 0x17) */
        uint8_t enc18 = charger_enc_2bit_58620(CFG_W(b, 0x18));
        uint8_t enc19 = charger_enc_2bit_58658(CFG_W(b, 0x19));
        uint8_t enc1a = charger_enc_2bit_58658(CFG_W(b, 0x1a));
        r1c = (uint8_t)(((enc19 & 3) << 2) | (b17 << 6) |
                        (enc1a & 3) | ((enc18 & 3) << 4));
    }
    if ((ret = reg_write_u8(dev, 0x1c, r1c)) < 0) {
        if ((*g_log_charger & 7) != 0) vm_log_simple(g_log_charger, 1, g_str_blob);
        return ret;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* charger_identify @ 0x2aa54                                                */
/*                                                                            */
/* Match a detected charger's reported current (param_2 in mA: 2000 or 5000) */
/* against the known charger-ID table (g_charger_id_table, stride 0xc), then */
/* compare its 16-byte serial via od_compare_serial. On match, copy the      */
/* table entry's id into *out and return true. Logs the formatted device id  */
/* as a struct event (0x24c0) when verbose.                                  */
/* ------------------------------------------------------------------------- */
int charger_identify(const void *info, int current_ma, uint32_t *out)
{
    uint8_t serial[20];
    uint16_t devid = *(const uint16_t *)((const uint8_t *)info + 3);
    const uint8_t *tbl = g_charger_id_table;   /* DAT_0002aae8 */
    int idx;
    int matched;

    od_format_id(serial, &g_str_blob, (char)devid, devid >> 8);

    if ((*g_log_charger & 7) > 2) {
        struct { void *fmt; void *p2; uint8_t *ser; int cur; uint16_t k; } rec;
        rec.p2  = (void *)&g_str_blob;
        rec.k   = 0x200;
        rec.fmt = (void *)&g_str_blob;
        rec.ser = serial;
        rec.cur = current_ma;
        vm_log_struct(g_log_charger, 0x24c0, &rec, 0);
    }

    if (current_ma == 2000)
        idx = 0;
    else if (current_ma == 5000)
        idx = 1;
    else
        return 0;   /* false */

    /* table entry: [idx*0xc + 0] = id, [idx*0xc + 4] = expected serial ptr. */
    matched = od_compare_serial(serial,
                                *(void **)(tbl + idx * 0xc + 4), 0x10);
    if (matched != 0)
        *out = *(const uint32_t *)(tbl + idx * 0xc);

    return matched != 0;
}

/* ------------------------------------------------------------------------- */
/* charger_publish_detected_event @ 0x2aaec                                  */
/*                                                                            */
/* Build a 0x22-byte "charger detected" record (device id + CRC16 header),   */
/* allocate an AEM event on channel 0x23 / id 0x1b2, copy the staged record  */
/* into it, and submit it. Logs the device id (struct event 0x1cc0) first.   */
/* ------------------------------------------------------------------------- */
void charger_publish_detected_event(uint32_t device)
{
    uint8_t  rec[0x22];
    void    *evt;

    if ((*g_log_charger & 7) > 2) {
        struct { void *fmt; void *p2; uint32_t dev; uint16_t k; } lr;
        lr.p2  = (void *)&g_str_blob;
        lr.k   = 0x200;
        lr.fmt = (void *)&g_str_blob;
        lr.dev = device;
        vm_log_struct(g_log_charger, 0x1cc0, &lr, 0);
    }

    evt_blob_zero(rec, 0, 0x22);
    rec[0x20] = 1;                       /* local_1a = 1: record flavour */
    evt_blob_set_dev(rec + 2, device);   /* fill device-id field */
    *(uint16_t *)rec = crc16_calc(rec + 2);   /* header CRC over the payload */

    evt = aem_event_alloc(0x23, 0x1b2, 5, 0);
    if (evt != NULL) {
        /* OEM copies the 0x22-byte 'rec' into evt+5 (the event payload). */
        uint8_t *dst = (uint8_t *)evt + 5;
        for (int i = 0; i < 0x22; i++)
            dst[i] = rec[i];
    }
    aem_event_submit(evt);
}

/* ------------------------------------------------------------------------- */
/* charger_publish_status_event @ 0x2ab90                                    */
/*                                                                            */
/* Emit a 5-byte charger-status notification: byte0 = state (1=idle when both */
/* operands are zero, else 2), then a u16 'code' field and a u32 'extra'.     */
/* Routed through the AEM handle table (g_aem_handles+0x10).                  */
/* ------------------------------------------------------------------------- */
void charger_publish_status_event(int code, int status, uint32_t extra)
{
    struct __attribute__((packed)) {
        uint8_t  state;
        uint16_t code;
        uint8_t  status_lo;
        uint8_t  status_hi;
        uint32_t extra;
    } rec;

    rec.code      = (uint16_t)code;
    rec.status_lo = (uint8_t)status;
    rec.status_hi = (uint8_t)((uint32_t)status >> 8);
    rec.state     = (code == 0 && status == 0) ? 1 : 2;
    rec.extra     = extra;

    aem_notify(*(void **)((uint8_t *)g_aem_handles + 0x10),
               (uint32_t)(uintptr_t)&g_str_blob /* DAT_0002abc0 */,
               &rec, 5);
}

/* ------------------------------------------------------------------------- */
/* battery_set_btp_charge_threshold @ 0x5aa6c                                 */
/*                                                                            */
/* Compute the BTP (Battery Trip Point) charge-threshold register value as   */
/* (design_capacity[ctx+0x2a] * pct) / 100, write it to gauge register 0x36, */
/* and cache it at ctx+0x24. Returns the I2C write status (0 == success).    */
/* ------------------------------------------------------------------------- */
int battery_set_btp_charge_threshold(void *self, int pct)
{
    int16_t *ctx = *(int16_t **)((uint8_t *)self + 0x10);
    /* ctx[0x2a/2] is the design-capacity scalar. */
    int16_t design = *(int16_t *)((uint8_t *)ctx + 0x2a);
    uint32_t val = ((uint32_t)(int32_t)(design * pct)) / 100u;
    int ret;

    ret = reg_write_u16(*(void **)((uint8_t *)self + 4), 0x36, val & 0xffff);
    if (ret != 0) {
        if ((*g_log_gauge & 7) != 0)
            vm_log_simple(g_log_gauge, 1, g_str_blob /* "BTP write fail" */);
    }
    *(int16_t *)((uint8_t *)ctx + 0x24) = (int16_t)val;
    return ret;
}

/* ------------------------------------------------------------------------- */
/* battery_gauge_write_config @ 0x5a158                                       */
/*                                                                            */
/* Two-phase fuel-gauge data-flash configuration:                            */
/*  1) Compare every gauge parameter (key, value, length) against what the    */
/*     gauge currently holds (gauge_compare_param). The OEM ORs a "changed"   */
/*     bit forward through the whole chain so that a single difference forces  */
/*     a rewrite of all subsequent params.                                    */
/*  2) If anything differs, unseal (gauge_unseal), stage every parameter      */
/*     (gauge_stage_param) and commit (gauge_commit_params).                  */
/*  3) Read back register 0x3c (design capacity) and verify it equals the     */
/*     configured value; mismatch => -14 (0xfffffff2).                        */
/*                                                                            */
/* The parameter table (key, ctx-offset, length) is reproduced verbatim.     */
/* Returns 0 on success or a negative gauge error.                            */
/* ------------------------------------------------------------------------- */

/* (key, ctx byte offset, byte length, stage_only). 'len'==1 reads a u8,
 * ==2 reads s16. 'stage_only'!=0 means the parameter is part of the WRITE-BACK
 * (stage) cascade only and is NOT compared in phase 1 — this matches the OEM,
 * whose compare chain (FUN_0005a01c) jumps 0x92a3 -> 0x92a7 while the stage
 * chain (FUN_00059e50) inserts 0x92a5 (ctx+0x30) between them. */
struct gauge_param { uint16_t key; uint16_t off; uint8_t len; uint8_t stage_only; };

static const struct gauge_param k_gauge_params[] = {
    { 0x929b, 0x28, 2, 0 }, { 0x929d, 0x2a, 2, 0 }, { 0x929f, 0x2c, 2, 0 },
    { 0x92a3, 0x2e, 2, 0 }, { 0x92a5, 0x30, 2, 1 }, { 0x92a7, 0x32, 2, 0 },
    { 0x92a9, 0x34, 2, 0 }, { 0x92ab, 0x36, 2, 0 }, { 0x92ad, 0x38, 2, 0 },
    { 0x92af, 0x3a, 2, 0 }, { 0x92b1, 0x3c, 1, 0 }, { 0x92b2, 0x3d, 1, 0 },
    { 0x92b3, 0x3e, 1, 0 }, { 0x92b4, 0x40, 2, 0 }, { 0x92b6, 0x42, 1, 0 },
    { 0x92b7, 0x44, 2, 0 }, { 0x92b9, 0x46, 1, 0 }, { 0x92ba, 0x48, 2, 0 },
    { 0x92bc, 0x4a, 1, 0 }, { 0x92bd, 0x4c, 2, 0 }, { 0x92bf, 0x4e, 2, 0 },
    { 0x92c1, 0x50, 2, 0 }, { 0x92c3, 0x52, 2, 0 }, { 0x92c5, 0x54, 2, 0 },
    { 0x92c7, 0x56, 2, 0 }, { 0x92c9, 0x58, 2, 0 }, { 0x92cb, 0x5a, 2, 0 },
    { 0x92cd, 0x5c, 2, 0 }, { 0x92cf, 0x5e, 2, 0 }, { 0x92d1, 0x60, 2, 0 },
    { 0x91de, 0x62, 1, 0 }, { 0x9217, 0x64, 2, 0 },
};
#define N_GAUGE_PARAMS (sizeof(k_gauge_params)/sizeof(k_gauge_params[0]))

static int gauge_read_param(const uint8_t *ctx, const struct gauge_param *p)
{
    if (p->len == 1)
        return (int)(uint8_t)ctx[p->off];
    return (int)*(const int16_t *)(ctx + p->off);   /* sign-extended s16 */
}

int battery_gauge_write_config(void *self)
{
    const uint8_t *ctx = *(const uint8_t **)((uint8_t *)self + 0x10);
    void *dev = *(void **)((uint8_t *)self + 4);
    int changed = 0;
    int cmp_failed = 0;
    uint32_t status = 0;
    uint16_t readback = 0;
    size_t i;

    /* Phase 1: compare every NON-stage-only parameter (OEM compare cascade
     * skips key 0x92a5). A non-zero result on any param forces 'changed'. */
    for (i = 0; i < N_GAUGE_PARAMS; i++) {
        int r;
        if (k_gauge_params[i].stage_only)
            continue;
        r = gauge_compare_param(self, k_gauge_params[i].key,
                                gauge_read_param(ctx, &k_gauge_params[i]),
                                k_gauge_params[i].len);
        if (r < 0) { cmp_failed = 1; break; }
        /* OEM ORs the running 'changed' flag into the next non-zero result. */
        if (r != 0) changed = 1;
    }

    if (cmp_failed) {
        if ((*g_log_gauge & 7) != 0)
            vm_log_simple(g_log_gauge, 1, g_str_blob /* "unable to compare parameters" */);
        return -1;
    }

    /* Phase 2: if any parameter differs, unseal + stage + commit them all.
     * The stage cascade writes back every entry (including the stage-only
     * key 0x92a5 at ctx+0x30, in its proper position). */
    if (changed) {
        if (gauge_unseal(self) == 0) {
            int ok = 1;
            for (i = 0; i < N_GAUGE_PARAMS && ok; i++) {
                int r = gauge_stage_param(dev, k_gauge_params[i].key,
                                          gauge_read_param(ctx, &k_gauge_params[i]),
                                          k_gauge_params[i].len);
                if (r < 0) ok = 0;
            }
            if (ok)
                gauge_commit_params(dev);
        }
    }

    /* Phase 3: read back register 0x3c (design capacity) and verify. */
    if ((int)(status = (uint32_t)reg_read_u16(dev, 0x3c, &readback)) < 0) {
        if ((*g_log_gauge & 7) != 0)
            vm_log_simple(g_log_gauge, 1, g_str_blob /* "Unable to write design register" */);
    } else {
        /* OEM sign-extends the stored design capacity to u32 (uVar32 =
         * (uint)*(short*)(ctx+0x2c)) and compares the zero-extended u16
         * readback against it; a negative stored capacity therefore never
         * matches. Keep that semantic rather than truncating 'want' to u16. */
        uint32_t want = (uint32_t)(int32_t)*(const int16_t *)(ctx + 0x2c);
        if ((uint32_t)readback == want)
            return 0;
        if ((*g_log_gauge & 7) != 0)
            vm_logf(g_log_gauge, 1, g_str_blob /* "Design capacity not equal ..." */,
                    want, (uint32_t)readback);
        status = 0xfffffff2u;   /* -14 */
    }

    if ((*g_log_gauge & 7) != 0)
        vm_log_simple(g_log_gauge, 1, g_str_blob /* "Design capacity not valid" */);
    return (int)status;
}

/* ------------------------------------------------------------------------- */
/* battery_gauge_init @ 0x5aaec                                               */
/*                                                                            */
/* Bring up the BQ27xxx fuel gauge:                                          */
/*  - verify the I2C bus device is ready,                                     */
/*  - probe device type (gauge_read_device_type) and reset via control reg 0, */
/*  - read the DEVICE_TYPE word (register 0x40) and require it == 0x0220,     */
/*  - push data-flash config (battery_gauge_write_config), apply extras, set  */
/*    the BTP charge/discharge thresholds,                                    */
/*  - configure the BTP interrupt GPIO and arm its edge-callback, then enable */
/*    the BTP IO config (control reg 0x920d) and commit.                      */
/*                                                                            */
/* Returns 0 on success, or a negative errno (-19 ENODEV, -22 EINVAL,        */
/* -134 (0xffffff7a) unsupported device).                                     */
/* ------------------------------------------------------------------------- */
int battery_gauge_init(void *self, uint32_t flags)
{
    /* self+4 -> bus-config table (array of device descriptors),
     * self+0x10 -> mutable gauge context. The OEM overlays the masked 'flags'
     * (param_2 & 0xffff) into the low half-word of the same stack word it then
     * reads the DEVICE_TYPE result back from; the reconstruction isolates the
     * read into its own 'devtype' (equivalent so long as reg_read_u16 writes
     * exactly 2 bytes), so 'flags' is otherwise unused here. */
    uint32_t *cfg = *(uint32_t **)((uint8_t *)self + 4);
    uint8_t  *ctx = *(uint8_t **)((uint8_t *)self + 0x10);
    void     *dev;
    uint16_t  devtype = 0;
    int       ret;

    (void)flags;

    if (device_is_ready((void *)(uintptr_t)cfg[0]) == 0) {
        if ((*g_log_gauge & 7) != 0)
            vm_log_simple(g_log_gauge, 1, g_str_blob /* "Bus device is not ready" */);
        return -0x13;   /* -19 ENODEV */
    }

    ret = gauge_read_device_type(self);
    if (ret < 0)
        return ret;

    k_busy_wait_us(0x2000, 0);
    dev = *(void **)((uint8_t *)self + 4);

    /* Soft reset via control register 0. */
    ret = reg_write_u16(dev, 0, 1);
    if (ret < 0) {
        if ((*g_log_gauge & 7) != 0)
            vm_log_simple(g_log_gauge, 1, g_str_blob /* "unable to write control register" */);
        return ret;
    }

    k_busy_wait_us(0x148, 0);
    ret = reg_read_u16(dev, 0x40, &devtype);
    if (ret < 0 && (*g_log_gauge & 7) != 0)
        vm_log_simple(g_log_gauge, 1, g_str_blob /* "unable to read" */);

    k_busy_wait_us(0x148, 0);
    if (devtype != 0x220) {
        if ((*g_log_gauge & 7) != 0)
            vm_logf(g_log_gauge, 1, g_str_blob /* "Unsupported device: 0x%04x" */, devtype);
        return -0x86;   /* -134 */
    }

    ret = battery_gauge_write_config(self);
    if (ret < 0)
        return ret;

    gauge_apply_extra(self);
    *(uint32_t *)(ctx + 0x20) = 0;
    battery_set_btp_charge_threshold(self, ctx[0x6a]);
    gauge_set_misc(self, ctx[0x6b]);

    /* --- BTP interrupt GPIO. cfg[2] is the GPIO port device, cfg[3] is the
     *     pin number, *(u16)(cfg+0xe) the base flags (| 0x10000 = interrupt). */
    if (device_is_ready((void *)(uintptr_t)cfg[2]) == 0) {
        if ((*g_log_gauge & 7) != 0)
            vm_log_simple(g_log_gauge, 1, g_str_blob /* "GPIO port not ready" */);
        return -0x13;   /* -19 */
    }

    {
        void *gpio = (void *)(uintptr_t)cfg[2];
        uint32_t pin = *(uint8_t *)((uint8_t *)cfg + 0xc);  /* cfg+3 byte */
        uint16_t base_flags = *(uint16_t *)((uint8_t *)cfg + 0xe);

        ret = gpio_pin_configure_raw(gpio, pin, base_flags | 0x10000u);
        if (ret < 0) {
            if ((*g_log_gauge & 7) != 0)
                vm_log_simple(g_log_gauge, 1, g_str_blob /* "Unable to configure GPIO pin" */);
            return -0x16;   /* -22 EINVAL */
        }

        /* Register the GPIO callback (ctx+4 is the gpio_callback struct). */
        *(void **)(ctx + 8) = (void *)0x78af4;          /* PTR_LAB_00078af4 handler */
        *(uint32_t *)(ctx + 0xc) = 1u << pin;           /* pin_mask */

        {
            void **api = *(void ***)((uint8_t *)gpio + 8);
            /* api[0x1c/4] = manage_callback, api[0x18/4] = pin_interrupt_configure. */
            int (*add_cb)(void *, void *, int) = (int (*)(void *, void *, int))(uintptr_t)api[7];
            int (*irq_cfg)(void *, uint32_t, uint32_t, uint32_t) =
                (int (*)(void *, uint32_t, uint32_t, uint32_t))(uintptr_t)api[6];

            if (add_cb != NULL && add_cb(gpio, ctx + 4, 1) >= 0 &&
                irq_cfg != NULL &&
                irq_cfg(gpio, pin, 0x1400000, 0x4000000) >= 0) {

                gauge_unseal(self);
                ret = gauge_stage_param(dev, 0x920d, 1, 1);
                if (ret == 0) {
                    gauge_commit_params(dev);
                    if ((*g_log_gauge & 7) > 2)
                        vm_log_simple(g_log_gauge, 3,
                                      g_str_blob /* "initialized successfully" */);
                    return 0;
                }
                if ((*g_log_gauge & 7) != 0)
                    vm_log_simple(g_log_gauge, 1,
                                  g_str_blob /* "Unable to set BTP IO Config" */);
                return ret;
            }
        }
        return -0x16;   /* -22 EINVAL */
    }
}