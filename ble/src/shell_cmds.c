/*
 * shell_cmds.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Debug-shell command handlers.  These are the leaf `shell_cmd_handler`s of the
 * Zephyr shell command groups (see ble/docs/shell.md) — reached only through the
 * shell command tables (no code xref), so the analyzer left them undefined; they
 * were recovered with ghidra_scripts/RecoverBleShellCmds.java and are named
 * <group>_cmd_<syntax>.
 *
 * Each is a thin argc/argv wrapper over an already-reconstructed subsystem
 * (power-state, battery/charger, elock, FMNA, audio, CAN OD, DTC, firmware
 * update). The `<group> on|off` / `reset` commands drive the per-ECU CAN power
 * rails; the `... state` commands dump status read over the CAN object
 * dictionary.
 *
 * Behaviour-oriented reconstruction from the Ghidra decompiler output; OEM
 * addresses (image base 0xC000) noted per function. Not byte-identical.
 * Self-contained: <stdint.h>/<stddef.h> + the vendor/subsystem externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- shell I/O (Zephyr shell, vendor) ----------------------------------- */
extern void shell_print(void *sh, const char *fmt, ...);          /* 0x6f948 shell_fprintf(NORMAL) */
extern void shell_error(void *sh, const char *fmt, ...);          /* 0x6f980 shell_fprintf(ERROR)  */
extern void shell_print_c(void *sh, int color, const char *fmt, ...); /* 0x6f92e */
extern void shell_field(void *sh, const char *label, unsigned v, const char *fmt); /* 0x32dfc */

/* ---- arg parsing (vendor libc/util) ------------------------------------- */
extern long dtc_pattern_match(const char *arg, const char *pattern);   /* strcmp-ish, 0 == match */
extern int  str_to_int(const char *s, int dflt, int base);        /* 0x6758c */
extern unsigned str_to_uint(const char *s, int base, int *err);   /* 0x6fbfe */
extern unsigned str_to_u8(const char *s, int base, void *out);    /* 0x6fc4c */
extern unsigned str_to_ring(const char *s, int a, int b);         /* 0x3a178 */

/* ---- CAN object-dictionary query (fills g_od_resp; 0 == ok) -------------- */
extern int      od_query(uint16_t obj, int len);                  /* 0x331b0 */
extern void     od_release(void);                                 /* 0x32e4c */
extern uint8_t *g_od_resp;                                        /* DAT_000335a4 / 0x33290 */

/* ---- subsystem entry points (reconstructed elsewhere) ------------------- */
extern int32_t ps_power_on_request(uint32_t consumer);            /* 0x29048 */
extern int32_t ps_power_off_request(uint32_t consumer);           /* 0x29134 */
extern uint8_t ps_power_state_get(void);                          /* 0x2900c */
extern void    ps_publish_evt_4b(uint32_t v);                     /* 0x2a424 */
extern void    ps_set_flag_publish_1b(int on);                    /* 0x2a44c */
extern void    actuator_power_domain_enable(int domain);          /* 0x2ad9c */
extern void    can_power_off(int domain);                         /* 0x2ad44 */
extern void    charger_identify(int arg);                         /* 0x2a8e4 */
extern void    batt_charge_disable(void);                         /* 0x2a5a4 */
extern void    handlebar_power_set(int on);                       /* 0x2ae50 */
extern void    motor_ctl_power_set(int on);                       /* 0x2ae7c */
extern void    powerecu_power_set(int on);                        /* 0x2ae88 */
extern void    charger_reset(void);                               /* 0x2abc4 */
extern void    handlebar_reset(void);                             /* 0x2a524 */
extern void    lights_reset(void);                                /* 0x2a540 */
extern void    motor_ctl_reset(void);                             /* 0x2a588 */
extern void    lipo_enter_shipping(uint8_t code);                 /* 0x2b564 */
extern void    dtc_clear_all(void);                               /* 0x2cf34 */
extern void    dtc_save(void);                                    /* 0x2cf78 */
extern void    elock_report_lock_state(uint8_t state);            /* 0x28760 */
extern void    elock_shell_print_state(void *sh, int z);          /* 0x28598 */
extern void    elock_lock_all(void);                              /* 0x288a0 */
extern void    elock_unlock_all(void);                            /* 0x28ae0 */
extern int     fmna_app_enable(int on);                           /* 0x33ca8 */
extern int     fmna_app_factory_reset(void);                      /* 0x33e00 */
extern int     fmna_stolen_mode_get(void);                        /* 0x62270 */
extern void    audio_play_current_bell(int secondary, int now);   /* 0x... bell */
extern void    audio_set_bell_index(uint8_t primary, uint8_t secondary); /* 0x... */

/* module-global test-capacity + ring/update helpers (vendor/sibling) */
extern void  batt_test_capacity_get(void *out, void *en);         /* 0x2a90c */
extern void  batt_test_capacity_set(void *vals, int en);          /* 0x2a920 */
extern int   fmna_toggle(int on);                                 /* 0x33ce4 */
extern int   fmna_disable(void);                                  /* 0x6d5aa */
extern int   fmna_factory_reset2(void);                           /* 0x62538 */
extern uint8_t g_fmna_enabled;                                    /* DAT_00033f50 / 0x33ab8 */

/* ---- literal strings (documented; real ptrs from the pools) ------------- */
#define S_ON  "on"
/* ------------------------------------------------------------------------- */

/* ===== power-tree groups: <ecu> on|off  ================================== */

/* battery_cmd_on -- 0x33100 : `battery on|off` -> whole-bike power request */
int32_t battery_cmd_on(void *sh, int argc, char **argv)
{
    (void)argc;
    if (dtc_pattern_match(argv[0], S_ON) == 0) {
        shell_print(sh, "Power battery on");
        ps_power_on_request(3);
    } else {
        shell_print(sh, "Power battery off");
        ps_power_off_request(3);
    }
    return 0;
}

/* can_cmd_on -- 0x330c4 : `can on|off` -> CAN power domain 4 */
int32_t can_cmd_on(void *sh, int argc, char **argv)
{
    (void)argc;
    if (dtc_pattern_match(argv[0], S_ON) == 0) {
        shell_print(sh, "CAN on");
        actuator_power_domain_enable(4);
    } else {
        shell_print(sh, "CAN off");
        can_power_off(4);
    }
    return 0;
}

/* handlebar_cmd_on -- 0x3301c */
int32_t handlebar_cmd_on(void *sh, int argc, char **argv)
{
    int off = (dtc_pattern_match(argv[0], S_ON) != 0);
    (void)argc;
    shell_print(sh, off ? "Handlebar off" : "Handlebar on");
    handlebar_power_set(!off);
    return 0;
}

/* lights_cmd_on -- 0x3308c */
int32_t lights_cmd_on(void *sh, int argc, char **argv)
{
    int off = (dtc_pattern_match(argv[0], S_ON) != 0);
    (void)argc;
    shell_print(sh, off ? "Lights off" : "Lights on");
    ps_set_flag_publish_1b(!off);
    return 0;
}

/* motor_control_cmd_on -- 0x33054 */
int32_t motor_control_cmd_on(void *sh, int argc, char **argv)
{
    int off = (dtc_pattern_match(argv[0], S_ON) != 0);
    (void)argc;
    shell_print(sh, off ? "Motor Controller off" : "Motor Controller on");
    motor_ctl_power_set(!off);
    return 0;
}

/* powerecu_cmd_on -- 0x32fe4 */
int32_t powerecu_cmd_on(void *sh, int argc, char **argv)
{
    int off = (dtc_pattern_match(argv[0], S_ON) != 0);
    (void)argc;
    shell_print(sh, off ? "Power ECU off" : "Power ECU on");
    powerecu_power_set(!off);
    return 0;
}

/* ===== per-ECU reset / misc ============================================== */

int32_t battery_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); ps_publish_evt_4b(11000); return 0; }

int32_t battery_cmd_unlock(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); charger_identify(7); return 0; }

int32_t charger_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); charger_reset(); return 0; }

int32_t handlebar_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); handlebar_reset(); return 0; }

int32_t lights_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); lights_reset(); return 0; }

int32_t motor_control_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); motor_ctl_reset(); return 0; }

int32_t powerecu_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); batt_charge_disable(); return 0; }

int32_t can_cmd_state(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "%s"); return 0; }

/* power_cmd_state -- 0x32d4c */
int32_t power_cmd_state(void *sh)
{ shell_print(sh, "Power state: %d", ps_power_state_get()); return 0; }

/* dtc_cmd_clear -- 0x2cf60 / dtc_cmd_save -- 0x2d028 */
int32_t dtc_cmd_clear(void *sh) { dtc_clear_all(); shell_print(sh, "DTCs cleared"); return 0; }
int32_t dtc_cmd_save(void *sh)  { dtc_save();      shell_print(sh, "DTCs saved");   return 0; }

/* lipo_cmd_enter_shipping -- 0x2b5e0 */
int32_t lipo_cmd_enter_shipping(void *sh, int argc, char **argv)
{
    uint8_t code = (uint8_t)str_to_u8(argv[1], 10, NULL);
    (void)argc;
    shell_print(sh, "%s", code);
    lipo_enter_shipping(code);
    return 0;
}

/* ===== elock (lock) group ================================================ */

/* lock_cmd_lock -- 0x6c842 */
int32_t lock_cmd_lock(void *sh)
{ elock_report_lock_state(1); elock_shell_print_state(sh, 0); return 0; }

/* lock_cmd_unlock -- 0x28b0c : `unlock [elock]` */
int32_t lock_cmd_unlock(void *sh, int argc, char **argv)
{
    if (argc == 2 && dtc_pattern_match(argv[1], "elock") == 0) {
        shell_print(sh, "Only unlock elock");
        elock_lock_all();
    } else {
        shell_print(sh, "Unlock");
        elock_unlock_all();
    }
    elock_shell_print_state(sh, 0);
    return 0;
}

/* ===== bell (audio) group ================================================ */

int32_t bell_cmd_info(void *sh, int argc, char **argv);   /* fwd (bell_cmd_set) */

/* bell_cmd_play -- 0x6c582 : `bell play <idx>` */
int32_t bell_cmd_play(void *sh, int argc, char **argv)
{
    int secondary = (str_to_int(argv[1], 0, 10) != 0);
    (void)sh; (void)argc;
    audio_play_current_bell(secondary, 1);
    return 0;
}

/* bell_cmd_set -- 0x6c5e0 : `bell set <p> <s>` */
int32_t bell_cmd_set(void *sh, int argc, char **argv)
{
    uint8_t p = (uint8_t)str_to_int(argv[1], 0, 10);
    uint8_t s = (uint8_t)str_to_int(argv[2], 0, 10);
    audio_set_bell_index(p, s);
    return bell_cmd_info(sh, argc, argv);
}

/* bell_cmd_info -- 0x268d8 (fwd-declared for bell_cmd_set) */
extern const char *const g_bell_names[7];    /* PTR_PTR_00026914 */
extern uint8_t g_bell_sel[2];                /* LAB_0002690c: [0]=primary [1]=secondary */
int32_t bell_cmd_info(void *sh, int argc, char **argv)
{
    unsigned p = g_bell_sel[0], s = g_bell_sel[1];
    (void)argc; (void)argv;
    shell_print(sh, "Primary bell sound: %s", p < 7 ? g_bell_names[p] : "RANDOM");
    shell_print(sh, "Secondary bell sound: %s", s < 7 ? g_bell_names[s] : "RANDOM");
    return 0;
}

/* bell_cmd_list -- 0x268a0 */
int32_t bell_cmd_list(void *sh)
{
    int i;
    for (i = 0; i < 7; i++)
        shell_print(sh, "%d - %s", i, g_bell_names[i]);
    shell_print(sh, "%d - RANDOM", 7);
    return 0;
}

/* ===== capacity group ==================================================== */

/* capacity_cmd_get -- 0x32f14 */
int32_t capacity_cmd_get(void *sh)
{
    int16_t *v; int8_t *en;
    batt_test_capacity_get(&v, &en);
    shell_print(sh, "Enabled : %s", *en ? "true" : "false");
    shell_print(sh, "RSOC : %u%%", (uint16_t)v[0]);
    shell_print(sh, "Remaining capacity : %u mAh", (uint16_t)v[1]);
    shell_print(sh, "Average current : %d mA", (int)v[2]);
    return 0;
}

/* capacity_cmd_set -- 0x32e74 : `capacity set <en> <rsoc> <cap> <curr>` */
int32_t capacity_cmd_set(void *sh, int argc, char **argv)
{
    struct { uint16_t rsoc, cap; int16_t curr; } t;
    int en = str_to_int(argv[1], 0, 10);
    (void)argc;
    t.rsoc = (uint16_t)str_to_int(argv[2], 0, 10);
    t.cap  = (uint16_t)str_to_int(argv[3], 0, 10);
    t.curr = (int16_t)str_to_int(argv[4], 0, 10);
    shell_print(sh, "Enabled : %s", en ? "true" : "false");
    shell_print(sh, "RSOC : %u%%", t.rsoc);
    shell_print(sh, "Remaining capacity : %u mAh", t.cap);
    shell_print(sh, "Average current : %d mA", t.curr);
    batt_test_capacity_set(&t, en != 0);
    return 0;
}

/* ===== battery / charger status dumps (CAN OD) =========================== */

/* battery_cmd_state -- 0x332c4 : dump the BMS status over OD objects 0x220-0x228 */
int32_t battery_cmd_state(void *sh)
{
    static const char *const modes[12] = {0};   /* PTR_LAB_000335ac name table */
    uint8_t *r;

    if (od_query(0x220, 7) == 0) {
        r = g_od_resp;
        unsigned m = ((r[0xb] & 0xf) - 2u) & 0xff;
        shell_print(sh, "Mode : %s", m < 12 ? modes[m] : "Unknown mode");
        shell_field(sh, "Flags", r[0xb] & 0xf0, "");
        shell_field(sh, "", r[5], ""); shell_field(sh, "", r[6], "");
        shell_field(sh, "", r[7], ""); shell_field(sh, "", r[8], "");
        shell_field(sh, "", r[9], ""); shell_field(sh, "", r[10], "");
    } else shell_error(sh, "Timeout getting battery status");
    od_release();

    if (od_query(0x224, 7) == 0) {
        r = g_od_resp;
        shell_field(sh, "", r[5], ""); shell_field(sh, "", r[6], "");
        shell_field(sh, "", r[7], ""); shell_field(sh, "", r[8], "");
        shell_field(sh, "Cell imbalance :", r[9], "");
    } else shell_error(sh, "Timeout getting battery status");
    od_release();

    if (od_query(0x223, 6) == 0) {
        r = g_od_resp;
        shell_print(sh, "Total voltage : %u mV",    *(uint16_t *)(r + 5));
        shell_print(sh, "Max. cell voltage : %u mV", *(uint16_t *)(r + 9));
        shell_print(sh, "Min. cell voltage : %d mv", *(uint16_t *)(r + 7));
    } else shell_error(sh, "Timeout getting battery voltage");
    od_release();

    if (od_query(0x221, 6) == 0) {
        r = g_od_resp;
        shell_print(sh, "RSOC : %u %%", *(uint16_t *)(r + 5));
        shell_print(sh, "Remaining capacity : %u mAh", *(uint16_t *)(r + 7));
        shell_print(sh, "Average current : %d mA", (int)*(int16_t *)(r + 9));
    } else shell_error(sh, "Timeout getting battery capacity");
    od_release();

    if (od_query(0x225, 8) == 0) {
        r = g_od_resp;
        shell_print(sh, "%d", (int)(int8_t)r[5]); shell_print(sh, "%d", (int)(int8_t)r[6]);
        shell_print(sh, "%d", (int)(int8_t)r[7]); shell_print(sh, "%d", (int)(int8_t)r[8]);
        shell_print(sh, "Discharge current : %d mA", *(uint16_t *)(r + 9));
        shell_print(sh, "Discharge current limit : %d mA", *(uint16_t *)(r + 0xb));
    } else shell_error(sh, "Timeout getting battery temperature");
    od_release();

    if (od_query(0x227, 8) == 0) {
        r = g_od_resp;
        shell_print(sh, "SOH : %u %%", (int)*(int16_t *)(r + 9));
        shell_print(sh, "Full charge capacity : %u mAh", (int)*(int16_t *)(r + 7));
        shell_print(sh, "Nominal capacity : %d mAh", (int)*(int16_t *)(r + 5));
        shell_print(sh, "Cycle count : %d", (int)*(int16_t *)(r + 0xb));
    } else shell_error(sh, "Timeout getting battery health");
    od_release();

    if (od_query(0x228, 0xd) == 0) {
        r = g_od_resp;
        shell_print(sh, "COCP event counter : %u", *(uint16_t *)(r + 7));
        shell_print(sh, "DOCP event counter : %u", *(uint16_t *)(r + 9));
        shell_print(sh, "OTP event counter : %u", *(uint16_t *)(r + 0xb));
        shell_print(sh, "Self discharge rate : %u %%", r[0xd]);
        shell_print(sh, "Effective pack energy : %u Wh", *(uint16_t *)(r + 0xe));
        shell_print(sh, "Effective pack capacity : %u mAh", *(uint16_t *)(r + 0x10));
    } else shell_error(sh, "Timeout getting battery lifetime");
    od_release();

    if (od_query(0x226, 0x1a) == 0) {
        int i;
        r = g_od_resp;
        for (i = 1; i != 0xd; i++)
            shell_print(sh, "Cell %02u : %u mV", i, *(uint16_t *)(r + i * 2 + 3));
    } else shell_error(sh, "Timeout getting battery cell voltages");
    od_release();
    return 0;
}

/* charger_cmd_state -- 0x331f8 : dump charger status over OD 0x240/0x241 */
int32_t charger_cmd_state(void *sh)
{
    uint8_t *r;
    if (od_query(0x240, 6) == 0) {
        r = g_od_resp;
        shell_field(sh, "", r[5], ""); shell_field(sh, "", r[6], "");
        shell_field(sh, "", r[8], ""); shell_field(sh, "Error flags :", r[10], "");
    } else shell_error(sh, "Timeout getting charger status");
    od_release();
    if (od_query(0x241, 8) == 0) {
        r = g_od_resp;
        shell_print(sh, "Voltage : %d mV (max %d mV)", *(uint16_t *)(r + 5), *(uint16_t *)(r + 9));
        shell_print(sh, "Current : %d mA (max %d mA)", *(uint16_t *)(r + 7), *(uint16_t *)(r + 0xb));
    } else shell_error(sh, "Timeout getting charger output");
    od_release();
    return 0;
}

/* ===== FMNA (Apple Find My) group ======================================== */

/* fmna_cmd_enable -- 0x33d60 : `fmna enable|disable` */
int32_t fmna_cmd_enable(void *sh, int argc, char **argv)
{
    int want = (dtc_pattern_match(argv[0], "enable") == 0);
    int rc;
    (void)argc;
    rc = fmna_toggle(want);
    if (rc == 0)
        shell_print(sh, "FMNA feature %s", want ? "enabled" : "disabled");
    else
        shell_error(sh, "Unable to toggle FMNA (err %d)", rc);
    return rc;
}

/* fmna_cmd_pair -- 0x33f00 : enter pairing mode */
int32_t fmna_cmd_pair(void *sh, int argc, char **argv)
{
    int rc;
    (void)argc; (void)argv;
    if (g_fmna_enabled != 1) {
        shell_error(sh, "FMNA feature disabled");
        return -22;
    }
    rc = fmna_app_enable(1);
    if ((rc == 0 || rc == -0x78) && (rc = fmna_app_factory_reset()) == 0)
        shell_print(sh, "FMNA pairing started");
    else
        shell_error(sh, rc == 0 ? "Unable to start FMNA pairing mode"
                                : "Unable to enable FMNA (err %d)", rc);
    return rc;
}

/* fmna_cmd_reset -- 0x33a68 : factory-reset Find My */
int32_t fmna_cmd_reset(void *sh, int argc, char **argv)
{
    int rc;
    (void)argc; (void)argv;
    if (g_fmna_enabled != 1) {
        shell_error(sh, "FMNA feature disabled");
        return -22;
    }
    rc = fmna_disable();
    if ((rc == 0 || rc == -0x78) && (rc = fmna_factory_reset2()) == 0)
        shell_print(sh, "FMNA factory reset successful");
    else
        shell_error(sh, rc == 0 ? "Unable to factory reset FMNA (err %d)"
                                : "Unable to disable FMNA (err %d)", rc);
    return rc;
}

/* fmna_cmd_state -- 0x33780 : dump the FMNA feature flags */
int32_t fmna_cmd_state(void *sh)
{
    extern uint8_t g_fmna_active, g_fmna_flag_a, g_fmna_flag_b, g_fmna_flag_c;
    shell_print(sh, "FMNA State");
    shell_print(sh, "Enabled : %s",     g_fmna_active   ? "true" : "false");
    shell_print(sh, "Stolen mode : %s",  fmna_stolen_mode_get() ? "true" : "false");
    shell_print(sh, "Flag : %s",         g_fmna_flag_a   ? "true" : "false");
    shell_print(sh, "Flag : %s",         g_fmna_flag_b   ? "true" : "false");
    shell_print(sh, "Flag : %s",         g_fmna_flag_c   ? "true" : "false");
    return 0;
}

/* ===== firmware update group ============================================= */

extern void *update_find_device(const char *name);               /* 0x2f604 */
extern int   update_reset_device(void *a, void *b);              /* 0x32a14 */
extern void  update_enter(void);                                 /* 0x6c8da */
extern void  update_exit(void);                                  /* 0x6c8e0 */

/* update_cmd_enter -- 0x32ddc : `update mode on|off` */
int32_t update_cmd_enter(void *sh, int argc, char **argv)
{
    (void)sh; (void)argc;
    if (dtc_pattern_match(argv[0], S_ON) == 0) update_enter();
    else                                        update_exit();
    return 0;
}

/* update_cmd_list -- 0x329dc : list updatable devices */
int32_t update_cmd_list(void *sh)
{
    extern const char *const g_update_devs[]; extern int g_update_dev_count;
    int i;
    for (i = 0; i < g_update_dev_count; i++)
        shell_print(sh, "%s", g_update_devs[i * 4]);
    return 0;
}

/* update_cmd_reset -- 0x32b80 : reset a device after update */
int32_t update_cmd_reset(void *sh, int argc, char **argv)
{
    void *dev = update_find_device(argv[1]);
    int rc;
    (void)argc;
    if (dev == NULL) { shell_error(sh, "unknown device"); return -0x13; }
    rc = update_reset_device(((void **)dev)[2], ((void **)dev)[3]);
    if (rc != 0) shell_error(sh, "unable to reset device (err %d)", rc);
    return rc;
}

/* ===== ring (handlebar LED) group -- CAN, thin wrappers ================== */

extern int  ring_play(const char *sel, int a, int b, unsigned mode);   /* 0x3120c */
extern void ring_soc(uint8_t v, unsigned sel);                         /* 0x3157c */
extern void ring_breath(unsigned br, unsigned rgb, unsigned t,
                        unsigned a, unsigned b);                       /* 0x31440 */

/* rings_cmd_get_brightness -- 0x30cd8 */
int32_t rings_cmd_get_brightness(void *sh)
{ extern uint8_t g_ring_brightness; shell_print(sh, "Brightness: %d", g_ring_brightness); return 0; }

/* rings_cmd_play -- 0x31400 : `rings play <sel> [mode]` */
int32_t rings_cmd_play(void *sh, unsigned argc, char **argv)
{
    unsigned mode = 1;
    if (argc >= 3) {
        int err = 0;
        mode = str_to_uint(argv[2], 10, &err);
        if (err) { shell_error(sh, "invalid argument"); return err; }
    }
    return ring_play(argv[1], 1, 1, mode);
}

/* rings_cmd_soc -- 0x6d3d4 : `rings soc <sel> <val>` */
int32_t rings_cmd_soc(void *sh, int argc, char **argv)
{
    unsigned sel = str_to_ring(argv[1], 1, 0);
    uint8_t v = (uint8_t)str_to_uint(argv[2], 10, NULL);
    (void)sh; (void)argc;
    ring_soc(v, sel);
    return 0;
}

/* rings_cmd_breath -- 0x6d3fa : `rings breath <a> <b> <br> <r> <g> <bl> <t>` */
void rings_cmd_breath(void *sh, int argc, char **argv)
{
    unsigned a  = str_to_ring(argv[1], 1, 0);
    unsigned b  = str_to_ring(argv[2], 1, 0);
    unsigned br = str_to_uint(argv[3], 10, NULL);
    unsigned r  = str_to_uint(argv[4], 10, NULL);
    unsigned g  = str_to_uint(argv[5], 10, NULL);
    unsigned bl = str_to_uint(argv[6], 10, NULL);
    unsigned t  = str_to_uint(argv[7], 10, NULL);
    (void)sh; (void)argc;
    ring_breath(br, (bl & 0xff) | ((g & 0xff) << 8) | ((r & 0xff) << 16), t, a, b);
}

/* ===== ring LED config (CAN OD write) ==================================== */

/* Generic OD transfer (write here): (transport, spec, 0, buf, len, 0, 0). */
extern int   od_transfer(void *transport, void *spec, int z, const void *buf,
                         unsigned len, int a, int b);              /* 0x79bb2 */
extern void *g_ring_od_transport;                                 /* DAT_00030c68 / 0x30ca4 */
extern void *g_ring_od_spec;                                      /* DAT_00030c6c / 0x30ca8 */
extern uint8_t *g_ring_brightness_p;                              /* DAT_00030ca0 */

/* rings_cmd_set -- 0x30d7c : `rings set <e1> <e2> <count> <r> <g> <b>` */
void rings_cmd_set(void *sh, int argc, char **argv)
{
    int e1 = str_to_int(argv[1], 0, 10);
    int e2 = str_to_int(argv[2], 0, 10);
    unsigned count = str_to_int(argv[3], 0, 10) & 0xff;
    uint8_t r = (uint8_t)str_to_int(argv[4], 0, 10);
    uint8_t g = (uint8_t)str_to_int(argv[5], 0, 10);
    uint8_t b = (uint8_t)str_to_int(argv[6], 0, 10);
    uint8_t frame[0x21];
    uint8_t *p = frame;
    unsigned i;
    (void)argc;

    shell_print(sh, "Ring set %d %d", e1 != 0, e2 != 0);
    for (i = 0; i < 0x21; i++) frame[i] = 0;
    for (i = 0; i != count; i++) { p[1] = r; p[2] = g; p += 3; p[0] = b; }
    frame[0] = (uint8_t)((e1 != 0) | ((e2 != 0) << 1));
    od_transfer(*(void **)((uint8_t *)g_ring_od_transport + 0x10),
                g_ring_od_spec, 0, frame, 0x21, 0, 0);
}

/* rings_cmd_set_brightness -- 0x30cac : `rings brightness <v>` */
void rings_cmd_set_brightness(void *sh, int argc, char **argv)
{
    uint8_t v = (uint8_t)str_to_uint(argv[1], 10, NULL);
    uint8_t frame[3] = { 0, 0, 0 };
    (void)argc;
    shell_print(sh, "Brightness: %d", v);
    *g_ring_brightness_p = v;
    frame[0] = v;
    od_transfer(*(void **)((uint8_t *)g_ring_od_transport + 0x10),
                g_ring_od_spec, 0, frame, 3, 0, 0);
}

/* ===== color group (settings-backed ring colours) ======================== */

extern uint32_t *g_color_table;                                   /* DAT_00030d74 */
extern void *g_color_settings;                                    /* DAT_00030d78 */
extern void  settings_store(void *area, void *table, int len);    /* 0x574c8 */

/* color_cmd_primary -- 0x30cf0 : `color <primary|secondary|positive|negative> <hex>` */
int32_t color_cmd_primary(void *sh, int argc, char **argv)
{
    int slot;
    int err = 0;
    uint32_t rgb;
    (void)argc;

    if (dtc_pattern_match(argv[0], "primary") == 0)        slot = 0;
    else if (dtc_pattern_match(argv[0], "secondary") == 0) slot = 1;
    else if (dtc_pattern_match(argv[0], "positive") == 0)  slot = 2;
    else if (dtc_pattern_match(argv[0], "negative") == 0)  slot = 3;
    else return -0x16;   /* -EINVAL */

    rgb = str_to_uint(argv[1], 0x10, &err);
    if (err != 0) {
        shell_error(sh, "Invalid argument");
        return err;
    }
    g_color_table[slot] = rgb;
    settings_store(g_color_settings, g_color_table, 0x10);
    return err;
}

/* ===== AEM (Application Event Manager) introspection ===================== */

extern void aem_profiling_apply(void);                            /* 0x3b0f8 */

/* aem_cmd_enable -- 0x706a6 / aem_cmd_disable -- 0x706b2 (both apply the flag). */
int32_t aem_cmd_enable(void)  { aem_profiling_apply(); return 0; }
int32_t aem_cmd_disable(void) { aem_profiling_apply(); return 0; }

/* AEM registries (linker-section arrays). */
extern uint32_t g_aem_events[];       /* PTR_PTR_0003b0a0 .. _0003b0a4, 24 B/entry */
extern uint32_t g_aem_events_end[];   /* PTR_PTR_0003b0a4 */
extern uint32_t g_aem_ev_bitmap[];    /* DAT_0003b0ac (enabled bits) */
extern int      g_aem_ev_stride;      /* DAT_0003b0a8 */
extern uint32_t g_aem_listeners[];    /* PTR_PTR_0003b030 .. _0003b034, 8 B/entry */
extern uint32_t g_aem_listeners_end[];/* PTR_PTR_0003b034 */
extern uint32_t g_aem_subs[];         /* PTR_PTR_0003afec .. _0003aff0, 24 B/entry */
extern uint32_t g_aem_subs_end[];     /* PTR_PTR_0003aff0 */

/* aem_cmd_show_events -- 0x3b03c */
int32_t aem_cmd_show_events(void *sh)
{
    uint32_t *e;
    shell_print_c(sh, 8, "Registered Events:");
    for (e = g_aem_events; e != g_aem_events_end; e += 6) {
        unsigned idx = (unsigned)g_aem_ev_stride * (unsigned)((e - g_aem_events) >> 3);
        unsigned en  = (g_aem_ev_bitmap[idx >> 5] >> (idx & 0x1f)) & 1u;
        shell_print_c(sh, 8, " - %c %s", (int)(en + 0x44), (const char *)e[0]);
    }
    return 0;
}

/* aem_cmd_show_listeners -- 0x3b000 */
int32_t aem_cmd_show_listeners(void *sh)
{
    uint32_t *l;
    shell_print_c(sh, 8, "Registered Listeners:");
    for (l = g_aem_listeners; l < g_aem_listeners_end; l += 2)
        shell_print_c(sh, 8, " - L:%s", (const char *)l[0]);
    return 0;
}

/* aem_cmd_show_subscribers -- 0x3af84 */
int32_t aem_cmd_show_subscribers(void *sh)
{
    uint32_t *ev;
    shell_print_c(sh, 8, "Registered Subscribers:");
    for (ev = g_aem_subs; ev < g_aem_subs_end; ev += 6) {
        uint32_t *sub;
        int any = 0;
        for (sub = (uint32_t *)ev[1]; sub != (uint32_t *)ev[2]; sub++) {
            shell_print_c(sh, 8, " - E:%s -> L:%s",
                          (const char *)ev[0], (const char *)*(uint32_t *)*sub);
            any = 1;
        }
        if (!any)
            shell_print_c(sh, 8, " - E:%s has no subscribers", (const char *)ev[0]);
        shell_print_c(sh, 8, "");
    }
    return 0;
}

/* ===== firmware update: install / version / start (flash-client vtable) === */

/* A device-update record: the CAN/flash client vtable is at +0x08, its arg +0x0c. */
struct flash_client {
    void *(*init)(void *arg);                                     /* [0] */
    int   (*get_version)(void *h, void *out);                     /* [1] */
    int   (*update_file)(void *h, void *file, int z, unsigned sz, void *out); /* [2] */
    int   (*update)(void *h, void *file, int z, unsigned sz, void *cb, void *sh); /* [3] */
    void  *reserved4;                                             /* [4] */
    void  (*deinit)(void *h);                                     /* [5] */
};

extern void *update_find_device(const char *name);               /* 0x2f604 */
extern int   update_reset_device(void *a, void *b);              /* 0x32a14 */
extern int   fs_open(void *h, const char *path, int mode);       /* 0x3c910 */
extern void  fs_seek(void *h, int z, int whence);                /* 0x3cae8 */
extern unsigned fs_size(void *h);                                /* 0x3cb24 */
extern void  fs_close(void *h);                                  /* 0x3ca34 */
extern int   aem_level(uint8_t *m);                              /* (*m & 7) */
extern void  aem_raise(void *m, uint32_t lvl, void *s);          /* 0x6efd8 */
extern uint8_t g_log_update[];                                   /* DAT_00032b68 / 0x32d30 */

/* device record layout: {..., struct flash_client **client @ +8, void *arg @ +0xc} */
#define DEV_CLIENT(d)  (*(struct flash_client **)((uint8_t *)(d) + 8))
#define DEV_ARG(d)     (*(void **)((uint8_t *)(d) + 0xc))

/* update_cmd_install -- 0x32a74 : `update install <dev> <file>` */
int32_t update_cmd_install(void *sh, int argc, char **argv)
{
    void *dev = update_find_device(argv[1]);
    struct flash_client *c;
    void *fh[4] = { 0, 0, 0, 0 };
    void *handle;
    const char *emsg = "unable to update device (err %d)";
    int rc;
    (void)argc;

    if (dev == NULL) { shell_error(sh, "unknown device"); return -0x13; }

    rc = fs_open(&fh, argv[2], 1);
    if (rc != 0) { shell_error(sh, emsg, rc); return rc; }

    c = DEV_CLIENT(dev);
    fs_seek(&fh, 0, 2);
    { unsigned sz = fs_size(&fh); fs_seek(&fh, 0, 0);
      handle = c->init(DEV_ARG(dev));
      if (handle == NULL) {
          if (aem_level(g_log_update)) aem_raise(g_log_update, 1, (void *)"failed to initialize client");
          fs_close(&fh);
          shell_error(sh, emsg, -0x16);
          return -0x16;
      }
      rc = c->update(handle, &fh, 0, sz, (void *)0 /* progress cb */, sh);
    }
    if (rc != 0) {
        if (aem_level(g_log_update)) aem_raise(g_log_update, 1, (void *)"failed update (err %d)");
        c->deinit(handle);
        fs_close(&fh);
        shell_error(sh, emsg, rc);
        return rc;
    }
    c->deinit(handle);
    fs_close(&fh);
    rc = update_reset_device(DEV_CLIENT(dev), DEV_ARG(dev));
    if (rc != 0) shell_error(sh, "unable to reset device (err %d)", rc);
    return rc;
}

/* update_cmd_version -- 0x32bc0 : `update version <dev> [file]` */
int32_t update_cmd_version(void *sh, int argc, char **argv)
{
    void *dev = update_find_device(argv[1]);
    struct flash_client *c;
    uint8_t ver[4] = { 0, 0, 0, 0 };
    int rc;

    if (dev == NULL) { shell_error(sh, "unknown device"); return -0x13; }
    c = DEV_CLIENT(dev);

    if (argc == 2) {                       /* live device version over the client */
        void *h;
        if (c->get_version == NULL) { shell_error(sh, "unable to update device (err %d)", -0x86); return -0x86; }
        h = c->init(DEV_ARG(dev));
        if (h == NULL) {
            if (aem_level(g_log_update)) aem_raise(g_log_update, 1, (void *)"failed to initialize client");
            shell_error(sh, "unable to update device (err %d)", -0x16);
            return -0x16;
        }
        rc = c->get_version(h, ver);
        c->deinit(h);
        if (rc != 0) {
            if (aem_level(g_log_update)) aem_raise(g_log_update, 1, (void *)"failed to get version (err %d)");
            shell_error(sh, "unable to update device (err %d)", rc);
            return rc;
        }
    } else if (argc == 3) {                /* version from an update file */
        void *fh[4] = { 0, 0, 0, 0 };
        rc = fs_open(&fh, argv[2], 1);
        if (rc != 0) { shell_error(sh, "unable to open file (err %d)", rc); return rc; }
        if (c->update_file == NULL) { shell_error(sh, "unable to update device (err %d)", -0x86); fs_close(&fh); return -0x86; }
        fs_seek(&fh, 0, 2);
        { unsigned sz = fs_size(&fh); void *h; fs_seek(&fh, 0, 0);
          h = c->init(DEV_ARG(dev));
          if (h == NULL) {
              if (aem_level(g_log_update)) aem_raise(g_log_update, 1, (void *)"failed to initialize client");
              shell_error(sh, "unable to update device (err %d)", -0x16); fs_close(&fh); return -0x16;
          }
          rc = c->update_file(h, &fh, 0, sz, ver);
          c->deinit(h);
        }
        if (rc != 0) {
            if (aem_level(g_log_update)) aem_raise(g_log_update, 1, (void *)"failed update (err %d)");
            shell_error(sh, "unable to update device (err %d)", rc); fs_close(&fh); return rc;
        }
        fs_close(&fh);
    } else {
        return -0x16;
    }
    shell_print(sh, "Version %d.%d.%d.%d", ver[0], ver[1], ver[2], ver[3]);
    return 0;
}

/* update_cmd_start -- 0x6d54a : `update start <file> [f]` (arm the OTA state) */
extern uint8_t *g_ota_state;                                      /* DAT_0002f6a4 */
extern volatile uint32_t g_ota_flags;                            /* DAT_0002f6ac */
extern void  ota_wake(void *sem);                                 /* 0x632e4 */
extern void *g_ota_sem;                                           /* DAT_0002f6b0 */
extern void  ota_set_name(void *st, int cap, void *spec, const char *name); /* 0x673e8 */
extern void *g_ota_name_spec;                                     /* DAT_0002f6a8 */

int32_t update_cmd_start(void *sh, unsigned argc, char **argv)
{
    int force = (argc >= 3) && (argv[2][0] == 'f');
    (void)sh;
    g_ota_state[0xff]  = 0;
    *(uint32_t *)(g_ota_state + 0x120) = 0;
    g_ota_state[0x11f] = (uint8_t)force;
    ota_set_name(g_ota_state, 0xff, g_ota_name_spec, argv[1]);
    __atomic_fetch_and(&g_ota_flags, ~2u, __ATOMIC_SEQ_CST);
    ota_wake(g_ota_sem);
    return 0;
}

/* ===== elock group ======================================================= */

extern void elock_power_set(int on);                              /* 0x2a4f0 */
extern void elock_hw_reset(void);                                 /* 0x2a5c0 */

/* elock_cmd_power -- 0x32fac : `elock turn on|off` */
int32_t elock_cmd_power(void *sh, int argc, char **argv)
{
    int off = (dtc_pattern_match(argv[0], S_ON) != 0);
    (void)argc;
    shell_print(sh, off ? "Elock off" : "Elock on");
    elock_power_set(!off);
    return 0;
}

/* elock_cmd_reset -- 0x32d78 : `elock reset` */
int32_t elock_cmd_reset(void *sh, int argc, char **argv)
{ (void)argc; (void)argv; shell_print(sh, "elock reset"); elock_hw_reset(); return 0; }
