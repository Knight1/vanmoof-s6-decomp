/*
 * shell_commands.c — VanMoof S6 "ble" (nRF52840 central controller)
 *
 * Zephyr-shell command handlers reached through the name->handler table at
 * OEM 0x95980. Each handler receives the standard Zephyr shell callback ABI:
 *
 *     void handler(const struct shell *sh, void *argv, size_t argc);
 *
 * For these particular commands the dispatcher pre-parses the argument vector
 * into a packed binary scratch buffer (argv) and passes the parsed element
 * count in argc; a handler only commits the new value(s) into its RAM-backed
 * configuration state when argc matches the exact element count it expects.
 *
 * Behaviour-oriented reconstruction (not byte-identical). Every vendor / RTOS /
 * SDK helper is declared as a local extern with its OEM address in a comment;
 * none of it is reconstructed here. Function-pointer indirection goes through
 * uintptr_t. OEM address of each handler is noted in its banner comment.
 *
 * Identification (name string -> command):
 *   0x261d0  "audio"             -> shell_cmd_audio_set
 *   0x26890  "bell"              -> shell_cmd_bell_set
 *   0x28298  "btn"               -> shell_cmd_btn_set
 *   0x30e24  "color_map"         -> shell_cmd_color_map_set
 *   0x32944  "ema_range_params"  -> shell_cmd_ema_range_params_set
 *   0x2d040  "light_thresholds"  -> shell_cmd_light_thresholds_set_u16
 *   0x2d050  "light_thresholds"  -> shell_cmd_light_thresholds_set_u32
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- *
 * RAM-backed configuration state (data RAM, base 0x20000000).
 * These are the absolute targets the OEM handlers write through DAT_ pointers.
 * Declared as externs so this translation unit stays self-contained; at link
 * time they resolve to the real .data/.bss objects.
 * ------------------------------------------------------------------------- */

/* "audio": single u8 (mode / enable flag).            DAT_000261dc -> 0x200131db */
extern volatile uint8_t  g_audio_setting;          /* 0x200131db */
/* "bell": u16 sound/bell id.                          DAT_0002689c -> 0x200131de */
extern volatile uint16_t g_bell_setting;           /* 0x200131de */
/* "btn": single u8 (touch-unlock button setting).     DAT_000282a4 -> 0x20013223 */
extern volatile uint8_t  g_btn_setting;            /* 0x20013223 */
/* "color_map": 16-byte (4-word) LED ring color map.   DAT_00030e44 -> 0x200021c0 */
extern volatile uint32_t g_color_map[4];           /* 0x200021c0 */
/* "light_thresholds": adjacent u16 / u32 fields.      0x200030e9 / 0x200030ed */
extern volatile uint32_t g_light_threshold_u32;    /* DAT_0002d05c -> 0x200030e9 */
extern volatile uint16_t g_light_threshold_u16;    /* DAT_0002d04c -> 0x200030ed */

/* "ema_range_params": 40-byte (10-word) range-estimator parameter table.
 * Laid out as 5 rows of {u32, u32}; each word is validated independently.
 * DAT_000326dc -> table base.                                                 */
extern volatile uint32_t g_ema_range_params[10];   /* 0x000326dc target */

/* ------------------------------------------------------------------------- *
 * Vendor / SDK / app helpers — declared extern, NOT reconstructed.
 * ------------------------------------------------------------------------- */

/* Per-command DTC / shell-context guard. Returns 0 to allow the command.
 * (decompiled as dtc_pattern_match(ctx_ptr, sh)).            OEM via DAT */
extern int      ema_cmd_guard(const void *ctx, const void *sh);

/* Range-parameter validators. *_check_zero returns nonzero when the value is
 * invalid/zero; *_check_bound returns nonzero when out of the allowed range.  */
extern int      ema_param_check_zero (uint32_t value, uint32_t arg);    /* FUN_0001f52c */
extern int      ema_param_check_bound(uint32_t value, uint32_t bound);  /* FUN_0001f568 */
extern uint32_t ema_param_bound_max;                                    /* DAT_000326e4 */
extern uint32_t ema_param_bound_min;                                    /* DAT_000326e0 */

/* fixed/float formatting helpers used to build a log record.                 */
extern uint64_t ema_value_to_q   (uint32_t value);                     /* FUN_0001e9f0 */
extern uint64_t ema_q_normalize  (int lo, int hi, int a, int b);       /* FUN_0001e734 */

/* Zephyr logging back-ends (level-gated; *_log_x core is FUN_0006efd8 /
 * FUN_000364f0). Address constants are the OEM log-source structures.        */
extern void     z_log_simple(void *src, int level, const void *msg, ...);         /* FUN_0006efd8 */
extern void     z_log_fmt   (void *src, uint32_t fmt_id, const void *args, int); /* FUN_000364f0 */

/* OEM log-source / message descriptors referenced by the ema handler. */
extern uint32_t ema_log_src_a;     /* DAT_000326d4 (level word in [0]) */
extern void    *ema_log_msg_started; /* DAT_000326d8 */
extern uint32_t ema_log_fmt_lo;    /* DAT_000326e8 */
extern uint32_t ema_log_fmt_hi;    /* DAT_000326ec */
extern uint32_t ema_log_src_b;     /* DAT_0003297c (level word in [0]) */
extern void    *ema_log_msg_denied;  /* DAT_00032980 */

/* ========================================================================= *
 * shell "audio" — OEM 0x261d0
 *
 * Command name "audio" (@0x80d85; subcommand "audio_fs" @0x80d8b).
 * Commits one byte of audio configuration when exactly one argument was
 * parsed; otherwise a no-op (treated as a query / malformed call).
 * ABI: (sh, argv, argc); argv points at the packed parsed value.
 * ========================================================================= */
void shell_cmd_audio_set(const void *sh, const uint8_t *argv, size_t argc)
{
    (void)sh;
    if (argc == 1) {
        g_audio_setting = *argv;
    }
}

/* ========================================================================= *
 * shell "bell" — OEM 0x26890
 *
 * Command name "bell" (@0x815c4: "Bell sound commands"). The "bell play"
 * subcommand selects/stores a 16-bit bell-sound id. Commits the u16 when two
 * argument bytes were parsed.
 * ========================================================================= */
void shell_cmd_bell_set(const void *sh, const uint16_t *argv, size_t argc)
{
    (void)sh;
    if (argc == 2) {
        g_bell_setting = *argv;
    }
}

/* ========================================================================= *
 * shell "btn" — OEM 0x28298
 *
 * Command name "btn" (@0x81c6d; associated asset "/audio/107_bell_flash.wav",
 * touch-unlock request handling). Commits one button-setting byte when exactly
 * one argument was parsed.
 * ========================================================================= */
void shell_cmd_btn_set(const void *sh, const uint8_t *argv, size_t argc)
{
    (void)sh;
    if (argc == 1) {
        g_btn_setting = *argv;
    }
}

/* ========================================================================= *
 * shell "color_map" — OEM 0x30e24
 *
 * Command name "color_map" (@0x8514b: "Rings set left: %d, right: %d,
 * num_leds: %d, r: %d, g: %d, b: %d"). Stores a 16-byte (4 x u32) LED ring
 * color map. Only commits when exactly 16 argument bytes were parsed. The OEM
 * copies the 16 bytes two words at a time into g_color_map[].
 * ========================================================================= */
void shell_cmd_color_map_set(const void *sh, const uint32_t *argv, size_t argc)
{
    (void)sh;
    if (argc == 0x10) {
        const uint32_t *src = argv;
        volatile uint32_t *dst = g_color_map;
        const uint32_t *end = argv + 4;
        do {
            uint32_t w1 = src[1];
            dst[0] = src[0];
            dst[1] = w1;
            dst += 2;
            src += 2;
        } while (src != end);
    }
}

/* ========================================================================= *
 * shell "ema_range_params" — OEM 0x32944
 *
 * Command name "ema_range_params" (@0x85714: "Ema current range"; subcommand
 * "range_estimator" -> "Started"). Loads a 40-byte (5 rows x {u32,u32})
 * range-estimator parameter table, then validates each of the 10 words:
 *   - even-column words are checked against ema_param_bound_max
 *   - odd-column  words are checked against ema_param_bound_min
 * A word failing the zero-check OR the bound-check is logged (level-gated) and
 * reset to 0. When argc != 0x28 (40) the new table is rejected and a "denied"
 * message is emitted instead; ema_cmd_guard() can also veto the whole command.
 * ========================================================================= */
void shell_cmd_ema_range_params_set(const void *sh, const uint32_t *argv,
                                     size_t argc, uint32_t param4)
{
    if (ema_cmd_guard(&ema_param_bound_max /*DAT_00032978*/, sh) != 0) {
        /* command vetoed by the shell/DTC guard */
        if ((ema_log_src_b & 7) != 0) {
            z_log_simple(&ema_log_src_b, 1, ema_log_msg_denied, param4); /* OEM forwards param_4 */
        }
        return;
    }

    /* Wrong argument count: warn but do not overwrite the live table. */
    if (argc != 0x28) {
        if ((ema_log_src_a & 7) != 0) {
            z_log_simple(&ema_log_src_a, 1, ema_log_msg_started);
        }
    }

    /* Copy the 40-byte payload (10 words) into the parameter table. */
    {
        const uint32_t *src = argv;
        volatile uint32_t *dst = g_ema_range_params;
        const uint32_t *end = argv + 10;
        do {
            uint32_t w1 = src[1];
            dst[0] = src[0];
            dst[1] = w1;
            dst += 2;
            src += 2;
        } while (src != end);
    }

    /* Validate the table row by row; zero out invalid entries, logging each. */
    {
        volatile uint32_t *row = g_ema_range_params;
        for (int idx = 0; idx != 5; idx++, row += 2) {
            uint32_t a = row[0];
            if (ema_param_check_zero(a, 0) != 0 ||
                ema_param_check_bound(a, ema_param_bound_max) != 0) {
                if ((ema_log_src_a & 7) != 0) {
                    uint64_t q = ema_q_normalize((int)ema_value_to_q(a),
                                                 (int)(ema_value_to_q(a) >> 32),
                                                 0, 0);
                    (void)q;
                    /* fmt id 0x3040, args {ema_log_fmt_lo, idx, q} */
                    z_log_fmt(&ema_log_src_a, 0x3040, &ema_log_fmt_lo, 0);
                }
                row[0] = 0;
            }

            uint32_t b = row[1];
            if (ema_param_check_zero(b, 0) != 0 ||
                ema_param_check_bound(b, ema_param_bound_min) != 0) {
                if ((ema_log_src_a & 7) != 0) {
                    uint64_t q = ema_q_normalize((int)ema_value_to_q(b),
                                                 (int)(ema_value_to_q(b) >> 32),
                                                 0, 0);
                    (void)q;
                    /* fmt id 0x3040, args {ema_log_fmt_hi, idx, q} */
                    z_log_fmt(&ema_log_src_a, 0x3040, &ema_log_fmt_hi, 0);
                }
                row[1] = 0;
            }
        }
    }
    (void)param4;
}

/* ========================================================================= *
 * shell "light_thresholds" (u16 field) — OEM 0x2d040
 *
 * Command name "light_thresholds" (@0x83f0f: "Enabled: %s", "State: ").
 * Sets the 16-bit threshold field when exactly two argument bytes were parsed.
 * ========================================================================= */
void shell_cmd_light_thresholds_set_u16(const void *sh, const uint16_t *argv,
                                        size_t argc)
{
    (void)sh;
    if (argc == 2) {
        g_light_threshold_u16 = *argv;
    }
}

/* ========================================================================= *
 * shell "light_thresholds" (u32 field) — OEM 0x2d050
 *
 * Companion to the above (same "light_thresholds" command group; name
 * @0x83ef5 "lights"/"drl"/"light_thresholds"). Sets the adjacent 32-bit
 * threshold field when exactly four argument bytes were parsed.
 * ========================================================================= */
void shell_cmd_light_thresholds_set_u32(const void *sh, const uint32_t *argv,
                                        size_t argc)
{
    (void)sh;
    if (argc == 4) {
        g_light_threshold_u32 = *argv;
    }
}