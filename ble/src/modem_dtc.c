/*
 * modem_dtc.c — VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Reconstructed VanMoof application logic for:
 *   - modem power/reset GPIO control + reset state machine
 *   - Diagnostic Trouble Code (DTC) setting + the DTC CAN/OD command handler
 *   - a small wildcard pattern-match helper used by the DTC handler
 *   - nRF91x1 modem info query (SIP / "mfw-pti" version string)
 *   - parsing a modem firmware version triplet out of an OTA filename
 *   - the full nRF modem firmware update (full modem firmware update, FMFU)
 *     driver: bootloader switch, wrapper/segment decode, SHA-256 verify,
 *     chunked write over the modem-control transport, signature verify.
 *
 * Behaviour-oriented translation of the OEM decompiler output — NOT byte
 * identical. OEM addresses are noted per function. All vendor / RTOS / SDK /
 * crypto / libc helpers are declared extern below with their OEM addresses.
 *
 * Self-contained: only <stdint.h> and <stddef.h>.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------- *
 *  Vendor / RTOS / SDK / app-framework externs (declared, never defined here)
 * ------------------------------------------------------------------------- */

/* Application Event Manager: allocate + submit an event to a channel.
 * (chan, event_id, payload_size, flags[, ...]) -> event buffer or NULL.   */
extern void *aem_event_alloc(int chan, int event_id, int size, int flags); /* 0x77cfc (FUN_00077cfc) */
extern int   aem_event_submit(void *evt);                                  /* 0x55564 (FUN_00055564) */

/* nRF GPIO helper (gpio_pin_set style): (port_or_spec, value).            */
extern void  vm_gpio_set(void *spec, int value);                           /* 0x6c3c4 (FUN_0006c3c4) */
/* small busy/timed delay (id, arg).                                        */
extern void  vm_delay(int id, int arg);                                    /* 0x63f14 (FUN_00063f14) */

/* Object-Dictionary / CAN read+write on a remote OD provider object.
 *   provider->vtbl->read (obj, id, sub, &val)   slot +0x10
 *   provider->vtbl->write(obj, id, sub, val, ..) slot +0x08              */
extern uint8_t *aem_log_get(void);          /* placeholder, see vm_log* below */

/* Logging — gated by (logmod_flags & 7). vm_logf is the printf-style sink. */
extern void vm_logf(uint32_t *logmod, int level, const char *fmt, ...);    /* 0x?????  (vm_logf) */
extern void vm_log_str(uint32_t *logmod, int level, const char *msg);      /* 0x6efd8 (FUN_0006efd8) */
extern void vm_log_int(uint32_t *logmod, const char *fmt, int v);          /* 0x6d30c (FUN_0006d30c) */
extern void vm_log_record(uint32_t *logmod, int code, void *rec, int x);   /* 0x364f0 (FUN_000364f0) */

/* canbus / OD transmit of a DTC value over the vm protocol.               */
extern int  ps_canbus_od_send(int dtc);                                    /* 0x???? (ps_canbus_od_send) */

/* DTC store backend.                                                       */
extern void dtc_store_record(int dtc, void *rec);                          /* 0x6ccce (FUN_0006ccce) */
extern int  dtc_make_record(int one, void *out);                           /* 0x3c414 (FUN_0003c414) */

/* misc copy / compare / parse helpers (libc-ish, vendor).                  */
extern void  vm_memcpy(void *dst, const void *src, int n);                 /* 0x7b26a (FUN_0007b26a) */
extern void  vm_memcpy2(void *dst, const void *src, int n);                /* 0x7b45c (FUN_0007b45c) */
extern int   vm_memcmp(const void *a, const void *b, int n);               /* 0x7b24a (FUN_0007b24a) */
extern int   vm_strlen_chk(const char *s, const char *tok);                        /* 0x7b4ca (FUN_0007b4ca) */
extern char *vm_strchr(const char *s, int c);                              /* 0x7b3c2 (FUN_0007b3c2) */
extern long  vm_strtol(const char *s, char **endp, int base);             /* 0x6758c (FUN_0006758c) */

/* nRF modem-control transport: OD read of the modem info object.          */
extern int  modemctl_od_read(void *provider, int arg, int obj_id, int sub);/* 0x63330 (FUN_00063330) */

/* nRF FMFU (full modem firmware update) driver glue (vendor lib wrapper). */
extern int  fmfu_set_state(int ctx, int arg, int state, int x);            /* 0x30008 (FUN_00030008) */
/* Decodes the FMFU wrapper header. Arg3 is the output region (see
 * fmfu_wrapper_out below); arg4 receives the wrapper-region length (ctx+0x428). */
extern int  fmfu_decode_wrapper(void *hdr, int len, void *wrap, void *wrap_len); /* 0x2e370 (FUN_0002e370) */
extern int  fmfu_decode_segments(uint32_t a, uint32_t b, void *segs, int x);/* 0x2e394 (FUN_0002e394) */
extern int  fmfu_write_blob(int ctx);                                      /* 0x6d2d0 (FUN_0006d2d0) */
extern int  fmfu_commit(int ctx);                                          /* 0x6d33c (FUN_0006d33c) */

/* filesystem (Zephyr fs_*).                                               */
extern int  fs_seek(int fp, int off, int whence);                          /* 0x3cae8 (FUN_0003cae8) */
extern int  fs_read(int fp, void *buf, int n);                             /* 0x3ca70 (FUN_0003ca70) */
extern int  fs_close_or_flush(void);                                       /* 0x63e10 (FUN_00063e10) */

/* SHA-256 (mbedTLS / PSA).                                                 */
extern void sha256_init(void *ctx);                                        /* 0x6a164 (FUN_0006a164) */
extern void sha256_update(void *ctx, const void *p, int n);                /* 0x6a1b4 (FUN_0006a1b4) */
extern void sha256_final(void *ctx, void *digest);                         /* 0x6a364 (FUN_0006a364) */

/* reset state-machine list glue (Zephyr style intrusive list).            */
extern void  rsm_list_lock(void *l);                                       /* 0x780f6 (FUN_000780f6) */
extern void  rsm_list_op(int node, int arg);                               /* 0x56b6c (FUN_00056b6c) */

/* forward decls of in-module functions */
void modem_reset_set(int active);
int  dtc_pattern_match(const uint8_t *pat, const uint8_t *val);
int  modem_get_info(void *out_sip);

/* ------------------------------------------------------------------------- *
 *  Module-global anchors (resolved at link time to the OEM .data/.bss).
 *  Kept as externs so the file stays self-contained and behaviour-exact.
 * ------------------------------------------------------------------------- */

/* modem_reset_set */
extern uint32_t *g_modem_reset_caps;     /* DAT_00025c8c : caps/flags word ptr  */
extern uint32_t  g_reset_evt_arg_off;    /* DAT_00025c90 : arg when active==0    */
extern uint32_t  g_reset_evt_arg_on;     /* DAT_00025c94 : arg when active!=0     */
extern uint32_t  g_reset_evt_w1;         /* DAT_00025c98                          */
extern uint32_t  g_reset_evt_w2;         /* DAT_00025c9c                          */
extern uint32_t  g_reset_evt_w0;         /* DAT_00025ca0                          */
extern uint8_t  *g_modem_run_gpio_flag;  /* DAT_00025ca4 : !active mirror byte    */
extern void     *g_modem_reset_gpio;     /* DAT_00025ca8 : RESET line gpio spec   */
extern void     *g_modem_pwr_gpio;       /* DAT_00025cac : PWR/strobe gpio spec   */

/* modem_reset_state_handler */
extern int  g_rsm_node;                  /* DAT_00025fac : reset-state-machine node */
extern int  g_rsm_ctx;                   /* DAT_00025fb0 : owning ctx (has +0xc50)  */
extern int  g_rsm_msg_active;            /* DAT_00025fb4                            */
extern int  g_rsm_msg_idle;             /* DAT_00025fb8                            */

/* dtc_set */
extern int     *g_dtc_provider;          /* DAT_0002ceb4 : OD provider (vtbl @ *p)  */
extern uint8_t *g_dtc_dirty;             /* DAT_0002ceb8 : "DTC table dirty" flag   */
extern uint32_t *g_dtc_logmod;           /* DAT_0002cebc : log module               */

/* dtc_can_cmd_handler */
extern uint8_t *g_dtc_clear_pattern;     /* DAT_0002da98 : 16-byte clear pattern     */
extern uint8_t *g_dtc_clear_match;       /* DAT_0002da9c : expected match buffer     */

/* modem_get_info */
extern void *g_modem_info_provider;      /* DAT_0002dcf4 : modem-control provider    */
extern void *g_modem_info_buf;           /* DAT_0002dcf8 : cached 0x50-byte info     */

/* modem_parse_version_from_filename */
extern uint32_t *g_modemfw_logmod;       /* DAT_0003015c                            */
extern const char *g_str_get_info_failed;/* DAT_00030160 : "modem info sip: %s" etc */
extern uint32_t g_pv_logrec_w1;          /* DAT_00030164                            */
extern uint32_t g_pv_logrec_w0;          /* DAT_00030168                            */
extern const char *g_str_mfw_pti;        /* DAT_0003016c : "mfw-pti"                 */

/* modem_firmware_update */
extern uint32_t *g_fmfu_logmod;          /* DAT_00030434                            */
extern uint32_t *g_fmfu_logmod2;         /* DAT_00030598                            */

/* ------------------------------------------------------------------------- *
 *  Reset-state-machine + DTC context offset map (documented, not a struct):
 *    rsm node:   +0x04 dispatch fn ptr, +0x1c next/prev link
 *    rsm ctx:    +0xc50 "current node" slot
 *
 *  modem_firmware_update ctx (param_1) layout:
 *    +0x04  source seek/offset (param_3)
 *    +0x08  source file handle (param_2)
 *    +0x28  1 KiB header/scratch buffer
 *    +0x428 wrapper-region length
 *    +0x42c 0x200-byte chunk buffer (also segment scratch, 256 ints)
 *    +0x62c total expected bytes accumulator
 *    +0x630 bytes-written accumulator
 *    +0x634 completion callback (void(*)(void *result, void *user))
 *    +0x638 callback user argument
 * ------------------------------------------------------------------------- */

/* nRF FMFU error returned by fmfu_write_blob when a retry is needed (-0x8c) */
#define FMFU_EAGAIN   (-0x8c)

/* AEM channel ids observed for the modem subsystem */
#define AEM_MODEM_INFO_EVT     0x1101
#define AEM_MODEM_FWU_START    0x1140
#define AEM_MODEM_FWU_CHUNK    0x1141
#define AEM_MODEM_FWU_VERIFY   0x1142

/* DTC object id (vm OD) used by the CAN handler */
#define DTC_OBJ_ID             0x9000

/* ========================================================================= *
 *  modem_reset_set — drive the modem RESET / PWR GPIOs.            @0x25c20
 *
 *  If the platform "caps" word has bit 2 (0x4) set, emit a reset event/log
 *  record (object 0x2500) carrying either the "active" or "idle" arg word.
 *  Then mirror !active into a status byte, drive the RESET line to `active`,
 *  strobe the PWR line (1 -> delay(0x21) -> 0).
 * ========================================================================= */
void modem_reset_set(int active)            /* OEM 0x25c20 */
{
    /* OEM log/event record laid out on the stack (5 words + u16). */
    uint32_t rec[5];
    uint16_t rec_tail;

    /* (*g_modem_reset_caps << 0x1d) < 0  <=>  bit 2 (0x4) set */
    if ((*g_modem_reset_caps << 0x1d) & 0x80000000u) {
        rec[3] = g_reset_evt_arg_on;        /* uStack_1c */
        if (active == 0)
            rec[3] = g_reset_evt_arg_off;
        rec[1] = g_reset_evt_w1;            /* local_24 */
        rec[2] = g_reset_evt_w2;            /* local_20 */
        rec_tail = 0x301;                   /* local_18 */
        rec[0] = g_reset_evt_w0;            /* local_28 */
        (void)rec_tail;
        vm_log_record(g_modem_reset_caps, 0x2500, &rec, 0);
    }

    /* status mirror: byte = !active */
    *g_modem_run_gpio_flag = (uint8_t)(((uint8_t)active) ^ 1);

    vm_gpio_set(g_modem_reset_gpio, active);
    vm_gpio_set(g_modem_pwr_gpio, 1);
    vm_delay(0x21, 0);
    vm_gpio_set(g_modem_pwr_gpio, 0);
}

/* ========================================================================= *
 *  modem_reset_state_handler — reset state-machine transition.    @0x25f44
 *
 *  param == 0  -> go idle:  detach node, restore ctx +0xc50 to the node,
 *                 relink node to its own sub-list head, assert reset (set 0),
 *                 then tail-call the node's dispatch fn with arg 0.
 *  param != 0  -> go active: detach, clear ctx +0xc50, splice `param` in as
 *                 the new node, deassert reset (set 1), call node dispatch.
 * ========================================================================= */
void modem_reset_state_handler(int param)   /* OEM 0x25f44 */
{
    int ctx  = g_rsm_ctx;
    int node = g_rsm_node;

    if (param != 0) {
        rsm_list_lock((void *)(intptr_t)g_rsm_node);
        rsm_list_op(node, g_rsm_msg_active);
        *(uint32_t *)(ctx + 0xc50) = 0;
        *(int *)(node  + 0x1c) = param;
        *(int *)(param + 0x1c) = node;
        (*(void (**)(int))(node + 4))(node);
        modem_reset_set(1);
        return;
    }

    rsm_list_lock((void *)(intptr_t)g_rsm_node);
    rsm_list_op(node, g_rsm_msg_idle);
    *(int *)(node + 0x1c) = node - 0x9b8;
    *(int *)(ctx  + 0xc50) = node;
    modem_reset_set(0);
    /* tail dispatch (OEM is an indirect tail-jump treated as a call) */
    (*(void (**)(int, int))(node + 4))(node, 0);
}

/* ========================================================================= *
 *  dtc_pattern_match — wildcard byte compare.                     @0x1f758
 *
 *  strcmp-style over `pat`/`val`. A pattern byte of 0x01 is a single-byte
 *  wildcard (always matches, regardless of the value byte). Termination is
 *  the standard NUL byte. Returns pat[i] - val[i] at the first mismatch
 *  (0 on full match), where a wildcard contributes its raw 0x01 difference
 *  exactly as the OEM does.
 * ========================================================================= */
int dtc_pattern_match(const uint8_t *pat, const uint8_t *val)   /* OEM 0x1f758 */
{
    unsigned p, v;
    int cont;

    do {
        p = *pat;
        v = *val;
        cont = (p == 1);          /* wildcard byte keeps the scan going */
        if (p != 0)
            cont = (p == v);      /* otherwise continue only while equal */
        pat++;
        val++;
    } while (cont);

    return (int)(p - v);
}

/* ========================================================================= *
 *  dtc_set — record/raise a Diagnostic Trouble Code.              @0x2ce30
 *
 *  Reads the current OD entry for `dtc` (provider->vtbl->read, slot +0x10).
 *  If the record's "raised" byte (bits 16..23 of word[1]) is clear, it bumps
 *  the occurrence counter (low 16 bits of word[1]) and sets the raised flag,
 *  builds a fresh DTC record (dtc_make_record), writes it back to the OD
 *  (slot +0x08), marks the DTC table dirty, logs "DTC_%04X SET", and persists
 *  via dtc_store_record.
 * ========================================================================= */
void dtc_set(uint32_t dtc)                  /* OEM 0x2ce30 */
{
    int *prov = g_dtc_provider;
    uint32_t entry[2];          /* local_30 = key/value word, local_2c = state */
    uint32_t rec[4];            /* local_28 */
    int rc;

    /* prov->vtbl->read(prov, read_fn, dtc, sub=0, &entry) — slot +0x10 */
    rc = (*(int (**)(int *, void *, uint32_t, int, void *))(*prov + 0x10))(
            prov, *(void **)(*prov + 0x10), dtc, 0, &entry);
    if (rc == 0) {
        entry[0] = 0;
        entry[1] = 0;
    }

    /* raised flag = bits 16..23 of entry[1]; act only when not yet raised */
    if (((entry[1] >> 0x10) & 0xff) == 0) {
        uint16_t cnt = (uint16_t)entry[1];
        /* OEM: local_2c._0_3_ = CONCAT12(1, sVar1+1) — a 3-byte partial write
         * that sets low 16 = ++count, byte[2] = 1 (raised), and clears the
         * top byte (bits 31..24) to 0. */
        entry[1] = ((uint32_t)1 << 16) |
                   (uint16_t)(cnt + 1);

        dtc_make_record(1, rec);
        entry[0] = rec[0];

        /* prov->vtbl->write(prov, write_fn, dtc, sub=0, rec[0], state, 0) +0x08 */
        (*(void (**)(int *, void *, uint32_t, int, uint32_t, uint32_t, int))(*prov + 8))(
            prov, *(void **)(*prov + 8), dtc, 0, rec[0], entry[1], 0);

        *g_dtc_dirty = 1;
        if ((*g_dtc_logmod & 7) != 0)
            vm_logf(g_dtc_logmod, 1, "DTC_%04X SET", dtc);

        dtc_store_record((int)dtc, &entry);
    }
}

/* ========================================================================= *
 *  dtc_can_cmd_handler — OD/CAN command entry for DTC 0x9000.     @0x2da50
 *
 *  Guards: non-NULL request, the clear-pattern's first byte is non-zero, and
 *  at least 16 payload bytes. On a guard failure it raises DTC 0x9000 and
 *  returns -22 (EINVAL).
 *
 *  When valid: match the stored clear pattern against the expected match
 *  buffer. No match -> set DTC 0x9000 locally; match -> broadcast DTC 0x9000
 *  over the OD/CAN bus. Either way, copy the 16-byte pattern into the request
 *  buffer and return 0.
 * ========================================================================= */
uint32_t dtc_can_cmd_handler(int req, uint32_t len)   /* OEM 0x2da50 */
{
    if ((req != 0) && (*g_dtc_clear_pattern != 0) && (0xf < len)) {
        if (dtc_pattern_match(g_dtc_clear_pattern, g_dtc_clear_match) == 0)
            dtc_set(DTC_OBJ_ID);
        else
            ps_canbus_od_send(DTC_OBJ_ID);

        vm_memcpy2((void *)(intptr_t)req, g_dtc_clear_pattern, 0x10);
        return 0;
    }

    dtc_set(DTC_OBJ_ID);
    return 0xffffffea;          /* -22 EINVAL */
}

/* ========================================================================= *
 *  modem_get_info — query the nRF91x1 modem SIP/version info.     @0x2dcb8
 *
 *  Submits an AEM "modem info" event (chan 0, id 0x1101, 4 bytes), then reads
 *  OD object 0xccd from the modem-control provider. On success copies the
 *  cached 0x50-byte info block to `out_sip` (when non-NULL) and returns 0;
 *  on read failure returns -116 (EDOM-ish OEM code 0xffffff8c).
 * ========================================================================= */
int modem_get_info(void *out_sip)           /* OEM 0x2dcb8 */
{
    int rc;

    aem_event_alloc(0, AEM_MODEM_INFO_EVT, 4, 0);
    aem_event_submit(NULL);                 /* OEM submits the just-allocated evt */

    rc = modemctl_od_read(g_modem_info_provider, 0, 0xccd, 0);
    if (rc != 0)
        return -0x74;                       /* 0xffffff8c */

    if (out_sip != NULL)
        vm_memcpy(out_sip, g_modem_info_buf, 0x50);
    return 0;
}

/* ========================================================================= *
 *  modem_parse_version_from_filename — extract a vX.Y.Z triplet.  @0x30094
 *
 *  out is a {u8 major; u8 minor; u16 patch; u32 reserved=0}-style record
 *  (param_2 is u16*). Pulls the running modem info (modem_get_info), logs the
 *  SIP string at verbose level, finds the "mfw-pti" token, and parses
 *  "<major>.<minor>.<patch>" decimal fields after the first '_' separator.
 *
 *  Returns 0 on success, the modem_get_info error verbatim on failure, or
 *  -22 (EINVAL) on a malformed version string.
 * ========================================================================= */
int modem_parse_version_from_filename(uint32_t fname_unused, uint16_t *out)  /* OEM 0x30094 */
{
    uint8_t  info[64];          /* auStack_68: full modem info block         */
    uint8_t  sip[16];           /* auStack_28: SIP/version sub-string buffer */
    char    *p;
    int      rc;
    uint16_t patch = 0;

    (void)fname_unused;

    rc = modem_get_info(info);
    if (rc != 0) {
        if ((*g_modemfw_logmod & 7) != 0)
            vm_log_str(g_modemfw_logmod, 1, g_str_get_info_failed);
        return rc;
    }

    /* verbose (>2) log record carrying the parsed SIP string (object 0x1cc0) */
    if (2 < (*g_modemfw_logmod & 7)) {
        uint32_t lr[5];
        uint16_t lr_tail;
        lr[0]   = g_pv_logrec_w0;
        lr[1]   = g_pv_logrec_w1;
        lr[2]   = (uint32_t)(uintptr_t)sip;
        lr_tail = 0x200;
        (void)lr_tail;
        vm_log_record(g_modemfw_logmod, 0x1cc0, &lr, 0);
    }

    /* out->reserved = 0 (word at out+2) */
    *(uint32_t *)(out + 2) = 0;

    /* locate the "mfw-pti" token; if absent, leave version 0.0.0 -> ok */
    if (vm_strlen_chk((const char *)sip, (const char *)g_str_mfw_pti) == 0) {
        p = vm_strchr((const char *)sip, '_');
        if (*p == '_') {
            char *end = p + 1;
            *(uint8_t *)out = (uint8_t)vm_strtol(end, &end, 10);   /* major */
            if (*end == '.') {
                end++;
                *((uint8_t *)out + 1) = (uint8_t)vm_strtol(end, &end, 10); /* minor */
                if (*end == '.') {
                    end++;
                    patch = (uint16_t)vm_strtol(end, &end, 10);    /* patch */
                    out[1] = patch;
                    return 0;
                }
            }
        }
        return -0x16;           /* EINVAL */
    }

    /* token not found: report version 0.0.0 */
    out[0] = 0;
    out[1] = patch;             /* 0 */
    return 0;
}

/* ========================================================================= *
 *  modem_firmware_update — full nRF modem firmware update (FMFU). @0x30170
 *
 *  Drives a modem firmware image (already on the filesystem) into the modem
 *  bootloader. High-level flow (faithful to the OEM control graph):
 *
 *    1. stash callback/user/source into ctx, raise AEM start event (0x1140).
 *    2. fmfu_set_state(ctx, 0x1e0000)  — enter bootloader. On failure log
 *       "Switching to bootloader failed, err: %d" and finish(state=1).
 *    3. seek+read the 1 KiB wrapper header; decode wrapper + segment table.
 *    4. byte-swap the 32-byte expected SHA-256 (local_564), sum segment sizes.
 *    5. require a 32-byte hash ("invalid hash length" otherwise).
 *    6. re-seek source, stream it through SHA-256, compare against the file's
 *       embedded hash ("invalid hash" on mismatch).
 *    7. for each segment: seek, read 0x200-byte chunks, push each as an AEM
 *       chunk event (0x1141) flagged last-of-segment, fmfu_write_blob, advance
 *       the 0x630 written-counter; on the final segment fmfu_commit (bl) then
 *       push a verify chunk (0x1142) and fmfu_set_state(...,0x1e0000) to run
 *       nrf_fmfu_verify_signature.
 *    8. fmfu_commit (fw), then invoke the completion callback with a result
 *       byte (1=bl-switch fail, 2=hash/verify fail, 3=success/other).
 *
 *  Error logging is gated by (logmod & 7); the OEM uses two log modules
 *  (g_fmfu_logmod / g_fmfu_logmod2). Returns the last fs/fmfu error (or 0).
 * ========================================================================= */
int modem_firmware_update(int ctx, int src_fp, int src_off,
                          uint32_t a4, void *cb, void *cb_arg)   /* OEM 0x30170 */
{
    uint8_t  exp_hash[32];      /* local_564: byte-swapped expected SHA-256  */
    /* fmfu_decode_wrapper output region (OEM stack: auStack_524[24] then the
     * four locals local_50c / local_508 / local_504 / uStack_500). */
    struct {
        uint8_t   pad[24];      /* auStack_524                                */
        uint32_t *hash_ptr;     /* local_50c: -> expected 32-byte hash        */
        int       hash_len;     /* local_508: must be 0x20                    */
        uint32_t  field0;       /* local_504: -> fmfu_decode_segments arg0    */
        uint32_t  field1;       /* uStack_500: -> fmfu_decode_segments arg1   */
    } wrap;
    uint8_t  calc_hash[32];     /* auStack_544: computed digest              */
    uint8_t  sha_ctx[256];      /* local_4f4/local_4f0 region (SHA-256 ctx)  */
    int     *seg_tbl;           /* local_42c: 256-int segment descriptor tbl */
    int      seg_words[256];
    /* local_2c: number of decoded segments, written by fmfu_decode_segments
     * into the stack slot adjacent to seg_words[] (init 0 keeps the C defined). */
    uint32_t seg_count = 0;
    uint8_t  result[8];
    void   (*finish)(void *res, void *user);
    int rc, rc2;
    uint32_t i, total, n;

    (void)a4;
    seg_tbl = seg_words;

    /* stash context (offsets documented in the header above) */
    *(int *)(ctx + 4)     = src_off;
    *(int *)(ctx + 8)     = src_fp;
    *(void **)(ctx + 0x634) = cb;
    *(void **)(ctx + 0x638) = cb_arg;
    finish = (void (*)(void *, void *))(uintptr_t)cb;

    /* AEM start event (mark last/flagged) */
    {
        uint8_t *evt = (uint8_t *)aem_event_alloc(1, AEM_MODEM_FWU_START, 5, 0);
        if (evt != NULL)
            evt[5] = 1;
    }
    aem_event_submit(NULL);

    /* ---- 1. enter modem bootloader -------------------------------------- */
    rc = fmfu_set_state(ctx, 0, 0x1e0000, 0);
    if (rc != 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_int(g_fmfu_logmod, "Switching to bootloader failed, err: %d", rc);
        if (finish == NULL) return rc;
        result[3] = 1;          /* bl-switch failure marker (local_4f0 = 1) */
        goto finish_call;
    }

    /* ---- 2. read + decode the wrapper header ---------------------------- */
    rc = fs_seek(src_fp, src_off, 0);
    if (rc < 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_int(g_fmfu_logmod, "fs_seek failed: %d", rc);
        goto finish_state3;
    }

    rc = fs_read(src_fp, (void *)(intptr_t)(ctx + 0x28), 0x400);
    if (rc < 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_int(g_fmfu_logmod, "fs_read failed: %d", rc);
        goto finish_state3;
    }

    rc2 = fmfu_decode_wrapper((void *)(intptr_t)(ctx + 0x28), rc,
                              &wrap, (void *)(intptr_t)(ctx + 0x428));
    if (rc2 != 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_str(g_fmfu_logmod, 1, "unable to decode wrapper");
        goto finish_state3;
    }

    /* wrapper-region length already lives at ctx+0x428.
     * OEM: FUN_0002e394(local_504, uStack_500, local_42c, 0) — the first two
     * args are distinct wrapper-output locals (local_504 / uStack_500), NOT
     * the first two words of the segment table. decode_segments fills the
     * table at seg_tbl and the segment count in seg_count (OEM local_2c, an
     * adjacent stack slot it writes as a side effect). */
    rc2 = fmfu_decode_segments(wrap.field0, wrap.field1, seg_tbl, 0);
    if (rc2 != 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_str(g_fmfu_logmod, 1, "unable to decode segments");
        goto finish_state3;
    }

    /* byte-swap the 32-byte expected hash (8 word pairs swapped) from
     * wrap.hash_ptr (OEM local_50c) into exp_hash (local_564). */
    {
        const uint32_t *s = wrap.hash_ptr;               /* local_50c source */
        uint32_t *d = (uint32_t *)exp_hash;              /* local_564 dest   */
        for (i = 0; i < 8; i += 2) {
            d[i]   = s[i];
            d[i+1] = s[i+1];
        }
    }

    /* sum segment sizes (seg_tbl[k*2+1]) over seg_count segments */
    total = 0;
    for (i = 0; i < seg_count; i++)
        total += (uint32_t)seg_tbl[i * 2 + 1];

    /* ---- 3. hash length must be 0x20 ----------------------------------- */
    if (wrap.hash_len != 0x20) {  /* local_508 */
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_str(g_fmfu_logmod, 1, "invalid hash length");
        if (finish == NULL) return rc;
        result[3] = 2;
        goto finish_state_only;
    }

    /* ---- 4. stream the source through SHA-256 and compare -------------- */
    src_off += *(int *)(ctx + 0x428);
    sha256_init(sha_ctx);
    fmfu_write_blob(ctx);
    rc = fs_seek(*(int *)(ctx + 8), src_off, 0);
    if (rc < 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_int(g_fmfu_logmod, "get_hash_from_file failed: %d", rc);
        goto finish_hash_fail;
    }

    for (; total != 0; total -= (uint32_t)rc) {
        n = (total > 0x1ff) ? 0x200 : total;
        rc = fs_read(*(int *)(ctx + 8), (void *)(intptr_t)(ctx + 0x42c), n);
        if (rc < 0) {
            if ((*g_fmfu_logmod & 7) != 0)
                vm_log_int(g_fmfu_logmod, "get_hash_from_file failed: %d", rc);
            goto finish_hash_fail;
        }
        sha256_update(sha_ctx, (void *)(intptr_t)(ctx + 0x42c), rc);
        fs_close_or_flush();
    }
    sha256_final(sha_ctx, calc_hash);

    if (vm_memcmp(exp_hash, calc_hash, 0x20) != 0) {
        if ((*g_fmfu_logmod & 7) != 0)
            vm_log_str(g_fmfu_logmod, 1, "invalid hash");
        if (finish == NULL) return 0;
        rc = 0;
        result[3] = 2;
        goto finish_state_only2;
    }

    /* ---- 5. account total expected bytes into ctx+0x62c ---------------- */
    for (i = 0; i < seg_count; i++)
        *(int *)(ctx + 0x62c) += seg_tbl[i * 2 + 1];

    /* ---- 6. write each segment in 0x200-byte chunks -------------------- */
    {
        int *seg = seg_tbl;
        int seg_base = 0;
        for (i = 0; i < seg_count; i++) {
            /* OEM: uVar12 = piVar13[1] (segment size), captured before the
             * inner while-loop; only the loop counter (uVar15/seg_len) is
             * decremented, uVar12 stays whole for the seek accumulator. */
            uint32_t orig_seg_len = (uint32_t)seg[1];
            uint32_t seg_len = orig_seg_len;
            int      dst_off = seg[0];

            rc = fs_seek(*(int *)(ctx + 8), src_off + seg_base, 0);
            if (rc < 0) {
                vm_log_int(g_fmfu_logmod2, "load_segment failed: %d", rc);
                goto finish_hash_fail;
            }

            while (seg_len != 0) {
                uint8_t *evt;
                uint32_t cl = (seg_len > 0x1ff) ? 0x200 : seg_len;
                int rl = fs_read(*(int *)(ctx + 8), (void *)(intptr_t)(ctx + 0x42c), cl);
                if (rl < 0) {
                    rc = rl;
                    if ((*g_fmfu_logmod & 7) != 0)
                        vm_log_int(g_fmfu_logmod, "flash_read failed: %d", rl);
                    goto finish_hash_fail;
                }

                /* push the chunk as an AEM event */
                evt = (uint8_t *)aem_event_alloc(rl + 7, AEM_MODEM_FWU_CHUNK, 5, 0);
                evt[5]  = (i == 0);            /* OEM: pbVar5[5] = uVar9 == 0 (first seg) */
                evt[0] |= 8;
                *(int *)(evt + 6) = dst_off;
                vm_memcpy(evt + 0xc, (void *)(intptr_t)(ctx + 0x42c), rl);
                *(int16_t *)(evt + 10) = (int16_t)rl;
                rc = (int)(intptr_t)aem_event_submit(evt);
                if (rc != 0) {
                    if ((*g_fmfu_logmod2 & 7) != 0)
                        vm_log_int(g_fmfu_logmod2, "unable to write chunk, err %d", rc);
                    vm_log_int(g_fmfu_logmod2, "write_chunk failed: %d", rc);
                    goto finish_hash_fail;
                }

                rc = fmfu_set_state(ctx, 0, 0x8000, 0);
                if (rc != 0) {
                    vm_log_int(g_fmfu_logmod2, "write_chunk failed: %d", rc);
                    goto finish_hash_fail;
                }

                dst_off += rl;
                *(int *)(ctx + 0x630) += rl;
                rc = fmfu_write_blob(ctx);
                seg_len -= (uint32_t)rl;
                if (rc == FMFU_EAGAIN) {
                    vm_log_int(g_fmfu_logmod2, "load_segment failed: %d", rc);
                    goto finish_hash_fail;
                }
            }

            /* last segment: commit bl, push verify chunk, run signature verify */
            if (i == 0) {       /* OEM: if (uVar9 == 0) — final-pass marker  */
                rc = fmfu_commit(ctx);
                if (rc != 0) {
                    if ((*g_fmfu_logmod & 7) != 0)
                        vm_log_int(g_fmfu_logmod,
                                   "nrf_modem_bootloader_update (bl) failed, err: %d", rc);
                    goto finish_hash_fail;
                }
                {
                    int wlen = *(int *)(ctx + 0x428);
                    uint8_t *evt = (uint8_t *)aem_event_alloc(wlen + 7,
                                       AEM_MODEM_FWU_VERIFY, 5, 0);
                    vm_memcpy(evt + 0xc, (void *)(intptr_t)(ctx + 0x28), wlen);
                    *(int16_t *)(evt + 10) = (int16_t)wlen;
                    rc = (int)(intptr_t)aem_event_submit(evt);
                    if (rc != 0) {
                        vm_log_int(g_fmfu_logmod2, "unable to write verify chunk, err %d", rc);
                        goto finish_state3;
                    }
                }
                rc = fmfu_set_state(ctx, 0, 0x1e0000, 0);
                if (rc != 0) {
                    vm_log_int(g_fmfu_logmod2, "nrf_fmfu_verify_signature failed, err: %d", rc);
                    goto finish_state3;
                }
            }

            seg_base += (int)orig_seg_len; /* OEM: iVar4 = iVar4 + uVar12 */
            seg += 2;
        }
    }

    /* ---- 7. final firmware commit -------------------------------------- */
    rc = fmfu_commit(ctx);
    if (rc != 0) {
        if ((*g_fmfu_logmod2 & 7) != 0)
            vm_log_int(g_fmfu_logmod2,
                       "nrf_modem_bootloader_update (fw) failed, err: %d", rc);
        goto finish_state3;
    }

    if (finish == NULL)
        return 0;

    result[0] = 2;              /* success path (local_4f4[0] = 2) */
    result[3] = 0;              /* local_4f0 = 0 */
    goto finish_call;

finish_hash_fail:
    finish = *(void (**)(void *, void *))(ctx + 0x634);
    if (finish == NULL)
        return rc;
    result[3] = 3;
    goto finish_state_only;

finish_state3:
    finish = *(void (**)(void *, void *))(ctx + 0x634);
    if (finish == NULL)
        return rc;
    result[3] = 3;             /* local_4f0 = 3 */

finish_state_only:
    result[0] = 3;             /* local_4f4[0] = 3 */

finish_state_only2:
finish_call:
    finish(result, *(void **)(ctx + 0x638));
    return rc;
}
