/* vmtp.h — VanMoof transport / BLE-auth reconstruction support.
 *
 * S6 `ble` (Nordic nRF52840, NCS 2.9.1 / Zephyr 3.7.99). Behaviour-oriented
 * reconstruction (per-TU compile gate, NOT byte-identical/linkable): the Zephyr
 * / SoftDevice-Controller / crypto framework is vendor and is modelled here as
 * external declarations, so the VanMoof logic in the src tree reads cleanly. OEM
 * addresses (image base 0xC000) are noted at each declaration / function.
 */
#ifndef VMTP_H
#define VMTP_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ logging */
/* The OEM log path is vm_logf (0x6efea) -> vm_log_core (0x6ef6a); every call
 * site is gated by `(*log_module & 7)` (the per-module level mask). We model the
 * module as an opaque handle and keep the gate. */
typedef const void *vm_log_module;
extern int  vm_log_enabled(vm_log_module m);                 /* (*m & 7) != 0 */
extern void vm_logf(vm_log_module m, int level, const char *fmt, ...); /* 0x6efea */
#define VM_LOG_ERR 1
#define VM_LOG(m, ...) do { if (vm_log_enabled(m)) vm_logf((m), VM_LOG_ERR, __VA_ARGS__); } while (0)

/* per-subsystem log modules (rodata module descriptors) */
extern vm_log_module vmtp_log;                 /* "vmtp_zephyr"            0x8ed75 */
extern vm_log_module auth_cert_log;            /* "auth_certificate_validator" 0x81143 */

/* --------------------------------------------------------- error codes (errno) */
#define VM_EINVAL   (-22)   /* 0xffffffea */
#define VM_EIO      (-5)
#define VM_EBADMSG  (-77)
#define VM_ENOTSUP  (-134)
#define VM_EBADF    (-9)    /* -0xb in the record path (no command cb / decode) */

/* ---------------------------------------------------- inbound/outbound record */
/* Records are the NDEF-style frames carried by vmtp; header byte low 2 bits =
 * record kind (1 = request). Payload length is a u16 at byte offset 5, payload
 * begins at byte offset 7. */
#define REC_KIND(rec)   ((rec)[0] & 3u)
#define REC_KIND_REQ    1u
#define REC_LEN(rec)    ((uint16_t)((rec)[5] | ((rec)[6] << 8)))
#define REC_PAYLOAD(rec) ((rec) + 7)

/* ------------------------------------------------------- BLE auth session 0x80 */
/* Per-connection auth/session object (param_2 of vmtp_auth_record_handler).
 * Wiped (memset 0, 0x80) whenever auth fails. Field offsets are OEM-observed;
 * accessed by macro to stay faithful to the decompiler's byte offsets. */
#define VM_SESSION_SIZE     0x80
#define SES_SUBJECT(s)      (*(uint32_t *)((s) + 0x00)) /* cert subject id */
#define SES_ID(s)           (*(uint32_t *)((s) + 0x04)) /* cert id */
#define SES_PUBINFO(s)      ((s) + 0x08)                /* published over OD */
#define SES_ROLE_SRC(s)     ((s)[0x20])                 /* byte fed to app-state event */
#define SES_KEYCTX(s)       ((s) + 0x46)                /* cert pubkey context */
#define SES_CHALLENGE(s)    ((s) + 0x68)                /* 16-byte challenge nonce */
#define SES_AUTH_ROLE(s)    (*(int8_t *)((s) + 0x78))   /* result: 0x01 ok / 0xfe / 0xff fail */
#define SES_ROLE_OK         0x01
#define SES_ROLE_SPECIAL    0xfe
#define SES_ROLE_FAIL       ((int8_t)0xff)

/* ------------------------------------------------------------- vendor externs */
/* net-buf style response pool (0x565d4) and unref (0x5661c). */
extern uint8_t *ble_pkt_buf_alloc(unsigned size);   /* 0x565d4 */
extern void     vmtp_pkt_unref(void *buf);          /* 0x5661c */

/* EC certificate/signature verify primitive (Nordic oberon, 0x68880). Returns 0
 * on a valid signature. */
extern int ec_signature_verify_core(const void *sig, const void *msg,
                                     unsigned msg_len, const void *key,
                                     const void *ctx);              /* 0x68880 */
/* Parse a verified certificate body into the session (subject/id/role/pubkey). */
extern int cert_parse_into_session(const void *cert, unsigned len,
                                   uint8_t *session);               /* 0x784ac */

/* NDEF/record reader + writer helpers (vendor record codec). */
extern void thunk_record_reader_init(void *rd, int n, const void *buf,
                                     unsigned len, ...);            /* 0x76b70 */
extern int  record_get_field(void *rd, void *out_field);           /* 0x76fd2 */
extern int  record_get_field2(void *rd, void *out_blob);           /* 0x77032 */
extern void record_writer_init(void *wr, int n, void *out, unsigned cap); /* 0x774c8 */
extern void record_begin(void *wr, int type);                      /* 0x77498 */
extern void record_set_status(void *wr, const int *status);        /* 0x77436 */
extern void record_add_blob(void *wr, const void *blob);           /* 0x77474 */
extern void record_end(void *wr, int type);                        /* 0x774a8 */

/* App Event Manager (the S6 internal bus). */
extern void *aem_event_alloc(int chan, int id, int sz);            /* 0x77cfc */
extern void  aem_event_submit(void);                               /* 0x55564 */
extern void  od_publish(vm_log_module m, int obj, const void *payload, int n); /* 0x364f0 */

/* misc vendor helpers used by the auth path */
extern void  gpio_pulse(int pin, int v);                           /* 0x63f14 */
extern int   challenge_nonce_is_zero(const void *p, unsigned n);   /* 0x3e894 */
extern void  mem_zero(void *p, int v, unsigned n);                 /* 0x7b2ba memset */

/* response transport vtable lookup (rsp ctx + 0x1c -> sender). */
struct vmtp_ctx;            /* opaque; rsp->chan->sender(chan, rsp_chan, pkt) */
struct vmtp_conn;          /* opaque; conn->command_cb(session) at +4 */

#endif /* VMTP_H */
