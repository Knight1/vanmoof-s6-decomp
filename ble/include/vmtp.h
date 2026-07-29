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
/* Per-connection auth/session object (param_2 of vmtp_auth_record_handler), a
 * 0x80-byte block wiped (memset 0) whenever auth fails. cert_parse_into_session
 * (@0x784ac) fills bytes 0x00..0x67 from the certificate's tagged fields; the
 * handler owns the challenge (+0x68) and the auth-state byte (+0x78). Full map
 * (offset / size / cert tag):
 *
 *   +0x00  4   'i'   subject id      SES_SUBJECT
 *   +0x04  4   'i'   cert id         SES_ID          (together: "id: %lld")
 *   +0x08  16  'b'   body / pubinfo  SES_PUBINFO     (published over OD)
 *   +0x18  8   'e'   validity/expiry SES_VALIDITY    (checked vs synced time)
 *   +0x20  1   'r'   certificate role SES_CERT_ROLE
 *   +0x21  1   -     owner/user flag SES_ID_IS_OWNER (1='o' owner, 0='u' user)
 *   +0x22  36  'o'/'u' owner/user id SES_ID_BLOB     ('o'<=0x24, 'u'<=0x10)
 *   +0x46  32  'p'   cert public key SES_KEYCTX      (verifies the challenge sig)
 *   +0x68  16  -     challenge nonce SES_CHALLENGE
 *   +0x78  1   -     auth state/result SES_AUTH_ROLE
 *
 * Accessed by macro to stay faithful to the decompiler's byte offsets. */
#define VM_SESSION_SIZE     0x80
#define SES_SUBJECT(s)      (*(uint32_t *)((s) + 0x00)) /* 'i' subject id */
#define SES_ID(s)           (*(uint32_t *)((s) + 0x04)) /* 'i' cert id     */
#define SES_PUBINFO(s)      ((s) + 0x08)                /* 'b' body, 16 B; published over OD */
#define SES_VALIDITY(s)     ((s) + 0x18)                /* 'e' validity/expiry, 8 B */
/* +0x20: the CERTIFICATE ROLE — the VanMoof "ble-role-N" number parsed from the
 * cert 'r' tag. Logged "user authenticated with certificate (... role: 0x%02X)"
 * and emitted on the app event bus (chan 4 / id 0xff03). The ble ECU derives and
 * reports the number but does NOT gate on it — enforcement is app/cloud-side (on
 * S5 it was the per-role MQTT ACL), so there is no role→permission table here.
 * Known role numbers (shared VanMoof cert authority; see the S5
 * `main/docs/mqtt-bus.md` / `mqtt-topics.md`):                                   */
#define VM_ROLE_OWNER   7    /* full control (settings/update/lock/ride/power/findmy) */
#define VM_ROLE_SHARED  11   /* shared bike: safe settings subset + lock/ride/power   */
/* 17 / 22 / 55 / 66 = privileged/internal (service, theft-recovery, factory/dev;
 * exact per-number privileges not fully pinned even in the S5 analysis).         */
#define SES_CERT_ROLE(s)    ((s)[0x20])
#define SES_ROLE_SRC(s)     SES_CERT_ROLE(s)            /* legacy alias */
#define SES_ID_IS_OWNER(s)  ((s)[0x21])                 /* 1='o' owner id / 0='u' user id @ +0x22 */
#define SES_ID_BLOB(s)      ((s) + 0x22)                /* 'o'/'u' owner/user id, <=0x24 B */
#define SES_KEYCTX(s)       ((s) + 0x46)                /* 'p' cert pubkey context, 32 B */
#define SES_CHALLENGE(s)    ((s) + 0x68)                /* 16-byte challenge nonce */
/* +0x78: auth STATE/result (NOT the cert role) — 0 initial, 1 cert-ok/awaiting
 * challenge, 2 fully authenticated, 0xfe special (cb returned -0xb), 0xff fail
 * (whole session wiped). */
#define SES_AUTH_ROLE(s)    (*(int8_t *)((s) + 0x78))
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
