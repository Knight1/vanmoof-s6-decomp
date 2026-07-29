/* vmtp_auth.c — VanMoof BLE phone-authentication record handler + cert chain.
 *
 * S6 `ble` (nRF52840). Reconstructed from Ghidra (image base 0xC000):
 *   vmtp_auth_record_handler   @ 0x56fd4
 *   vmtp_auth_cert_extract     @ 0x5732c
 *   vmtp_auth_signature_verify @ 0x572b4
 *
 * Protocol (two request records over the `com.vanmoof.app` GATT service):
 *   1. CERTIFICATE: payload = [64-byte signature][certificate body]. The cert is
 *      verified against the CA context (ec_signature_verify_core), its fields
 *      (subject/id/role/pubkey) parsed into the session, an optional app command
 *      callback is run, and a fresh challenge nonce is returned to the phone.
 *   2. SIGNATURE: the phone signs the challenge with the cert key; the device
 *      verifies it against SES_CHALLENGE using the parsed cert pubkey.
 * The session role byte (SES_AUTH_ROLE, 0x78) records the result; on any failure
 * the entire 0x80-byte session is wiped. Behaviour-oriented (vendor record codec,
 * crypto, event bus and GATT transport are external).
 */
#include "vmtp.h"

/* extra externs / module handles (OEM globals) */
extern const void *auth_cert_validator_ctx;             /* 0x5728c CA validator ctx */
extern vm_log_module auth_state_log;                    /* 0x57284 */
extern int  challenge_prepare(void *out, unsigned n);   /* 0x3e894 (0 = ok) */
extern int  vmtp_response_send(struct vmtp_ctx *rsp, const void *pkt); /* rsp+0x1c vtable */
extern unsigned record_writer_len(void *wr, const uint8_t *start);    /* writer cursor - start */

typedef int (*vmtp_command_cb)(uint8_t *session);
#define CONN_COMMAND_CB(c)  (*(vmtp_command_cb *)((uint8_t *)(c) + 4))

struct rec_field { const uint8_t *ptr; unsigned len; };

/* publish the authenticated session info on an OD object (0x1c40 / 0x3cc0). */
static void publish_auth_event(uint8_t *session, int obj)
{
    if (vm_log_enabled(auth_state_log))
        od_publish(auth_state_log, obj, SES_PUBINFO(session), 0);
}

/* notify the app layer (App Event Manager channel) of the new auth role. */
static void emit_auth_state_event(uint8_t *session)
{
    void *ev = aem_event_alloc(4, 0xff03, 1);
    if (ev != NULL)
        *(uint32_t *)((uint8_t *)ev + 5) = (uint8_t)SES_ROLE_SRC(session);
    aem_event_submit();
}

/* vmtp_auth_signature_verify @ 0x572b4 — verify a [64-byte sig | cert] blob is
 * CA-signed and parse the certificate into the session. Returns 0 on success. */
int vmtp_auth_signature_verify(const void *ca_ctx, const uint8_t *blob,
                               unsigned blob_len, uint8_t *session)
{
    if (blob_len < 0x40) {
        VM_LOG(auth_cert_log, "certificate too short");
        return VM_EINVAL;
    }
    if (ec_signature_verify_core(blob, blob + 0x40, blob_len - 0x40,
                                 ca_ctx, session) != 0) {
        VM_LOG(auth_cert_log, "invalid certificate signature");
        return -13;                              /* 0xfffffff3 */
    }
    if (cert_parse_into_session(blob + 0x40, blob_len - 0x40, session) == 0)
        return 0;
    VM_LOG(auth_cert_log, "certificate parse failed");
    return VM_EINVAL;
}

/* record-codec field readers used by the cert parser (vendor CBOR/record lib). */
extern int  record_reader_remaining(void *rd);          /* nonzero while fields left */
extern int  record_reader_finish(void *rd);             /* 0x76d24 (nonzero = ok)     */
extern int  record_read_tag(void *rd, void **tag_out);  /* 0x77038 (tag byte)         */
extern int  record_read_blob2(void *rd, struct rec_field *out); /* 0x77032            */
extern int  record_read_id(void *rd, void *out8);       /* 0x76f96 ('i' subject id)   */
extern int  record_read_time(void *rd, void *out);      /* 0x76f36 ('e' validity)     */
extern int  record_read_u8(void *rd, void *out);        /* 0x76f5e ('r' role)         */
extern int  record_read_validate(void *rd, int z);      /* 0x77192 ('f' signature)    */
extern void mem_copy_bounded(void *dst, const void *src, unsigned n); /* 0x7b26a      */

/* cert_parse_into_session @ 0x784ac — decode the tagged certificate body into the
 * per-connection session.  The cert is a record of single-char-tagged fields; the
 * VanMoof-specific mapping into the 0x80-byte session:
 *
 *   'i' subject id   -> SES_SUBJECT (+0x00, u64: id at +0x04, "id: %lld")
 *   'b' body blob    -> SES_PUBINFO (+0x08, <=16 B; published over OD)
 *   'e' validity     -> +0x18 (expiry; checked against synced system time)
 *   'r' ROLE byte    -> SES_CERT_ROLE (+0x20) — the certificate's authorisation
 *                       role, logged as "role: 0x%02X" and emitted on the app
 *                       event bus (chan 4 / id 0xff03). A single opaque byte:
 *                       the ble ECU does NOT enumerate or gate on it — the value
 *                       is assigned by VanMoof's cert authority and enforced
 *                       app/cloud-side; the firmware only reports it.
 *   'o' owner id     -> +0x22 (<=0x24 B) and SES_ID_IS_OWNER (+0x21) = 1
 *   'u' user id      -> +0x22 (<=0x10 B) and SES_ID_IS_OWNER (+0x21) = 0
 *   'p' public key   -> SES_KEYCTX (+0x46, <=0x20 B; verifies the challenge sig)
 *   'f' signature    -> validated in-place (record_read_validate)
 *
 * Returns 0 on a complete, well-formed certificate; -10 on a truncated/short
 * record; -11 on an unknown tag or malformed field. */
int cert_parse_into_session(const void *cert, unsigned len, uint8_t *session)
{
    uint8_t rd[0x90];        /* record-reader state (OEM auStack_c4 + scratch) */
    struct rec_field f;
    void *tag;
    uint8_t role;

    thunk_record_reader_init(rd, 5, cert, len, 1, (void *)0, 0);
    mem_zero(session, 0, 0x68);

    if (record_reader_remaining(rd) == 0)
        return -10;                          /* 0xfffffff6 */

    while (record_reader_remaining(rd) != 0) {
        if (record_read_tag(rd, &tag) == 0)
            return -10;
        switch (*(uint8_t *)tag) {
        case 'i':                            /* subject id -> +0x00 */
            if (record_read_id(rd, session) == 0) return -11;
            break;
        case 'b':                            /* body blob -> SES_PUBINFO (<=16) */
            if (record_read_blob2(rd, &f) == 0) return -11;
            mem_copy_bounded(SES_PUBINFO(session), f.ptr, f.len > 0x10 ? 0x10 : f.len);
            break;
        case 'e':                            /* validity -> SES_VALIDITY */
            if (record_read_time(rd, SES_VALIDITY(session)) == 0) return -11;
            break;
        case 'r':                            /* ROLE -> SES_CERT_ROLE */
            if (record_read_u8(rd, &role) == 0) return -11;
            SES_CERT_ROLE(session) = role;
            break;
        case 'o':                            /* owner id -> SES_ID_BLOB (<=0x24) */
            if (record_read_blob2(rd, &f) == 0) return -11;
            mem_copy_bounded(SES_ID_BLOB(session), f.ptr, f.len > 0x24 ? 0x24 : f.len);
            SES_ID_IS_OWNER(session) = 1;
            break;
        case 'u':                            /* user id -> SES_ID_BLOB (<=0x10) */
            if (record_read_blob2(rd, &f) == 0) return -11;
            mem_copy_bounded(SES_ID_BLOB(session), f.ptr, f.len > 0x10 ? 0x10 : f.len);
            SES_ID_IS_OWNER(session) = 0;
            break;
        case 'p':                            /* pubkey -> SES_KEYCTX (<=32) */
            if (record_read_blob2(rd, &f) == 0) return -11;
            mem_copy_bounded(SES_KEYCTX(session), f.ptr, f.len > 0x20 ? 0x20 : f.len);
            break;
        case 'f':                            /* embedded signature (validate) */
            if (record_read_validate(rd, 0) == 0) return -11;
            break;
        default:
            return -11;                      /* 0xfffffff5 unknown tag */
        }
    }
    return record_reader_finish(rd) != 0 ? 0 : -10;
}

/* vmtp_auth_cert_extract @ 0x5732c — pull the certificate record out of the
 * inbound payload and hand it to the signature verifier. */
int vmtp_auth_cert_extract(const void *ca_ctx, const void *payload,
                           unsigned payload_len, uint8_t *session)
{
    uint8_t rd[72];
    struct rec_field field;

    thunk_record_reader_init(rd, 3, payload, payload_len, 1, (void *)0, 0);
    if (record_get_field(rd, &field) == 0) {
        VM_LOG(auth_cert_log, "missing certificate record");
        return VM_EINVAL;
    }
    return vmtp_auth_signature_verify(ca_ctx, field.ptr, field.len, session);
}

/* vmtp_auth_record_handler @ 0x56fd4 — top-level handler for an inbound auth
 * request record; builds and sends the response record. */
int vmtp_auth_record_handler(struct vmtp_conn *conn, uint8_t *session,
                             struct vmtp_ctx *rsp, uint8_t *rec)
{
    uint8_t *resp;
    uint8_t wr[108];                     /* record writer state */
    int role, status, rc;

    if (REC_KIND(rec) != REC_KIND_REQ)
        return VM_EINVAL;

    resp = ble_pkt_buf_alloc(0x102);
    resp[0] = (resp[0] & 0xf0) | 9;      /* response record type */
    resp[1] = 0;
    resp[2] = 0xff;
    record_writer_init(wr, 3, resp + 7, 0x100);
    record_begin(wr, 2);

    role = SES_AUTH_ROLE(session);
    if (role == 0) {
        /* ---- message 1: certificate ---- */
        gpio_pulse(0x148, 0);
        rc = vmtp_auth_cert_extract(auth_cert_validator_ctx,
                                    REC_PAYLOAD(rec), REC_LEN(rec), session);
        if (rc == 0) {
            vmtp_command_cb cb = CONN_COMMAND_CB(conn);
            if (cb == NULL) {
                publish_auth_event(session, 0x1c40);
                role = SES_ROLE_FAIL;
            } else {
                int crc = cb(session);
                role = SES_ROLE_OK;
                if (crc != 0) {
                    if (crc != VM_EBADF) {       /* -0xb */
                        publish_auth_event(session, 0x1c40);
                        role = SES_ROLE_FAIL;
                    } else {
                        role = SES_ROLE_SPECIAL; /* 0xfe */
                    }
                }
            }
        } else {
            role = SES_ROLE_FAIL;
        }
        SES_AUTH_ROLE(session) = (int8_t)role;

        emit_auth_state_event(session);
        gpio_pulse(0x148, 0);

        status = SES_AUTH_ROLE(session);
        record_set_status(wr, &status);

        if (SES_AUTH_ROLE(session) == SES_ROLE_OK) {
            if (challenge_prepare(SES_CHALLENGE(session), 0x10) != 0) {
                VM_LOG(auth_cert_log, "challenge prepare failed");
                rc = -13;
                goto cleanup;
            }
            record_add_blob(wr, SES_CHALLENGE(session)); /* return challenge */
        }
    } else if (role == 1) {
        /* ---- message 2: signature over the challenge ---- */
        struct rec_field sig;
        uint8_t rd[72];

        gpio_pulse(0x148, 0);
        thunk_record_reader_init(rd, 3, REC_PAYLOAD(rec), REC_LEN(rec));

        if (SES_AUTH_ROLE(session) == SES_ROLE_OK) {
            if (record_get_field2(rd, &sig) == 0) {
                VM_LOG(auth_state_log, "cannot parse signature record");
                status = -1;
            } else if (sig.len != 0x40) {
                VM_LOG(auth_state_log, "bad signature length");
                status = -1;
            } else if (ec_signature_verify_core(sig.ptr, SES_CHALLENGE(session),
                                                0x10, SES_KEYCTX(session), 0) != 0) {
                VM_LOG(auth_state_log, "challenge signature invalid");
                status = -1;
            } else {
                publish_auth_event(session, 0x3cc0);   /* authenticated */
                status = 2;
            }
        } else {
            VM_LOG(auth_state_log, "unexpected auth state");
            status = -1;
        }
        SES_AUTH_ROLE(session) = (int8_t)status;
        record_set_status(wr, &status);
    } else {
        /* unexpected role/state */
        VM_LOG(auth_cert_log, "unexpected auth role %d", role);
        rc = -13;
        goto cleanup;
    }

    if (SES_AUTH_ROLE(session) == SES_ROLE_FAIL)
        mem_zero(session, 0, VM_SESSION_SIZE);

    record_end(wr, 2);
    {
        uint16_t plen = (uint16_t)record_writer_len(wr, resp + 7);
        uint16_t tot  = (uint16_t)(plen + 2);
        resp[5] = (uint8_t)plen; resp[6] = (uint8_t)(plen >> 8);
        resp[3] = (uint8_t)tot;  resp[4] = (uint8_t)(tot >> 8);
    }
    rc = vmtp_response_send(rsp, resp);

cleanup:
    vmtp_pkt_unref(rec);
    vmtp_pkt_unref(resp);
    return rc;
}
