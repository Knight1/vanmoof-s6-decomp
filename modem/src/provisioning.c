/*
 * provisioning.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * Cloud-gateway certificate + JWT provisioning. The modem is the bike's AWS-IoT
 * uplink; before it can connect it must hold a client certificate (provisioned
 * over MQTT from the factory/cloud into the nRF modem key store) and it mints a
 * short-lived JWT device token for auth. Reconstructed from Ghidra (image base
 * 0x10000):
 *   cert_provisioning_handle @ 0x252e0
 *   jwt_generate             @ 0x38ad4
 *
 * The nRF modem "key management" (AT%CMNG-backed cert store), the AT-command
 * formatter, and the event bus are vendor (NCS `modem_key_mgmt` / `nrf_modem` /
 * Zephyr) and declared extern. Behaviour-oriented; not byte-identical.
 * Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- nRF modem key management (sec_tag cert store, AT%CMNG) — vendor ------ */
extern int  modem_key_mgmt_write (int sec_tag, int type, const void *buf, unsigned len); /* 0x3726c */
extern int  modem_key_mgmt_cmp   (int sec_tag, int type, const void *buf, unsigned len); /* 0x372bc */
extern int  modem_key_mgmt_delete(int sec_tag, int type);                    /* 0x37350 */
extern int  modem_key_mgmt_exists(int sec_tag, int type, char *out_exists);  /* 0x3738c */

/* ---- AT command + libc-ish helpers (vendor / newlib) --------------------- */
extern int      at_cmd_printf(void *dst, unsigned cap, const char *fmt, ...); /* 0x4b44c */
extern char    *vm_strchr    (const char *s, int c);                         /* 0x5c886 */
extern int      hex2bin      (const char *hex, int hexlen, void *out, int outcap); /* 0x52864 */
extern unsigned vm_strlen    (const char *s);                                /* 0x20c74 */
extern void     mem_set      (void *d, int v, unsigned n);                    /* 0x5c574 */
extern void    *vm_malloc    (unsigned n, int z);                             /* 0x5c4c0 */
extern void     vm_free      (void *p);                                       /* 0x5c4aa */
extern void     vm_memcpy    (void *d, const void *s, unsigned n);            /* 0x5c526 / 0x5c540 */

/* ---- connection / provisioning state + event bus ------------------------- */
extern void     provisioning_set_state(int st);                              /* 0x3510c */
extern int      certs_all_provisioned(void);                                 /* 0x25258 (nonzero = ready) */
extern void    *evt_alloc(int chan, int id, int sz);                         /* 0x59bbe */
extern void     evt_send (void *evt);                                        /* 0x4866c */

/* ---- logging (Zephyr LOG shim; gate = *mod & 7) -------------------------- */
extern uint8_t  g_log_cert[];                       /* DAT_000254a0 */
extern void     log_msg(void *mod, int lvl, const void *fmt, ...);           /* 0x53280/0x53294/0x5326e/0x53294 */
static int log_on (const uint8_t *m) { return (m[0] & 7) != 0; }
static int log_dbg(const uint8_t *m) { return (m[0] & 7) > 2; }

/* VanMoof modem sec_tag for the client certificate chain. */
#define VM_SEC_TAG   0xc9   /* 201 */
#define SHA256_LEN   0x20

/* Provisioning result event (chan 0x23, id 0x1111): a 0x22-byte status record
 * {ok:u8, hash_len:u8, hash[0x20]}. */
#define PROV_EVT_CHAN 0x23
#define PROV_EVT_ID   0x1111
#define PROV_EVT_SZ   0x22

/* ---- inbound cert-provisioning message (MQTT payload) -------------------- */
/* {..., type:u8@+5, len:u16@+6, data[]@+8}. Cert type: 0=CA, 1=cert, 2=key. */
#define CM_TYPE(m)  (*(uint8_t  *)((uint8_t *)(m) + 5))
#define CM_LEN(m)   (*(uint16_t *)((uint8_t *)(m) + 6))
#define CM_DATA(m)  ((uint8_t *)(m) + 8)

/* -------------------------------------------------------------------------
 * cert_provisioning_handle  --  0x252e0
 *
 * Handle a `provisioning/certificate` message: write the cert (type 0..2) into
 * the modem key store at sec_tag 201, or delete it when len==0. After a write,
 * read the stored cert's SHA-256 back (AT%CMNG=1) and validate it (0x20 bytes).
 * Publish a status record and, if the full chain is now provisioned, mark the
 * connection ready.
 * ------------------------------------------------------------------------- */
void cert_provisioning_handle(void *msg)
{
    struct { uint8_t ok; uint8_t hash_len; uint8_t hash[SHA256_LEN]; } result;
    char at_rsp[132];
    uint8_t type = CM_TYPE(msg);

    mem_set(&result.hash_len, 0, PROV_EVT_SZ);   /* clears hash_len + hash[] */
    result.ok = 1;

    if (log_dbg(g_log_cert))
        log_msg(g_log_cert, 3, "provision_certificate %d, %d", type, CM_LEN(msg));

    if (type >= 3) {
        if (log_on(g_log_cert)) log_msg(g_log_cert, 1, "invalid certificate type");
        goto publish;
    }

    provisioning_set_state(0);
    if (log_dbg(g_log_cert))
        log_msg(g_log_cert, 3, "provisioning certificate (len=%d)", CM_LEN(msg));

    if (CM_LEN(msg) == 0) {                       /* delete */
        if (modem_key_mgmt_delete(VM_SEC_TAG, type) != 0)
            goto publish;
        result.ok = 0;
        goto publish;
    }

    /* if a different cert is already present, remove it first */
    {
        char exists = 0;
        if (modem_key_mgmt_exists(VM_SEC_TAG, type, &exists) == 0 && exists) {
            if (modem_key_mgmt_cmp(VM_SEC_TAG, type, CM_DATA(msg), CM_LEN(msg)) == 0) {
                result.ok = 0;                    /* identical — nothing to do */
                goto publish;
            }
            modem_key_mgmt_delete(VM_SEC_TAG, type);
        }
    }

    if (modem_key_mgmt_write(VM_SEC_TAG, type, CM_DATA(msg), CM_LEN(msg)) != 0) {
        if (log_dbg(g_log_cert)) log_msg(g_log_cert, 3, "failed storing certificate %u", VM_SEC_TAG);
        goto publish;
    }
    if (log_dbg(g_log_cert)) log_msg(g_log_cert, 3, "certificate stored %u", VM_SEC_TAG);

    /* read the stored cert's SHA-256 back for verification */
    if (at_cmd_printf(at_rsp, 0x80, "AT%%CMNG=1,%u,%u", VM_SEC_TAG, type) != 0) {
        if (log_on(g_log_cert)) log_msg(g_log_cert, 1, "unable to read hash (err=...)");
    } else {
        char *h0 = vm_strchr(at_rsp, '"');
        if (h0 == NULL) {
            if (log_on(g_log_cert)) log_msg(g_log_cert, 1, "unable to find start of hash");
        } else {
            char *h1 = vm_strchr(h0 + 1, '"');
            if (h1 == NULL) {
                if (log_on(g_log_cert)) log_msg(g_log_cert, 1, "unable to find end of hash");
            } else {
                if (hex2bin(h0 + 1, (int)(h1 - (h0 + 1)), result.hash, SHA256_LEN) != SHA256_LEN
                    && log_on(g_log_cert))
                    log_msg(g_log_cert, 1, "invalid sha256 hash length");
                result.hash_len = SHA256_LEN;
                result.ok = 0;
                goto publish;
            }
        }
    }
    if (log_on(g_log_cert)) log_msg(g_log_cert, 1, "unable to read certificate sha256");

publish:
    {
        uint8_t *evt = (uint8_t *)evt_alloc(PROV_EVT_CHAN, PROV_EVT_ID, 1);
        if (evt != NULL)
            vm_memcpy(evt + 5, &result, PROV_EVT_SZ);
        evt_send(evt);
    }
    provisioning_set_state(certs_all_provisioned() != 0 ? 1 : 0x2c);
}

/* -------------------------------------------------------------------------
 * jwt_generate  --  0x38ad4
 *
 * Mint a device JWT via the modem's `AT%JWT` command, then convert the returned
 * token from standard base64 to base64url ('+' -> '-', '/' -> '_', strip '=')
 * so it is a valid JWT. Writes into req->out (allocating it if req->out == NULL).
 * ------------------------------------------------------------------------- */
struct jwt_req {
    const char *sub;       /* +0x00 subject (0 = omit sub/aud)         */
    uint8_t     aud;       /* +0x04 audience byte                       */
    uint8_t     sec_tag;   /* +0x05 signing key sec_tag                 */
    uint16_t    _pad06;    /* +0x06                                     */
    uint32_t    exp;       /* +0x08 expiry (seconds)                    */
    int         alg;       /* +0x0c JWT alg  (0 = default)              */
    int         key_type;  /* +0x10 key type (0 = default)              */
    char       *out;       /* +0x14 output buffer (0 -> allocate)       */
    unsigned    out_len;   /* +0x18 output capacity                     */
};

extern const char *g_jwt_fmt_basic;   /* DAT_00038c1c "AT%%JWT=%d,%u,\"%s\",\"%s\"" */
extern const char *g_jwt_fmt_full;    /* DAT_00038c20 (with sub/aud)               */
extern int         g_jwt_default_id;  /* DAT_00038c18 default alg/key-type          */

int jwt_generate(struct jwt_req *req)
{
    char *buf;
    int   rc, alg, kt;
    char *tok, *end, *p;
    unsigned need;

    if (req == NULL)
        return -0x16;                                 /* -EINVAL */
    if (req->sec_tag != 0 && req->out_len == 0)
        return -0x7a;                                 /* -122 */

    buf = (char *)vm_malloc(0x352, 1);
    if (buf == NULL)
        return -0xc;                                  /* -ENOMEM */

    alg = req->alg ? req->alg : g_jwt_default_id;
    kt  = req->key_type ? req->key_type : g_jwt_default_id;

    if (req->sub == NULL)
        rc = at_cmd_printf(buf, 0x352, g_jwt_fmt_full, req->sec_tag, req->exp, alg, kt);
    else
        rc = at_cmd_printf(buf, 0x352, g_jwt_fmt_basic, req->sec_tag, req->exp, alg, kt,
                           req->sub, (char)req->aud);
    if (rc != 0) {
        if (rc > 0) rc = -8;
        goto out;
    }

    /* the JWT is returned quoted in the AT response */
    tok = vm_strchr(buf, '"');
    if (tok == NULL) { rc = -0x4d; goto out; }        /* -EBADMSG */
    tok++;
    end = vm_strchr(tok, '"');
    if (end == NULL) { rc = -0x4d; goto out; }
    *end = 0;

    vm_memcpy(buf, tok, vm_strlen(tok) + 1);          /* pack to buf start */
    need = vm_strlen(buf) + 1;

    if (req->out == NULL) {
        req->out = (char *)vm_malloc(need, 1);
        if (req->out == NULL) { rc = -0xc; goto out; }
        req->out_len = need;
    } else if (req->out_len < need) {
        rc = -7;                                      /* buffer too small */
        goto out;
    }

    /* base64 -> base64url */
    while ((p = vm_strchr(buf, '+')) != NULL) *p = '-';
    while ((p = vm_strchr(buf, '/')) != NULL) *p = '_';
    if ((p = vm_strchr(buf, '=')) != NULL) *p = 0;    /* strip padding */

    vm_memcpy(req->out, buf, need);
    rc = 0;

out:
    vm_free(buf);
    return rc;
}

/* ---- keygen handler externs ---------------------------------------------- */
extern int      get_ecu_id  (char out_id[16]);       /* 0x25860 (0 = ok, id set) */
extern uint16_t vm_strnlen  (const void *s, unsigned n);            /* 0x59052 */
extern int      vm_strncmp  (const void *s, const void *pfx, int n);/* 0x5c8b0 (0=match) */
extern void     evt_free    (void *evt);             /* 0x49738 */
extern void     at_cmd_exec (const char *fmt, void *io);           /* 0x5225a */
extern uint8_t  g_log_prov[];                        /* DAT_000251cc */

#define KEYGEN_EVT_CHAN 0x403
#define KEYGEN_EVT_ID   0x1110   /* CSR-ready event (cloud signs it -> cert)   */
#define KEYGEN_KEY_TYPE 2        /* EC keypair                                 */

/* -------------------------------------------------------------------------
 * keygen_handle  --  0x25034
 *
 * `provisioning/generate_key`: generate the device keypair + CSR on the modem.
 * Refuses if the ECU id isn't set or a client cert (type 1) is already present.
 * Runs `AT%KEYGEN=201,2,0,"O=VanMoof,CN=<ecu_id>"`, strips the `%KEYGEN: "`
 * prefix and the trailing COSE-Sign1 part after the '.', and publishes the CSR
 * (event 0x1110) for the cloud to sign into a client certificate.
 * ------------------------------------------------------------------------- */
void keygen_handle(void)
{
    char     ecu_id[16];
    char     exists = 0;
    uint8_t *evt, *body;
    uint16_t len;
    char    *dot;

    if (get_ecu_id(ecu_id) != 0) {
        if (log_on(g_log_prov)) log_msg(g_log_prov, 1, "ECU ID is not set");
        return;
    }
    provisioning_set_state(0);

    /* already have a client cert? nothing to do */
    if (modem_key_mgmt_exists(VM_SEC_TAG, 1, &exists) == 0 && exists) {
        if ((g_log_prov[0] & 6) != 0)
            log_msg(g_log_prov, 2, "ignoring request when client certificate is already provisioned");
        return;
    }
    /* drop any stale private key */
    if (modem_key_mgmt_exists(VM_SEC_TAG, KEYGEN_KEY_TYPE, &exists) == 0 && exists)
        modem_key_mgmt_delete(VM_SEC_TAG, KEYGEN_KEY_TYPE);

    evt  = (uint8_t *)evt_alloc(KEYGEN_EVT_CHAN, KEYGEN_EVT_ID, 1);
    body = evt + 8;
    evt[5] = 3;

    if (at_cmd_printf(body, 0x400, "AT%%KEYGEN=%u,%u,0,\"O=VanMoof,CN=%s\"",
                      VM_SEC_TAG, KEYGEN_KEY_TYPE, ecu_id) != 0) {
        if (log_on(g_log_prov)) {
            log_msg(g_log_prov, 1, "unable to generate key (err=...)");
            log_msg(g_log_prov, 1, "modem_key_mgmt_keygen");
        }
        evt_free(evt);
        return;
    }
    at_cmd_exec("%s", body);                          /* run it; response into body */

    len = vm_strnlen(body, 0x400);
    *(uint16_t *)(evt + 6) = len;

    if (vm_strncmp(body, "%KEYGEN: \"", 10) != 0) {
        if (log_on(g_log_prov)) log_msg(g_log_prov, 1, "invalid CSR response (prefix)");
        return;
    }
    vm_memcpy(body, body + 10, len - 10);             /* strip the prefix */
    dot = vm_strchr((char *)body, '.');               /* COSE-Sign1 separator */
    if (dot == NULL) {
        if (log_on(g_log_prov)) log_msg(g_log_prov, 1, "invalid CSR response (cose sign)");
        return;
    }
    *dot = 0;
    *(uint16_t *)(evt + 6) = vm_strnlen(body, 0x400);
    evt[0] &= 0xf7;
    if (log_dbg(g_log_prov)) log_msg(g_log_prov, 3, "key generated %u", VM_SEC_TAG);
    evt_send(evt);
}
