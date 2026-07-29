/*
 * identity.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * Device identity: reads the modem's IMEI / ICCID / IMSI / firmware version and
 * publishes them as the device-info record the cloud gateway reports. Recovered
 * from the app-in-a-gap dispatch (reached via the provisioning handler table).
 *   modem_info_publish       @ 0x24a7c
 *   provisioning_device_info @ 0x24c2c  (get-responder wrapper)
 *
 * The nRF modem_info AT reads and the event bus are vendor. Behaviour-oriented
 * reconstruction from Ghidra (image base 0x10000); not byte-identical.
 * Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- nRF modem_info (AT-backed identity reads) — vendor ------------------ */
/* modem_info_string_get(type, buf, cap): type 0x13=IMEI, 0x0e=ICCID, 0x12=IMSI.
 * Returns the string length, or negative on error. */
extern int  modem_info_get    (int type, char *buf, unsigned cap);           /* 0x366f0 */
extern int  modem_info_version(char *buf, unsigned cap);                     /* 0x369f8 (0 = ok) */
extern unsigned vm_strlen     (const char *s);                              /* 0x20c74 */
extern void vm_strncpy        (char *dst, const char *src, unsigned n);     /* 0x5c8d4 */

/* ---- event bus / logging ------------------------------------------------- */
extern void *evt_publish(int id, const void *payload, unsigned len);         /* 0x515cc */
extern void  evt_send   (void);                                              /* 0x4866c (send the built event) */
extern void *evt_alloc  (int chan, int id, int sz);                          /* 0x59bbe */
extern void  log_msg    (void *mod, int lvl, const void *fmt, ...);          /* 0x53280 */
extern void  log_fmt    (void *mod, int code, void *arg_block);              /* 0x51650 */
extern uint8_t g_log_info[];                        /* DAT_00024bf8 */
static int log_on (const uint8_t *m) { return (m[0] & 7) != 0; }
static int log_dbg(const uint8_t *m) { return (m[0] & 7) > 2; }

/* ---- modem_info type ids ------------------------------------------------- */
#define MI_IMEI   0x13
#define MI_ICCID  0x0e
#define MI_IMSI   0x12

/* device-info record (0x50 B) with the four fields + their lengths. Field
 * offsets are OEM-observed; the record base is the global below. */
extern uint8_t g_device_info[0x50];                 /* DAT_00024bf4 (record base) */
#define DI_IMEI(r)      ((char *)((r) + 0x00))       /* DAT_00024bf0 */
#define DI_IMEI_LEN(r)  (*(int16_t *)((r) + 0x12))
#define DI_IMSI(r)      ((char *)((r) + 0x14))       /* DAT_00024c24-2 */
#define DI_IMSI_LEN(r)  (*(int16_t *)((r) + 0x12))   /* stored at imsi-2 */
#define DI_ICCID(r)     ((char *)((r) + 0x26))       /* DAT_00024c00 */
#define DI_ICCID_LEN(r) (*(int16_t *)((r) + 0x24))
#define DI_VERSION(r)   ((char *)((r) + 0x40))       /* DAT_00024c10 */
#define DI_VER_LEN(r)   (*(int16_t *)((r) + 0x3e))

/* -------------------------------------------------------------------------
 * modem_info_publish  --  0x24a7c
 *
 * Read IMEI / ICCID / IMSI / firmware-version from the modem into the device-info
 * record and publish it (event 0x1101, 0x50 bytes). Each read logs on error;
 * at debug level the four values are traced (imei/iccid/imsi/version).
 * ------------------------------------------------------------------------- */
void modem_info_publish(void)
{
    uint8_t *r = g_device_info;
    char     ver[44];
    int      rc;

    rc = modem_info_get(MI_IMEI, DI_IMEI(r), 0x10);
    DI_IMEI_LEN(r) = (int16_t)rc;
    if (rc < 0 && log_on(g_log_info)) log_msg(g_log_info, 1, "unable to read imei %d", rc);

    rc = modem_info_get(MI_ICCID, DI_ICCID(r), 0x18);
    DI_ICCID_LEN(r) = (int16_t)rc;
    if (rc < 0 && log_on(g_log_info)) log_msg(g_log_info, 1, "unable to read iccid %d", rc);

    rc = modem_info_get(MI_IMSI, DI_IMSI(r), 0x10);
    DI_IMSI_LEN(r) = (int16_t)rc;
    if (rc < 0 && log_on(g_log_info)) log_msg(g_log_info, 1, "unable to read imsi %d", rc);

    rc = modem_info_version(ver, 0x29);
    if (rc != 0 && log_on(g_log_info)) log_msg(g_log_info, 1, "unable to get modem version (err=%d)", rc);

    vm_strncpy(DI_VERSION(r), ver, 0x10);
    DI_VER_LEN(r) = (int16_t)vm_strlen(DI_VERSION(r));

    evt_publish(0x1101, r, 0x50);
    evt_send();

    if (log_dbg(g_log_info)) {
        struct { void *tag; const char *val; uint16_t code; } a;
        a.code = 0x200;
        a.tag = (void *)0;
        a.val = DI_IMEI(r);    log_fmt(g_log_info, 0x1cc0, &a);
        a.val = DI_ICCID(r);   log_fmt(g_log_info, 0x1cc0, &a);
        a.val = DI_IMSI(r);    log_fmt(g_log_info, 0x1cc0, &a);
        a.val = DI_VERSION(r); log_fmt(g_log_info, 0x1cc0, &a);
    }
}

/* -------------------------------------------------------------------------
 * provisioning_device_info  --  0x24c2c
 *
 * `provisioning/*` get-responder: refresh the device-info record and emit it.
 * ------------------------------------------------------------------------- */
void provisioning_device_info(void)
{
    modem_info_publish();
    evt_publish(0x1101, g_device_info, 0x50);
    evt_send();
}
