/*
 * od_framework.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * Framework OD handlers (the shared 0x0100xx00 object set). Same OD ids and
 * semantics as the LPC trio (frontlight/src/od_framework.c, rearlight/src/
 * od_handlers.c), but a different build/revision of the framework: the
 * provisioning data is a 40-B struct record in flash area 4 (no raw page
 * offsets, no LPC CMPA lockdown), and the updater stages an MCUboot image in
 * flash area 2 (60 KB, 2 KB pages; no VMFW header / anti-rollback check here).
 *
 *   config_load                @ 0x8005ce0
 *   config_save                @ 0x800ae36
 *   od_write_lock              @ 0x800af56  OD 01009400
 *   od_write_blob16            @ 0x800af28  OD 01009200
 *   od_write_record13          @ 0x800aef0  OD 01008800
 *   od_report_13               @ 0x800ae6c  OD 01008700
 *   od_read_blob_responder     @ 0x800aea6  OD 01009100
 *   od_report_slot_geometry    @ 0x80052a4  OD 01008100  {0x800, 30}
 *   od_read_hw_id              @ 0x80052c0  OD 01008900  0x20240627
 *   fw_trailer_get             @ 0x8004a40  VMFW record at 0x080007d8 (boot area)
 *   od_report_version_record   @ 0x800ac58  OD 01008000
 *   od_report_fw_version       @ 0x8005264  OD 01009500
 *   od_report_image_crc        @ 0x800ad40  OD 01008400
 *   od_ota_begin               @ 0x8006b08  OD 01008200
 *   od_ota_write               @ 0x8005ca8  OD 01008300
 *   od_image_commit            @ 0x8006bbc  OD 01008500
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;
struct od_payload { uint8_t *data; uint32_t len; };

extern int   can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                              uint8_t *addr, int base, unsigned total);   /* 0x800ab60 */
/* MCUboot-style flash-area API (area 2 = staged image, area 4 = config) */
extern int   flash_area_read(int area, uint32_t off, void *dst, uint32_t len);   /* 0x8005bfc */
extern int   flash_area_erase(int area, uint32_t off, uint32_t len);             /* 0x8005934 */
extern int   flash_area_write(int area, uint32_t off, const void *src, uint32_t len); /* 0x8004808 */
extern int   image_crc32(uint32_t off, uint32_t len, uint32_t *crc);     /* 0x8005c2c */
extern int   image_check_ready(void);                                    /* 0x800603c */
extern void  log_printf(int lvl, const char *fmt, ...);                  /* 0x8006890 */
extern void *vm_memset(void *dst, int c, size_t n);                      /* 0x800b1f6 */
extern void *vm_memcpy(void *dst, const void *src, size_t n);            /* 0x800b1ba */

extern volatile uint16_t g_ota_wr;     /* 0x200012d0 */
extern volatile uint16_t g_ota_end;    /* 0x200012ce */

#define AREA_IMAGE      2
#define AREA_CONFIG     4
#define PAGE            0x800u
#define MARKER_OFF      0xe800u        /* last page of the 60 KB staged slot */
#define SLOT_SIZE       0xf000u
#define STAGED_HDR      ((const volatile uint8_t *)0x08011000u)
#define MCUBOOT_MAGIC   0x96f3b83du
#define TLV_INFO_MAGIC  0x6907u
#define CFG_MAGIC       0x564d4d46u    /* 0x8005d20 */
#define VMFW_MAGIC      0x57464d56u    /* "VMFW" */

/* ---- config record (flash area 4, offset 0, 40 B) ------------------------ */
struct cfg_record {
    uint32_t magic;          /* +0x00 */
    uint8_t  rec13[13];      /* +0x04 provisioning record (01008800/01008700) */
    uint8_t  blob16[16];     /* +0x11 (01009200/01009100) */
    uint8_t  locked;         /* +0x21 write-once */
    uint8_t  pad[6];
};

/* -------------------------------------------------------------------------
 * config_load  --  0x8005ce0
 *   Read the record; on read error or bad magic re-initialise the in-memory
 *   copy (magic set, data zeroed, unlocked) and return -22.
 * ------------------------------------------------------------------------- */
int config_load(struct cfg_record *r)
{
    if (flash_area_read(AREA_CONFIG, 0, r, 40) == 0 && r->magic == CFG_MAGIC)
        return 0;

    r->magic = CFG_MAGIC;
    vm_memset(r->rec13, 0, 13);
    vm_memset(r->blob16, 0, 16);
    r->locked = 0;
    return -22;
}

/* -------------------------------------------------------------------------
 * config_save  --  0x800ae36
 *   -22 if already locked; optionally lock; erase the 2 KB area and write.
 * ------------------------------------------------------------------------- */
int config_save(struct cfg_record *r, int lock)
{
    int rc;

    if (r->locked != 0)
        return -22;
    if (lock)
        r->locked = 1;

    rc = flash_area_erase(AREA_CONFIG, 0, PAGE);
    if (rc != 0)
        return rc;
    return flash_area_write(AREA_CONFIG, 0, r, 40);
}

/* write handlers: load (result ignored, so a first write formats it), patch, save */
int od_write_lock(void)                                               /* 0x800af56 */
{
    struct cfg_record r;

    config_load(&r);
    return config_save(&r, 1);
}

int od_write_blob16(struct od_slot *slots, struct od_reg *reg, void *addr,
                    struct od_payload *p)                             /* 0x800af28 */
{
    struct cfg_record r;

    config_load(&r);
    vm_memcpy(r.blob16, p->data, 16);
    return config_save(&r, 0);
}

int od_write_record13(struct od_slot *slots, struct od_reg *reg, void *addr,
                      struct od_payload *p)                           /* 0x800aef0 */
{
    struct cfg_record r;

    config_load(&r);
    vm_memcpy(r.rec13, p->data, 13);
    return config_save(&r, 0);
}

/* read responders: -22 when the record is not valid */
int od_report_13(struct od_slot *slots, struct od_reg *reg, uint8_t *addr) /* 0x800ae6c */
{
    struct cfg_record r;
    uint8_t out[13];

    if (config_load(&r) != 0)
        return -22;
    vm_memcpy(out, r.rec13, 13);
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)out, 13);
}

int od_read_blob_responder(struct od_slot *slots, struct od_reg *reg, uint8_t *addr) /* 0x800aea6 */
{
    struct cfg_record r;
    uint8_t out[16];

    if (config_load(&r) != 0)
        return -22;
    vm_memcpy(out, r.blob16, 16);
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)out, 16);
}

int od_report_slot_geometry(struct od_slot *slots, struct od_reg *reg, uint8_t *addr) /* 0x80052a4 */
{
    uint32_t v = 0x001e0800u;           /* {u16 page 0x800, u16 30 pages} */
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&v, 4);
}

int od_read_hw_id(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)  /* 0x80052c0 */
{
    uint32_t v = 0x20240627u;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&v, 4);
}

/* -------------------------------------------------------------------------
 * fw_trailer_get  --  0x8004a40
 *   *out = the VMFW record at 0x080007d8 (inside the 8 KB boot area below the
 *   MCUboot slot); -22 unless it starts with "VMFW".
 * ------------------------------------------------------------------------- */
int fw_trailer_get(const uint8_t **out)
{
    const uint8_t *t = (const uint8_t *)0x080007d8u;

    *out = t;
    return (*(const uint32_t *)t == VMFW_MAGIC) ? 0 : -22;
}

int od_report_version_record(struct od_slot *slots, struct od_reg *reg, uint8_t *addr) /* 0x800ac58 */
{
    const uint8_t *t;
    struct __attribute__((packed)) {
        uint8_t  tag;            /* 0x56 */
        uint16_t ver;            /* rev16 of trailer u16 @+4 */
        uint8_t  a, b, c, d;     /* 8, 1, 8, 0 */
    } rec;

    if (fw_trailer_get(&t) != 0)
        return -22;
    rec.tag = 0x56;
    rec.ver = (uint16_t)((*(const uint16_t *)(t + 4) << 8) | (*(const uint16_t *)(t + 4) >> 8));
    rec.a = 8; rec.b = 1; rec.c = 8; rec.d = 0;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&rec, 7);
}

int od_report_fw_version(struct od_slot *slots, struct od_reg *reg, uint8_t *addr) /* 0x8005264 */
{
    const uint8_t *t;
    uint32_t rec[4];

    if (fw_trailer_get(&t) != 0)
        return -22;
    rec[0] = *(const uint32_t *)(t + 4);
    rec[1] = *(const uint32_t *)(t + 0x10);
    rec[2] = 0x00080801u;              /* 0x80052a0 */
    rec[3] = 0x136e;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0x10);
}

/* -------------------------------------------------------------------------
 * od_report_image_crc  --  0x800ad40   (request u16 page; 0xffff = whole slot)
 * ------------------------------------------------------------------------- */
int od_report_image_crc(struct od_slot *slots, struct od_reg *reg, uint8_t *addr,
                        struct od_payload *p)
{
    uint16_t page = *(const uint16_t *)p->data;
    uint32_t crc = 0;
    int rc;

    if (page == 0xffff)
        rc = image_crc32(0, SLOT_SIZE, &crc);
    else
        rc = image_crc32((uint32_t)page << 11, PAGE, &crc);
    if (rc != 0)
        return -22;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&crc, 4);
}

/* -------------------------------------------------------------------------
 * od_ota_begin  --  0x8006b08   ({u16 first_page, u16 count})
 *   Clear the allow-update marker (erase the marker page unless its last word
 *   is blank), erase the requested pages, set the 16-bit write window.
 * ------------------------------------------------------------------------- */
int od_ota_begin(struct od_slot *slots, struct od_reg *reg, void *addr,
                 struct od_payload *p)
{
    const uint16_t *d = (const uint16_t *)p->data;
    uint32_t marker = 0;
    uint32_t page;
    uint16_t first, wr;
    int rc;

    {
        uint8_t buf[PAGE];

        if (flash_area_read(AREA_IMAGE, MARKER_OFF, buf, PAGE) != 0)
            vm_memset(buf, 0, PAGE);
        vm_memcpy(&marker, &buf[PAGE - 4], 4);
        if (marker + 1u != 0 && flash_area_erase(AREA_IMAGE, MARKER_OFF, PAGE) != 0)
            return -14;
    }

    first = d[0];
    for (page = first; (uint32_t)first + d[1] > page; page++) {
        rc = flash_area_erase(AREA_IMAGE, page << 11, PAGE);
        if (rc != 0) {
            log_printf(0, "E>failed to erase page %d (err=%d)\n", page, rc);
            return -14;
        }
    }

    wr = (uint16_t)(first << 11);
    g_ota_wr  = wr;
    g_ota_end = (uint16_t)(wr + ((uint32_t)d[1] << 11));
    return 0;
}

/* -------------------------------------------------------------------------
 * od_ota_write  --  0x8005ca8   ({data, len}); +22 (sic) past the window end
 * ------------------------------------------------------------------------- */
int od_ota_write(struct od_slot *slots, struct od_reg *reg, void *addr,
                 struct od_payload *p)
{
    if (g_ota_end < g_ota_wr)
        return 22;
    if (flash_area_write(AREA_IMAGE, g_ota_wr, p->data, p->len) != 0)
        return -14;
    g_ota_wr = (uint16_t)(g_ota_wr + p->len);
    return 0;
}

/* -------------------------------------------------------------------------
 * od_image_commit  --  0x8006bbc   (request u32 CRC; 1-B status reply)
 *   Check the staged MCUboot image (header magic, TLV-info magic 0x6907), CRC
 *   hdr_size + img_size + TLV-info total and compare; then write the CRC into
 *   the last 4 bytes of the marker page (allow-update). Status: 0, -14, -34,
 *   or the flash write rc.
 * ------------------------------------------------------------------------- */
void od_image_commit(struct od_slot *slots, struct od_reg *reg, uint8_t *addr,
                     struct od_payload *p)
{
    uint32_t expected = *(const uint32_t *)p->data;
    int32_t  status = 0;
    int      rc;

    rc = image_check_ready();
    if (rc != 0) {
        log_printf(0, "E>sys_image_validate failed ret=%d\n", rc);
        status = -14;
    } else if (*(const volatile uint32_t *)STAGED_HDR != MCUBOOT_MAGIC) {
        log_printf(0, "E>sys_image_size failed ret=%d\n", -22);
        status = -14;
    } else {
        uint16_t hdr_size  = *(const volatile uint16_t *)(STAGED_HDR + 8);
        uint16_t prot_tlv  = *(const volatile uint16_t *)(STAGED_HDR + 10);
        uint32_t img_size  = *(const volatile uint32_t *)(STAGED_HDR + 12);
        uint32_t body      = hdr_size + img_size;
        const volatile uint8_t *tlv = STAGED_HDR + body + prot_tlv;

        if (*(const volatile uint16_t *)tlv != TLV_INFO_MAGIC) {
            log_printf(0, "E>sys_image_size failed ret=%d\n", -22);
            status = -14;
        } else {
            uint32_t crc = 0;

            rc = image_crc32(0, body + *(const volatile uint16_t *)(tlv + 2), &crc);
            if (rc != 0 || crc != expected) {
                log_printf(0, "E>Image CRC failed %u vs %u\n", crc, expected);
                status = -34;
            } else {
                uint32_t trailer = crc;
                uint8_t  buf[PAGE];

                flash_area_read(AREA_IMAGE, MARKER_OFF, buf, PAGE);     /* rc ignored */
                flash_area_erase(AREA_IMAGE, MARKER_OFF, PAGE);         /* rc ignored */
                vm_memcpy(&buf[PAGE - 4], &trailer, 4);
                rc = flash_area_write(AREA_IMAGE, MARKER_OFF, buf, PAGE);
                if (rc != 0) {
                    log_printf(0, "E>sys_image_allow_update failed ret=%d\n", rc);
                    status = rc;
                }
            }
        }
    }

    can_frame_encode(slots, reg, addr, (int)(uintptr_t)&status, 1);
}
