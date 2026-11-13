/*
 * od_framework.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * SHARED LPC-trio framework: this file is the same reconstruction as
 * frontlight/src/od_framework.c (instruction skeletons of all handlers compared
 * across the three images; OD ids identical). The inline address comments below
 * are FRONTLIGHT addresses; the rearlight addresses are:
 *     config_store_write       0x18a8   (frontlight 0x1a38)
 *     config_production_lock   0x1434   (frontlight 0x15b0)
 *     od_write_record13        0x3d7e   (frontlight 0x41e8)
 *     od_write_blob16          0x3db6   (frontlight 0x4220)
 *     od_write_lock            0x3dc4   (frontlight 0x422e)
 *     sys_image_validate       0x20f0   (frontlight 0x2280)
 *     sys_image_clear_marker   0x3f48   (frontlight 0x43b2)
 *     od_ota_begin             0x268c   (frontlight 0x281c)
 *     od_ota_write             0x201c   (frontlight 0x21ac)
 *     od_image_commit          0x2700   (frontlight 0x2890)
 *     can_frame_encode         0x3ba0   (frontlight 0x3ffc)
 *     storage_ensure_ready     0x1374   (frontlight 0x14d0)
 *     storage_read             0x10a4   (frontlight 0x11f0)
 *     storage_write              tbd    (frontlight 0x1450)
 *     vm_memcpy                0x3fb8   (frontlight 0x4422)
 *     vm_memset                0x3fd2   (frontlight 0x443c)
 *     sys_image_info           0x196c   (frontlight 0x1afc)
 *     image_read               0x2054   (frontlight 0x21e4)
 *     image_crc32              0x2164   (frontlight 0x22f4)
 *     flash_page_write         0x1fa8   (frontlight 0x2138)
 *     flash_erase              0x21dc   (frontlight 0x2514)
 *     flash_cache_flush        0x1f20   (frontlight 0x20b0)
 *     log_printf               0x2418   (frontlight 0x25a8)
 *
 * See the frontlight copy for the full commentary.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;

/* Received payload as passed to handlers (can_od.c: &pdata). */
struct od_payload {
    uint8_t  *data;
    uint32_t  len;
};

/* Staged-image slot geometry. */
struct sys_image_info {
    uint32_t sector;       /* +0 (= page_size in practice) */
    uint32_t page_size;    /* +4 */
    uint32_t size;         /* +8 */
    uint32_t base;         /* +c */
};

/* ---- externs ------------------------------------------------------------- */
extern int can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);   /* 0x3ffc */
extern int  storage_ensure_ready(void);                                  /* 0x14d0 */
extern int  storage_read(void *dev, void *dst, int off, int len);        /* 0x11f0 */
extern int  storage_write(void *dev, const void *src);                   /* 0x1450 */
extern void vm_memcpy(void *dst, const void *src, unsigned n);           /* 0x4422 */
extern void vm_memset(void *dst, int v, unsigned n);                     /* 0x443c */
extern int  sys_image_info(int slot, struct sys_image_info *out);        /* 0x1afc */
extern int  image_read(uint32_t off, void *dst, uint32_t len);           /* 0x21e4 */
extern int  image_crc32(uint32_t off, uint32_t len, uint32_t *crc);      /* 0x22f4 */
extern int  flash_page_write(uint32_t off, const void *src, uint32_t len); /* 0x2138 */
extern int  flash_erase(uint32_t off, uint32_t len);                     /* 0x2514 */
extern int  flash_cache_flush(void);                                     /* 0x20b0 */
extern void log_printf(int lvl, const char *fmt, ...);                   /* 0x25a8 */

extern uint8_t g_cfg_dev[];               /* 0x200006a4 */
extern volatile uint16_t g_ota_wr;        /* 0x200006e6: write cursor  */
extern volatile uint16_t g_ota_end;       /* 0x200006e4: end of region */

#define CFG_PAGE_LEN   0x200
#define CFG_DATA_OFF   0x30
#define CFG_LOCK_OFF   0x3e

/* -------------------------------------------------------------------------
 * config_store_write  --  0x1a38
 *   Read the config page; refuse (-22) if its lock byte is set; store `lock`
 *   there, copy src/len to page+0x30+off (if both given), write back.
 *   -5 storage not ready, -14 read/write failure.
 * ------------------------------------------------------------------------- */
int config_store_write(const void *src, unsigned len, unsigned off, uint8_t lock)
{
    uint8_t page[CFG_PAGE_LEN];

    if (storage_ensure_ready() != 0)
        return -5;

    vm_memset(page, 0, CFG_PAGE_LEN);
    if (storage_read(g_cfg_dev, page, 0, CFG_PAGE_LEN) != 0)
        return -14;

    if (page[CFG_LOCK_OFF] != 0)
        return -22;
    page[CFG_LOCK_OFF] = lock;

    if (src != NULL && len != 0)
        vm_memcpy(&page[CFG_DATA_OFF + off], src, len);

    if (storage_write(g_cfg_dev, page) != 0)
        return -14;
    return 0;
}

/* -------------------------------------------------------------------------
 * config_production_lock  --  0x15b0
 *   word0 |= 0x70; words at +0x10/+0x14 = 0xff2000df / 0xffff0000. Writes
 *   only if anything changed. -5 not ready, -14 read/write failure.
 * ------------------------------------------------------------------------- */
int config_production_lock(void)
{
    uint32_t page[CFG_PAGE_LEN / 4];
    uint32_t w0, n0, old4, old5;

    if (storage_ensure_ready() != 0)
        return -5;
    if (storage_read(g_cfg_dev, page, 0, CFG_PAGE_LEN) != 0)
        return -14;

    w0   = page[0];
    n0   = w0 | 0x70u;
    old4 = page[4];
    old5 = page[5];
    page[0] = n0;
    page[4] = 0xff2000dfu;
    page[5] = 0xffff0000u;

    if (w0 == n0 && old4 == 0xff2000dfu && old5 == 0xffff0000u)
        return 0;

    if (storage_write(g_cfg_dev, page) != 0)
        return -14;
    return 0;
}

/* -------------------------------------------------------------------------
 * od_write_record13  --  0x41e8   (OD 01008800 write, 13 B)
 *   Store {1 (valid), data[0..12], 0} at page+0x30 (read back by 01008700).
 * ------------------------------------------------------------------------- */
int od_write_record13(struct od_slot *slots, struct od_reg *reg, void *addr,
                      struct od_payload *p)
{
    uint8_t rec[15];
    unsigned i;

    rec[14] = 0;
    rec[0]  = 1;
    for (i = 0; i < 13; i++)
        rec[1 + i] = p->data[i];

    return config_store_write(rec, 15, 0, 0);
}

/* -------------------------------------------------------------------------
 * od_write_blob16  --  0x4220   (OD 01009200 write, 16 B)
 *   Store 16 bytes at page+0x40 (read back by 01009100).
 * ------------------------------------------------------------------------- */
int od_write_blob16(struct od_slot *slots, struct od_reg *reg, void *addr,
                    struct od_payload *p)
{
    return config_store_write(p->data, 16, 16, 0);
}

/* -------------------------------------------------------------------------
 * od_write_lock  --  0x422e   (OD 01009400 write, 0 B)
 *   Set the write-once lock byte, then apply the production lock.
 * ------------------------------------------------------------------------- */
int od_write_lock(void)
{
    int rc = config_store_write(NULL, 0, 0, 1);

    if (rc != 0)
        return rc;
    return config_production_lock();
}

/* -------------------------------------------------------------------------
 * sys_image_validate  --  0x2280
 *   Read the staged image's first 512 B and check its VMFW header:
 *     magic "VMFW" @0x134, img_len @0x140 <= slot-2 size,
 *     version (b138<<24 | b139<<16 | u16@0x13a) - 1 > 0x01080006
 *   (i.e. refuse anything older than 1.8.8: anti-rollback floor).
 *   On success *out = img_len. -14 slot/read error, -22 header rejected.
 *   The OEM calls this body under both sys_image_validate and
 *   sys_image_size (identical functions folded by the compiler).
 * ------------------------------------------------------------------------- */
int sys_image_validate(uint32_t *out)
{
    struct sys_image_info s1, s2;
    uint8_t  hdr[CFG_PAGE_LEN];
    uint32_t len, ver;

    if (sys_image_info(2, &s2) != 0)
        return -14;
    if (sys_image_info(1, &s1) != 0)
        return -14;
    if (image_read(0, hdr, CFG_PAGE_LEN) != 0)
        return -14;

    if (*(uint32_t *)&hdr[0x134] != 0x57464d56u)          /* "VMFW" */
        return -22;
    len = *(uint32_t *)&hdr[0x140];
    if (len > s2.size)
        return -22;

    ver = ((uint32_t)hdr[0x138] << 24) | ((uint32_t)hdr[0x139] << 16)
        | *(uint16_t *)&hdr[0x13a];
    if (ver - 1u <= 0x01080006u)
        return -22;

    *out = len;
    return 0;
}

/* -------------------------------------------------------------------------
 * sys_image_clear_marker  --  0x43b2
 *   Read the last page of slot 2 (zero-filled if the read fails); unless its
 *   trailing word is 0xffffffff, erase that page. -14 on any failure.
 * ------------------------------------------------------------------------- */
int sys_image_clear_marker(void)
{
    struct sys_image_info s;
    uint32_t marker = 0;
    uint32_t last;

    if (sys_image_info(2, &s) != 0)
        return -14;

    {
        uint8_t buf[s.page_size];

        last = s.size - s.page_size;
        if (image_read(last, buf, s.page_size) != 0)
            vm_memset(buf, 0, s.page_size);
        vm_memcpy(&marker, &buf[s.page_size - 4], 4);
    }

    if (marker + 1u == 0)
        return 0;
    if (flash_erase(last, s.page_size) != 0)
        return -14;
    return 0;
}

/* -------------------------------------------------------------------------
 * od_ota_begin  --  0x281c   (OD 01008200, 4 B: {u16 first_page, u16 count})
 *   Erase pages first..first+count-1 of slot 2 and set the write window
 *   [first*pg, (first+count)*pg) (16-bit). -14 on any failure.
 * ------------------------------------------------------------------------- */
int od_ota_begin(struct od_slot *slots, struct od_reg *reg, void *addr,
                 struct od_payload *p)
{
    const uint16_t *d = (const uint16_t *)p->data;
    struct sys_image_info s;
    uint32_t page;
    uint16_t wr;
    int rc;

    if (sys_image_info(2, &s) != 0)
        return -14;
    if (flash_cache_flush() != 0)
        return -14;
    if (sys_image_clear_marker() != 0)
        return -14;

    for (page = d[0]; (uint32_t)d[0] + d[1] > page; page++) {
        rc = flash_erase(s.page_size * page, s.page_size);
        if (rc != 0) {
            log_printf(0, "E>failed to erase page %d (err=%d)\n", page, rc);
            return -14;
        }
    }

    wr = (uint16_t)(d[0] * s.page_size);
    g_ota_wr  = wr;
    g_ota_end = (uint16_t)(d[1] * s.page_size + wr);
    return 0;
}

/* -------------------------------------------------------------------------
 * od_ota_write  --  0x21ac   (OD 01008300, {data, len})
 *   Append a chunk at the cursor. Returns +22 (sic, positive) if the cursor
 *   is already past the window end; no check of cursor+len against the end.
 * ------------------------------------------------------------------------- */
int od_ota_write(struct od_slot *slots, struct od_reg *reg, void *addr,
                 struct od_payload *p)
{
    if (g_ota_end < g_ota_wr)
        return 22;
    if (flash_page_write(g_ota_wr, p->data, p->len) != 0)
        return -14;
    g_ota_wr = (uint16_t)(g_ota_wr + p->len);
    return 0;
}

/* -------------------------------------------------------------------------
 * od_image_commit  --  0x2890   (OD 01008500, request u32 CRC, 1-B reply)
 *   Validate the staged image, CRC it against the requested value, then write
 *   the CRC into the last 4 bytes of the slot's last page (allow-update
 *   marker). Reply status: 0, -5 (flush), -14 (validate/size/marker),
 *   -34 (CRC mismatch).
 * ------------------------------------------------------------------------- */
void od_image_commit(struct od_slot *slots, struct od_reg *reg, uint8_t *addr,
                     struct od_payload *p)
{
    uint32_t expected = *(uint32_t *)p->data;
    int32_t  status = 0;
    struct sys_image_info s;
    uint32_t size, crc, trailer, last;
    int rc;

    if (flash_cache_flush() != 0) {
        status = -5;
        goto reply;
    }

    rc = sys_image_validate((uint32_t *)&s);
    if (rc != 0) {
        log_printf(0, "E>sys_image_validate failed ret=%d\n", rc);
        status = -14;
        goto reply;
    }

    size = 0;
    rc = sys_image_validate(&size);               /* OEM: sys_image_size */
    if (rc != 0) {
        log_printf(0, "E>sys_image_size failed ret=%d\n", rc);
        status = -14;
        goto reply;
    }

    crc = 0;
    if (image_crc32(0, size, &crc) != 0 || crc != expected) {
        log_printf(0, "E>Image CRC failed %u vs %u\n", crc, expected);
        status = -34;
        goto reply;
    }
    trailer = crc;

    if (sys_image_info(2, &s) != 0)
        goto marker_fail;

    {
        uint8_t buf[s.page_size];

        last = s.size - s.page_size;
        if (image_read(last, buf, s.page_size) != 0)
            vm_memset(buf, 0xff, s.page_size);
        vm_memcpy(&buf[s.page_size - 4], &trailer, 4);

        if (flash_erase(last, s.page_size) != 0
            || flash_page_write(last, buf, s.page_size) != 0
            || flash_cache_flush() != 0)
            goto marker_fail;
    }
    goto reply;

marker_fail:
    log_printf(0, "E>sys_image_allow_update failed ret=%d\n", -14);
    status = -14;

reply:
    can_frame_encode(slots, reg, addr, (int)(uintptr_t)&status, 1);
}
