/*
 * od_handlers.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * SHARED LPC-trio framework read-responders (same OD ids in frontlight and
 * motor_sensor): provisioning record / blob read-back, firmware version reports,
 * and the staged-image geometry + CRC used by the over-CAN updater (writes and
 * OTA begin/write/commit are in frontlight/src/od_framework.c). Each replies via
 * can_frame_encode (can_od.c). The names were corrected 2026-11-09: these were
 * first read as light-state responders; their helpers are the VMFW image API.
 *
 *   od_read_blob_responder @ 0x13f0  read 0x40-B stored record -> reply 0x10 B
 *   od_report_13           @ 0x3d02  getter -> reply 13 B
 *   od_report_version_record @ 0x3e1a  OD 01008000: {0x56, bswap16(fw ver lo), 8,1,8,0} 7 B
 *   od_report_fw_version     @ 0x19d4  OD 01009500: {fw ver, build, tag, 0x136e} 0x10 B
 *   od_report_slot_geometry  @ 0x3e6a  OD 01008100: staged slot {u16 page, u16 pages} 4 B
 *   od_report_image_crc      @ 0x3ee4  OD 01008400: CRC32 of slot page N (0xffff = all) 4 B
 *
 * The OD registration (which OD address -> which handler) is a flash table at
 * 0x4218 (24-B records; see docs/progress.md for the decoded map); these are the
 * leaf responders. Storage/state accessors are vendor/framework externs.
 * Behaviour-oriented reconstruction from the Ghidra decompile (image base 0xC00; addresses are link addresses).
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;

/* ---- vm CAN/OD TX (can_od.c) --------------------------------------------- */
extern int can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                            uint8_t *addr, int base, unsigned total);   /* 0x3ba0 */

/* ---- storage + VMFW image accessors (framework) -------------------------- */
extern int  storage_ensure_ready(void);                                /* 0x1374 (0=ready) */
extern int  storage_read(void *dev, void *dst, int a, int b);          /* 0x10a4 (0=ok)    */
extern void *g_store_blob;    /* DAT_00001430 */

/* sys_image_info(slot, out): out = {sector, page_size, size, base} of image
 * slot `slot` (0 running, 2 staged); always 0. fw_trailer_get(out): *out =
 * slot0 base+size-0x28, -22 unless it starts with "VMFW", -14 on info error. */
extern int  sys_image_info(int slot, void *out);                       /* 0x196c */
extern int  fw_trailer_get(void *out);                                 /* 0x199c */
extern int  report13_get(void *out);                                   /* 0x13a4 */
extern int  image_crc32(int off, int len, void *crc);                  /* 0x2164 */
extern int  flash_cache_flush(void);                                   /* 0x1f20 */

extern uint32_t g_state_tag;   /* DAT_00001a14 (constant packed into od_report_fw_version) */

/* -------------------------------------------------------------------------
 * od_read_blob_responder  --  0x13f0
 *   Read a 0x40-B stored record, reply its first 0x10 bytes. (Same shape as the
 *   frontlight responder.)
 * ------------------------------------------------------------------------- */
int od_read_blob_responder(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    uint8_t rec[0x10];

    if (storage_ensure_ready() != 0)
        return -0x5;
    if (storage_read(g_store_blob, rec, 0x40, 0x10) != 0)
        return -0xe;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0x10);
}

/* -------------------------------------------------------------------------
 * od_report_13  --  0x3d02
 *   Fetch a 13-byte report record and reply it.
 * ------------------------------------------------------------------------- */
void od_report_13(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    uint8_t rec[0x10];
    if (report13_get(rec) == 0)
        can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0xd);
}

/* -------------------------------------------------------------------------
 * od_report_version_record  --  0x3e1a
 *   OD 01008000: 7-byte version record {0x56, bswap16(trailer ver lo16), 8,1,8,0}.
 * ------------------------------------------------------------------------- */
int od_report_version_record(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    int st;
    if (fw_trailer_get(&st) != 0)
        return -0x16;
    {
        uint16_t v = *(uint16_t *)(st + 4);
        struct __attribute__((packed)) {
            uint8_t  tag;      /* 0x56 */
            uint16_t val;      /* byte-swapped state word */
            uint8_t  a, b, c, d;
        } rec;
        rec.tag = 0x56;
        rec.val = (uint16_t)((v << 8) | (v >> 8));
        rec.a = 8; rec.b = 1; rec.c = 8; rec.d = 0;
        return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&rec, 7);
    }
}

/* -------------------------------------------------------------------------
 * od_report_fw_version  --  0x19d4
 *   OD 01009500: firmware version {trailer ver @+4, build @+0x10, g_state_tag,
 *   0x136e (= the VMFW build marker of this image)}.
 * ------------------------------------------------------------------------- */
int od_report_fw_version(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    int st;
    if (fw_trailer_get(&st) != 0)
        return -0x16;
    {
        uint32_t rec[4];
        rec[0] = *(uint32_t *)(st + 4);
        rec[1] = *(uint32_t *)(st + 0x10);
        rec[2] = g_state_tag;
        rec[3] = 0x136e;
        return can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0x10);
    }
}

/* -------------------------------------------------------------------------
 * od_report_slot_geometry  --  0x3e6a
 *   OD 01008100: staged slot geometry {u16 page_size, u16 size/page_size}; the
 *   host reads this before OTA begin ({first_page, count}).
 * ------------------------------------------------------------------------- */
int od_report_slot_geometry(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    struct { uint8_t raw[4]; uint32_t page_size, size; } s;
    if (sys_image_info(2, s.raw) != 0)
        return -0xe;
    {
        struct { uint16_t page_size; uint16_t pages; } rec;
        rec.page_size = (uint16_t)s.page_size;
        rec.pages     = (uint16_t)(s.size / s.page_size);
        return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&rec, 4);
    }
}

/* -------------------------------------------------------------------------
 * od_report_image_crc  --  0x3ee4
 *   OD 01008400: CRC32 of staged-slot page N (request u16 N), or of the whole
 *   slot for N = 0xffff. Reply 4 B (table timeout 1000 for the slow CRC).
 * ------------------------------------------------------------------------- */
int od_report_image_crc(struct od_slot *slots, struct od_reg *reg, uint8_t *addr,
                     uint8_t **req)
{
    uint16_t page = *(uint16_t *)*req;
    /* sys_image_info(2, buf) = {sector, page_size@+4, size@+8, (base)} */
    uint8_t  buf[12];
    int      out = 0;
    int      page_size, size, off, len;

    if (flash_cache_flush() != 0 || sys_image_info(2, buf) != 0)
        return -0xe;

    page_size = *(int32_t *)(buf + 4);
    size      = *(int32_t *)(buf + 8);
    if (page == 0xffff) {                /* whole slot */
        off = 0;
        len = size;
    } else {                             /* one page   */
        off = page_size * (int)(unsigned)page;
        len = page_size;
    }
    if (image_crc32(off, len, &out) != 0)
        return -0x16;
    return can_frame_encode(slots, reg, addr, (int)(uintptr_t)&out, 4);
}
