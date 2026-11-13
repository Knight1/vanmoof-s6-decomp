/*
 * lpc_flash.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55S0x/S1x Cortex-M33, VMFW)
 *
 * SHARED LPC-trio flash layer: same reconstruction as frontlight/src/lpc_flash.c
 * (instruction skeletons identical to frontlight). Inline address comments below
 * are FRONTLIGHT addresses; the rearlight ones are:
 *     flash_cache_invalidate  0x1924   (frontlight 0x1ab4)
 *     flash_init_once         0x1950   (frontlight 0x1ae0)
 *     sys_image_info          0x196c   (frontlight 0x1afc)
 *     fw_trailer_get          0x199c   (frontlight 0x1b2c)
 *     flash_cache_flush       0x1f20   (frontlight 0x20b0)
 *     flash_page_write        0x1fa8   (frontlight 0x2138)
 *     image_read              0x2054   (frontlight 0x21e4)
 *     image_crc32             0x2164   (frontlight 0x22f4)
 *     flash_erase             0x21dc   (frontlight 0x2514)
 *     CLOCK_GetCoreSysClkFreq 0x0fdc   (frontlight 0x1128, vendor)
 */

/*
 * lpc_flash.c  --  VanMoof S6 "frontlight" ECU (NXP LPC55S0x/S1x Cortex-M33, VMFW)
 *
 * Flash layer of the LPC-trio updater: a 512-B write-back page cache over the
 * on-chip flash, region-bounded reads/erases of the staged image slot, and the
 * image CRC32. Shared by rearlight (byte-identical); motor_sensor has the same
 * logic compiled with the SDK calls not inlined.
 *
 *   flash_cache_invalidate  @ 0x1ab4
 *   flash_init_once         @ 0x1ae0
 *   sys_image_info          @ 0x1afc
 *   fw_trailer_get          @ 0x1b2c
 *   flash_cache_flush       @ 0x20b0
 *   flash_page_write        @ 0x2138
 *   image_read              @ 0x21e4
 *   image_crc32             @ 0x22f4
 *   flash_erase             @ 0x2514
 *
 * Vendor: the ROM flash driver calls (NXP SDK fsl_iap FLASH_Init / Program /
 * Erase / VerifyErase / Read, incl. its ROM-version switch between the API tree
 * at 0x1301fe00 and fixed ROM entry points) are inlined in the OEM; they appear
 * here as extern calls. CLOCK_GetCoreSysClkFreq (0x1128) is the SDK clock driver.
 *
 * Flash layout (region table @0x44b0, {base, size}):
 *   0 boot   0x0000 +0x0c00     2 staged image 0x8000 +0x7400
 *   1 app    0x0c00 +0x7400     3 data         0xf400 +0x0c00
 * Offsets taken by image_read / flash_erase / flash_page_write are relative to
 * the staged slot (0x8000) and bounded by 0x7400.
 *
 * Addresses are link addresses (Ghidra image base 0xC00). Reconstructed from
 * the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t PFlashBlockBase;      /* +0x00 */
    uint32_t PFlashTotalSize;      /* +0x04 */
    uint32_t PFlashBlockCount;     /* +0x08 */
    uint32_t PFlashPageSize;       /* +0x0c (0 until initialised) */
    uint32_t PFlashSectorSize;     /* +0x10 */
} flash_config_t;

extern flash_config_t g_flash_cfg;             /* 0x20000080 */
extern volatile uint32_t g_cache_page;         /* 0x20000000 (0xffff = none) */
extern volatile uint8_t  g_cache_region;       /* 0x20000014 (5 = none) */
extern uint8_t           g_cache_buf[512];     /* 0x20000afa */
extern const uint32_t    g_flash_regions[][2]; /* 0x44b0 {base, size} */
extern const uint32_t    g_crc_nibble[16];     /* 0x444c (CRC-32, 0xedb88320) */

/* NXP SDK (vendor) */
extern int      FLASH_Init(flash_config_t *cfg);                                      /* 0x11c4 */
extern int      FLASH_Program(flash_config_t *cfg, uint32_t addr, const uint8_t *src, uint32_t len);
extern int      FLASH_Erase(flash_config_t *cfg, uint32_t addr, uint32_t len, uint32_t key);
extern int      FLASH_VerifyErase(flash_config_t *cfg, uint32_t addr, uint32_t len);  /* 0 = blank */
extern int      FLASH_Read(flash_config_t *cfg, uint32_t addr, uint8_t *dst, uint32_t len);
extern uint32_t CLOCK_GetCoreSysClkFreq(void);                                        /* 0x1128 */
extern void    *vm_memset(void *dst, int c, size_t n);                                /* 0x443c */
extern void    *vm_memcpy(void *dst, const void *src, size_t n);                      /* 0x4422 */

#define SLOT_BASE       0x8000u
#define SLOT_SIZE       0x7400u
#define PAGE            512u
#define FLASH_MAX_HZ    100000000u            /* 0x05f5e100 */
#define ERASE_KEY       0x6b65666cu           /* "kefl" */

/* -------------------------------------------------------------------------
 * flash_cache_invalidate  --  0x1ab4
 * ------------------------------------------------------------------------- */
void flash_cache_invalidate(void)
{
    vm_memset(g_cache_buf, 0xff, PAGE);
    g_cache_page = 0xffff;
    g_cache_region = 5;
}

/* -------------------------------------------------------------------------
 * flash_init_once  --  0x1ae0
 * ------------------------------------------------------------------------- */
void flash_init_once(void)
{
    if (g_flash_cfg.PFlashPageSize != 0)
        return;
    if (FLASH_Init(&g_flash_cfg) == 0)
        flash_cache_invalidate();
}

/* Staged/running-image slot geometry (same layout as od_framework.c). */
struct sys_image_info {
    uint32_t sector;       /* +0 (= PFlashPageSize) */
    uint32_t page_size;    /* +4 (= PFlashPageSize) */
    uint32_t size;         /* +8 region size */
    uint32_t base;         /* +c region base */
};

/* -------------------------------------------------------------------------
 * sys_image_info  --  0x1afc
 *   Geometry of flash region `slot` (0 boot, 1 app, 2 staged). Always 0.
 * ------------------------------------------------------------------------- */
int sys_image_info(int slot, struct sys_image_info *out)
{
    uint32_t pg;

    flash_init_once();
    pg = g_flash_cfg.PFlashPageSize;
    out->sector = pg;
    out->page_size = pg;
    out->size = g_flash_regions[slot][1];
    out->base = g_flash_regions[slot][0];
    return 0;
}

/* -------------------------------------------------------------------------
 * fw_trailer_get  --  0x1b2c
 *   *out = address of the 40-B trailer at the end of region 0; -22 unless it
 *   starts with "VMFW", -14 if the geometry lookup fails.
 * ------------------------------------------------------------------------- */
#define VMFW_MAGIC      0x57464d56u           /* "VMFW" */

int fw_trailer_get(const uint32_t **out)
{
    struct sys_image_info s;
    const uint32_t *t;

    if (sys_image_info(0, &s) != 0)
        return -14;
    t = (const uint32_t *)(uintptr_t)(s.base + s.size - 0x28u);
    *out = t;
    return (*t != VMFW_MAGIC) ? -22 : 0;
}

/* -------------------------------------------------------------------------
 * flash_cache_flush  --  0x20b0
 *   Program the cached page (if any) and invalidate the cache. Refused above
 *   100 MHz core clock.
 * ------------------------------------------------------------------------- */
int flash_cache_flush(void)
{
    uint32_t page = g_cache_page;
    uint8_t  region = g_cache_region;
    uint32_t addr;
    int rc;

    if (page == 0xffff || region == 5)
        return 0;

    addr = g_flash_regions[region][0] + (page << 9);
    if (CLOCK_GetCoreSysClkFreq() > FLASH_MAX_HZ) {
        flash_cache_invalidate();
        return -14;
    }
    rc = FLASH_Program(&g_flash_cfg, addr, g_cache_buf, PAGE);
    flash_cache_invalidate();
    return (rc != 0) ? -14 : 0;
}

/* -------------------------------------------------------------------------
 * flash_page_write  --  0x2138   (slot-relative offset)
 *   Write-only cache: on a page change the old page is flushed but the new
 *   page is NOT read back, so callers must write whole erased pages in order
 *   (as the OTA path does).
 * ------------------------------------------------------------------------- */
int flash_page_write(uint32_t off, const void *src, uint32_t len)
{
    uint32_t page = off >> 9;

    flash_init_once();
    if (len > PAGE || off + len > SLOT_SIZE)
        return -22;

    if (g_cache_page != page || g_cache_region != 2) {
        if (flash_cache_flush() != 0)
            return -14;
        g_cache_page = page;
        g_cache_region = 2;
    }
    vm_memcpy(&g_cache_buf[off & 0x1ffu], src, len);
    return 0;
}

/* -------------------------------------------------------------------------
 * image_read  --  0x21e4   (slot-relative); a blank range reads as 0xff
 * ------------------------------------------------------------------------- */
int image_read(uint32_t off, void *dst, uint32_t len)
{
    uint32_t addr;

    flash_init_once();
    if (off + len > SLOT_SIZE)
        return -22;
    if (flash_cache_flush() != 0)
        return -14;

    addr = off + SLOT_BASE;
    if (FLASH_VerifyErase(&g_flash_cfg, addr, len) == 0) {
        vm_memset(dst, 0xff, len);
        return 0;
    }
    return (FLASH_Read(&g_flash_cfg, addr, (uint8_t *)dst, len) != 0) ? -14 : 0;
}

/* -------------------------------------------------------------------------
 * image_crc32  --  0x22f4   (standard CRC-32, nibble table, 64-B chunks)
 *   *crc carries the running value (start with 0). -22 on a read error.
 * ------------------------------------------------------------------------- */
int image_crc32(uint32_t off, uint32_t len, uint32_t *crc)
{
    uint8_t buf[64];

    while (len != 0) {
        uint32_t n = (len >= 64) ? 64 : len;
        uint32_t c, i;

        if (image_read(off, buf, n) != 0)
            return -22;
        c = ~*crc;
        for (i = 0; i != n; i++) {
            uint8_t b = buf[i];
            c = g_crc_nibble[(b ^ c) & 0xfu] ^ (c >> 4);
            c = g_crc_nibble[((b >> 4) ^ c) & 0xfu] ^ (c >> 4);
        }
        *crc = ~c;
        len -= n;
        off += n;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * flash_erase  --  0x2514   (slot-relative)
 *   Skips the erase when the range is already blank; NOTE the OEM checks
 *   PFlashSectorSize bytes from the start (not `len`).
 * ------------------------------------------------------------------------- */
int flash_erase(uint32_t off, uint32_t len)
{
    uint32_t addr;

    flash_init_once();
    if (off + len > SLOT_SIZE)
        return -22;
    if (flash_cache_flush() != 0)
        return -14;

    addr = off + SLOT_BASE;
    if (FLASH_VerifyErase(&g_flash_cfg, addr, g_flash_cfg.PFlashSectorSize) == 0)
        return 0;
    if (CLOCK_GetCoreSysClkFreq() > FLASH_MAX_HZ)
        return -14;
    return (FLASH_Erase(&g_flash_cfg, addr, len, ERASE_KEY) != 0) ? -14 : 0;
}
