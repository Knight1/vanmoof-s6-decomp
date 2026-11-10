/*
 * sensor.c  --  VanMoof S6 "motor_sensor" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * motor_sensor-specific application layer. The vm CAN/OD core (can_od_rx_dispatch,
 * can_isr, can_frame_encode) is the shared LPC-trio framework (see frontlight
 * can_od.c) and is an extern here. This TU holds:
 *
 *   od_read_hw_id          @ 0x0f9c  OD 01008900 read: reply u32 0x20240627
 *   temp_adc_isr           @ 0x0f20  ADC0 IRQ (IRQ22): NTC sample -> deg C -> cb
 *   od_send_if_active      @ 0x16b8  publish an OD object if its mode == 2
 *   temp_report            @ 0x16d8  temperature cb: publish OD 010003a1 (1 B)
 *   wheel_timeout_cb       @ 0x16f4  CTIMER0 timeout: publish speed {0, 2500}
 *   odometer_find_slot     @ 0x1620  first programmed page of the 6-page ring
 *   odometer_load          @ 0x1bc4  read + magic-check the current ring page
 *   odometer_save          @ 0x1c0c  write count to the next ring page, erase old
 *   od_write_odometer_save @ 0x1ca0  OD 010004a1 write: persist pulse count now
 *   wheel_pulse_cb         @ 0x1cac  CTIMER0 pulse: speed/period + distance
 *
 * Addresses are link addresses (Ghidra image base 0xC00; file offset = addr - 0xC00).
 *
 * OD objects published (node byte 0xa1; records in the flash OD table @0x5090):
 *   010001a1  4 B  { u16 speed, u16 period/100 }      (record @0x5228)
 *   010002a1  4 B  u32 distance                       (record @0x51f8)
 *   010003a1  1 B  s8  motor temperature, deg C       (record @0x5240)
 *
 * Behaviour-oriented reconstruction from the Ghidra decompile, cross-checked
 * against the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg {
    uint32_t id;      /* +0x00 OD id (e.g. 0x010003a1)                    */
    uint8_t  mode;    /* +0x04 2 = notify/publish                         */
};

/* ---- shared vm CAN/OD core (frontlight can_od.c) ------------------------- */
extern int can_frame_encode(struct od_slot *slots, const struct od_reg *reg,
                            uint8_t *addr, int base, unsigned total);  /* 0x48ac */

/* ---- vendor / framework externs ------------------------------------------ */
/* NXP IAP flash wrappers over the flash context @0x200002e8. */
extern int  flash_verify_erase(void *ctx, uint32_t addr, uint32_t len);       /* 0x1158 (0 = blank) */
extern int  flash_read(void *ctx, uint32_t addr, void *dst, uint32_t len);    /* 0x1114 */
extern int  flash_program_page(uint32_t addr, const void *buf);               /* 0x185c */
extern int  flash_erase(void *ctx, uint32_t addr, uint32_t len);              /* 0x1808 */
extern void *mem_set(void *dst, int c, size_t n);                             /* 0x4d1e */
extern int  mem_cmp(const void *a, const void *b, size_t n);                  /* 0x4cfa */

extern uint8_t g_flash_ctx[];                  /* 0x200002e8 */
extern struct od_slot g_can_slots;             /* 0x20000370 (DAT_000016d4) */
extern void (*g_temp_cb)(int8_t deg_c);        /* 0x200002a4, = temp_report (set in main) */

/* OD records (flash, link addresses) */
extern const struct od_reg od_rec_speed;       /* 0x5228: 010001a1 */
extern const struct od_reg od_rec_distance;    /* 0x51f8: 010002a1 */
extern const struct od_reg od_rec_temp;        /* 0x5240: 010003a1 */

/* ---- MMIO (LPC55xx) ------------------------------------------------------ */
#define ADC0_RESFIFO0   (*(volatile uint32_t *)0x400a0300u)
#define CTIMER0_TCR     (*(volatile uint32_t *)0x40008004u)
#define CTIMER0_TC      (*(volatile uint32_t *)0x40008008u)
#define CTIMER0_MR0     (*(volatile uint32_t *)0x40008018u)

/* -------------------------------------------------------------------------
 * od_read_hw_id  --  0x0f9c
 *   OD 01008900 (read): reply the 4-byte constant 0x20240627 (date-coded id).
 * ------------------------------------------------------------------------- */
void od_read_hw_id(struct od_slot *slots, const struct od_reg *reg, uint8_t *addr)
{
    uint32_t id = 0x20240627u;                   /* DAT_00000fb4 */
    can_frame_encode(slots, reg, addr, (int)(uintptr_t)&id, 4);
}

/* -------------------------------------------------------------------------
 * temp_adc_isr  --  0x0f20 (vector IRQ22 = ADC0)
 *   Pop one ADC0 FIFO0 result; if valid (bit31) map it through the descending
 *   166-entry NTC table: the first index whose entry is below the sample gives
 *   deg C = index - 40 (range -40..125); past the table end -> 127. Tail-calls
 *   the temperature callback.
 * ------------------------------------------------------------------------- */
static const uint16_t ntc_table[166] = {       /* 0x4e18 */
    63992, 63878, 63757, 63629, 63493, 63348, 63196, 63034, 62863, 62683, 62493, 62292,
    62080, 61858, 61624, 61378, 61120, 60849, 60566, 60269, 59959, 59635, 59297, 58944,
    58577, 58195, 57797, 57385, 56957, 56514, 56055, 55581, 55091, 54586, 54066, 53530,
    52979, 52414, 51833, 51239, 50631, 50010, 49375, 48729, 48070, 47400, 46719, 46029,
    45329, 44620, 43904, 43180, 42450, 41715, 40975, 40231, 39485, 38736, 37986, 37235,
    36485, 35736, 34989, 34244, 33504, 32767, 32035, 31309, 30589, 29876, 29171, 28473,
    27784, 27104, 26433, 25772, 25121, 24480, 23851, 23232, 22624, 22028, 21444, 20871,
    20310, 19760, 19223, 18698, 18184, 17683, 17193, 16715, 16249, 15794, 15351, 14919,
    14498, 14088, 13689, 13301, 12924, 12556, 12199, 11852, 11515, 11187, 10868, 10558,
    10258, 9966, 9683, 9408, 9140, 8881, 8630, 8386, 8149, 7919, 7696, 7480,
    7271, 7067, 6870, 6679, 6493, 6313, 6139, 5969, 5805, 5646, 5492, 5342,
    5197, 5056, 4919, 4787, 4658, 4534, 4413, 4296, 4182, 4072, 3965, 3861,
    3760, 3662, 3567, 3475, 3386, 3299, 3215, 3133, 3054, 2977, 2902, 2829,
    2759, 2690, 2623, 2559, 2496, 2435, 2376, 2318, 2262, 2208,
};

void temp_adc_isr(void)
{
    int32_t res = (int32_t)ADC0_RESFIFO0;
    int i;

    if (res >= 0)                                /* bit31 VALID clear */
        return;

    for (i = 0; i != 166; i++) {
        if ((uint16_t)res > ntc_table[i]) {
            g_temp_cb((int8_t)(i - 40));
            return;
        }
    }
    g_temp_cb(127);
}

/* -------------------------------------------------------------------------
 * od_send_if_active  --  0x16b8
 *   Publish `len` bytes of `data` on OD object `reg` if it is a notify object.
 * ------------------------------------------------------------------------- */
void od_send_if_active(const struct od_reg *reg, void *data, unsigned len)
{
    if (reg->mode == 2)
        can_frame_encode(&g_can_slots, reg, 0, (int)(uintptr_t)data, len);
}

/* -------------------------------------------------------------------------
 * temp_report  --  0x16d8
 *   Temperature callback: publish the 1-byte reading on OD 010003a1.
 * ------------------------------------------------------------------------- */
void temp_report(int8_t deg_c)
{
    int8_t v = deg_c;
    od_send_if_active(&od_rec_temp, &v, 1);
}

/* ---- wheel pulse state (0x20000324) -------------------------------------- */
struct wheel_state {
    uint32_t pulses;     /* +0 total pulse count (persisted as the odometer) */
    uint32_t scale;      /* +4 191 (variant 'A'/'V') or 211, set in main      */
};
extern struct wheel_state g_wheel;   /* 0x20000324 */
extern uint8_t g_wheel_armed;        /* 0x20000d28 */

/* -------------------------------------------------------------------------
 * wheel_timeout_cb  --  0x16f4 (CTIMER0 match callback, .data init @0x506c)
 *   No pulse within the window: reset the counter, set the max window
 *   (MR0 = 249999), disarm, and publish speed {0, 2500}.
 * ------------------------------------------------------------------------- */
void wheel_timeout_cb(void)
{
    union { uint16_t h[2]; uint32_t w; } msg;

    CTIMER0_TCR |= 2u;                           /* counter reset */
    CTIMER0_TCR &= ~2u;
    CTIMER0_MR0 = 0x3d08fu;
    if (g_wheel_armed != 0)
        g_wheel_armed = 0;

    msg.w = 0x09c40000u;                         /* {speed 0, period/100 2500} */
    od_send_if_active(&od_rec_speed, &msg, 4);
}

/* -------------------------------------------------------------------------
 * odometer_find_slot  --  0x1620
 *   Ring of 6 x 512-B flash pages at 0xF400..0xFE00 (pages 0x7a..0x7f). The
 *   current slot is the first page that is not blank; -2 if all are erased.
 * ------------------------------------------------------------------------- */
int odometer_find_slot(void)
{
    int i;

    for (i = 0; i != 6; i++) {
        if (flash_verify_erase(g_flash_ctx, 0xf400u + ((uint32_t)i << 9), 0x200) != 0)
            return i;
    }
    return -2;
}

/* -------------------------------------------------------------------------
 * odometer_load  --  0x1bc4
 *   Read the 12-B head of the current ring page; accept it if it starts with
 *   the 6-B magic "VMKYS\0" and return the u32 at +8.
 * ------------------------------------------------------------------------- */
static const char odo_magic[6] = { 'V', 'M', 'K', 'Y', 'S', 0 };   /* 0x4f6e */

int odometer_load(uint32_t *out)
{
    uint32_t buf[3];
    int slot = odometer_find_slot();

    if (slot < 0)
        return -2;
    if (flash_read(g_flash_ctx, (uint32_t)(slot + 0x7a) << 9, buf, 12) != 0)
        return -0xe;
    if (mem_cmp(odo_magic, buf, 6) != 0)
        return -2;
    *out = buf[2];
    return 0;
}

/* -------------------------------------------------------------------------
 * odometer_save  --  0x1c0c
 *   Persist `count` if it differs from the stored value. The page is
 *   {7-B header "VMKYS\0\x02" (0x5057), pad, u32 count @+8, zero fill}.
 *   No valid slot -> program page 0x7a (0xF400) and return its status.
 *   Otherwise program slot (cur+1)%6, then erase the old slot (-14 on failure).
 * ------------------------------------------------------------------------- */
extern const uint8_t odo_header[7];          /* 0x5057: 'V','M','K','Y','S',0,2 */

int odometer_save(uint32_t count)
{
    uint32_t stored;
    uint8_t  page[0x200];
    int      cur, rc;

    if (odometer_load(&stored) != 0)
        stored = 0;
    if (stored == count)
        return 0;

    mem_set(page, 0, sizeof page);
    *(uint32_t *)&page[0] = *(const uint32_t *)&odo_header[0];
    *(uint16_t *)&page[4] = *(const uint16_t *)&odo_header[4];
    page[6]               = odo_header[6];
    *(uint32_t *)&page[8] = count;

    cur = odometer_find_slot();
    if (cur < 0)
        return flash_program_page(0xf400u, page);

    rc = flash_program_page((uint32_t)(((cur + 1) % 6) + 0x7a) << 9, page);
    if (rc != 0)
        return rc;

    if (flash_erase(g_flash_ctx, (uint32_t)(cur + 0x7a) << 9, 0x200) != 0)
        return -0xe;
    return 0;
}

/* -------------------------------------------------------------------------
 * od_write_odometer_save  --  0x1ca0
 *   OD 010004a1 (write) handler: persist the current pulse count now.
 *   (Tail call; the request arguments are ignored.)
 * ------------------------------------------------------------------------- */
int od_write_odometer_save(void)
{
    return odometer_save(g_wheel.pulses);
}

/* -------------------------------------------------------------------------
 * wheel_pulse_cb  --  0x1cac (CTIMER0 pulse callback, .data init @0x507c)
 *   One wheel-magnet pulse (6 per revolution). `ticks` = CTIMER0 count since
 *   the previous pulse. The first pulse after a timeout only arms. Then:
 *     window   = min(2*ticks, 250000);  MR0 = window - 1
 *     speed    = (360000000 / (6*ticks)) * scale / 1000
 *     publish  010001a1 { u16 speed, u16 window/100 }
 *     every 30 pulses (5 rev): publish 010002a1 u32 (pulses/6)*scale/100
 *     every 6000 pulses: odometer_save(pulses)
 * ------------------------------------------------------------------------- */
void wheel_pulse_cb(void)
{
    uint32_t ticks = CTIMER0_TC;
    uint32_t window, n;
    union { uint16_t h[2]; uint32_t w; } msg;

    CTIMER0_TCR |= 2u;                           /* counter reset */
    CTIMER0_TCR &= ~2u;

    if (ticks == 0)
        return;
    if (g_wheel_armed == 0) {
        g_wheel_armed = 1;
        return;
    }

    window = ticks * 2u;
    if (window >= 0x3d090u)
        window = 0x3d090u;
    CTIMER0_MR0 = window - 1u;

    msg.h[1] = (uint16_t)(window / 100u);
    msg.h[0] = (uint16_t)((0x15752a00u / (ticks * 6u)) * g_wheel.scale / 1000u);
    od_send_if_active(&od_rec_speed, &msg, 4);

    n = ++g_wheel.pulses;
    if (n % 30u == 0) {
        msg.w = (n / 6u) * g_wheel.scale / 100u;
        od_send_if_active(&od_rec_distance, &msg, 4);
    }

    if (g_wheel.pulses % 6000u == 0)
        odometer_save(g_wheel.pulses);
}
