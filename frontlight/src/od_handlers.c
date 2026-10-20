/*
 * od_handlers.c  --  VanMoof S6 "frontlight" ECU (NXP LPC-class Cortex-M, VMFW)
 *
 * Frontlight OD object read-responders. These are registered as the `handler`
 * for specific vm CAN/OD objects; when a read request arrives, the RX dispatcher
 * (can_od_rx_dispatch, can_od.c) calls them with the OD address, and they reply
 * by reading a stored record from the persistent-storage device and emitting it
 * as a CAN/OD response via can_frame_encode.
 *
 *   can_report_publish     @ 0x0900   reply 13 B from a 0x30-B stored record
 *   od_read_blob_responder @ 0x096c   reply 0x10 B from a 0x40-B stored record
 *
 * NOTE: the OD registration table (which OD address maps to which handler) is
 * RAM-resident (g_od_regs @ 0x4678, past the 0x3c70 flash image), populated by an
 * init routine at startup, so the address<->handler wiring is not statically
 * readable from the image. These handlers are the leaf responders.
 *
 * The persistent-storage device + its HAL are vendor/framework. Behaviour-
 * oriented reconstruction from the struct-typed Ghidra decompile (image base 0x0,
 * raw LPC). Not byte-identical.
 */

#include <stdint.h>
#include <stddef.h>

/* od_reg / od_slot are defined in can_od.c; here they are opaque to the handler. */
struct od_slot;
struct od_reg;

/* ---- vm CAN/OD TX (can_od.c) --------------------------------------------- */
extern void can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);   /* 0x33fc */

/* ---- persistent-storage device + HAL (vendor) ---------------------------- */
/* Lazily bring the storage device up (probe + init on first use); 0 = ready,
 * -5 on failure. */
extern int  storage_ensure_ready(void);                                 /* 0x08d0 */
/* Read from the storage device (dev, dst, a, b); 0 on success. Arg semantics are
 * the device-API's (len/offset), kept in OEM order. */
extern int  storage_read(void *dev, void *dst, int a, int b);           /* 0x05f0 */

extern void *g_store_report;   /* DAT_00000968 (record for the 13-B report)   */
extern void *g_store_blob;     /* DAT_000009ac (record for the 0x10-B blob)   */

/* -------------------------------------------------------------------------
 * can_report_publish  --  0x0900
 *
 * OD read-responder: ensure storage is ready, read a 0x30-byte record; if its
 * leading status byte == 1 (record valid), transmit the 13 payload bytes that
 * follow the status byte as the OD response.
 * ------------------------------------------------------------------------- */
void can_report_publish(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    uint8_t  rec[0x30];
    uint8_t  out[13];

    if (storage_ensure_ready() != 0)
        return;
    if (storage_read(g_store_report, rec, 0x30, 0xf) != 0)
        return;
    if (rec[0] != 1)                 /* record status: 1 = valid */
        return;

    for (int i = 0; i < 13; i++)     /* payload = record[1..13] (skip status) */
        out[i] = rec[1 + i];
    can_frame_encode(slots, reg, addr, (int)(uintptr_t)out, 13);
}

/* -------------------------------------------------------------------------
 * od_read_blob_responder  --  0x096c
 *
 * OD read-responder: ensure storage is ready, read a 0x40-byte record, and
 * transmit its first 0x10 bytes as the OD response.
 * ------------------------------------------------------------------------- */
void od_read_blob_responder(struct od_slot *slots, struct od_reg *reg, uint8_t *addr)
{
    uint8_t rec[0x40];

    if (storage_ensure_ready() != 0)
        return;
    if (storage_read(g_store_blob, rec, 0x40, 0x10) != 0)
        return;
    can_frame_encode(slots, reg, addr, (int)(uintptr_t)rec, 0x10);
}
