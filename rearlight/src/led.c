/*
 * led.c  --  VanMoof S6 "rearlight" ECU (NXP LPC55xx-class Cortex-M, VMFW)
 *
 * SHARED LPC-trio core: byte-for-byte the same reconstruction as
 * frontlight/src/led.c (led_spi_transfer prologue is byte-identical; rearlight
 * OEM address 0x09e4 vs frontlight 0xbcc). Sonnet-verified in the frontlight
 * copy (0 findings, incl. the critical TX-frame-selection logic).
 *
 * The LED-driver output path: a full-duplex SPI transaction over the LPC55xx
 * Flexcomm SPI (base 0x40089000; FIFOCFG@0xe00, FIFOSTAT@0xe04, FIFOWR@0xe20,
 * FIFORD@0xe30). It builds a 4-byte command header from the call args, streams
 * it plus per-channel pad bytes out of the TX FIFO while draining the RX FIFO
 * into a receive buffer, and asserts EOT + the channel's SSEL on the final frame.
 *
 *   led_spi_transfer @ 0x0bcc
 *   led_active_index @ 0x3546 (returns the active LED channel index = 2)
 *
 * The Flexcomm SPI FIFO register semantics are the standard LPC55xx IP; the
 * command-header format and the per-channel frame config are VanMoof's LED
 * protocol. Behaviour-oriented reconstruction from the Ghidra decompile
 * (image base 0x0). MMIO is reproduced verbatim. Not byte-identical.
 *
 * NOTE (to verify): this routine is dense MMIO with a dual TX/RX frame loop and
 * variable frame width (8- vs 16-bit); the frame-count / RX-store bookkeeping is
 * transcribed close to the decompiler's control flow and should be checked
 * against disassembly.
 */

#include <stdint.h>
#include <stddef.h>

/* Flexcomm SPI FIFO registers (LPC55xx), base = g_spi_base (0x40089000). */
extern uint32_t g_spi_base;   /* DAT_00000cdc */
#define SPI(off)  (*(volatile uint32_t *)(g_spi_base + (off)))
#define FIFOCFG   0xe00
#define FIFOSTAT  0xe04       /* 0x20 = TXNOTFULL, 0x40 = RXNOTEMPTY, 0x10 = TXEMPTY */
#define FIFOWR    0xe20       /* data | LEN[27:24] | TXSSEL[19:16] | EOT(0x100000) */
#define FIFORD    0xe30

extern unsigned led_active_index(void);   /* 0x3546 (=2) */
/* per-channel frame config: [i*2]=frame width flag (<9 = 8-bit else 16-bit),
 * [i*2+1]=SSEL line number. */
extern uint8_t g_led_frame_cfg[];         /* DAT_00000ce0 */
/* per-channel pad/fill byte streamed after the header. */
extern uint8_t g_led_pad[];               /* DAT_00000ce4 */

/* -------------------------------------------------------------------------
 * led_spi_transfer  --  0x0bcc
 *
 * cmd/sub/arg → 4-byte header {cmd<<1, sub, arg>>16 (u16)}. Streams the header
 * then pad bytes over SPI while receiving into rxbuf; EOT + SSEL deassert on the
 * last frame.
 * ------------------------------------------------------------------------- */
void led_spi_transfer(uint8_t cmd, uint8_t sub, uint32_t rx_init, uint32_t arg)
{
    unsigned idx   = led_active_index();
    uint8_t  width = g_led_frame_cfg[idx * 2];          /* <9 => 8-bit frames */
    uint8_t  ssel  = g_led_frame_cfg[idx * 2 + 1];
    uint32_t rxcfg = SPI(FIFOCFG);                       /* holds the RX depth field */

    /* 4-byte TX command header, little-endian: {cmd<<1, sub, (arg>>16) u16} */
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(cmd << 1);
    hdr[1] = sub;
    hdr[2] = (uint8_t)(arg >> 16);
    hdr[3] = (uint8_t)(arg >> 24);

    /* rx receive buffer (rx_init seeds the first word, as the OEM does). */
    uint8_t  rxbuf[8];
    *(uint32_t *)rxbuf = rx_init;

    int      hdr_rem = 2;                     /* header units still to send */
    unsigned rx_rem  = 2;                     /* words still to receive     */
    unsigned inflight = 0;
    uint8_t *rxp = rxbuf;
    uint8_t *hp  = hdr;

    /* base FIFOWR control word: SSEL-deassert mask (all high except this line) +
     * frame length in the LEN field. */
    uint32_t ctl = (~(1u << ((ssel + 0x10) & 0xff)) & 0xf0000u)
                 | ((uint32_t)(width & 0xf) << 0x18);

    SPI(FIFOCFG)  |= 0x30000;                 /* enable TX/RX FIFOs */
    SPI(FIFOSTAT) |= 3;                        /* clear TX/RX error flags */

    for (;;) {
        /* completion: nothing left to send or receive, wait TX empty, done. */
        if (rx_rem == 0 && inflight == 0 && hdr_rem == 0) {
            while ((int)(SPI(FIFOSTAT) << 0x1b) >= 0)   /* wait TXEMPTY (bit4) */
                ;
            return;
        }

        /* drain one RX frame if available */
        if ((SPI(FIFOSTAT) & 0x40) != 0) {              /* RXNOTEMPTY */
            uint32_t rx = SPI(FIFORD);
            if (rx_rem != 0) {
                rxp[0] = (uint8_t)rx;
                if (width < 9) {
                    rxp += 1;
                    rx_rem -= 1;
                } else {
                    rxp[1] = (uint8_t)(rx >> 8);
                    rxp += 2;
                    rx_rem -= 2;
                }
            }
            inflight--;
        }

        /* only feed the TX FIFO when it can take a frame and we are under the
         * RX-FIFO depth window (rxcfg>>1 & 0x18). */
        if ((SPI(FIFOSTAT) & 0x20) == 0 || inflight >= ((rxcfg >> 1) & 0x18))
            continue;

        {
            uint32_t data;
            if (hdr_rem != 0) {
                /* still sending the header */
                if (width < 9) {
                    hdr_rem -= 1;
                    data = *hp;
                    hp += 1;
                } else {
                    hdr_rem -= 2;
                    data = *(uint16_t *)hp;
                    hp += 2;
                }
                if (hdr_rem == 0)
                    ctl |= 0x100000;            /* EOT on the final header frame */
            } else {
                /* header done: stream pad bytes until the frame count is reached */
                unsigned need = (inflight + 1) << (width >> 3);
                if (need > rx_rem)
                    continue;                    /* enough queued */
                data = (uint32_t)((g_led_pad[idx] << 8) | g_led_pad[idx]);
                if (need == rx_rem)
                    ctl |= 0x100000;             /* EOT on the last pad frame */
            }
            SPI(FIFOWR) = data | ctl;
            inflight++;
        }
    }
}
