/*
 * net_monitor.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * Cellular network-status telemetry. A work handler queries the modem for its
 * current registration/operator via `AT%XMONITOR`, parses the operator name and
 * PLMN (MCC/MNC), and publishes the network-status record as event 0x1104.
 *
 * Recovered from an app-in-a-gap (the handler is reached only through the work
 * item registered by net_monitor_init, so the analyzer never disassembled it):
 *   net_monitor_init    @ 0x247fc  (0x1958-B context bring-up + work/cb register)
 *   net_monitor_publish @ 0x2487c  (AT%XMONITOR query -> parse -> publish 0x1104)
 *
 * The AT interface + Zephyr work/k_poll are vendor. Behaviour-oriented
 * reconstruction from Ghidra (image base 0x10000, Cortex-M33); not byte-identical.
 * Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* nrf_modem AT scanf: run `cmd`, parse the reply per `fmt` into the outputs;
 * returns the number of fields matched (<=0 on error / no match).             */
extern int  at_scanf(const char *cmd, const char *fmt, void *o0, void *o1);   /* 0x4b65c */
extern uint16_t buf_checksum(const void *p, unsigned n);                       /* 0x59052 */
extern uint32_t parse_uint  (const void *s, int base, int radix);              /* 0x4f8dc */

/* AEM event bus. */
extern void *evt_publish(int id, const void *payload, unsigned len);           /* 0x515cc */
extern void  evt_send   (void);                                                /* 0x4866c */

/* Network-monitor context (0x1958 B; init'd by net_monitor_init). Fields used
 * by the publisher (OEM byte offsets):
 *   +0x02 u32  MCC  (first 3 PLMN digits)
 *   +0x06 u32  MNC  (last 3 PLMN digits)
 *   +0x14 u16  name checksum (0 until captured -> also the "have data" flag)
 *   +0x16 65 B operator name string (from "%64[^\"]")                          */
extern uint8_t *g_net_ctx;   /* 0x2001ac30 */

/* AT%XMONITOR command + its scanf format (rodata). */
extern const char S_AT_XMONITOR[];   /* 0x5fcb7 "AT%XMONITOR" */
extern const char S_XMONITOR_FMT[];  /* 0x5fc8c "%%XMONITOR: %*u,\"%64[^\"]\",...,\"%6[^\"]\"," */

/* -------------------------------------------------------------------------
 * net_monitor_publish  --  0x2487c
 *
 * If the network name has not been captured yet (ctx+0x14 == 0), query
 * AT%XMONITOR and parse it: store the operator-name checksum, and (when more
 * than the name matched) split the 6-digit PLMN into MCC (ctx+2) and MNC
 * (ctx+6). Always publish the 0x57-byte network-status record as event 0x1104.
 * ------------------------------------------------------------------------- */
void net_monitor_publish(void)
{
    uint8_t *ctx = g_net_ctx;
    uint32_t plmn = 0;      /* "%6[^\"]" capture -> 6 ASCII digits */
    int      matched;

    if (*(uint16_t *)(ctx + 0x14) == 0) {
        matched = at_scanf(S_AT_XMONITOR, S_XMONITOR_FMT, ctx + 0x16, &plmn);
        if (matched > 0) {
            *(uint16_t *)(ctx + 0x14) = buf_checksum(ctx + 0x16, 0x41);
            if (matched != 1) {
                /* PLMN string split: high 3 digits = MCC, low 3 = MNC */
                *(uint32_t *)(ctx + 6) = parse_uint((uint8_t *)&plmn + 3, 0, 10);
                plmn &= 0xffffff;
                *(uint32_t *)(ctx + 2) = parse_uint(&plmn, 0, 10);
            }
        }
    }

    evt_publish(0x1104, ctx, 0x57);
    evt_send();
}
