/* vmtp_can.c — VanMoof transport over CAN: bring-up + TX-complete callback.
 *
 * S6 `ble` (nRF52840). Reconstructed from Ghidra (image base 0xC000):
 *   vmtp_can_init          @ 0x5dddc
 *   vmtp_zephyr_can_tx_done @ 0x5dd4c
 * Behaviour-oriented: the Zephyr CAN driver / k_thread framework is vendor and
 * is modelled as externs (see below). Not byte-identical.
 */
#include "vmtp.h"

/* vmtp module/state object (mod+0x10). Field offsets are OEM. */
#define ST_CAN_DEV(s)    (*(const void **)((s) + 0xb88))
#define ST_RX_THREAD(s)  ((void *)((s) + 0xb90))
#define ST_RX_CB(s)      (*(const void **)((s) + 0xc48))
#define ST_RX_STACK(s)   (*(void **)((s) + 0xc4c))
#define ST_TX_ERRORS(s)  (*(uint32_t *)((s) + 0xc5c))

/* config object (mod+4): { const void *can_dev @0x00; uint8_t bitrate_idx @0x04; } */

/* vendor (Zephyr CAN driver + kernel) — satisfied at link time */
extern const void *can_device_ready(void);                              /* 0x7a4bc */
extern int  can_configure(uint8_t *st, uint8_t bitrate_idx, int mode);  /* 0x79b6e (0 = ok) */
extern void k_thread_create_rx(void *thr, void *stack, unsigned sz,
                               void (*entry)(void *), void *arg,
                               int a, int b, int prio, int c);           /* 0x6399c */
extern void vmtp_rx_thread(void *arg);                                   /* RX work entry (0x5de60) */
extern void thread_name_set(void);                                      /* thunk 0x63d34 */
extern int  vmtp_endpoint_register(const void *dev, const void *rx_cb,
                                   void *ep, int flags, void *arg);      /* 0x4a660 */
extern int  vmtp_endpoint_start(void *ep);                              /* (*ep+8)+4 vtable */

#define CAN_BITRATE_VMTP  0   /* DAT_0005de54 (1 Mbps profile) */
#define VMTP_RX_STACK_SZ  0x1000
#define VMTP_RX_PRIO      5

/* vmtp_can_init @ 0x5dddc — open the CAN device, spawn the RX work thread, and
 * register the VanMoof vm/OD endpoint. Returns 0 on success, negative errno. */
int vmtp_can_init(uint8_t *mod)
{
    uint8_t *cfg = *(uint8_t **)(mod + 4);
    uint8_t *st  = *(uint8_t **)(mod + 0x10);
    const void *dev = *(const void **)cfg;

    ST_CAN_DEV(st) = dev;

    if (can_device_ready() == NULL)
        return -19;                          /* -ENODEV (0xffffffed) */

    if (can_configure(st, cfg[4], CAN_BITRATE_VMTP) != 0) {
        int rc = -5;                         /* -EIO */
        VM_LOG(vmtp_log, "unable to start can device err=%d", rc);
        return rc;
    }

    /* RX work thread (0x1000-byte stack, prio 5) */
    k_thread_create_rx(ST_RX_THREAD(st), ST_RX_STACK(st), VMTP_RX_STACK_SZ,
                       vmtp_rx_thread, st, 0, 0, VMTP_RX_PRIO, 0);
    thread_name_set();

    {
        uint8_t ep[24];
        int rc;
        mem_zero(ep, 0, sizeof ep);
        rc = vmtp_endpoint_register(dev, ST_RX_CB(st), ep, 0, mod);
        if (rc < 0) {
            VM_LOG(vmtp_log, "unable to add filter for can device err=%d", rc);
            return rc;
        }
        rc = vmtp_endpoint_start(ep);
        if (rc == 0)
            return 0;
        VM_LOG(vmtp_log, "unable to initialize VMTP can err=%d", rc);
        return rc;
    }
}

/* vmtp_zephyr_can_tx_done @ 0x5dd4c — CAN TX-complete callback; on a non-zero
 * status it logs and bumps the per-state TX error counter. */
void vmtp_zephyr_can_tx_done(uint8_t *mod, int status)
{
    if (status != 0) {
        uint8_t *st = *(uint8_t **)(mod + 0x10);
        VM_LOG(vmtp_log, "CAN TX ERROR %d", status);
        ST_TX_ERRORS(st)++;
    }
}
