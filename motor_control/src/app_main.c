/*
 * app_main.c  --  VanMoof S6 "motor_control" ECU (STM32G4 Cortex-M4F, MCUboot)
 *
 * Application tail of main (0x8008b42 .. end, never returns). Everything in
 * main before it is CubeMX/HAL peripheral init, MCSDK setup and the motor
 * gate-driver register configuration (vendor-shaped, not reconstructed).
 *
 *   mc_app_run   @ 0x8008b42   watchdog start, TIM2 event-timer base,
 *                              periodic jobs, OD request retry loop
 *
 * Scheduling: TIM2 counts microseconds (170 MHz / (169+1)); the event-timer
 * service (evt_timer.c) runs mc_periodic_1s every 1 s (heartbeat, status,
 * IWDG refresh) and mc_publish_telemetry every 100 ms. The IWDG is only
 * refreshed from the 1 s job, so a stalled timer chain resets the ECU.
 *
 * Addresses are link addresses (Ghidra image base 0x08002000). Reconstructed
 * from the disassembly.
 */

#include <stdint.h>
#include <stddef.h>

struct od_slot;
struct od_reg;
struct evt_timer;
typedef void (*evt_cb_t)(struct evt_timer *t);

extern void evt_timer_arm(struct evt_timer *t, uint32_t ticks, evt_cb_t cb, int periodic); /* 0x80056c0 */
extern void mc_periodic_1s(void);                                  /* 0x8006398 */
extern void mc_publish_telemetry(void);                            /* 0x80066d0 */
extern int  can_frame_encode(struct od_slot *slots, struct od_reg *reg,
                             uint8_t *addr, int base, unsigned total);   /* 0x800ab60 */
extern void od_slot_finish(void *slot_obj, int rc);                /* 0x800556c */

extern struct evt_timer g_tmr_periodic_1s;   /* 0x20000960 */
extern struct evt_timer g_tmr_telemetry;     /* 0x20000948 */
extern volatile uint32_t g_ms_now;           /* 0x200009d8 */
extern uint8_t g_can_slots_mem[];            /* 0x20000a14 (struct od_slot[10]) */
#define g_can_slots ((struct od_slot *)g_can_slots_mem)

#define REG32(a)        (*(volatile uint32_t *)(a))
#define RCC_CSR         REG32(0x40021094u)
#define RCC_APB1ENR1    REG32(0x40021058u)
#define IWDG_KR         REG32(0x40003000u)
#define IWDG_PR         REG32(0x40003004u)
#define IWDG_RLR        REG32(0x40003008u)
#define IWDG_SR         REG32(0x4000300cu)
#define IWDG_WINR       REG32(0x40003010u)
#define TIM2_CR1        REG32(0x40000000u)
#define TIM2_DIER       REG32(0x4000000cu)
#define TIM2_SR         REG32(0x40000010u)
#define TIM2_PSC        REG32(0x40000028u)
#define NVIC_ISER0      REG32(0xe000e100u)
#define NVIC_IPR_TIM2   (*(volatile uint8_t *)0xe000e41cu)   /* IRQ28 */

struct od_retry {                    /* = &slot.obj, stride 0x5c */
    struct od_reg *obj;
    uint8_t  addr[3];
    uint8_t  pad;
    uint32_t total;
    uint8_t  buf[0x40];
    uint8_t  retries;
    uint8_t  pad2[3];
    uint32_t deadline;
};
#define OD_REG_FLAG3(r)   (((uint8_t *)(r))[3])
#define OD_REG_TIMEOUT(r) (((uint32_t *)(r))[3])

/* -------------------------------------------------------------------------
 * mc_app_run  --  0x8008b42
 * ------------------------------------------------------------------------- */
void mc_app_run(void)
{
    /* LSI on, then start and configure the independent watchdog */
    RCC_CSR |= 1u;                               /* LSION */
    while ((RCC_CSR & 2u) == 0)                  /* LSIRDY */
        ;
    IWDG_KR = 0xcccc;                            /* start   */
    IWDG_KR = 0x5555;                            /* unlock  */
    IWDG_PR = 3;                                 /* /32     */
    IWDG_RLR = 0x5b7;
    while ((IWDG_SR & 7u) != 0)
        ;
    IWDG_WINR = 0xfff;                           /* no window (also reloads) */

    mc_periodic_1s();

    /* TIM2: 1 us tick, down-counting one-pulse event-timer base, update IRQ */
    RCC_APB1ENR1 |= 1u;                          /* TIM2EN */
    TIM2_PSC = 169;
    TIM2_CR1 |= 0x10u;                           /* DIR = down */
    TIM2_CR1 |= 0x08u;                           /* OPM */
    TIM2_CR1 |= 0x01u;                           /* CEN */
    TIM2_SR &= ~1u;                              /* clear UIF */
    TIM2_DIER |= 1u;                             /* UIE */
    NVIC_IPR_TIM2 = 0xf0;
    NVIC_ISER0 = 1u << 28;

    evt_timer_arm(&g_tmr_periodic_1s, 1000000u, (evt_cb_t)mc_periodic_1s, 1);
    evt_timer_arm(&g_tmr_telemetry,    100000u, (evt_cb_t)mc_publish_telemetry, 1);

    /* OD request retry, forever */
    for (;;) {
        uint32_t now = g_ms_now;
        struct od_retry *r = (struct od_retry *)(g_can_slots_mem + 8);
        int i;

        for (i = 0; i != 10; i++, r = (struct od_retry *)((uint8_t *)r + 0x5c)) {
            int rc;
            if (r->obj == NULL || r->deadline >= now)
                continue;
            if (OD_REG_FLAG3(r->obj) == 0 && r->retries != 0) {
                r->retries--;
                r->deadline = OD_REG_TIMEOUT(r->obj) + now;
                rc = can_frame_encode(g_can_slots, r->obj, r->addr,
                                      (int)(uintptr_t)r->buf, r->total);
                if (rc == 0)
                    continue;
            } else {
                rc = -116;
            }
            od_slot_finish(r, rc);
        }
    }
}
