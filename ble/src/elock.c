/*
 * elock.c  -  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Electronic kick-lock (e-lock / frame-lock) actuator driver and lock-state
 * FSM, reconstructed from the OEM "ble.bin" image (image base 0xC000).
 *
 * Behaviour-oriented clean-room translation.  Vendor/RTOS/SDK helpers are
 * declared extern with their OEM addresses; no vendor code is reconstructed
 * here.  Snake_case OEM function names are preserved and each function is
 * commented with its OEM address.
 *
 * Self-contained: compiles with only <stdint.h> + <stddef.h>.
 *
 * Naming/offset notes
 * -------------------
 * The OEM accesses a flat set of module-global pointers (a mix of RAM state
 * at 0x2000xxxx and const config in flash at 0x080xxxxx) loaded from a
 * literal pool.  We model each such global as a typed extern symbol with a
 * descriptive name; the exact link address is given in a comment.  Where the
 * decompiler reads through a base pointer + index*4 table, we model it as an
 * extern array.  Several helper IDs (event channel ids, OD object ids, audio
 * cue ids) are reproduced verbatim from the decompilation.
 *
 * NOTE: an earlier pass collapsed several distinct OEM DAT_* slots into one
 * extern.  They are now split back out per-role (each with its own OEM
 * address comment) because the decompilation reads/writes them independently.
 */

#include <stdint.h>
#include <stddef.h>
void elock_request_present_init(void);
uint32_t actuator_power_domain_enable(uint32_t which);

/* ------------------------------------------------------------------------- *
 *  Vendor / RTOS / SDK / sibling-module helpers (declared, not defined).
 *  Addresses are OEM image offsets (image base 0xC000 already applied by
 *  Ghidra labels).
 * ------------------------------------------------------------------------- */

/* Application-Event-Manager: allocate an event of (chan,id,size); returns the
 * event buffer (a payload byte at +5 is filled by callers) or NULL. */
extern void *aem_event_alloc(int chan, int id, int sz, int flags); /* FUN_00077cfc @0x77cfc */
/* Submit the most-recently allocated AEM event onto the bus. */
extern int   aem_event_submit(void);                               /* FUN_00055564 @0x55564 */

/* Mutex / critical-section guard around the lock-state globals. */
extern void  elock_lock_acquire(void *mtx, int a, int b, int c);   /* FUN_00063118 @0x63118 */
extern void  elock_lock_release(void *mtx);                        /* FUN_00063208 @0x63208 */

/* Structured trace/log emit (module, msg-id, &args, 0).  Gated by the
 * per-module log-level byte (low 3 bits == verbosity). */
extern void  vm_logf(void *mod, int msg_id, const void *args, int z); /* FUN_000364f0 @0x364f0 */

/* Timer / work scheduling helpers (8.16 / 8000-tick fixed-point deadlines). */
extern void  vm_timer_reschedule(void *t, uint32_t arg, uint32_t ticks, int z); /* FUN_000637f8 @0x637f8 */
extern void  vm_timer_arm(void *t, uint32_t arg, uint32_t ticks, int z);        /* FUN_00063790 @0x63790 */
extern void  vm_timer_kick(void *t, int a, uint32_t ticks, int z);              /* FUN_00063118-family FUN_00063118? */
extern void  vm_work_submit(void *w);                                           /* FUN_0007aad4 @0x7aad4 */
extern int64_t vm_uptime_scaled(void);                                          /* thunk_FUN_00064484 @0x64484 */
extern int64_t vm_scale_ticks(int lo, int hi, int div, int z);                  /* FUN_0001f6a8 @0x1f6a8 */
extern void  vm_yield_pump(void);                                               /* FUN_00063f14 @0x63f14 */

/* Actuator / motor-driver primitives. */
extern int   actuator_fault_check(void);          /* FUN_000319e0 @0x319e0 */
extern int   actuator_busy_check(void);           /* FUN_000319ec @0x319ec */
extern int64_t actuator_drive_query(uint32_t target); /* FUN_00031770 @0x31770 (no-arg and (arg) forms) */
extern int   actuator_pulse(uint32_t profile, int a, int b, int c); /* FUN_0003120c @0x3120c */
extern void  actuator_settle_delay(int ms);       /* FUN_000319f8 @0x319f8 */

/* Power-domain / CAN helpers. */
extern void  can_power_off(int which);            /* can_power_off @ (sibling) */
extern int   power_domain_request(void *dom, void *pstate); /* FUN_0006f146 @0x6f146 */
extern int   power_domain_commit(void *dom);      /* FUN_00036aa4 @0x36aa4 */

/* Object-Dictionary publish helpers. */
extern void  od_set_u8(int obj_id, void *val, int len);          /* FUN_0006c818 @0x6c818 */
extern void  od_notify(void *node, void *val, int len);          /* FUN_00038234 @0x38234 */
extern void  od_event_push(void *q, int id, int v);              /* FUN_0006efd8 @0x6efd8 */

/* Audio cue playback (cue-id, channel 0xe, repeat). */
extern void  audio_play(void *cue, int chan, int rep);           /* audio_play @ (sibling) */

/* AEM message-pump entry used by elock_request_present_init / _unlock_complete. */
extern void  aem_send(uint32_t handler, void *a, int b, void *c, int d, int e, int f); /* FUN_00079bb2 @0x79bb2 */

/* Backup/secondary unlock attempt count (config). */
extern int   backup_unlock_is_active(void);       /* backup_unlock_is_active @ (sibling) */

/* One-time hardware/peripheral init kicked on first FSM entry. */
extern void  elock_hw_init(void);                 /* thunk_FUN_00060e80 @0x60e80 */

/* Re-entry into the FSM after a committed transition. */
extern void  elock_fsm_transition_done(void);     /* FUN_00027144 @0x27144 */

/* ------------------------------------------------------------------------- *
 *  Module globals (link addresses in comments).  RAM state vs. flash config.
 * ------------------------------------------------------------------------- */

/* lock-state mutex object */
extern void     *g_elock_mtx;            /* DAT_00027198 */

/* current lock state byte / requested lock state byte */
extern uint8_t   g_lock_state_cur;       /* DAT_00027418 / DAT_000271c8 / DAT_00027364 */
extern uint8_t   g_lock_state_req;       /* DAT_0002741c / DAT_000271cc / DAT_00027368 */

/* per-state callback table; each entry is 0x34 bytes, +0x30 holds a fn ptr */
extern uint8_t   g_state_cb_table[];     /* DAT_00027420 / DAT_0002737c */

/* unlock-in-progress flag (drive pulse latched) */
extern char      g_unlock_active;        /* DAT_00027ab0 */
/* "stuck"/retry latch used in state 3 handling */
extern char      g_retry_latched;        /* DAT_00027acc */
/* unlock-complete pending flag */
extern char      g_unlock_complete_pending; /* DAT_00027b74 */

/* present-sensor (elock_is_present): cached present byte + override byte */
extern char      g_present_cached;       /* DAT_00028abc */
extern char      g_present_override;     /* DAT_00028ac0 */

/* present-sensor sentinel byte read by elock_touch_unlock_request (distinct
 * from g_present_cached used by elock_is_present). */
extern int8_t    g_touch_present;        /* DAT_00028448 */

/* retry / step counters */
extern int32_t   g_step_ctr;             /* DAT_00027ab4 */
extern int32_t   g_backup_attempt;       /* DAT_000277b4 */
extern int32_t   g_backup_scale;         /* DAT_000277b8 */
extern int32_t   g_unlock_count;         /* DAT_00027728 */
extern int32_t   g_drive_phase;          /* DAT_00027ae4 */
extern int32_t   g_drive_phase_b;        /* DAT_00027730 */
extern uint32_t g_drive_ts[2];          /* DAT_000288dc (2-word OD timestamp) */

/* timer/work handles + config blobs referenced by id (opaque) */
extern void     *g_t_step;               /* DAT_00027ab8 */
extern void     *g_t_unlock;             /* DAT_00027ad0 */
extern void     *g_t_retry;              /* DAT_00027adc */
extern void     *g_t_retry_b;            /* DAT_0002773c */
extern void     *g_t_backup;             /* DAT_000277c4 */
extern void     *g_t_drive_pulse;        /* DAT_00027848 (elock_drive_unlock_pulse timer) */
extern void     *g_t_complete_followup;  /* DAT_00028b08 (elock_unlock_complete follow-up timer) */
extern void     *g_w_unlock;             /* DAT_0002772c */
extern void     *g_actuator_pd;          /* DAT_0002addc */
extern uint8_t   g_pd_mask;              /* DAT_0002add4 */
extern void     *g_w_pd;                 /* DAT_0002add8 */

/* report value byte for OD object 0x160 */
extern uint8_t   g_report_val;           /* DAT_00028784 */

/* backup-unlock profile table (DAT_000277bc); indexed by the clamped attempt
 * count [0,2]. */
extern uint32_t  g_backup_profile_table[]; /* DAT_000277bc */

/* unlock-cycle-complete latch read in elock_unlock_complete */
extern char      g_complete_relatch;     /* DAT_00028b04 */

/* drive-profile / audio cue config slots (distinct OEM DAT_* per call site). */
extern uint32_t  g_profile_unlock;       /* DAT_00027840 (drive_unlock_pulse profile) */
extern void     *g_cue_unlock;           /* DAT_00027844 (drive_unlock_pulse cue) */
extern uint32_t  g_profile_step_a;       /* DAT_00027ae0 (step <3 first pulse) */
extern uint32_t  g_profile_step_b;       /* DAT_00027aec (step <3 second pulse) */
extern void     *g_cue_step;             /* DAT_00027ae8 (step <3 cue) */
extern uint32_t  g_profile_stuck;        /* DAT_00027ad4 (step stuck pulse) */
extern void     *g_cue_stuck;            /* DAT_00027ad8 (step stuck cue) */
extern void     *g_cue_backup;           /* DAT_000277c0 (step backup cue) */
extern uint32_t  g_profile_retail;       /* DAT_00027734 (mid-unlock tail pulse) */
extern void     *g_cue_retail;           /* DAT_00027738 (mid-unlock tail cue) */

/* OD/log config blobs */
extern uint8_t   g_log_mod_a;            /* DAT_00027abc (low3 = verbosity) */
extern uint8_t   g_log_mod_b;            /* DAT_00027408 / DAT_00027360 */
extern uint8_t   g_log_mod_c;            /* DAT_0002844c */
extern int32_t   g_max_retries;          /* DAT_00027ac4 (compared < 3) */
extern void     *g_log_arg_2;            /* DAT_00027ac0 (od_event_push arg) */
extern void     *g_log_arg_3;            /* DAT_00027ac8 (od_event_push arg) */

/* present-query AEM routing: dispatch object (handler at +0x10) and node arg
 * are two distinct OEM pointer slots. */
extern void     *g_od_present_dispatch;  /* DAT_00028758 */
extern void     *g_od_present_node;      /* DAT_0002875c */

/* unlock-complete AEM routing: three distinct pointer slots. */
extern void     *g_od_complete_dispatch; /* PTR_DAT_000288e0 (handler at +0x10) */
extern void     *g_od_complete_node;     /* PTR_DAT_000288e4 */
extern void     *g_od_complete_data;     /* PTR_DAT_000288e8 */

/* ========================================================================= */

/*
 * elock_mutex_unlock  -  release the lock-state critical section.
 * OEM: 0x27190
 */
void elock_mutex_unlock(void)
{
    elock_lock_release(g_elock_mtx);
}

/*
 * elock_state_differs  -  under the lock, test whether the current lock
 * state byte differs from the requested one.  Returns nonzero (true) when
 * a transition is pending.
 * OEM: 0x2719c
 */
int elock_state_differs(void)
{
    char cur, req;

    elock_lock_acquire(&g_log_mod_b, 0, -1, -1); /* FUN_00063118(DAT_271c4, ...) */
    cur = (char)g_lock_state_cur; /* *DAT_271c8 */
    req = (char)g_lock_state_req; /* *DAT_271cc */
    elock_mutex_unlock();
    return cur != req;
}

/*
 * elock_fsm_transition  -  perform the pending lock-state transition: invoke
 * the leave-callback for the new state's table entry, commit the state byte,
 * release the lock and re-enter the FSM.  No-op (but still releases) when
 * the state does not actually differ.
 * OEM: 0x272d8
 */
void elock_fsm_transition(void)
{
    int differs;
    void (*cb)(int);

    elock_lock_acquire(&g_log_mod_b, 0, -1, -1); /* FUN_00063118(DAT_2735c, ...) */
    differs = elock_state_differs();
    if (differs == 0) {
        elock_mutex_unlock();
        return;
    }

    if ((g_log_mod_b & 7) > 2) {
        /* trace old->new state names; msg id 0x28c0 */
        uint32_t args[5];
        args[0] = ((uint32_t *)&g_state_cb_table)[g_lock_state_cur]; /* state-name str */
        args[1] = ((uint32_t *)&g_state_cb_table)[g_lock_state_req];
        vm_logf(&g_log_mod_b, 0x28c0, args, 0);
    }

    /* per-(new)state callback at table[req].entry+0x30, called with old state */
    cb = *(void (**)(int))(&g_state_cb_table[(uint32_t)g_lock_state_req * 0x34]);
    if (cb != NULL)
        cb((int)g_lock_state_cur);

    g_lock_state_cur = g_lock_state_req;
    elock_mutex_unlock();
    elock_fsm_transition_done();
}

/*
 * elock_set_lock_state  -  request a new lock state.  Emits an optional
 * trace, and if the requested state differs and no transition is already
 * pending, latches the request, runs the target state's enter-callback and
 * (when that returns nonzero / is absent) drives the transition.
 * OEM: 0x27380
 */
void elock_set_lock_state(uint32_t state)
{
    uint8_t old;
    int differs;
    int (*cb)(uint32_t);

    elock_lock_acquire(&g_log_mod_b, 0, -1, -1); /* FUN_00063118(DAT_27404, ...) */

    if ((g_log_mod_b & 7) > 2) {
        /* trace requested state; msg id 0x1cc0 */
        uint32_t args[4];
        args[0] = ((uint32_t *)&g_state_cb_table)[state]; /* state-name str */
        args[1] = 0;            /* DAT_27410 */
        args[2] = 0x200;        /* literal 0x200 (local_14) */
        vm_logf(&g_log_mod_b, 0x1cc0, args, 0);
    }

    if (g_lock_state_cur != (uint8_t)state) {
        differs = elock_state_differs();
        if (differs == 0) {
            old = g_lock_state_cur;
            g_lock_state_req = (char)state;
            cb = *(int (**)(uint32_t))(&g_state_cb_table[(uint32_t)old * 0x34 + 0x30]);
            if (cb == NULL || cb(state) != 0)
                elock_fsm_transition();
        }
    }
    elock_mutex_unlock();
}

/*
 * elock_is_present  -  return whether the e-lock module is physically
 * present.  Triggers a one-shot present query on first use; an override byte
 * forces "present" when set to 1.
 * OEM: 0x28a9c
 */
int elock_is_present(void)
{
    if (g_present_cached == '\0')
        elock_request_present_init();

    if (g_present_override == '\x01')
        return 1;
    return g_present_cached == '\x01';
}

/*
 * elock_request_present_init  -  kick the AEM handler that queries the lock's
 * presence sensor (asynchronous; result lands in g_present_cached).  The
 * handler source and the node argument are two distinct OEM globals.
 * OEM: 0x2873c
 */
void elock_request_present_init(void)
{
    aem_send(*(uint32_t *)((uint8_t *)g_od_present_dispatch + 0x10),
             g_od_present_node, 0, 0, 0, 0, 0);
}

/*
 * elock_touch_unlock_request  -  user touched/tapped to request unlock.
 * Returns -128 (0xffffff80) when the module is absent (sensor == -1);
 * otherwise emits an optional trace, posts AEM event (chan 1, id 0x163,
 * payload[5]=1) and submits it.
 * OEM: 0x283f0
 */
int elock_touch_unlock_request(void)
{
    void    *ev;

    if (g_touch_present == -1)      /* *DAT_00028448 */
        return -128; /* 0xffffff80 */

    if ((int8_t)(g_log_mod_c << 5) < 0) { /* bit2 of verbosity field set */
        uint32_t args[3];
        args[0] = 3;     /* local_20 */
        args[1] = 0;     /* DAT_28450 */
        args[2] = 0;     /* DAT_28454 */
        vm_logf(&g_log_mod_c, 0x1900, args, 0);
    }

    ev = aem_event_alloc(1, 0x163, 1, 0);
    if (ev != NULL)
        ((uint8_t *)ev)[5] = 1;
    return aem_event_submit();
}

/*
 * elock_drive_unlock_pulse  -  fire the actuator unlock pulse: only when the
 * actuator reports no fault and is not busy.  Enables the actuator power
 * domain, drives the unlock profile, plays the unlock audio cue and arms the
 * drive-pulse settle timer with an 8.16 fixed-point deadline.
 * OEM: 0x277e4
 */
void elock_drive_unlock_pulse(void)
{
    uint32_t pulse_ms;
    int64_t  deadline;
    int64_t  scaled;

    if (actuator_fault_check() != 0)
        return;
    if (actuator_busy_check() != 0)
        return;

    actuator_power_domain_enable(1);
    pulse_ms = (uint32_t)actuator_pulse(g_profile_unlock, 1, 1, 0 /* OEM: 3-arg call */);
    audio_play(g_cue_unlock, 0xe, 1);

    /* deadline = max(pulse_ms,0) * 0x8000 + 999, then /1000 */
    deadline = (int64_t)(int32_t)(pulse_ms & ~((int32_t)pulse_ms >> 31)) * 0x8000 + 999;
    scaled = vm_scale_ticks((int)deadline, (int)((uint64_t)deadline >> 32), 1000, 0);
    vm_timer_arm(g_t_drive_pulse, (uint32_t)((uint64_t)scaled >> 32),
                 (uint32_t)scaled, (int)((uint64_t)scaled >> 32));
}

/*
 * elock_report_lock_state  -  publish the lock state byte: update OD object
 * 0x160, submit the pending AEM event and notify the OD node subscribers.
 * OEM: 0x28760
 */
void elock_report_lock_state(uint8_t value)
{
    g_report_val = value;
    od_set_u8(0x160, &g_report_val, 1);
    aem_event_submit();
    od_notify(g_od_complete_node, &g_report_val, 1);
}

/*
 * elock_unlock_complete  -  called when an unlock cycle finishes.  Clears the
 * pending flag, reports state 0 (unlocked), optionally arms a follow-up
 * timer, timestamps the completion (uptime*1000 packed as a 64-bit value
 * into a 2-word OD field) and pushes the completion AEM event.
 * OEM: 0x27b64
 */
void elock_unlock_complete(void)
{
    int64_t  uptime_us;
    uint32_t hi;
    uint32_t *ts;

    if (g_unlock_complete_pending == '\0')
        return;

    g_unlock_complete_pending = '\0';
    elock_report_lock_state(0);

    if (g_complete_relatch == '\x01')                 /* *DAT_28b04 */
        vm_timer_arm(g_t_complete_followup, 0, 0x10000, 0); /* DAT_28b08 */

    uptime_us = vm_uptime_scaled() * 1000;
    hi = (uint32_t)((uint64_t)uptime_us >> 32);
    /* pack as a >>15 shifted 64-bit timestamp into a 2-word OD field */
    ts = g_drive_ts;
    ts[0] = ((uint32_t)uptime_us >> 15) | (hi << 17);
    ts[1] = hi >> 15;

    /* three distinct OEM pointer slots: dispatch (handler at +0x10), node, data */
    aem_send(*(uint32_t *)((uint8_t *)g_od_complete_dispatch + 0x10),
             g_od_complete_node, 0, g_od_complete_data, 8, 0, 0);
}

/*
 * actuator_power_domain_enable  -  set bit (1<<which) in the actuator power
 * mask, submit the power-domain work item, then request the power domain.
 * The request receives a pointer to the MSB (byte[3]) of a 4-byte stack slot;
 * if the request succeeds and that ack byte is 1, commit the domain.  Returns
 * 0 on the failure paths / when no commit was needed.
 * OEM: 0x2ad9c
 */
uint32_t actuator_power_domain_enable(uint32_t which)
{
    uint8_t  state_word[4] = {0, 0, 0, 0};
    int rc;
    uint32_t ret;

    g_pd_mask |= (uint8_t)(1u << (which & 0xff));
    vm_work_submit(g_w_pd);

    /* OEM passes (int)&uStack_c + 3 — pointer to the MSB of the stack word. */
    rc = power_domain_request(g_actuator_pd, &state_word[3]);
    if (rc != 0)
        return 0;

    ret = 0;
    if (state_word[3] == '\x01')      /* uStack_c._3_1_ == 0x01 */
        ret = (uint32_t)power_domain_commit(g_actuator_pd);
    return ret;
}

/*
 * elock_state_machine_step  -  the periodic e-lock FSM tick.  Driven from a
 * timer; param points at a small state record:
 *   param[0] = sub-phase / retry counter
 *   param[1] = FSM state    (0 idle, 1 lock-request, 3 unlock-drive)
 *   param[2..5] = u32 sub-state
 *
 * Behaviour (translated from the decompiler):
 *  - On very first entry ((state[0]&0xfd)==0 && state[1]==0): one-time HW init.
 *  - When NOT mid-unlock (g_unlock_active==0):
 *      * state==1, substate==1: if not present -> force lock (state 1);
 *        else maybe emit OD event, request touch-unlock, and if that returns
 *        nonzero and no pulse latched -> drive the unlock pulse.
 *      * present && state==3: request touch-unlock; if actuator fault-free,
 *        query the drive.  When the drive query returns ZERO, enter the
 *        first-pass-unlock / stuck path (depending on g_max_retries); when it
 *        returns NONZERO, run elock_drive_unlock_pulse() (phase=0).  Either
 *        way an AEM event (chan1,id0x164,payload[5]=phase) is then posted.
 *  - When mid-unlock (g_unlock_active!=0) and state==0: advance the settle
 *    counter / backup-unlock attempts; on each tick either re-arm the step
 *    timer, retry a backup unlock pulse, or (on success) lock + power off.
 * OEM: 0x278fc
 */
void elock_state_machine_step(uint8_t *state)
{
    int present;
    int rc;
    uint32_t pulse;
    int64_t  deadline, scaled;
    void    *ev;
    uint32_t *resched_arg; /* puVar7: r1 carried into the LAB_0002794e reschedule */

    /* one-time hardware init on the very first idle tick */
    if (((state[0] & 0xfd) == 0) && (state[1] == 0))
        elock_hw_init();

    /* puVar7 = DAT_00027ab4 (the g_step_ctr pointer) on entry */
    resched_arg = (uint32_t *)&g_step_ctr;

    if (g_unlock_active == '\0') {
        /* ---- not mid-unlock ---- */

        if (state[1] == 1 && *(int *)(state + 2) == 1) {
            present = elock_is_present();
            if (present == 0) {
                elock_set_lock_state(1);
            } else {
                if ((g_log_mod_a & 6) != 0)
                    od_event_push(&g_log_mod_a, 2, (int)(uintptr_t)g_log_arg_2); /* DAT_27ac0 */
                if (elock_touch_unlock_request() != 0 && g_unlock_active == '\0')
                    elock_drive_unlock_pulse();
            }
        }

        present = elock_is_present();
        if (present != 0 && state[1] == 3) {
            elock_touch_unlock_request();
            if (actuator_fault_check() != 0)
                return;

            if ((int)actuator_drive_query(0) == 0) {
                int phase;

                if (g_max_retries < 3) {
                    /* first-pass unlock drive */
                    actuator_power_domain_enable(1);
                    actuator_settle_delay(10);
                    g_step_ctr = 0;       /* *DAT_27ab4 = 0 */
                    g_drive_phase = 0;    /* *DAT_27ae4 = 0 */
                    rc = actuator_pulse(g_profile_step_a, 1, 1, 0 /* OEM: 3-arg call */);
                    audio_play(g_cue_step, 0xe, 1);
                    if (rc > 0) {
                        deadline = (int64_t)rc * 0x8000 + 999;
                        vm_scale_ticks((int)deadline, (int)((uint64_t)deadline >> 32), 1000, 0);
                        vm_yield_pump();
                    }
                    /* r1 out of the second pulse is carried into the reschedule */
                    pulse = (uint32_t)actuator_pulse(g_profile_step_b, 1, 1, 0xff);
                    resched_arg = (uint32_t *)(uintptr_t)pulse; /* puVar7 = extraout_r1_01 */
                    g_unlock_active = '\x01';
                    /* re-arm step timer with a 0x18000-tick deadline (LAB_0002794e) */
                    vm_timer_reschedule(g_t_step, (uint32_t)(uintptr_t)resched_arg, 0x18000, 0);
                    return;
                }

                /* retry budget exhausted: stuck/backup path */
                if ((g_log_mod_a & 7) > 2)
                    od_event_push(&g_log_mod_a, 3, (int)(uintptr_t)g_log_arg_3); /* DAT_27ac8 */
                if (g_retry_latched == '\0')
                    vm_timer_arm(g_t_unlock, 0, 0xf0000, 0);
                g_retry_latched = '\x01';

                if (actuator_busy_check() != 0)
                    return;

                pulse = (uint32_t)actuator_pulse(g_profile_stuck, 1, 1, 1);
                audio_play(g_cue_stuck, 0xe, 1);
                deadline = (int64_t)(int32_t)(pulse & ~((int32_t)pulse >> 31)) * 0x8000 + 999;
                scaled = vm_scale_ticks((int)deadline, (int)((uint64_t)deadline >> 32), 1000, 0);
                vm_timer_arm(g_t_retry, (uint32_t)((uint64_t)scaled >> 32),
                             (uint32_t)scaled, (int)((uint64_t)scaled >> 32));
                phase = 2; /* stuck */

                ev = aem_event_alloc(1, 0x164, 1, 1);
                if (ev != NULL)
                    ((uint8_t *)ev)[5] = (uint8_t)phase;
                aem_event_submit();
                return;
            }

            /* drive query nonzero: drive the unlock pulse, phase 0 */
            elock_drive_unlock_pulse();
            ev = aem_event_alloc(1, 0x164, 1, 1);
            if (ev != NULL)
                ((uint8_t *)ev)[5] = 0; /* phase = 0 */
            aem_event_submit();
            return;
        }
        return;
    }

    /* ---- mid-unlock (g_unlock_active != 0) ---- */
    if (state[1] != 0)
        return;

    if (state[0] < 3) {
        /* settle phase: tick the step counter unless we've hit a 10-modulo
         * boundary (==9), in which case fall through to the drive re-pulse. */
        if (g_step_ctr % 10 != 9) {
            g_step_ctr++;
            /* LAB_0002794e: reschedule with puVar7 (= g_step_ctr ptr here) */
            vm_timer_reschedule(g_t_step, (uint32_t)(uintptr_t)resched_arg, 0x8000, 0);
            return;
        }
    } else {
        if ((uint32_t)(state[0] - 3) > 1)
            return; /* states 4,5 handled; others ignored */

        /* backup-unlock attempts */
        uint32_t attempt = (uint32_t)g_backup_attempt; /* uVar9 = *DAT_277b4 (pre-increment) */
        g_backup_attempt = (int32_t)(attempt + 1);
        if ((int)(attempt + 1) < backup_unlock_is_active()) {
            /* clamp the attempt index to [0,2] and select a profile entry */
            uint32_t idx = attempt;
            if ((int)idx > 1)
                idx = 2;
            idx = idx & ~((int32_t)idx >> 31); /* clamp negatives to 0 */
            g_backup_scale *= 10;
            actuator_pulse(g_backup_profile_table[idx], 1, 1, 0xff);
            audio_play(g_cue_backup, 0xe, 1);
            /* extraout_r1 carried into the timer arm; modelled as 0 */
            vm_timer_arm(g_t_backup, 0, 0x18000, 0);
            return;
        }
        rc = (int)actuator_drive_query((uint32_t)g_backup_scale); /* FUN_00031770(*DAT_277b8) */
        if (rc != 0) {
            elock_set_lock_state(1);
            can_power_off(1);
            return;
        }
    }

    /* common drive re-pulse tail (reached from both the ==9 boundary and the
     * backup "succeeded but not yet locked" case). */
    g_unlock_count++;
    vm_work_submit(g_w_unlock);
    g_drive_phase_b = 0; /* *DAT_27730 = 0 */
    pulse = 0;
    if (actuator_busy_check() == 0) {
        pulse = (uint32_t)actuator_pulse(g_profile_retail, 1, 1, 1);
        audio_play(g_cue_retail, 0xe, 1);
    }
    deadline = (int64_t)(int32_t)(pulse & ~((int32_t)pulse >> 31)) * 0x8000 + 999;
    scaled = vm_scale_ticks((int)deadline, (int)((uint64_t)deadline >> 32), 1000, 0);
    vm_timer_arm(g_t_retry_b, (uint32_t)((uint64_t)scaled >> 32),
                 (uint32_t)scaled, (int)((uint64_t)scaled >> 32));
}
