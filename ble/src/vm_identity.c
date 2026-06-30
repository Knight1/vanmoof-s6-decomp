/* vm_identity.c — VanMoof S6 `ble` ECU identity / odometer / service-mode logic.
 *
 * S6 `ble` (nRF52840, NCS 2.9.1 / Zephyr 3.7.99). Reconstructed from Ghidra
 * (image base 0xC000):
 *   vm_identity_format_ids     @ 0x2d508
 *   vm_identity_load_id        @ 0x2d604
 *   vm_identity_set_id         @ 0x2d6a0
 *   vm_enter_service_mode      @ 0x28134
 *   vm_odo_update              @ 0x31ff0
 *   vm_state_restore_distance  @ 0x3213c
 *
 * Two loosely-related concerns live here, as in the OEM image:
 *   - Identity: the shell command that prints / sets the ECU+frame+bike IDs,
 *     and the persisted-ID loader that reads the 16-byte ECU ID out of the
 *     key/value store, mirrors it to RAM, and publishes it on the CAN OD bus.
 *   - Motion: the odometer accumulator that runs off the motor distance CAN
 *     message and the boot-time "restored distance" audio cue.
 *
 * Behaviour-oriented: the shell printer, key/value store, OD-publish, audio and
 * power-sequencer primitives are vendor/platform externs (declared below with
 * their OEM addresses) and are NOT reconstructed here.
 */
#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 *  Vendor / platform externs (OEM addresses in comments)
 * ------------------------------------------------------------------ */

/* Diagnostic-shell formatted printer: fprintf-style onto a shell context. */
extern void shell_fprintf(void *sh, const char *fmt, ...);   /* 0x6f948 */
/* Diagnostic-shell error printer (newline-terminated single-line variant). */
extern void shell_error(void *sh, const char *fmt, ...);     /* 0x6f980 */

/* Key/value (settings) store: does a persisted ECU-ID record exist & match? */
extern int  dtc_pattern_match(void *store, const void *pattern); /* 0x1f758 */
/* Read a record into nothing-yet: returns the stored value length. */
extern unsigned kv_get_len(void *key, unsigned cap);          /* 0x76c74 */
/* Copy the stored ECU-ID (<=16 bytes) into the RAM mirror; returns a handle. */
extern uint32_t kv_load_value(void *dst, void *key, unsigned cap); /* 0x7b45c */
/* Submit a CAN/OD event descriptor (object id in r1) to the bus. */
extern void od_event_submit(void *node, unsigned obj, void *desc, int flags); /* 0x364f0 */
/* Finalise / commit the OD object; returns a status. */
extern uint32_t od_commit(void *node);                        /* 0x38334 */
/* Publish an OD object id on the CAN bus (small dispatch helper). */
extern void od_publish_obj(unsigned obj_id);                  /* 0x31eb8 */

/* Monotonic distance source (returns a 64-bit revolution/tick count). */
extern long long motor_distance_get(void);                    /* 0x7ae6a */

/* Logging gate + formatted logger, used exactly as the OEM (module-gated). */
/* The OEM tests (module->flags & 7) > 2 inline; modelled via vm_log_level(). */
extern void vm_logf(void *mod, int level, const char *fmt, ...); /* 0x6efea */

/* Power-sequencer / actuator primitives for service mode. */
extern void actuator_power_domain_enable(int domain);         /* power seq */
extern void ps_power_on_request(int arg);
extern void ps_set_flag_publish_1b(int v);
extern void ps_set_charging_flag_publish(int v);
extern void backup_unlock_get_lockout_count(void);
extern void shell_print_lines(void *sh, void *arg, int a, int b); /* 0x63790 */
extern void shell_warn(void *mod, int level, void *arg);      /* 0x6efd8 */

/* Audio cue primitives for the boot "restored distance" announcement. */
extern void audio_player_reset(void);
extern void audio_enqueue_play_cmd(void *clip, int id, int prio, void *cb); /* 0x3213c uses */

/* ------------------------------------------------------------------ *
 *  Module globals (OEM RAM / rodata addresses)
 * ------------------------------------------------------------------ */

/* Lock-state flag byte: nonzero => "locked", zero => "unlocked".  @0x20013302 */
extern volatile uint8_t  ecu_lock_flag;
/* RAM string mirrors printed by the identity command. */
extern char ecu_id_str[];        /* @0x200030ef */
extern char frame_id_str[];      /* @0x200132f2 */
extern char bike_id_str[];       /* @0x200132e2 */

/* Odometer accumulator state.  All are 32-bit counters in RAM. */
extern uint32_t *const odo_last_motor_distance;  /* DAT_00032088 -> @0x2000fecc */
extern void     *const odo_log_mod;              /* DAT_0003208c -> @0x20003378 */
extern uint32_t *const odo_prev_pair;            /* DAT_00032094 -> @0x200135d3 (s32@+2 = last motor dist) */
extern uint32_t *const odo_total_a;              /* DAT_00032098 -> @0x2000fed4 */
extern uint32_t *const odo_total_b;              /* DAT_0003209c -> @0x2000fed0 */
extern uint32_t *const odo_total_c;              /* DAT_000320a0 -> @0x2000fed8 */

/* Persisted-ID loader handles. */
extern void *const id_kv_store;       /* DAT_0002d680 */
extern const void *id_kv_pattern;     /* DAT_0002d67c */
extern volatile uint8_t *const id_loaded_flag; /* DAT_0002d684 -> set to 1 on load */
extern void *const id_kv_key;         /* DAT_0002d688 */
extern uint32_t *const id_od_node;    /* DAT_0002d68c (bit-29 gate + event node) */
extern void *const id_od_desc_a;      /* DAT_0002d690 */
extern void *const id_od_desc_b;      /* DAT_0002d694 */
extern void *const id_od_desc_c;      /* DAT_0002d698 */
extern void *const id_od_commit_node; /* DAT_0002d69c */

/* Service-mode shell module/args. */
extern uint32_t *const svc_log_mod;   /* DAT_00028174 */
extern void *const svc_log_arg;       /* DAT_00028178 */
extern void *const svc_shell_arg;     /* DAT_0002817c */

/* Boot audio cue clip + callback for the "restored distance" announcement. */
extern void *const restore_audio_clip; /* DAT_0003215c */
extern void *const restore_audio_cb;   /* DAT_00032158 */

/* The odometer log format string lives in rodata.  @0x000855b9 */
#define ODO_LOG_FMT  "Motor distance %u"

/* ------------------------------------------------------------------ *
 *  CAN motor-distance message layout (unaligned, packed on the wire)
 * ------------------------------------------------------------------ */
/* Fields are read at byte offsets directly off the inbound message pointer:
 *   +0x05 : u32  (mirrored into odo_prev_pair[0])
 *   +0x07 : s32  motor distance      (delta vs. s32 @ odo_prev_pair+2)
 *   +0x09 : u32  (mirrored into odo_prev_pair[1])
 */
static inline uint32_t msg_u32(const void *m, unsigned off)
{
    uint32_t v;
    const uint8_t *p = (const uint8_t *)m + off;
    /* deliberate unaligned 32-bit load (Cortex-M4 ldr handles it) */
    v  = (uint32_t)p[0];
    v |= (uint32_t)p[1] << 8;
    v |= (uint32_t)p[2] << 16;
    v |= (uint32_t)p[3] << 24;
    return v;
}

/* ------------------------------------------------------------------ *
 *  Identity command + persistence
 * ------------------------------------------------------------------ */

/* vm_identity_format_ids @ 0x2d508
 * Prints the ECU info block to a diagnostic-shell context: the ECU ID and its
 * lock state, the frame ID, and the bike ID.  Always returns 0.
 *
 * Note: the OEM symbol carries extra args (param_2..param_4) it does not use in
 * this print path; the disassembled body only consumes the shell context. */
int vm_identity_format_ids(void *sh)
{
    const char *lock = "unlocked";          /* 0x8403c */
    if (ecu_lock_flag != 0)
        lock = "locked";                    /* 0x81aa1 */

    shell_fprintf(sh, "ECU Info\n");                         /* 0x84045 */
    shell_fprintf(sh, "\tECU ID   : %s (%s)\n", ecu_id_str, lock); /* 0x8404f */
    shell_fprintf(sh, "\tFrame ID : %s\n", frame_id_str);    /* 0x84064 */
    shell_fprintf(sh, "\tBike ID  : %s\n", bike_id_str);     /* 0x84074 */
    return 0;
}

/* vm_identity_load_id @ 0x2d604
 * Load the persisted 16-byte ECU ID from the key/value store, mirror it to RAM
 * and publish it on the OD bus.  Returns:
 *    0           on success (after od_commit),
 *   -1  (0xffffffff)  if no persisted ID record exists yet,
 *  -22  (EINVAL)      if the stored value exceeds 16 bytes.
 *
 * The OEM takes 4 params; p2/p3 are unused and p4 is saved to the stack but
 * never read in a meaningful path — kept for ABI fidelity. */
int vm_identity_load_id(void *key, uint32_t p2, uint32_t p3, uint32_t p4)
{
    (void)p2;
    (void)p3;
    (void)p4;

    if (dtc_pattern_match(id_kv_store, id_kv_pattern) == 0)
        return -1;                          /* no ID provisioned */

    if (kv_get_len(key, 0x10) > 0x0f)
        return -22;                         /* value too large -> EINVAL */

    *id_loaded_flag = 1;
    {
        uint32_t handle = kv_load_value(id_kv_key, key, 0x10);

        /* bit-29 of *id_od_node gated: emit the ID change as an OD event */
        if ((int)(*id_od_node << 29) < 0) {
            /* On-stack event descriptor (matches the OEM frame layout):
             *   +0x00 : id_od_desc_c
             *   +0x04 : id_od_desc_a
             *   +0x08 : id_od_desc_b
             *   +0x0c : handle (from kv_load_value)
             *   +0x10 : u16 0x0301
             */
            struct {
                void    *c;
                void    *a;
                void    *b;
                uint32_t handle;
                uint16_t tag;
            } desc;
            desc.c      = id_od_desc_c;
            desc.a      = id_od_desc_a;
            desc.b      = id_od_desc_b;
            desc.handle = handle;
            desc.tag    = 0x0301;
            od_event_submit(id_od_node, 0x2500, &desc, 0);
        }
    }
    return (int)od_commit(id_od_commit_node);
}

/* vm_identity_set_id @ 0x2d6a0
 * Shell handler that provisions a new ID.  It first (re)loads the persisted ECU
 * ID via vm_identity_load_id() using the command context's stored key
 * (ctx->key @ +4); the load result selects the response:
 *    -1   -> "Not allowed to set ID before ECU ID is set\n"
 *   -22   -> "Invalid ID\n"
 *     0   -> proceed: format/echo the IDs back to the shell
 *  other  -> "Setting ID failed: %d\n"
 * Returns the load result code. */
int vm_identity_set_id(void *sh, void *unused, void *ctx, void *arg4)
{
    void *key = *(void **)((uint8_t *)ctx + 4);
    /* OEM calls vm_identity_load_id with only the key; the extra params are
     * unused by the callee, so 0 is passed for ABI completeness. */
    int rc = vm_identity_load_id(key, 0, 0, 0);

    if (rc == -1) {
        shell_error(sh, "Not allowed to set ID before ECU ID is set\n"); /* 0x8409a */
    } else if (rc == -22) {
        shell_error(sh, "Invalid ID\n");                  /* 0x840c6 */
    } else if (rc == 0) {
        /* OEM: vm_identity_format_ids(sh, unused, ctx, 1, arg4) */
        (void)unused;
        (void)arg4;
        vm_identity_format_ids(sh);
    } else {
        shell_error(sh, "Setting ID failed: %d\n", rc);   /* 0x840d2 */
    }
    return rc;
}

/* ------------------------------------------------------------------ *
 *  Service mode
 * ------------------------------------------------------------------ */

/* vm_enter_service_mode @ 0x28134
 * Bring the bike into service mode: power the actuator domains, request power-on,
 * raise the service/charging publish flags, and clear the backup-unlock lockout
 * counter.  If the service log module is gated on, emit a warning line, then
 * print the service banner to the shell. */
void vm_enter_service_mode(void)
{
    actuator_power_domain_enable(3);
    ps_power_on_request(0);
    ps_set_flag_publish_1b(1);
    ps_set_charging_flag_publish(1);
    backup_unlock_get_lockout_count();

    if ((*svc_log_mod & 6) != 0)
        shell_warn(svc_log_mod, 2, svc_log_arg);

    shell_print_lines(svc_shell_arg, 0, 0, 0);
}

/* ------------------------------------------------------------------ *
 *  Odometer
 * ------------------------------------------------------------------ */

/* vm_odo_update @ 0x31ff0
 * Driven by the motor-distance CAN message (msg = arg).  Computes the absolute
 * motor distance in metres ( = motor_distance_get() * 1000 >> 15 ), and:
 *   - every 10 m of advance, latches the new value and logs "Motor distance %u"
 *     (gated on the odo log module level > 2);
 *   - integrates the per-message motor-distance delta (msg+0x07) into the three
 *     odometer totals, but only when the delta is in (0 .. 0x1f2]; on a valid
 *     delta it re-publishes OD objects 0x114 and 0x113;
 *   - always mirrors msg+0x05 / msg+0x09 into odo_prev_pair for the next delta.
 *
 * The OEM takes 4 params; p2/p3 are unused and p4 is forwarded to vm_logf as
 * its 5th argument. */
void vm_odo_update(const void *msg, uint32_t p2, uint32_t p3, uint32_t p4)
{
    long long ticks = motor_distance_get();

    (void)p2;
    (void)p3;
    /* (ticks * 1000) >> 15, full 64-bit intermediate as the OEM (umull/mla). */
    uint64_t scaled = (uint64_t)(ticks * 1000);
    uint32_t dist_m = (uint32_t)(scaled >> 15);

    if ((uint32_t)(dist_m - *odo_last_motor_distance) > 9999u) {
        *odo_last_motor_distance = dist_m;
        /* OEM: if ((*odo_log_mod & 7) > 2) vm_logf(...) */
        if ((*(uint32_t *)odo_log_mod & 7) > 2)
            vm_logf(odo_log_mod, 3, ODO_LOG_FMT, (unsigned)msg_u32(msg, 0x07), p4);
    }

    {
        /* delta vs. last latched motor distance: OEM does a signed 32-bit
         * (unaligned) load at odo_prev_pair + 2 bytes. */
        int32_t motor = (int32_t)msg_u32(msg, 0x07);
        int32_t last  = (int32_t)msg_u32(odo_prev_pair, 2);
        int32_t delta = motor - last;

        /* OEM gate: accept 1 .. 0x1f3 exclusive, i.e. 1..0x1f2 (and != 0). */
        if (delta != 0 && (uint32_t)(delta - 1) <= 0x1f2u) {
            *odo_total_a += (uint32_t)delta;
            *odo_total_b += (uint32_t)delta;
            *odo_total_c += (uint32_t)delta;
            od_publish_obj(0x114);
            od_publish_obj(0x113);
        }
    }

    /* mirror the message tail for the next delta computation */
    odo_prev_pair[0] = msg_u32(msg, 0x05);
    odo_prev_pair[1] = msg_u32(msg, 0x09);
}

/* vm_state_restore_distance @ 0x3213c
 * Boot-time cue: re-arm the audio player and enqueue the "restored distance"
 * announcement (clip id 0xe, priority 1) once the odometer state has been
 * restored from persistence. */
void vm_state_restore_distance(void)
{
    actuator_power_domain_enable(4);
    audio_player_reset();
    audio_enqueue_play_cmd(restore_audio_clip, 0x0e, 1, restore_audio_cb);
}
