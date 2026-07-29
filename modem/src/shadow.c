/*
 * shadow.c  --  VanMoof S6 "modem" ECU (Nordic nRF91x1, NCS 2.9.1 / TF-M)
 *
 * The AWS-IoT device-shadow reporting layer. When the cloud pushes desired state
 * (settings / telemetry config) on `vm/things/<thing>/shadow/update/delta`, the
 * setting/telemetry dispatchers apply each key and then call shadow_report_setting
 * to write the applied value into the bike's *reported* shadow tree, which is then
 * published back to `$aws/things/<thing>/shadow/update`. This closes the
 * desired -> apply -> reported loop the app/cloud uses to confirm state.
 *
 * Shadow document shape (a lazily-built JSON/CBOR object tree):
 *   { "state": { "desired": { <group>: { <key>: <val> } },
 *                "reported": { <group>: { <key>: <val> } } } }
 *
 * shadow_report_setting always writes reported[group][key]; when `mirror` is set
 * it also writes desired[group][key] (used for locally-originated changes that
 * must update desired too). A dirty shadow is flushed by a scheduled work item.
 *
 * Behaviour-oriented reconstruction from Ghidra (image base 0x10000, Cortex-M33);
 * not byte-identical. The JSON tree + work scheduler are vendor (externs below).
 *   shadow_report_setting @ 0x26440
 *   (aws_shadow_connect   @ 0x4094c  builds the shadow topics + connects; named)
 */

#include <stdint.h>
#include <stddef.h>

/* ---- JSON/CBOR object tree (vendor) -------------------------------------- */
extern void *json_new    (void);                                  /* 0x42224 (new object node) */
extern void  json_set    (void *parent, const char *key, void *child); /* 0x580aa */
extern void *json_get    (void *parent, const char *key);         /* 0x58092 (NULL if absent) */
extern void  json_unset  (void *node, const char *key);           /* 0x58104 (drop existing member) */

/* ---- shadow document lock + publish scheduling (vendor) ------------------ */
extern void  shadow_lock  (void *doc, const char *key, int a, int b, int mirror); /* 0x4d5c4 */
extern void  shadow_unlock(void *doc);                            /* 0x4d6b4 */
extern int   work_schedule(void *work, int a, int flags, int b);  /* 0x4dc0c */

extern void  *g_shadow_doc;    /* DAT_00026538 (lock target) */
extern void **g_shadow_root;   /* DAT_0002654c (root object, lazily built) */
extern void  *g_shadow_work;   /* DAT_00026548 (publish work item) */

/* shadow tree key names (rodata). */
extern const char s_state[];     /* 0x6b752 "state"    */
extern const char s_desired[];   /* "desired"          */
extern const char s_reported[];  /* "reported"         */

/* -------------------------------------------------------------------------
 * shadow_report_setting  --  0x26440
 *
 *   group  : shadow sub-object name ("settings" / "provisioning" /
 *            "device_shadow_telemetry" / ...)
 *   key    : the setting key
 *   value  : the JSON/CBOR value node to store
 *   mirror : also write desired[group][key] (not just reported)
 * ------------------------------------------------------------------------- */
void shadow_report_setting(const char *group, const char *key, void *value, int mirror)
{
    void *state, *desired, *reported, *grp_obj;

    shadow_lock(g_shadow_doc, key, -1, -1, mirror);

    if (*g_shadow_root == NULL) {
        /* first use: build state.{desired,reported} skeleton */
        void *root = json_new();
        *g_shadow_root = root;
        state    = json_new();
        desired  = json_new();
        reported = json_new();
        json_set(root,  s_state,    state);
        json_set(state, s_desired,  desired);
        json_set(state, s_reported, reported);
    } else {
        state    = json_get(*g_shadow_root, s_state);
        desired  = json_get(state, s_desired);
        reported = json_get(state, s_reported);
    }

    /* reported[group][key] = value */
    grp_obj = json_get(reported, group);
    if (grp_obj == NULL) {
        grp_obj = json_new();
        json_set(reported, group, grp_obj);
    }
    json_unset(grp_obj, key);
    json_set(grp_obj, key, value);

    /* mirror to desired[group][key] when requested */
    if (mirror != 0) {
        grp_obj = json_get(desired, group);
        if (grp_obj == NULL) {
            grp_obj = json_new();
            json_set(desired, group, grp_obj);
        }
        json_unset(grp_obj, key);
        json_set(grp_obj, key, value);
    }

    shadow_unlock(g_shadow_doc);
    work_schedule(g_shadow_work, 0, 0x8000, 0);   /* flush shadow -> cloud */
}
