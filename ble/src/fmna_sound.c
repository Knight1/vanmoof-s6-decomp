/*
 * fmna_sound.c  --  VanMoof S6 "ble" ECU (nRF52840, NCS 2.9.1 / Zephyr 3.7.99)
 *
 * Apple Find My (FMNA) "play sound" glue.  Recovered from the dispatch-table gap
 * (0x336b4 / 0x33acc-0x33bd0) next to the reconstructed FMNA integration in
 * fmna_glue.c.  When an owner (or the Find My network) asks the bike to play its
 * locate sound, the FMNA library invokes these callbacks; they drive the bike's
 * audio player and the sound-timeout work.
 *
 *   - fmna_app_sound_start          start the locate sound (/audio/16_locate.wav)
 *   - fmna_app_sound_stop           stop playback
 *   - fmna_app_sound_timeout        playback timer expired -> stop
 *   - fmna_app_sound_stop_indicate  ack completion back to the FMNA library
 *   - fmna_sound_fmn_stop_req       FMN network asked us to stop -> cancel + stop
 *
 * Only the VanMoof glue is reconstructed here; the FMNA protocol library and the
 * audio player are vendor and are declared extern.  Behaviour-oriented, from the
 * Ghidra decompiler output; OEM addresses (image base 0xC000) noted per function.
 * Not byte-identical.  Self-contained: <stdint.h>/<stddef.h> + the externs below.
 */

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Vendor / RTOS / SDK / FMNA externs (OEM image addresses, base 0xC000).
 * ------------------------------------------------------------------------- */

/* AEM logging + state-machine event post. */
extern void aem_log_v(void *log_mod, uint32_t code, void *arg_block, int z);   /* 0x364f0 */
extern void aem_sm_post_event(void *sm, uint32_t r1, void *target, int z);     /* 0x637f8 */
extern void vm_logf(void *log_mod, uint32_t level, const char *fmt, ...);      /* 0x6efea */

/* Bike audio player: start a clip (path, volume, loop?), and reset/stop.        */
extern void audio_play(const char *path, int volume, int loop);                /* 0x26794 */
extern void audio_player_reset(void);                                          /* 0x2671c */

/* FMNA protocol library (vendor): acknowledge sound completion to Find My.       */
extern int  fmna_sound_completed_indicate(void);                               /* 0x613fc */

/* Zephyr: cancel the sound-timeout delayable work. */
extern void k_work_cancel(void *work);                                         /* 0x7aad4 */

/* -------------------------------------------------------------------------
 * Global state (resolved from OEM PC-relative literal pools).
 * ------------------------------------------------------------------------- */
extern void   *g_fmna_sound_sm;              /* DAT_00033b84 (SM ctx for start)  */
extern void   *g_fmna_sound_timeout_work;    /* DAT_00033be0                     */

/* Per-callback AEM log-module objects (first byte holds the enable/level bits).  */
extern uint8_t g_log_fmna_sound_start[];     /* DAT_00033b88                     */
extern uint8_t g_log_fmna_sound_stop[];      /* DAT_000336e8                     */
extern uint8_t g_log_fmna_sound_ind[];       /* DAT_00033b34                     */
extern uint8_t g_log_fmna_sound_fmn[];       /* DAT_00033bd4                     */

/* Documented OEM strings (real pointers from the literal pools). */
#define MSG_START     "%s: Starting to play sound"                          /* 0x86853 */
#define MSG_STOP      "%s: Stopping the sound from being played"            /* 0x865f4 */
#define MSG_TIMEOUT   "%s: Sound playing timed out"                         /* 0x86809 */
#define MSG_FMN_STOP  "%s: Received a request from FMN to stop playing sound" /* 0x8686e */
#define MSG_IND_FAIL  "fmna_sound_completed_indicate failed (err %d)"       /* 0x86825 */
#define WAV_LOCATE    "/audio/16_locate.wav"                                /* 0x33b94 */

/* AEM info gate: OEM tests (first_byte << 0x1d) < 0, i.e. bit 2 (0x4). */
static inline int aem_info_enabled(const uint8_t *m) { return (m[0] & 0x4) != 0; }

/* Standard "%s: <msg>" info-log arg block (module tag + message pointer). */
struct fmna_log_arg { uint32_t level; const char *msg; const char *mod; };

/* Forward decls (intra-unit call chain). */
void fmna_app_sound_stop(void);
void fmna_app_sound_timeout(void);

/* -------------------------------------------------------------------------
 * fmna_app_sound_start  --  0x33b3c
 *
 * Start the Find My locate sound: post the sound state-machine event, optionally
 * log "Starting to play sound", then kick the audio player with the locate clip.
 * ------------------------------------------------------------------------- */
void fmna_app_sound_start(void)
{
    aem_sm_post_event(g_fmna_sound_sm, 0, (void *)0x28000 /* LAB_00028000 */, 0);

    if (aem_info_enabled(g_log_fmna_sound_start)) {
        struct fmna_log_arg a = { 3, MSG_START, "fmna_app_sound_start" };
        aem_log_v(g_log_fmna_sound_start, 0x1900, &a, 0);
    }

    audio_play(WAV_LOCATE, 0xf, 1);
}

/* -------------------------------------------------------------------------
 * fmna_app_sound_stop  --  0x336b4
 *
 * Stop playback: optionally log "Stopping the sound", then reset the audio
 * player.
 * ------------------------------------------------------------------------- */
void fmna_app_sound_stop(void)
{
    if (aem_info_enabled(g_log_fmna_sound_stop)) {
        struct fmna_log_arg a = { 3, MSG_STOP, "fmna_sound" };
        aem_log_v(g_log_fmna_sound_stop, 0x1900, &a, 0);
    }
    audio_player_reset();
}

/* -------------------------------------------------------------------------
 * fmna_app_sound_timeout  --  0x33acc
 *
 * The sound-playing timer expired: log "Sound playing timed out", then stop.
 * ------------------------------------------------------------------------- */
void fmna_app_sound_timeout(void)
{
    if (aem_info_enabled(g_log_fmna_sound_stop /* DAT_00033b00 */)) {
        struct fmna_log_arg a = { 3, MSG_TIMEOUT, "fmna_sound" };
        aem_log_v(g_log_fmna_sound_stop, 0x1900, &a, 0);
    }
    fmna_app_sound_stop();
}

/* -------------------------------------------------------------------------
 * fmna_app_sound_stop_indicate  --  0x33b0c
 *
 * Acknowledge sound completion to the FMNA library.  On success run the timeout
 * cleanup; on error log "fmna_sound_completed_indicate failed".
 * ------------------------------------------------------------------------- */
void fmna_app_sound_stop_indicate(void)
{
    int err = fmna_sound_completed_indicate();

    if (err == 0) {
        fmna_app_sound_timeout();
        return;
    }
    if ((g_log_fmna_sound_ind[0] & 7) != 0)
        vm_logf(g_log_fmna_sound_ind, 1, MSG_IND_FAIL, err);
}

/* -------------------------------------------------------------------------
 * fmna_sound_fmn_stop_req  --  0x33b98
 *
 * The Find My network asked us to stop the sound: optionally log it, cancel the
 * sound-timeout work, then stop playback.
 * ------------------------------------------------------------------------- */
void fmna_sound_fmn_stop_req(void)
{
    if (aem_info_enabled(g_log_fmna_sound_fmn)) {
        struct fmna_log_arg a = { 3, MSG_FMN_STOP, "fmna_sound" };
        aem_log_v(g_log_fmna_sound_fmn, 0x1900, &a, 0);
    }
    k_work_cancel(g_fmna_sound_timeout_work);
    fmna_app_sound_stop();
}
