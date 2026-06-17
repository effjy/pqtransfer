/*
 * main.c - PQ Transfer GTK3 GUI.
 *
 * A small front-end over the peer-to-peer engine in transfer.c. One peer
 * receives (listens on a port); the other sends (connects to it). The actual
 * transfer runs on a worker thread so the network wait and the per-chunk
 * authenticated encryption never freeze the UI.
 */
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include "crypto.h"
#include "transfer.h"
#include "secure_buffer.h"

#ifndef PQTRANSFER_VERSION
#define PQTRANSFER_VERSION "1.0.1"
#endif
#define APP_ID "org.pqtransfer.PQTransfer"
#define DEFAULT_PORT 5800

/* Cyber-styled dark theme. Applied app-wide via a CSS provider. */
static const char *APP_CSS =
    "window, .pqx-root {"
    "  background-color: #070b12;"
    "  color: #c8f7ff;"
    "}"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a0f1a, #0e1726, #0a0f1a);"
    "  border-bottom: 1px solid #00e5ff;"
    "  box-shadow: 0 1px 8px rgba(0,229,255,0.35);"
    "  min-height: 40px;"
    "}"
    "headerbar .title {"
    "  color: #00e5ff;"
    "  font-family: monospace;"
    "  font-weight: bold;"
    "  letter-spacing: 3px;"
    "}"
    "headerbar .subtitle { color: #3d7d8f; font-family: monospace; }"
    ".hb-title {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  letter-spacing: 2px;"
    "}"
    "headerbar button {"
    "  padding: 2px 10px; margin: 4px 2px; min-height: 0; min-width: 0;"
    "  letter-spacing: 0;"
    "}"
    "headerbar button.titlebutton {"
    "  padding: 2px; margin: 2px; min-height: 22px; min-width: 22px;"
    "}"
    "label { color: #9fd6e6; font-family: monospace; }"
    ".field-label { color: #5fb4c9; letter-spacing: 1px; }"
    ".brand {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 22px; letter-spacing: 6px;"
    "}"
    ".subtitle { color: #3d7d8f; font-size: 10px; letter-spacing: 4px; }"
    ".hint { color: #3d7d8f; font-size: 10px; }"
    "entry {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a;"
    "  border-radius: 4px; padding: 7px; font-family: monospace;"
    "  caret-color: #00e5ff;"
    "}"
    "entry:focus {"
    "  border-color: #00e5ff;"
    "  box-shadow: 0 0 6px rgba(0,229,255,0.6);"
    "}"
    "combobox box, combobox button, combobox {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a; border-radius: 4px;"
    "  font-family: monospace;"
    "}"
    "combobox button:hover { border-color: #00e5ff; }"
    "radiobutton, checkbutton { color: #9fd6e6; font-family: monospace; }"
    "radiobutton check, checkbutton check {"
    "  background-color: #0c1421; border: 1px solid #2a6b80;"
    "}"
    "radiobutton check:checked, checkbutton check:checked {"
    "  background-color: #00e5ff; border-color: #00e5ff;"
    "}"
    "button {"
    "  background: #0e1b2b; color: #9fe9ff;"
    "  border: 1px solid #1d4c5e; border-radius: 4px;"
    "  padding: 7px 14px; font-family: monospace; letter-spacing: 1px;"
    "}"
    "button:hover {"
    "  border-color: #00e5ff; color: #ffffff;"
    "  box-shadow: 0 0 8px rgba(0,229,255,0.45);"
    "}"
    "button:active { background: #102a3a; }"
    "button:disabled { color: #3a566a; border-color: #16313e; }"
    ".action-button {"
    "  background: linear-gradient(90deg, #00b3c4, #00e5ff);"
    "  color: #02121a; font-weight: bold; letter-spacing: 2px;"
    "  border: 1px solid #00e5ff;"
    "}"
    ".action-button:hover {"
    "  box-shadow: 0 0 14px rgba(0,229,255,0.8);"
    "  color: #000000;"
    "}"
    "progressbar text { color: #9fe9ff; font-family: monospace; font-size: 10px; }"
    "progressbar trough {"
    "  background-color: #0c1421; border: 1px solid #14384a;"
    "  border-radius: 4px; min-height: 18px;"
    "}"
    "progressbar progress {"
    "  background: linear-gradient(90deg, #00b3c4, #39ff14);"
    "  border-radius: 4px; min-height: 18px;"
    "  box-shadow: 0 0 10px rgba(57,255,20,0.6);"
    "}"
    ".status-ok { color: #39ff14; }"
    ".status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }";

#define PASS_MAX 4096

typedef struct Job Job;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;
    GtkWidget *radio_send;
    GtkWidget *radio_recv;
    GtkWidget *host_label;
    GtkWidget *host_entry;
    GtkWidget *port_entry;
    GtkWidget *path_label;
    GtkWidget *path_entry;
    GtkWidget *path_btn;
    GtkWidget *cipher_combo;
    GtkWidget *pass_entry;
    GtkWidget *reveal_check;
    GtkWidget *action_button;
    GtkWidget *progress;
    GtkWidget *status;
    guint      pulse_id;        /* "waiting" pulse timer, 0 if none */
    gboolean   pulsing;
    volatile int window_gone;   /* set when the window is destroyed */
    Job * volatile current_job; /* in-flight job, or NULL */
} App;

/* Shared between worker thread and main loop. */
struct Job {
    App        *app;
    int         send;                 /* 1 = send, 0 = receive */
    char        host[256];            /* remote host (send) / bind addr (recv) */
    uint16_t    port;
    char        path[4096];           /* file to send / folder to save into */
    char        passphrase[PASS_MAX];
    cipher_id_t cipher;
    /* results */
    int         rc;
    char        err[256];
    char        saved_path[4096];     /* receive: where the file landed */
    /* progress (written by worker, read on main loop), guarded by plock. */
    GMutex            plock;
    double            fraction;
    uint64_t          done_bytes;
    uint64_t          total_bytes;
    volatile int      cancelled;
    volatile gint     idle_queued;
};

/* ----- progress plumbing ----------------------------------------------- */

static void human_size(uint64_t b, char *out, size_t n) {
    const char *u[] = { "B", "KB", "MB", "GB", "TB" };
    double v = (double)b; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    snprintf(out, n, i == 0 ? "%.0f %s" : "%.1f %s", v, u[i]);
}

static gboolean update_progress_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;
    g_atomic_int_set(&job->idle_queued, 0);
    if (app->window_gone) return G_SOURCE_REMOVE;
    app->pulsing = FALSE;
    GtkProgressBar *pb = GTK_PROGRESS_BAR(app->progress);
    g_mutex_lock(&job->plock);
    double   fraction = job->fraction;
    uint64_t done = job->done_bytes, tot = job->total_bytes;
    g_mutex_unlock(&job->plock);
    gtk_progress_bar_set_fraction(pb, fraction);
    char d[32], t[32], txt[96];
    human_size(done, d, sizeof d);
    human_size(tot, t, sizeof t);
    if (tot)
        snprintf(txt, sizeof txt, "%.0f%%   %s / %s", fraction * 100.0, d, t);
    else
        snprintf(txt, sizeof txt, "%s", d);
    gtk_progress_bar_set_text(pb, txt);
    return G_SOURCE_REMOVE;
}

static int progress_cb(uint64_t done, uint64_t total, void *user) {
    Job *job = user;
    g_mutex_lock(&job->plock);
    job->done_bytes = done;
    job->total_bytes = total;
    job->fraction = total ? (double)done / (double)total : 0.0;
    g_mutex_unlock(&job->plock);
    if (g_atomic_int_compare_and_exchange(&job->idle_queued, 0, 1))
        g_idle_add(update_progress_idle, job);
    return job->cancelled;
}

/* ----- status / lifecycle helpers -------------------------------------- */

static void set_status(App *app, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(app->status);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(app->status), text);
}

static void stop_pulse(App *app) {
    app->pulsing = FALSE;
    if (app->pulse_id) {
        g_source_remove(app->pulse_id);
        app->pulse_id = 0;
    }
}

static void free_app(App *app) {
    stop_pulse(app);
    g_free(app);
}

/* Re-enable the inputs after a job ends. */
static void set_running_ui(App *app, gboolean running) {
    gtk_widget_set_sensitive(app->radio_send, !running);
    gtk_widget_set_sensitive(app->radio_recv, !running);
    gtk_widget_set_sensitive(app->host_entry, !running);
    gtk_widget_set_sensitive(app->port_entry, !running);
    gtk_widget_set_sensitive(app->path_entry, !running);
    gtk_widget_set_sensitive(app->path_btn, !running);
    gtk_widget_set_sensitive(app->pass_entry, !running);
    gboolean send = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_send));
    gtk_widget_set_sensitive(app->cipher_combo, !running && send);
    /* While running the action button becomes a Cancel control. */
    gtk_button_set_label(GTK_BUTTON(app->action_button),
                         running ? "CANCEL" : (send ? "SEND" : "RECEIVE"));
}

static gboolean job_finished_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;

    app->current_job = NULL;
    stop_pulse(app);

    if (app->window_gone) {
        sodium_munlock(job->passphrase, sizeof(job->passphrase));
        g_mutex_clear(&job->plock);
        g_free(job);
        g_application_release(G_APPLICATION(app->gapp));
        free_app(app);
        return G_SOURCE_REMOVE;
    }

    set_running_ui(app, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress),
                                  job->rc == 0 ? 1.0 : 0.0);

    if (job->rc == 0) {
        gchar *msg = job->send
            ? g_strdup("\xE2\x9C\x94 File sent successfully.")
            : g_strdup_printf("\xE2\x9C\x94 File received:\n%s", job->saved_path);
        set_status(app, "status-ok", msg);
        g_free(msg);
    } else {
        gchar *msg = g_strdup_printf("\xE2\x9C\x96 %s", job->err);
        set_status(app, "status-err", msg);
        g_free(msg);
    }

    sodium_munlock(job->passphrase, sizeof(job->passphrase));
    g_mutex_clear(&job->plock);
    g_free(job);
    g_application_release(G_APPLICATION(app->gapp));
    return G_SOURCE_REMOVE;
}

static gboolean pulse_cb(gpointer data) {
    App *app = data;
    if (!app->pulsing || app->window_gone) { app->pulse_id = 0; return G_SOURCE_REMOVE; }
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress));
    return G_SOURCE_CONTINUE;
}

/* ----- worker thread ---------------------------------------------------- */

static gpointer worker_thread(gpointer data) {
    Job *job = data;
    if (job->send) {
        job->rc = pqx_send(job->host, job->port, job->path, job->cipher,
                           job->passphrase, progress_cb, job, &job->cancelled,
                           job->err, sizeof(job->err));
    } else {
        job->rc = pqx_receive(job->host, job->port, job->path, job->passphrase,
                              progress_cb, job, &job->cancelled,
                              job->saved_path, sizeof(job->saved_path),
                              job->err, sizeof(job->err));
    }
    g_idle_add(job_finished_idle, job);
    return NULL;
}

/* ----- UI callbacks ----------------------------------------------------- */

static void on_reveal_toggled(GtkToggleButton *btn, gpointer user) {
    App *app = user;
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry),
                             gtk_toggle_button_get_active(btn));
}

static void browse_path(App *app, gboolean folder) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        folder ? "Select a folder to save into" : "Select the file to send",
        GTK_WINDOW(app->window),
        folder ? GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER
               : GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        folder ? "_Choose" : "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_entry_set_text(GTK_ENTRY(app->path_entry), f);
        g_free(f);
    }
    gtk_widget_destroy(dlg);
}

static void on_browse(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    gboolean send = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_send));
    browse_path(app, !send);          /* receive picks a folder */
}

static void on_mode_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn;
    App *app = user;
    gboolean send = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_send));
    gtk_label_set_text(GTK_LABEL(app->host_label),
                       send ? "Receiver host:" : "Listen on:");
    gtk_label_set_text(GTK_LABEL(app->path_label),
                       send ? "File to send:" : "Save to folder:");
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->host_entry),
                       send ? "e.g. 192.168.1.42" : "blank = all interfaces");
    gtk_widget_set_sensitive(app->cipher_combo, send);
    gtk_button_set_label(GTK_BUTTON(app->action_button), send ? "SEND" : "RECEIVE");
    gtk_entry_set_text(GTK_ENTRY(app->path_entry), "");
}

static void warn(App *app, const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static void on_action(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;

    /* If a transfer is in flight, this button is a Cancel control. */
    if (app->current_job) {
        app->current_job->cancelled = 1;
        set_status(app, "status-run", "\xE2\x96\xB6 Cancelling\xE2\x80\xA6");
        return;
    }

    gboolean send = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_send));
    const char *host = gtk_entry_get_text(GTK_ENTRY(app->host_entry));
    const char *ports = gtk_entry_get_text(GTK_ENTRY(app->port_entry));
    const char *path = gtk_entry_get_text(GTK_ENTRY(app->path_entry));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(app->pass_entry));

    if (send && (!host || !*host)) { warn(app, "Enter the receiver's host or IP address."); return; }
    if (!path || !*path) {
        warn(app, send ? "Choose a file to send." : "Choose a folder to save into.");
        return;
    }
    int port = ports && *ports ? atoi(ports) : 0;
    if (port < 1 || port > 65535) { warn(app, "Enter a port between 1 and 65535."); return; }
    if (strlen(pass) >= PASS_MAX) { warn(app, "Passphrase is too long."); return; }
    if (host && strlen(host) >= sizeof ((Job *)0)->host) { warn(app, "Host is too long."); return; }
    if (strlen(path) >= sizeof ((Job *)0)->path) { warn(app, "Path is too long."); return; }

    Job *job = g_new0(Job, 1);
    g_mutex_init(&job->plock);
    sodium_mlock(job->passphrase, sizeof(job->passphrase));
    job->app = app;
    job->send = send ? 1 : 0;
    job->port = (uint16_t)port;
    g_strlcpy(job->host, host ? host : "", sizeof(job->host));
    g_strlcpy(job->path, path, sizeof(job->path));
    g_strlcpy(job->passphrase, pass ? pass : "", sizeof(job->passphrase));

    const gchar *cid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->cipher_combo));
    job->cipher = cid ? (cipher_id_t)atoi(cid) : CIPHER_AES_256_GCM;

    set_running_ui(app, TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress),
                              send ? "connecting\xE2\x80\xA6" : "waiting for sender\xE2\x80\xA6");
    set_status(app, "status-run",
               send ? "\xE2\x96\xB6 Connecting and negotiating keys\xE2\x80\xA6"
                    : "\xE2\x96\xB6 Listening for an incoming transfer\xE2\x80\xA6");

    app->pulsing = TRUE;
    if (app->pulse_id == 0)
        app->pulse_id = g_timeout_add(110, pulse_cb, app);

    app->current_job = job;
    g_application_hold(G_APPLICATION(app->gapp));

    GError *gerr = NULL;
    GThread *t = g_thread_try_new("pqx-worker", worker_thread, job, &gerr);
    if (!t) {
        g_application_release(G_APPLICATION(app->gapp));
        app->current_job = NULL;
        stop_pulse(app);
        set_running_ui(app, FALSE);
        set_status(app, "status-err", "\xE2\x9C\x96 Could not start worker thread.");
        sodium_munlock(job->passphrase, sizeof(job->passphrase));
        g_mutex_clear(&job->plock);
        g_free(job);
        if (gerr) g_error_free(gerr);
        return;
    }
    g_thread_unref(t);
}

static void on_about(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const gchar *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const gchar *features =
        "PQ Transfer sends a file directly between two machines over an\n"
        "end-to-end encrypted channel — no server, no cloud.\n\n"
        "Features:\n"
        "• Direct peer-to-peer TCP transfer (one sends, one receives)\n"
        "• Post-quantum hybrid key agreement (Kyber-1024 + X448):\n"
        "  the session key stays secure as long as either primitive holds\n"
        "• AES-256-GCM (default), XChaCha20-Poly1305 or\n"
        "  ChaCha20-Poly1305 authenticated encryption\n"
        "• Optional shared passphrase via a real CPace PAKE (Ristretto255):\n"
        "  authenticates the channel with no offline dictionary attack\n"
        "• Chunked streaming with per-chunk authentication\n"
        "  (tamper, reorder and truncation detection)\n"
        "• Hardened memory: passphrases and keys are kept in locked,\n"
        "  non-dumpable memory and never hit swap";

    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "PQ Transfer");
    gtk_about_dialog_set_version(ad, PQTRANSFER_VERSION);
    gtk_about_dialog_set_comments(ad, features);
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "© 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "pqtransfer");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- layout helpers --------------------------------------------------- */

static GtkWidget *labeled_row(GtkWidget *label, GtkWidget *widget, GtkWidget *extra) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_size_request(label, 120, -1);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(label), "field-label");
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), widget, TRUE, TRUE, 0);
    if (extra) gtk_box_pack_start(GTK_BOX(box), extra, FALSE, FALSE, 0);
    return box;
}

static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w;
    App *app = user;
    app->window_gone = 1;
    Job *job = app->current_job;
    if (job) job->cancelled = 1;     /* worker owns app lifetime, frees it later */
    else     free_app(app);
}

static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;

    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQ Transfer");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 600, -1);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pqtransfer");
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *title_lbl = gtk_label_new("PQ TRANSFER  \xC2\xB7  v" PQTRANSFER_VERSION);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);
    GtkWidget *hb_about = gtk_button_new_with_label("About");
    g_signal_connect(hb_about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(root), "pqx-root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 18);
    gtk_container_add(GTK_CONTAINER(app->window), root);

    GtkWidget *brand = gtk_label_new("\xE2\x87\x84 P Q   T R A N S F E R");
    gtk_label_set_xalign(GTK_LABEL(brand), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(brand), "brand");
    gtk_box_pack_start(GTK_BOX(root), brand, FALSE, FALSE, 0);
    GtkWidget *sub = gtk_label_new("POST-QUANTUM  PEER-TO-PEER  FILE  TRANSFER");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "subtitle");
    gtk_box_pack_start(GTK_BOX(root), sub, FALSE, FALSE, 0);
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(root), sep, FALSE, FALSE, 6);

    /* Mode selection */
    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    app->radio_send = gtk_radio_button_new_with_label(NULL, "Send");
    app->radio_recv = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->radio_send), "Receive");
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_send, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_recv, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), labeled_row(gtk_label_new("Mode:"), mode_box, NULL),
                       FALSE, FALSE, 0);

    /* Host / bind address */
    app->host_label = gtk_label_new("Receiver host:");
    app->host_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->host_entry), "e.g. 192.168.1.42");
    gtk_box_pack_start(GTK_BOX(root), labeled_row(app->host_label, app->host_entry, NULL),
                       FALSE, FALSE, 0);

    /* Port */
    app->port_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->port_entry), "5800");
    gtk_entry_set_width_chars(GTK_ENTRY(app->port_entry), 6);
    GtkWidget *port_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(port_box), app->port_entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), labeled_row(gtk_label_new("Port:"), port_box, NULL),
                       FALSE, FALSE, 0);

    /* File / folder */
    app->path_label = gtk_label_new("File to send:");
    app->path_entry = gtk_entry_new();
    app->path_btn = gtk_button_new_with_label("Browse…");
    g_signal_connect(app->path_btn, "clicked", G_CALLBACK(on_browse), app);
    gtk_box_pack_start(GTK_BOX(root), labeled_row(app->path_label, app->path_entry, app->path_btn),
                       FALSE, FALSE, 0);

    /* Cipher (sender chooses; receiver auto-detects from the handshake) */
    app->cipher_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "1", "AES-256-GCM (default)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "2", "XChaCha20-Poly1305");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "3", "ChaCha20-Poly1305");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->cipher_combo), "1");
    gtk_box_pack_start(GTK_BOX(root), labeled_row(gtk_label_new("Cipher:"), app->cipher_combo, NULL),
                       FALSE, FALSE, 0);

    /* Shared passphrase (optional but recommended). Stored in a libsodium
     * secure buffer (locked, non-dumpable, zeroed on free). */
    GtkEntryBuffer *pass_buf = secure_entry_buffer_new();
    app->pass_entry = gtk_entry_new_with_buffer(pass_buf);
    g_object_unref(pass_buf);
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->pass_entry), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->pass_entry), "shared secret — must match on both peers");
    app->reveal_check = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(app->reveal_check, "toggled", G_CALLBACK(on_reveal_toggled), app);
    gtk_box_pack_start(GTK_BOX(root),
                       labeled_row(gtk_label_new("Passphrase:"), app->pass_entry, app->reveal_check),
                       FALSE, FALSE, 0);

    /* Action button */
    app->action_button = gtk_button_new_with_label("SEND");
    gtk_widget_set_hexpand(app->action_button, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(app->action_button), "action-button");
    g_signal_connect(app->action_button, "clicked", G_CALLBACK(on_action), app);
    gtk_box_pack_start(GTK_BOX(root), app->action_button, FALSE, FALSE, 8);

    /* Progress + status */
    app->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "idle");
    gtk_box_pack_start(GTK_BOX(root), app->progress, FALSE, FALSE, 0);
    app->status = gtk_label_new("Ready. One peer receives, the other sends.");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->status, FALSE, FALSE, 0);

    g_signal_connect(app->radio_send, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->radio_recv, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    gtk_widget_show_all(app->window);
}

int main(int argc, char **argv) {
    if (ciphers_init() != 0) {
        g_printerr("Failed to initialise crypto library.\n");
        return 1;
    }
    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
