/*
 * secure_buffer.c - GtkEntryBuffer backed by libsodium guarded memory.
 *
 * The text is stored in a sodium_malloc'd, NUL-terminated buffer that is
 * locked into RAM (no swap), placed between guard pages and zeroed when
 * freed. We override the four storage vfuncs of GtkEntryBuffer; the base
 * class still handles signals and the max-length clamp before calling us.
 *
 * The character/byte bookkeeping mirrors GTK's own default buffer
 * implementation so behaviour (UTF-8 positions, etc.) is identical.
 */
#include "secure_buffer.h"

#include <sodium.h>
#include <string.h>

struct _SecureEntryBuffer {
    GtkEntryBuffer parent_instance;
    char  *text;       /* sodium_malloc'd, always NUL-terminated */
    gsize  cap;        /* allocated bytes (includes room for NUL) */
    gsize  n_bytes;    /* length in bytes, excluding NUL */
    guint  n_chars;    /* length in characters */
};

G_DEFINE_TYPE(SecureEntryBuffer, secure_entry_buffer, GTK_TYPE_ENTRY_BUFFER)

/* Ensure at least `need` bytes (including the NUL terminator) are available,
 * growing into a fresh guarded allocation and wiping the old one. */
static void ensure_cap(SecureEntryBuffer *self, gsize need) {
    if (need <= self->cap) return;
    gsize newcap = self->cap ? self->cap : 32;
    while (newcap < need) newcap *= 2;
    char *nt = sodium_malloc(newcap);
    if (!nt) g_error("secure_buffer: out of locked memory");
    if (self->text) {
        memcpy(nt, self->text, self->n_bytes + 1);  /* copy text + NUL */
        sodium_free(self->text);                     /* zeroes old region */
    } else {
        nt[0] = '\0';
    }
    self->text = nt;
    self->cap = newcap;
}

static const char *seb_get_text(GtkEntryBuffer *buffer, gsize *n_bytes) {
    SecureEntryBuffer *self = SECURE_ENTRY_BUFFER(buffer);
    if (n_bytes) *n_bytes = self->n_bytes;
    return self->text ? self->text : "";
}

static guint seb_get_length(GtkEntryBuffer *buffer) {
    return SECURE_ENTRY_BUFFER(buffer)->n_chars;
}

static guint seb_insert_text(GtkEntryBuffer *buffer, guint position,
                             const char *chars, guint n_chars) {
    SecureEntryBuffer *self = SECURE_ENTRY_BUFFER(buffer);
    gsize n_bytes = g_utf8_offset_to_pointer(chars, n_chars) - chars;

    ensure_cap(self, self->n_bytes + n_bytes + 1);

    gsize at = g_utf8_offset_to_pointer(self->text, position) - self->text;
    memmove(self->text + at + n_bytes, self->text + at, self->n_bytes - at);
    memcpy(self->text + at, chars, n_bytes);

    self->n_bytes += n_bytes;
    self->n_chars += n_chars;
    self->text[self->n_bytes] = '\0';

    gtk_entry_buffer_emit_inserted_text(buffer, position, chars, n_chars);
    return n_chars;
}

static guint seb_delete_text(GtkEntryBuffer *buffer, guint position,
                             guint n_chars) {
    SecureEntryBuffer *self = SECURE_ENTRY_BUFFER(buffer);

    if (position > self->n_chars) position = self->n_chars;
    if (position + n_chars > self->n_chars) n_chars = self->n_chars - position;

    if (n_chars > 0) {
        gsize start = g_utf8_offset_to_pointer(self->text, position) - self->text;
        gsize end   = g_utf8_offset_to_pointer(self->text, position + n_chars) - self->text;

        memmove(self->text + start, self->text + end, self->n_bytes - end);
        self->n_bytes -= (end - start);
        self->n_chars -= n_chars;
        self->text[self->n_bytes] = '\0';

        gtk_entry_buffer_emit_deleted_text(buffer, position, n_chars);
    }
    return n_chars;
}

static void secure_entry_buffer_finalize(GObject *obj) {
    SecureEntryBuffer *self = SECURE_ENTRY_BUFFER(obj);
    if (self->text) {
        sodium_free(self->text);   /* zeroes the guarded region */
        self->text = NULL;
    }
    self->cap = self->n_bytes = 0;
    self->n_chars = 0;
    G_OBJECT_CLASS(secure_entry_buffer_parent_class)->finalize(obj);
}

static void secure_entry_buffer_init(SecureEntryBuffer *self) {
    self->text = NULL;
    self->cap = self->n_bytes = 0;
    self->n_chars = 0;
    ensure_cap(self, 1);   /* allocate an empty, NUL-terminated buffer */
}

static void secure_entry_buffer_class_init(SecureEntryBufferClass *klass) {
    G_OBJECT_CLASS(klass)->finalize = secure_entry_buffer_finalize;

    GtkEntryBufferClass *bc = GTK_ENTRY_BUFFER_CLASS(klass);
    bc->get_text    = seb_get_text;
    bc->get_length  = seb_get_length;
    bc->insert_text = seb_insert_text;
    bc->delete_text = seb_delete_text;
}

GtkEntryBuffer *secure_entry_buffer_new(void) {
    return g_object_new(SECURE_TYPE_ENTRY_BUFFER, NULL);
}
