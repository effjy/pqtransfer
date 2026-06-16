/*
 * secure_buffer.h - A GtkEntryBuffer whose text lives in libsodium guarded,
 * locked memory (sodium_malloc): no swap, non-dumpable, zeroed on free.
 *
 * Use it as the buffer of the password GtkEntry. This keeps the entry's
 * primary copy of the password out of swappable/dumpable memory. Note that
 * GTK still makes transient copies for rendering (Pango), the clipboard and
 * the input method, so this hardens but does not fully eliminate exposure.
 *
 * Requires sodium_init() to have been called first.
 */
#ifndef CIPHERS_SECURE_BUFFER_H
#define CIPHERS_SECURE_BUFFER_H

#include <gtk/gtk.h>

#define SECURE_TYPE_ENTRY_BUFFER (secure_entry_buffer_get_type())
G_DECLARE_FINAL_TYPE(SecureEntryBuffer, secure_entry_buffer,
                     SECURE, ENTRY_BUFFER, GtkEntryBuffer)

/* Create a new secure entry buffer (floating/owned like any GObject). */
GtkEntryBuffer *secure_entry_buffer_new(void);

#endif /* CIPHERS_SECURE_BUFFER_H */
