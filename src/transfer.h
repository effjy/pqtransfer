/*
 * transfer.h - PQ Transfer peer-to-peer file transfer engine.
 *
 * A direct TCP transfer protected by the same post-quantum hybrid KEM
 * (Kyber-1024 + X448) and AEAD ciphers used by the file engine in crypto.c.
 * One peer receives (listens on a port); the other sends (connects to it).
 *
 * Handshake (all sizes from hybrid_kem.h / the cipher registry):
 *
 *   receiver -> sender   MAGIC | salt(16) | hybrid_pk(HK_PK_LEN)
 *   sender   -> receiver MAGIC | cipher_id(1) | kem_ct(HK_KEM_CT_LEN)
 *                              | base_nonce(nonce_len)
 *
 * The receiver generates a fresh hybrid keypair per connection and sends its
 * public key; the sender encapsulates to it, yielding a 32-byte shared secret.
 * If a passphrase is supplied, it is stretched with Argon2id over the salt and
 * folded into the shared secret, so a passive eavesdropper learns nothing and
 * an active man-in-the-middle (who cannot know the passphrase) derives a
 * different key and fails the very first authentication tag.
 *
 * After the handshake the file is streamed as a sequence of AEAD frames,
 * identical in shape to the on-disk format: [uint32 clen][clen bytes]. Frame 0
 * carries metadata (filename + size); the remaining frames carry the file in
 * 64 KiB chunks. Per-chunk associated data = counter(8) || final(1), so
 * reordering, truncation or tampering is detected.
 */
#ifndef PQX_TRANSFER_H
#define PQX_TRANSFER_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

/* Progress callback: bytes transferred / total. Return non-zero to abort. */
typedef int (*pqx_progress_cb)(uint64_t done, uint64_t total, void *user);

/* Receive a file. Listens on bind_addr (NULL or "" = all interfaces) and
 * port, accepts a single sender, and writes the received file into out_dir.
 * The full saved path is copied into saved_path (size saved_len).
 *
 * passphrase may be NULL/empty (confidentiality only) or a shared secret word
 * that both peers must match (authenticates the channel against tampering and
 * man-in-the-middle). *cancel, if non-NULL, is polled to abort.
 *
 * Returns 0 on success; non-zero on failure with a message in err. */
int pqx_receive(const char *bind_addr, uint16_t port,
                const char *out_dir, const char *passphrase,
                pqx_progress_cb cb, void *cb_user, volatile int *cancel,
                char *saved_path, size_t saved_len,
                char *err, size_t errlen);

/* Send a file. Connects to host:port and transfers in_path encrypted under
 * the chosen cipher. passphrase and cancel behave as for pqx_receive.
 *
 * Returns 0 on success; non-zero on failure with a message in err. */
int pqx_send(const char *host, uint16_t port,
             const char *in_path, cipher_id_t cipher, const char *passphrase,
             pqx_progress_cb cb, void *cb_user, volatile int *cancel,
             char *err, size_t errlen);

#endif /* PQX_TRANSFER_H */
