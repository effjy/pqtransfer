/*
 * crypto.h - Ciphers core encryption engine.
 *
 * The engine is deliberately built around a small cipher registry so that
 * new AEAD ciphers (e.g. Serpent) can be added later by appending a single
 * entry to the table in crypto.c -- the GUI and file format need no changes.
 */
#ifndef CIPHERS_CRYPTO_H
#define CIPHERS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Cipher identifiers stored in the file header. Never renumber existing
 * values -- only append new ones so old files keep decrypting. */
typedef enum {
    CIPHER_AES_256_GCM            = 1,
    CIPHER_XCHACHA20_POLY1305     = 2,
    CIPHER_CHACHA20_POLY1305_IETF = 3,
} cipher_id_t;

/* Key derivation strength presets. Medium is the minimum recommended:
 * 1 GiB memory and multi-lane (parallel) Argon2id. */
typedef enum {
    KDF_BASIC  = 0,
    KDF_MEDIUM = 1,   /* minimum: 1 GiB, parallel */
    KDF_STRONG = 2,
} kdf_level_t;

/* Progress callback: called periodically with bytes processed / total.
 * Return 0 to continue, non-zero to abort the operation. */
typedef int (*ciphers_progress_cb)(uint64_t done, uint64_t total, void *user);

/* Initialise the crypto subsystem (libsodium). Returns 0 on success. */
int ciphers_init(void);

/* Returns 1 if the given cipher is usable on this machine, else 0.
 * (AES-256-GCM requires hardware AES support.) */
int ciphers_cipher_available(cipher_id_t id);

/* Human-readable name for a cipher id, or NULL if unknown. */
const char *ciphers_cipher_name(cipher_id_t id);

/* Encrypt in_path -> out_path. Returns 0 on success; on failure returns
 * non-zero and fills err (size errlen) with a message.
 *
 * If hybrid is non-zero, a post-quantum hybrid KEM layer is used: a fresh
 * Kyber-1024 + X448 keypair is generated for the file, its secret key is
 * wrapped with the Argon2id password-derived master key, and the KEM
 * shared secret becomes the AEAD key. The password still protects
 * everything, so decryption needs only the password. */
int ciphers_encrypt_file(const char *in_path, const char *out_path,
                         const char *password, cipher_id_t cipher,
                         kdf_level_t level, int hybrid,
                         ciphers_progress_cb cb, void *cb_user,
                         char *err, size_t errlen);

/* Decrypt in_path -> out_path. The cipher and KDF parameters are read from
 * the file header. Returns 0 on success; non-zero on failure (wrong
 * password, corruption, etc.). */
int ciphers_decrypt_file(const char *in_path, const char *out_path,
                         const char *password,
                         ciphers_progress_cb cb, void *cb_user,
                         char *err, size_t errlen);

/* ----- AEAD primitive access -------------------------------------------- *
 * These expose the cipher registry directly so other modules (e.g. the
 * peer-to-peer transfer engine) can run the same authenticated ciphers over
 * an arbitrary byte stream without duplicating the adapter table. */

/* Parameters of a registered cipher. */
typedef struct {
    const char *name;
    size_t      key_len;
    size_t      nonce_len;
    size_t      tag_len;
} ciphers_aead_t;

/* Fill out with the parameters of cipher id. Returns 0 on success, -1 if the
 * id is unknown. */
int ciphers_aead_info(cipher_id_t id, ciphers_aead_t *out);

/* One-shot combined-mode AEAD seal/open with the registry cipher. The output
 * length is written to *clen / *mlen. Return 0 on success, non-zero on
 * failure (unknown cipher, or a failed authentication tag on open). */
int ciphers_aead_seal(cipher_id_t id, uint8_t *c, size_t *clen,
                      const uint8_t *m, size_t mlen,
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *nonce, const uint8_t *key);
int ciphers_aead_open(cipher_id_t id, uint8_t *m, size_t *mlen,
                      const uint8_t *c, size_t clen,
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *nonce, const uint8_t *key);

#endif /* CIPHERS_CRYPTO_H */
