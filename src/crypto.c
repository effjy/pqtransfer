/*
 * crypto.c - Ciphers core encryption engine.
 *
 * File format (all integers little-endian):
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *   0       8     magic  "CIPHERS\0"
 *   8       1     format_version (currently 1)
 *   9       1     cipher_id
 *   10      1     kdf_id (1 = Argon2id)
 *   11      1     kdf_level (informational)
 *   12      4     argon2 t_cost (iterations)
 *   16      4     argon2 m_cost (KiB)
 *   20      4     argon2 parallelism (lanes/threads)
 *   24      16    salt
 *   40      N     base nonce (N = cipher nonce length)
 *   ...           sequence of frames
 *
 * Each frame: [uint32 clen][clen bytes AEAD ciphertext+tag].
 * The plaintext is split into 64 KiB chunks. Per-chunk nonce = base nonce
 * with a 64-bit little-endian counter XORed into its trailing 8 bytes.
 * Associated data per chunk = counter(8) || final_flag(1), which
 * authenticates chunk ordering and detects truncation of the stream.
 */
#include "crypto.h"
#include "hybrid_kem.h"

#include <sodium.h>
#include <argon2.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define MAGIC          "CIPHERS\0"
#define MAGIC_LEN      8
#define FORMAT_VERSION 1          /* password-only: Argon2id -> AEAD key      */
#define FORMAT_VERSION_HYBRID 2   /* Kyber-1024 + X448 hybrid KEM (see below) */
#define KDF_ID_ARGON2ID 1
#define SALT_LEN       16
#define CHUNK_SIZE     65536
#define MAX_NONCE_LEN  24
#define MAX_TAG_LEN    16

/* ----- Hybrid KEM (format version 2) layout ----------------------------- *
 * The 40-byte common header (magic .. salt) is followed by a hybrid block,
 * then the base nonce and the usual AEAD frames. The hybrid block holds the
 * file's secret key wrapped with the Argon2id password-derived master key
 * (XChaCha20-Poly1305) and the KEM ciphertext. On decryption the password
 * unwraps the secret key, which decapsulates the KEM ciphertext back to the
 * AEAD key.
 *
 * The per-file public keys are deliberately NOT stored: decapsulation needs
 * only the secret key and the KEM ciphertext, so keeping the public keys
 * would just add ~1.6 KiB of unauthenticated (malleable) header bytes. Every
 * byte that remains is authenticated -- the wrap nonce and wrapped secret key
 * by the wrap's Poly1305 tag, and the KEM ciphertext transitively, since
 * altering it changes the decapsulated key and fails the frame AEAD tags. */
#define HYBRID_MASTERKEY_LEN  crypto_aead_xchacha20poly1305_ietf_KEYBYTES  /* 32 */
#define WRAP_NONCE_LEN        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES /* 24 */
#define WRAP_ABYTES           crypto_aead_xchacha20poly1305_ietf_ABYTES    /* 16 */
#define WRAPPED_SK_LEN        (HK_SK_LEN + WRAP_ABYTES)
#define HYBRID_BLOCK_LEN      (WRAP_NONCE_LEN + WRAPPED_SK_LEN + HK_KEM_CT_LEN)
/* Domain string bound as associated data when wrapping the secret key. */
#define WRAP_AD               ((const unsigned char *)"CIPHERS-HYBRID-WRAP")
#define WRAP_AD_LEN           19

/* Upper bounds on KDF parameters accepted from a file header on decryption.
 * A header is untrusted input; without these limits a malicious file could
 * request a multi-terabyte Argon2id allocation (instant OOM) or an absurd
 * iteration/lane count that hangs the process. The ceilings comfortably
 * cover the STRONG preset (4 GiB / t=4 / 8 lanes). */
#define MAX_KDF_M_COST    (4u * 1024u * 1024u)  /* KiB = 4 GiB */
#define MAX_KDF_T_COST    16u
#define MAX_KDF_PARALLEL  16u

/* ----- Cipher registry -------------------------------------------------- */

typedef int (*aead_encrypt_fn)(unsigned char *c, unsigned long long *clen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nonce, const unsigned char *key);

typedef int (*aead_decrypt_fn)(unsigned char *m, unsigned long long *mlen,
                               const unsigned char *c, unsigned long long clen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nonce, const unsigned char *key);

/* Adapters to give both AEADs a uniform signature (drop the unused
 * nsec argument that libsodium's combined-mode functions expose). */
static int aes_enc(unsigned char *c, unsigned long long *clen,
                   const unsigned char *m, unsigned long long mlen,
                   const unsigned char *ad, unsigned long long adlen,
                   const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int aes_dec(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *c, unsigned long long clen,
                   const unsigned char *ad, unsigned long long adlen,
                   const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}
static int xchacha_enc(unsigned char *c, unsigned long long *clen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int xchacha_dec(unsigned char *m, unsigned long long *mlen,
                       const unsigned char *c, unsigned long long clen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}
static int chacha_ietf_enc(unsigned char *c, unsigned long long *clen,
                           const unsigned char *m, unsigned long long mlen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *n, const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int chacha_ietf_dec(unsigned char *m, unsigned long long *mlen,
                           const unsigned char *c, unsigned long long clen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *n, const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}

typedef struct {
    cipher_id_t      id;
    const char      *name;
    size_t           key_len;
    size_t           nonce_len;
    size_t           tag_len;
    aead_encrypt_fn  encrypt;
    aead_decrypt_fn  decrypt;
} cipher_t;

/* To add a new cipher later (e.g. Serpent), append an entry here and a
 * matching id in crypto.h. Nothing else needs to change. */
static const cipher_t g_ciphers[] = {
    { CIPHER_AES_256_GCM, "AES-256-GCM",
      crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_NPUBBYTES,
      crypto_aead_aes256gcm_ABYTES, aes_enc, aes_dec },
    { CIPHER_XCHACHA20_POLY1305, "XChaCha20-Poly1305",
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES, xchacha_enc, xchacha_dec },
    { CIPHER_CHACHA20_POLY1305_IETF, "ChaCha20-Poly1305",
      crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_chacha20poly1305_ietf_ABYTES, chacha_ietf_enc, chacha_ietf_dec },
};
static const size_t g_ciphers_n = sizeof(g_ciphers) / sizeof(g_ciphers[0]);

static const cipher_t *find_cipher(cipher_id_t id) {
    for (size_t i = 0; i < g_ciphers_n; i++)
        if (g_ciphers[i].id == id) return &g_ciphers[i];
    return NULL;
}

const char *ciphers_cipher_name(cipher_id_t id) {
    const cipher_t *c = find_cipher(id);
    return c ? c->name : NULL;
}

int ciphers_cipher_available(cipher_id_t id) {
    if (id == CIPHER_AES_256_GCM)
        return crypto_aead_aes256gcm_is_available() ? 1 : 0;
    return find_cipher(id) != NULL;
}

int ciphers_aead_info(cipher_id_t id, ciphers_aead_t *out) {
    const cipher_t *c = find_cipher(id);
    if (!c || !out) return -1;
    out->name      = c->name;
    out->key_len   = c->key_len;
    out->nonce_len = c->nonce_len;
    out->tag_len   = c->tag_len;
    return 0;
}

int ciphers_aead_seal(cipher_id_t id, uint8_t *c, size_t *clen,
                      const uint8_t *m, size_t mlen,
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *nonce, const uint8_t *key) {
    const cipher_t *cph = find_cipher(id);
    if (!cph) return -1;
    unsigned long long out = 0;
    int rc = cph->encrypt(c, &out, m, mlen, ad, adlen, nonce, key);
    if (rc == 0 && clen) *clen = (size_t)out;
    return rc;
}

int ciphers_aead_open(cipher_id_t id, uint8_t *m, size_t *mlen,
                      const uint8_t *c, size_t clen,
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *nonce, const uint8_t *key) {
    const cipher_t *cph = find_cipher(id);
    if (!cph) return -1;
    unsigned long long out = 0;
    int rc = cph->decrypt(m, &out, c, clen, ad, adlen, nonce, key);
    if (rc == 0 && mlen) *mlen = (size_t)out;
    return rc;
}

/* ----- KDF -------------------------------------------------------------- */

typedef struct {
    uint32_t t_cost;
    uint32_t m_cost;       /* KiB */
    uint32_t parallelism;
} kdf_params_t;

static void kdf_params_for_level(kdf_level_t level, kdf_params_t *p) {
    switch (level) {
    case KDF_BASIC:
        p->t_cost = 3;  p->m_cost = 256u * 1024u;  p->parallelism = 4; /* 256 MiB */
        break;
    case KDF_STRONG:
        p->t_cost = 4;  p->m_cost = 4u * 1024u * 1024u; p->parallelism = 8; /* 4 GiB */
        break;
    case KDF_MEDIUM:
    default:
        p->t_cost = 3;  p->m_cost = 1u * 1024u * 1024u; p->parallelism = 4; /* 1 GiB */
        break;
    }
}

static int derive_key(const char *password, const uint8_t *salt,
                      const kdf_params_t *p, uint8_t *key, size_t key_len) {
    int rc = argon2id_hash_raw(p->t_cost, p->m_cost, p->parallelism,
                               password, strlen(password),
                               salt, SALT_LEN, key, key_len);
    return rc == ARGON2_OK ? 0 : -1;
}

/* ----- Hybrid KEM helpers ----------------------------------------------- */

/* Build the hybrid block and produce the 32-byte AEAD file key.
 * Generates a fresh Kyber-1024 + X448 keypair, wraps its secret key with the
 * password-derived master key, encapsulates to its public key, and lays the
 * wrap nonce, wrapped secret key and KEM ciphertext into block
 * (HYBRID_BLOCK_LEN bytes). The per-file public keys are deliberately not
 * stored (see the format notes above). Returns 0 on success, -1 on failure. */
static int hybrid_build(const char *password, const uint8_t *salt,
                        const kdf_params_t *kp,
                        uint8_t block[HYBRID_BLOCK_LEN],
                        uint8_t file_key[HK_SHARED_SECRET_LEN]) {
    uint8_t master[HYBRID_MASTERKEY_LEN];
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];   /* kyber_sk || x448_sk */
    int ret = -1;

    sodium_mlock(master, sizeof(master));
    sodium_mlock(hybrid_sk, sizeof(hybrid_sk));

    if (derive_key(password, salt, kp, master, sizeof(master)) != 0) goto out;
    if (hk_generate_keypair(kyber_pk, hybrid_sk,
                            x448_pk, hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;

    uint8_t *p = block;
    uint8_t *wrap_nonce = p;       p += WRAP_NONCE_LEN;
    uint8_t *wrapped_sk = p;       p += WRAPPED_SK_LEN;
    uint8_t *kem_ct     = p;       /* HK_KEM_CT_LEN */

    randombytes_buf(wrap_nonce, WRAP_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(wrapped_sk, NULL,
        hybrid_sk, HK_SK_LEN, WRAP_AD, WRAP_AD_LEN, NULL, wrap_nonce, master);

    if (hk_encapsulate(file_key, kem_ct, kyber_pk, x448_pk) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(hybrid_sk, sizeof(hybrid_sk));
    return ret;
}

/* Recover the 32-byte AEAD file key from a hybrid block: derive the master
 * key from the password, unwrap the secret key, and decapsulate the KEM
 * ciphertext. Returns 0 on success, -1 on failure (e.g. wrong password,
 * which is caught by the wrap tag). */
static int hybrid_open(const char *password, const uint8_t *salt,
                       const kdf_params_t *kp,
                       const uint8_t block[HYBRID_BLOCK_LEN],
                       uint8_t file_key[HK_SHARED_SECRET_LEN]) {
    uint8_t master[HYBRID_MASTERKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];
    int ret = -1;

    sodium_mlock(master, sizeof(master));
    sodium_mlock(hybrid_sk, sizeof(hybrid_sk));

    const uint8_t *wrap_nonce = block;
    const uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    const uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;

    if (derive_key(password, salt, kp, master, sizeof(master)) != 0) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(hybrid_sk, NULL, NULL,
            wrapped_sk, WRAPPED_SK_LEN, WRAP_AD, WRAP_AD_LEN, wrap_nonce, master) != 0)
        goto out;   /* wrong password or tampered key material */

    if (hk_decapsulate(file_key, kem_ct, hybrid_sk,
                       hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(hybrid_sk, sizeof(hybrid_sk));
    return ret;
}

/* ----- Little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* Build per-chunk nonce: base nonce XOR counter into trailing 8 bytes. */
static void chunk_nonce(uint8_t *out, const uint8_t *base, size_t nlen, uint64_t ctr) {
    memcpy(out, base, nlen);
    for (int i = 0; i < 8; i++)
        out[nlen - 8 + i] ^= (uint8_t)((ctr >> (8 * i)) & 0xff);
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) { snprintf(err, errlen, "%s", msg); }
}

/* Returns 1 if the two paths refer to the same existing file (same device
 * and inode, so symlinks/hardlinks are caught too). Prevents the output
 * from clobbering the input, which "wb" would otherwise truncate. */
static int same_file(const char *a, const char *b) {
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

/* Build a sibling temporary path "<out_path>.ciphers-tmp" into buf. We write
 * output here and rename() onto out_path only on success, so a pre-existing
 * output file is never truncated or deleted by a failed/cancelled operation
 * (e.g. a wrong decryption password). Returns 0 on success, -1 if the name
 * would not fit. */
static int make_tmp_path(const char *out_path, char *buf, size_t buflen) {
    int n = snprintf(buf, buflen, "%s.ciphers-tmp", out_path);
    return (n < 0 || (size_t)n >= buflen) ? -1 : 0;
}

/* ----- Public API ------------------------------------------------------- */

int ciphers_init(void) {
    if (sodium_init() < 0) return -1;

    /* Keep secrets off disk. Core dumps can contain the derived key, the
     * password and plaintext, so disable them; on Linux also clear the
     * dumpable flag (blocks ptrace and /proc-based core capture). Locked
     * pages (sodium_mlock, used per-operation below) cover the swap file:
     * mlock pins them in RAM and marks them MADV_DONTDUMP. */
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    return 0;
}

int ciphers_encrypt_file(const char *in_path, const char *out_path,
                         const char *password, cipher_id_t cipher_id,
                         kdf_level_t level, int hybrid,
                         ciphers_progress_cb cb, void *cb_user,
                         char *err, size_t errlen) {
    if (!password || !*password) {
        seterr(err, errlen, "A password is required."); return -1;
    }
    const cipher_t *cph = find_cipher(cipher_id);
    if (!cph) { seterr(err, errlen, "Unknown cipher."); return -1; }
    /* The hybrid KEM shared secret is 32 bytes, matching the AEAD key length
     * of every cipher in the registry; guard the assumption explicitly. */
    if (hybrid && cph->key_len != HK_SHARED_SECRET_LEN) {
        seterr(err, errlen, "Hybrid mode requires a 256-bit cipher key."); return -1;
    }
    if (!ciphers_cipher_available(cipher_id)) {
        seterr(err, errlen, "Cipher not supported on this CPU (AES-256-GCM needs hardware AES).");
        return -1;
    }

    if (same_file(in_path, out_path)) {
        seterr(err, errlen, "Input and output must be different files.");
        return -1;
    }

    char tmp_path[4096 + 16];
    if (make_tmp_path(out_path, tmp_path, sizeof(tmp_path)) != 0) {
        seterr(err, errlen, "Output path is too long."); return -1;
    }
    /* The temp file is opened with "wb" (truncates). If it happens to resolve
     * to the input file, that would destroy the input before we read it. */
    if (same_file(in_path, tmp_path)) {
        seterr(err, errlen, "Input and output must be different files.");
        return -1;
    }

    FILE *in = fopen(in_path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open input file."); return -1; }
    FILE *out = fopen(tmp_path, "wb");
    if (!out) { seterr(err, errlen, "Cannot open output file."); fclose(in); return -1; }

    int ret = -1;
    uint8_t key[64]; /* >= any key_len */
    uint8_t salt[SALT_LEN];
    uint8_t base_nonce[MAX_NONCE_LEN];
    /* Pin the key (and, below, the plaintext) in RAM so they cannot be
     * written to swap, and mark them non-dumpable. munlock at 'done' also
     * zeroes them. */
    sodium_mlock(key, sizeof(key));
    kdf_params_t kp;
    kdf_params_for_level(level, &kp);

    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(base_nonce, cph->nonce_len);

    /* The hybrid block is large (~6.5 KiB); allocate it on the heap so it is
     * only present when actually encrypting in hybrid mode. */
    uint8_t *hybrid_block = NULL;
    if (hybrid) {
        hybrid_block = malloc(HYBRID_BLOCK_LEN);
        if (!hybrid_block) { seterr(err, errlen, "Out of memory."); goto done; }
        if (hybrid_build(password, salt, &kp, hybrid_block, key) != 0) {
            seterr(err, errlen, "Hybrid key setup failed (KDF memory, or crypto error).");
            free(hybrid_block); hybrid_block = NULL; goto done;
        }
    } else if (derive_key(password, salt, &kp, key, cph->key_len) != 0) {
        seterr(err, errlen, "Key derivation failed (insufficient memory for this KDF level?).");
        goto done;
    }

    /* Header */
    uint8_t hdr[40];
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[8]  = hybrid ? FORMAT_VERSION_HYBRID : FORMAT_VERSION;
    hdr[9]  = (uint8_t)cipher_id;
    hdr[10] = KDF_ID_ARGON2ID;
    hdr[11] = (uint8_t)level;
    put_u32(hdr + 12, kp.t_cost);
    put_u32(hdr + 16, kp.m_cost);
    put_u32(hdr + 20, kp.parallelism);
    memcpy(hdr + 24, salt, SALT_LEN);
    if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr) ||
        (hybrid && fwrite(hybrid_block, 1, HYBRID_BLOCK_LEN, out) != HYBRID_BLOCK_LEN) ||
        fwrite(base_nonce, 1, cph->nonce_len, out) != cph->nonce_len) {
        seterr(err, errlen, "Write error."); free(hybrid_block); goto done;
    }
    free(hybrid_block); hybrid_block = NULL;

    /* Determine total size for progress. */
    uint64_t total = 0;
    if (fseek(in, 0, SEEK_END) == 0) { long t = ftell(in); if (t > 0) total = (uint64_t)t; }
    rewind(in);

    uint8_t  plain[CHUNK_SIZE];
    uint8_t  ct[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  nonce[MAX_NONCE_LEN];
    uint8_t  ad[9];
    uint8_t  lenbuf[4];
    uint64_t ctr = 0, done_bytes = 0;
    sodium_mlock(plain, sizeof(plain));   /* holds cleartext */

    for (;;) {
        size_t n = fread(plain, 1, CHUNK_SIZE, in);
        if (n == 0 && !feof(in)) { seterr(err, errlen, "Read error."); goto done; }
        int final = feof(in) ? 1 : 0;

        put_u32(ad, (uint32_t)(ctr & 0xffffffff));
        ad[4] = (uint8_t)((ctr >> 32) & 0xff);
        ad[5] = (uint8_t)((ctr >> 40) & 0xff);
        ad[6] = (uint8_t)((ctr >> 48) & 0xff);
        ad[7] = (uint8_t)((ctr >> 56) & 0xff);
        ad[8] = (uint8_t)final;

        chunk_nonce(nonce, base_nonce, cph->nonce_len, ctr);

        unsigned long long clen = 0;
        if (cph->encrypt(ct, &clen, plain, n, ad, sizeof(ad), nonce, key) != 0) {
            seterr(err, errlen, "Encryption failed."); goto done;
        }
        put_u32(lenbuf, (uint32_t)clen);
        if (fwrite(lenbuf, 1, 4, out) != 4 ||
            fwrite(ct, 1, (size_t)clen, out) != (size_t)clen) {
            seterr(err, errlen, "Write error."); goto done;
        }

        done_bytes += n;
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) break;
    }

    ret = 0;
done:
    /* munlock zeroes the buffers before unpinning them. (Safe to call even
     * if we jumped here before mlocking 'plain'.) */
    sodium_munlock(key, sizeof(key));
    sodium_munlock(plain, sizeof(plain));
    fclose(in);
    /* Flush and confirm the temp file is intact before promoting it. */
    if (ret == 0 && (fflush(out) != 0 || ferror(out))) {
        seterr(err, errlen, "Write error."); ret = -1;
    }
    fclose(out);
    if (ret == 0 && rename(tmp_path, out_path) != 0) {
        seterr(err, errlen, "Could not write output file."); ret = -1;
    }
    /* Only ever remove our own temp file, never a pre-existing output. */
    if (ret != 0) remove(tmp_path);
    return ret;
}

int ciphers_decrypt_file(const char *in_path, const char *out_path,
                         const char *password,
                         ciphers_progress_cb cb, void *cb_user,
                         char *err, size_t errlen) {
    if (same_file(in_path, out_path)) {
        seterr(err, errlen, "Input and output must be different files.");
        return -1;
    }

    char tmp_path[4096 + 16];
    if (make_tmp_path(out_path, tmp_path, sizeof(tmp_path)) != 0) {
        seterr(err, errlen, "Output path is too long."); return -1;
    }
    /* The temp file is opened with "wb" (truncates). If it happens to resolve
     * to the input file, that would destroy the input before we read it. */
    if (same_file(in_path, tmp_path)) {
        seterr(err, errlen, "Input and output must be different files.");
        return -1;
    }

    FILE *in = fopen(in_path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open input file."); return -1; }

    int ret = -1;
    FILE *out = NULL;
    uint8_t key[64];
    /* Pin the key (and, below, the recovered plaintext) in RAM: no swap,
     * non-dumpable, zeroed on munlock at 'done'. */
    sodium_mlock(key, sizeof(key));

    uint8_t hdr[40];
    if (fread(hdr, 1, sizeof(hdr), in) != sizeof(hdr) ||
        memcmp(hdr, MAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Not a Ciphers file (bad magic)."); goto done;
    }
    int hybrid = (hdr[8] == FORMAT_VERSION_HYBRID);
    if (hdr[8] != FORMAT_VERSION && !hybrid) {
        seterr(err, errlen, "Unsupported file format version."); goto done;
    }
    cipher_id_t cipher_id = (cipher_id_t)hdr[9];
    const cipher_t *cph = find_cipher(cipher_id);
    if (!cph) { seterr(err, errlen, "Unknown cipher in file."); goto done; }
    if (!ciphers_cipher_available(cipher_id)) {
        seterr(err, errlen, "Cipher in file not supported on this CPU."); goto done;
    }
    if (hdr[10] != KDF_ID_ARGON2ID) {
        seterr(err, errlen, "Unknown KDF in file."); goto done;
    }

    kdf_params_t kp;
    kp.t_cost = get_u32(hdr + 12);
    kp.m_cost = get_u32(hdr + 16);
    kp.parallelism = get_u32(hdr + 20);

    /* The header is untrusted: reject parameters that would make Argon2id
     * exhaust memory or hang. Legitimate files never exceed these bounds.
     * Argon2 also requires m_cost >= 8 * parallelism; enforce that here so an
     * out-of-range header is reported precisely instead of failing later
     * inside the KDF with a generic "key derivation failed". */
    if (kp.t_cost == 0 || kp.t_cost > MAX_KDF_T_COST ||
        kp.parallelism == 0 || kp.parallelism > MAX_KDF_PARALLEL ||
        kp.m_cost < 8u * kp.parallelism || kp.m_cost > MAX_KDF_M_COST) {
        seterr(err, errlen, "Invalid or unsafe KDF parameters in file."); goto done;
    }

    /* In hybrid mode the secret-key/KEM block precedes the base nonce. */
    if (hybrid) {
        if (cph->key_len != HK_SHARED_SECRET_LEN) {
            seterr(err, errlen, "Hybrid file uses an unsupported cipher key length."); goto done;
        }
        uint8_t *hybrid_block = malloc(HYBRID_BLOCK_LEN);
        if (!hybrid_block) { seterr(err, errlen, "Out of memory."); goto done; }
        if (fread(hybrid_block, 1, HYBRID_BLOCK_LEN, in) != HYBRID_BLOCK_LEN) {
            seterr(err, errlen, "Truncated header."); free(hybrid_block); goto done;
        }
        int hrc = hybrid_open(password, hdr + 24, &kp, hybrid_block, key);
        free(hybrid_block);
        if (hrc != 0) {
            seterr(err, errlen, "Decryption failed: wrong password or corrupted/tampered file.");
            goto done;
        }
    }

    uint8_t base_nonce[MAX_NONCE_LEN];
    if (fread(base_nonce, 1, cph->nonce_len, in) != cph->nonce_len) {
        seterr(err, errlen, "Truncated header."); goto done;
    }

    if (!hybrid && derive_key(password, hdr + 24, &kp, key, cph->key_len) != 0) {
        seterr(err, errlen, "Key derivation failed."); goto done;
    }

    out = fopen(tmp_path, "wb");
    if (!out) { seterr(err, errlen, "Cannot open output file."); goto done; }

    /* total = remaining file size for progress. done_bytes (below) counts
     * each frame's 4-byte length prefix plus its ciphertext so the fraction
     * tracks the actual bytes consumed and reaches 100% at the end. */
    uint64_t total = 0;
    long cur = ftell(in);
    if (cur >= 0 && fseek(in, 0, SEEK_END) == 0) {
        long e = ftell(in);
        if (e > cur) total = (uint64_t)(e - cur);
        fseek(in, cur, SEEK_SET);   /* only restore if we actually moved */
    }

    uint8_t  ct[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  plain[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  nonce[MAX_NONCE_LEN];
    uint8_t  ad[9];
    uint8_t  lenbuf[4];
    uint64_t ctr = 0, done_bytes = 0;
    int saw_final = 0;
    sodium_mlock(plain, sizeof(plain));   /* holds recovered cleartext */

    for (;;) {
        size_t r = fread(lenbuf, 1, 4, in);
        if (r == 0 && feof(in)) break;          /* clean end of frames */
        if (r != 4) { seterr(err, errlen, "Truncated file."); goto done; }
        uint32_t clen = get_u32(lenbuf);
        if (clen > sizeof(ct) || clen < cph->tag_len) {
            seterr(err, errlen, "Corrupt frame length."); goto done;
        }
        if (fread(ct, 1, clen, in) != clen) {
            seterr(err, errlen, "Truncated file."); goto done;
        }

        /* Peek whether another frame follows to know if this is final. */
        int final = 0;
        int ch = fgetc(in);
        if (ch == EOF) final = 1; else ungetc(ch, in);

        put_u32(ad, (uint32_t)(ctr & 0xffffffff));
        ad[4] = (uint8_t)((ctr >> 32) & 0xff);
        ad[5] = (uint8_t)((ctr >> 40) & 0xff);
        ad[6] = (uint8_t)((ctr >> 48) & 0xff);
        ad[7] = (uint8_t)((ctr >> 56) & 0xff);
        ad[8] = (uint8_t)final;

        chunk_nonce(nonce, base_nonce, cph->nonce_len, ctr);

        unsigned long long mlen = 0;
        if (cph->decrypt(plain, &mlen, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
            seterr(err, errlen, "Decryption failed: wrong password or corrupted/tampered file.");
            goto done;
        }
        if (mlen && fwrite(plain, 1, (size_t)mlen, out) != (size_t)mlen) {
            seterr(err, errlen, "Write error."); goto done;
        }

        done_bytes += (uint64_t)clen + 4u;   /* ciphertext + length prefix */
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) { saw_final = 1; break; }
    }

    if (!saw_final) { seterr(err, errlen, "File is truncated (missing final block)."); goto done; }
    ret = 0;
done:
    /* munlock zeroes the buffers before unpinning them. (Safe to call even
     * if we jumped here before mlocking 'plain'.) */
    sodium_munlock(key, sizeof(key));
    sodium_munlock(plain, sizeof(plain));
    if (in) fclose(in);
    if (out) {
        if (ret == 0 && (fflush(out) != 0 || ferror(out))) {
            seterr(err, errlen, "Write error."); ret = -1;
        }
        fclose(out);
        if (ret == 0 && rename(tmp_path, out_path) != 0) {
            seterr(err, errlen, "Could not write output file."); ret = -1;
        }
        /* Only ever remove our own temp file, never a pre-existing output. */
        if (ret != 0) remove(tmp_path);
    }
    return ret;
}
