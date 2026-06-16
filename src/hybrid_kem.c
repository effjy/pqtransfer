/*
 * hybrid_kem.c - Kyber-1024 + X448 hybrid KEM (see hybrid_kem.h).
 *
 * Kyber-1024 comes from the bundled CRYSTALS reference code in kyber/
 * (compiled with -DKYBER_K=4); X448 is provided by OpenSSL's EVP_PKEY
 * interface; the two shared secrets are bound together with libsodium's
 * BLAKE2b (crypto_generichash) keyed by the domain string "HYBRID".
 */
#include "hybrid_kem.h"

#include <string.h>
#include <sodium.h>
#include <openssl/evp.h>

/* Kyber-1024 reference entry points (KYBER_K=4). Declared here so this file
 * does not need to pull in the kyber headers. */
extern int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ----- X448 helpers (OpenSSL) ------------------------------------------- */

static int x448_keypair(uint8_t pub[HK_X448_PUBKEY_LEN],
                        uint8_t priv[HK_X448_PRIVKEY_LEN]) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);
    if (!pctx) return -1;

    int ret = -1;
    if (EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_keygen(pctx, &pkey) > 0) {
        size_t pub_len = HK_X448_PUBKEY_LEN;
        size_t priv_len = HK_X448_PRIVKEY_LEN;
        if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) > 0 &&
            EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) > 0 &&
            pub_len == HK_X448_PUBKEY_LEN && priv_len == HK_X448_PRIVKEY_LEN) {
            ret = 0;
        }
    }
    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int x448_scalarmult(uint8_t shared[HK_X448_PUBKEY_LEN],
                           const uint8_t priv[HK_X448_PRIVKEY_LEN],
                           const uint8_t pub[HK_X448_PUBKEY_LEN]) {
    EVP_PKEY *priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, priv, HK_X448_PRIVKEY_LEN);
    EVP_PKEY *pub_pkey  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, pub, HK_X448_PUBKEY_LEN);
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if (priv_pkey && pub_pkey && (ctx = EVP_PKEY_CTX_new(priv_pkey, NULL)) != NULL) {
        size_t secret_len = HK_X448_PUBKEY_LEN;
        if (EVP_PKEY_derive_init(ctx) > 0 &&
            EVP_PKEY_derive_set_peer(ctx, pub_pkey) > 0 &&
            EVP_PKEY_derive(ctx, shared, &secret_len) > 0 &&
            secret_len == HK_X448_PUBKEY_LEN) {
            ret = 0;
        }
    }
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (priv_pkey) EVP_PKEY_free(priv_pkey);
    if (pub_pkey) EVP_PKEY_free(pub_pkey);
    return ret;
}

/* Mix the two component secrets into the final 32-byte key. */
static void hybrid_kdf(uint8_t out[HK_SHARED_SECRET_LEN],
                       const uint8_t ss_kyber[HK_KYBER_SSBYTES],
                       const uint8_t ss_x448[HK_X448_PUBKEY_LEN]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, (const uint8_t *)"HYBRID", 6, HK_SHARED_SECRET_LEN);
    crypto_generichash_update(&st, ss_kyber, HK_KYBER_SSBYTES);
    crypto_generichash_update(&st, ss_x448, HK_X448_PUBKEY_LEN);
    crypto_generichash_final(&st, out, HK_SHARED_SECRET_LEN);
}

/* ----- Public API ------------------------------------------------------- */

int hk_generate_keypair(uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES],
                        uint8_t kyber_sk[HK_KYBER_SECRETKEYBYTES],
                        uint8_t x448_pk[HK_X448_PUBKEY_LEN],
                        uint8_t x448_sk[HK_X448_PRIVKEY_LEN]) {
    if (pqcrystals_kyber1024_ref_keypair(kyber_pk, kyber_sk) != 0) return -1;
    if (x448_keypair(x448_pk, x448_sk) != 0) return -1;
    return 0;
}

int hk_encapsulate(uint8_t shared_secret[HK_SHARED_SECRET_LEN],
                   uint8_t kem_ct[HK_KEM_CT_LEN],
                   const uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES],
                   const uint8_t x448_pk[HK_X448_PUBKEY_LEN]) {
    uint8_t ct_kyber[HK_KYBER_CIPHERTEXTBYTES], ss_kyber[HK_KYBER_SSBYTES];
    uint8_t eph_pub[HK_X448_PUBKEY_LEN], eph_priv[HK_X448_PRIVKEY_LEN];
    uint8_t ss_x[HK_X448_PUBKEY_LEN];
    int ret = -1;

    if (pqcrystals_kyber1024_ref_enc(ct_kyber, ss_kyber, kyber_pk) != 0) goto out;
    if (x448_keypair(eph_pub, eph_priv) != 0) goto out;
    if (x448_scalarmult(ss_x, eph_priv, x448_pk) != 0) goto out;

    hybrid_kdf(shared_secret, ss_kyber, ss_x);
    memcpy(kem_ct, ct_kyber, HK_KYBER_CIPHERTEXTBYTES);
    memcpy(kem_ct + HK_KYBER_CIPHERTEXTBYTES, eph_pub, HK_X448_PUBKEY_LEN);
    ret = 0;
out:
    sodium_memzero(ss_kyber, sizeof(ss_kyber));
    sodium_memzero(eph_priv, sizeof(eph_priv));
    sodium_memzero(ss_x, sizeof(ss_x));
    return ret;
}

int hk_decapsulate(uint8_t shared_secret[HK_SHARED_SECRET_LEN],
                   const uint8_t kem_ct[HK_KEM_CT_LEN],
                   const uint8_t kyber_sk[HK_KYBER_SECRETKEYBYTES],
                   const uint8_t x448_sk[HK_X448_PRIVKEY_LEN]) {
    const uint8_t *ct_kyber = kem_ct;
    const uint8_t *eph_pub  = kem_ct + HK_KYBER_CIPHERTEXTBYTES;
    uint8_t ss_kyber[HK_KYBER_SSBYTES], ss_x[HK_X448_PUBKEY_LEN];
    int ret = -1;

    if (pqcrystals_kyber1024_ref_dec(ss_kyber, ct_kyber, kyber_sk) != 0) goto out;
    if (x448_scalarmult(ss_x, x448_sk, eph_pub) != 0) goto out;

    hybrid_kdf(shared_secret, ss_kyber, ss_x);
    ret = 0;
out:
    sodium_memzero(ss_kyber, sizeof(ss_kyber));
    sodium_memzero(ss_x, sizeof(ss_x));
    return ret;
}
