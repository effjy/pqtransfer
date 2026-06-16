/*
 * cpace.c - CPace balanced PAKE over Ristretto255 (see cpace.h).
 *
 * Built entirely on libsodium: crypto_core_ristretto255_from_hash is the
 * map-to-group ("Map2Point"), crypto_scalarmult_ristretto255 is the group
 * operation (and rejects the identity result), and crypto_generichash
 * (BLAKE2b) supplies both the 64-byte hash for the generator and the ISK.
 */
#include "cpace.h"

#include <sodium.h>
#include <string.h>

/* Domain-separation strings keep the generator hash and the ISK hash in
 * disjoint namespaces. */
static const char DSI_GEN[] = "PQTransfer-CPace-gen-v1";
static const char DSI_ISK[] = "PQTransfer-CPace-isk-v1";

/* Append a 4-byte little-endian length followed by the bytes, so distinct
 * (passphrase, sid) pairs can never collide into the same hash input. */
static void update_lv(crypto_generichash_state *h, const void *data, size_t len) {
    uint8_t lb[4] = {
        (uint8_t)(len & 0xff), (uint8_t)((len >> 8) & 0xff),
        (uint8_t)((len >> 16) & 0xff), (uint8_t)((len >> 24) & 0xff)
    };
    crypto_generichash_update(h, lb, sizeof(lb));
    if (len) crypto_generichash_update(h, data, len);
}

/* g = Map2Point( BLAKE2b-512( DSI_GEN | LV(PRS) | LV(sid) ) ). */
static void cpace_generator(uint8_t g[32], const char *passphrase,
                            const uint8_t *sid, size_t sid_len) {
    uint8_t h64[crypto_core_ristretto255_HASHBYTES];   /* 64 */
    crypto_generichash_state h;
    crypto_generichash_init(&h, NULL, 0, sizeof(h64));
    crypto_generichash_update(&h, (const uint8_t *)DSI_GEN, sizeof(DSI_GEN) - 1);
    update_lv(&h, passphrase, passphrase ? strlen(passphrase) : 0);
    update_lv(&h, sid, sid_len);
    crypto_generichash_final(&h, h64, sizeof(h64));
    crypto_core_ristretto255_from_hash(g, h64);
    sodium_memzero(h64, sizeof(h64));
}

int cpace_start(cpace_state *st, uint8_t out_msg[CPACE_MSG_LEN],
                const char *passphrase, const uint8_t *sid, size_t sid_len) {
    uint8_t g[32];
    cpace_generator(g, passphrase, sid, sid_len);
    crypto_core_ristretto255_scalar_random(st->scalar);
    /* Y = scalar * g. Fails only if g is the identity, which Map2Point never
     * produces for our inputs; treat any failure as fatal. */
    int rc = crypto_scalarmult_ristretto255(st->msg, st->scalar, g);
    sodium_memzero(g, sizeof(g));
    if (rc != 0) { sodium_memzero(st->scalar, sizeof(st->scalar)); return -1; }
    memcpy(out_msg, st->msg, CPACE_MSG_LEN);
    return 0;
}

int cpace_finish(uint8_t isk[CPACE_ISK_LEN], const cpace_state *st,
                 const uint8_t peer_msg[CPACE_MSG_LEN],
                 const uint8_t Ya[CPACE_MSG_LEN], const uint8_t Yb[CPACE_MSG_LEN],
                 const uint8_t *sid, size_t sid_len) {
    uint8_t K[32];
    /* K = our scalar * peer point. Returns -1 if the peer sent the identity
     * (or otherwise drove the result to the identity) -- reject that. */
    if (crypto_scalarmult_ristretto255(K, st->scalar, peer_msg) != 0) {
        sodium_memzero(K, sizeof(K));
        return -1;
    }
    crypto_generichash_state h;
    crypto_generichash_init(&h, NULL, 0, CPACE_ISK_LEN);
    crypto_generichash_update(&h, (const uint8_t *)DSI_ISK, sizeof(DSI_ISK) - 1);
    update_lv(&h, sid, sid_len);
    crypto_generichash_update(&h, Ya, CPACE_MSG_LEN);
    crypto_generichash_update(&h, Yb, CPACE_MSG_LEN);
    crypto_generichash_update(&h, K, sizeof(K));
    crypto_generichash_final(&h, isk, CPACE_ISK_LEN);
    sodium_memzero(K, sizeof(K));
    return 0;
}

void cpace_state_wipe(cpace_state *st) {
    sodium_memzero(st->scalar, sizeof(st->scalar));
}
