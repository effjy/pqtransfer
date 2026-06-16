/*
 * cpace.h - CPace balanced PAKE over Ristretto255.
 *
 * CPace lets two parties that share a (possibly low-entropy) passphrase derive
 * a strong, mutually-authenticated key while leaking *nothing* about the
 * passphrase to the network. Crucially — unlike a "hash the passphrase into the
 * key" scheme — the protocol messages are independent of the passphrase, so an
 * active attacker gets at most ONE online guess per connection and cannot mount
 * an offline dictionary attack.
 *
 * Flow (one message each way; PQ Transfer carries them inside its handshake):
 *
 *   g  = Map2Point( H( DSI | len(PRS) PRS | len(sid) sid ) )      // both sides
 *   ya, yb random scalars
 *   Ya = ya * g   (sender)        Yb = yb * g   (receiver)        // exchanged
 *   K  = ya * Yb = yb * Ya                                        // shared point
 *   ISK = H( DSI_ISK | sid | Ya | Yb | K )                        // session key
 *
 * The ISK is then folded into PQ Transfer's hybrid-KEM secret, so the channel
 * key is secure if either the KEM holds (post-quantum confidentiality) or the
 * passphrase is unknown to an active attacker (authentication).
 *
 * Reference: draft-irtf-cfrg-cpace, instantiated on libsodium Ristretto255.
 */
#ifndef PQX_CPACE_H
#define PQX_CPACE_H

#include <stddef.h>
#include <stdint.h>

#define CPACE_MSG_LEN  32     /* a Ristretto255 point (our Y value)   */
#define CPACE_ISK_LEN  32     /* derived intermediate session key     */

/* Per-session secret state: our scalar and our public message. */
typedef struct {
    uint8_t scalar[32];       /* y  (secret; zero with cpace_state_wipe) */
    uint8_t msg[CPACE_MSG_LEN]; /* Y = y * g (public) */
} cpace_state;

/* Begin CPace: derive the passphrase-dependent generator from (passphrase,
 * sid), pick a random scalar, and produce our public message in out_msg
 * (CPACE_MSG_LEN bytes). passphrase may be empty (then CPace degrades to a
 * plain ephemeral DH that adds confidentiality but no authentication).
 * Returns 0 on success, -1 on failure. */
int cpace_start(cpace_state *st, uint8_t out_msg[CPACE_MSG_LEN],
                const char *passphrase,
                const uint8_t *sid, size_t sid_len);

/* Finish CPace once the peer's message is known. Ya and Yb are the sender's
 * and the receiver's public messages respectively, supplied in that fixed
 * order on both ends so the transcript hash matches. peer_msg is whichever of
 * the two is *not* ours. Writes the intermediate session key to isk.
 * Returns 0 on success, -1 on failure (e.g. peer sent an invalid point). */
int cpace_finish(uint8_t isk[CPACE_ISK_LEN], const cpace_state *st,
                 const uint8_t peer_msg[CPACE_MSG_LEN],
                 const uint8_t Ya[CPACE_MSG_LEN],
                 const uint8_t Yb[CPACE_MSG_LEN],
                 const uint8_t *sid, size_t sid_len);

/* Zero the secret scalar in st. */
void cpace_state_wipe(cpace_state *st);

#endif /* PQX_CPACE_H */
