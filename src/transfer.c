/*
 * transfer.c - PQ Transfer peer-to-peer transfer engine (see transfer.h).
 *
 * Reuses the hybrid KEM (hybrid_kem.c) and the AEAD cipher registry exposed
 * by crypto.c. Networking is plain blocking TCP made cancel-responsive by
 * driving every socket wait through poll() in short slices.
 */
#include "transfer.h"
#include "hybrid_kem.h"
#include "cpace.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define CHUNK        65536
#define SALT_LEN     16
#define MAX_NONCE    24
#define MAX_TAG      16
#define MAX_NAME     1024
#define MAGIC_LEN    8

/* Protocol magic + version. Bump the trailing byte on any wire change. */
static const uint8_t TMAGIC[MAGIC_LEN] = { 'P','Q','X','F','E','R', 0x01, 0x00 };

/* Returned by the IO helpers to distinguish a user cancel from an error. */
#define IO_OK      0
#define IO_ERR    -1
#define IO_CANCEL -2

/* ----- little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void put_u64(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}
static uint64_t get_u64(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    return v;
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

/* Per-chunk nonce: base nonce XOR counter into its trailing 8 bytes. */
static void chunk_nonce(uint8_t *out, const uint8_t *base, size_t nlen, uint64_t ctr) {
    memcpy(out, base, nlen);
    for (int i = 0; i < 8; i++)
        out[nlen - 8 + i] ^= (uint8_t)((ctr >> (8 * i)) & 0xff);
}

/* ----- cancel-aware socket IO ------------------------------------------ */

static int set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return (fl < 0) ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Wait until fd is ready for `events`, polling in 200 ms slices so a cancel
 * request is observed promptly. Returns IO_OK, IO_ERR or IO_CANCEL. */
static int wait_io(int fd, short events, volatile int *cancel) {
    struct pollfd pfd = { fd, events, 0 };
    for (;;) {
        if (cancel && *cancel) return IO_CANCEL;
        int r = poll(&pfd, 1, 200);
        if (r < 0) { if (errno == EINTR) continue; return IO_ERR; }
        if (r == 0) continue;                 /* slice elapsed, keep waiting */
        if (pfd.revents & (POLLERR | POLLNVAL)) return IO_ERR;
        return IO_OK;
    }
}

static int io_read_all(int fd, void *buf, size_t n, volatile int *cancel) {
    uint8_t *p = buf; size_t off = 0;
    while (off < n) {
        int w = wait_io(fd, POLLIN, cancel);
        if (w != IO_OK) return w;
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r == 0) return IO_ERR;            /* peer closed early */
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return IO_ERR;
        }
        off += (size_t)r;
    }
    return IO_OK;
}

static int io_write_all(int fd, const void *buf, size_t n, volatile int *cancel) {
    const uint8_t *p = buf; size_t off = 0;
    while (off < n) {
        int w = wait_io(fd, POLLOUT, cancel);
        if (w != IO_OK) return w;
        ssize_t r = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return IO_ERR;
        }
        off += (size_t)r;
    }
    return IO_OK;
}

/* Map an IO result onto err + return value for the public API. */
static int io_fail(int rc, char *err, size_t errlen, const char *what) {
    if (rc == IO_CANCEL) seterr(err, errlen, "Cancelled.");
    else                 seterr(err, errlen, what);
    return -1;
}

/* ----- session key ----------------------------------------------------- */

/* The channel key binds together the post-quantum KEM secret and the CPace
 * PAKE output (keyed by the CPace ISK), plus both CPace messages as transcript.
 *
 * Security: the key stays secret if EITHER the hybrid KEM holds (post-quantum
 * confidentiality against any passive attacker) OR the passphrase is unknown to
 * an active attacker (CPace gives mutual authentication with no offline
 * dictionary attack -- one online guess per connection). With an empty
 * passphrase CPace degrades to a plain ephemeral DH: it still contributes
 * confidentiality, but provides no authentication, so the KEM alone protects
 * the transfer against passive eavesdroppers. */
static void derive_final_key(uint8_t key[32], const uint8_t isk[CPACE_ISK_LEN],
                             const uint8_t kem_shared[32],
                             const uint8_t Ya[CPACE_MSG_LEN],
                             const uint8_t Yb[CPACE_MSG_LEN]) {
    crypto_generichash_state h;
    crypto_generichash_init(&h, isk, CPACE_ISK_LEN, 32);   /* keyed by the ISK */
    crypto_generichash_update(&h, (const uint8_t *)"PQTransfer-final-v1", 19);
    crypto_generichash_update(&h, kem_shared, 32);
    crypto_generichash_update(&h, Ya, CPACE_MSG_LEN);
    crypto_generichash_update(&h, Yb, CPACE_MSG_LEN);
    crypto_generichash_final(&h, key, 32);
}

/* ----- framing --------------------------------------------------------- *
 * Wire frame: [u8 final][u32 clen][clen bytes AEAD ct+tag].
 * The `final` flag is sent in clear but bound into the AEAD associated data
 * (counter(8) || final(1)), so flipping it on the wire fails authentication. */

static int send_frame(int fd, cipher_id_t cipher, const uint8_t *base_nonce,
                      size_t nonce_len, const uint8_t *key, uint64_t ctr,
                      int final, const uint8_t *pt, size_t ptlen,
                      volatile int *cancel) {
    uint8_t ad[9];   put_u64(ad, ctr); ad[8] = (uint8_t)final;
    uint8_t nonce[MAX_NONCE];
    chunk_nonce(nonce, base_nonce, nonce_len, ctr);

    uint8_t ct[CHUNK + MAX_TAG];
    size_t clen = 0;
    if (ciphers_aead_seal(cipher, ct, &clen, pt, ptlen, ad, sizeof(ad), nonce, key) != 0)
        return IO_ERR;

    uint8_t hdr[5];
    hdr[0] = (uint8_t)final;
    put_u32(hdr + 1, (uint32_t)clen);
    int rc = io_write_all(fd, hdr, sizeof(hdr), cancel);
    if (rc != IO_OK) return rc;
    return io_write_all(fd, ct, clen, cancel);
}

/* Receive and authenticate one frame. *final / *ptlen are set on success. */
static int recv_frame(int fd, cipher_id_t cipher, const uint8_t *base_nonce,
                      size_t nonce_len, size_t tag_len, const uint8_t *key,
                      uint64_t ctr, int *final, uint8_t *pt, size_t *ptlen,
                      volatile int *cancel) {
    uint8_t hdr[5];
    int rc = io_read_all(fd, hdr, sizeof(hdr), cancel);
    if (rc != IO_OK) return rc;
    int fin = hdr[0] ? 1 : 0;
    uint32_t clen = get_u32(hdr + 1);
    if (clen < tag_len || clen > CHUNK + tag_len) return IO_ERR;   /* corrupt */

    uint8_t ct[CHUNK + MAX_TAG];
    rc = io_read_all(fd, ct, clen, cancel);
    if (rc != IO_OK) return rc;

    uint8_t ad[9];   put_u64(ad, ctr); ad[8] = (uint8_t)fin;
    uint8_t nonce[MAX_NONCE];
    chunk_nonce(nonce, base_nonce, nonce_len, ctr);

    if (ciphers_aead_open(cipher, pt, ptlen, ct, clen, ad, sizeof(ad), nonce, key) != 0)
        return IO_ERR;            /* wrong passphrase, MITM, or tampered frame */
    *final = fin;
    return IO_OK;
}

/* ----- filename hygiene ------------------------------------------------- */

/* Reduce a received name to a safe basename within out_dir (no path
 * traversal), and pick a non-clobbering path. Writes the chosen path to
 * out_path. Returns 0 on success, -1 if the path would not fit. */
static int safe_output_path(const char *out_dir, const char *name,
                            char *out_path, size_t out_len) {
    /* Keep only the final path component; reject empty / dot names. */
    const char *base = name;
    for (const char *p = name; *p; p++)
        if (*p == '/' || *p == '\\') base = p + 1;
    if (!*base || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        base = "received.bin";

    char candidate[4096];
    int n = snprintf(candidate, sizeof(candidate), "%s/%s", out_dir, base);
    if (n < 0 || (size_t)n >= sizeof(candidate)) return -1;

    /* If it exists, insert " (k)" before the extension until a free name. */
    struct stat st;
    if (stat(candidate, &st) != 0) {
        if ((size_t)n >= out_len) return -1;
        memcpy(out_path, candidate, (size_t)n + 1);
        return 0;
    }
    const char *dot = strrchr(base, '.');
    char stem[MAX_NAME + 1], ext[256];
    if (dot && dot != base) {
        size_t sl = (size_t)(dot - base);
        if (sl >= sizeof(stem)) sl = sizeof(stem) - 1;
        memcpy(stem, base, sl); stem[sl] = '\0';
        snprintf(ext, sizeof(ext), "%s", dot);
    } else {
        snprintf(stem, sizeof(stem), "%s", base);
        ext[0] = '\0';
    }
    for (int k = 1; k < 10000; k++) {
        n = snprintf(candidate, sizeof(candidate), "%s/%s (%d)%s",
                     out_dir, stem, k, ext);
        if (n < 0 || (size_t)n >= sizeof(candidate)) return -1;
        if (stat(candidate, &st) != 0) {
            if ((size_t)n >= out_len) return -1;
            memcpy(out_path, candidate, (size_t)n + 1);
            return 0;
        }
    }
    return -1;
}

/* fsync the directory containing `path`, so the rename that publishes the
 * received file is itself durable -- otherwise a crash just after rename()
 * can leave the directory entry pointing at a truncated (or missing) file on
 * some filesystems. Best-effort: failures here do not fail the transfer. */
static void fsync_parent_dir(const char *path) {
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (slash == path) {
        dir[0] = '/'; dir[1] = '\0';
    } else if (slash) {
        size_t n = (size_t)(slash - path);
        if (n >= sizeof(dir)) return;
        memcpy(dir, path, n); dir[n] = '\0';
    } else {
        dir[0] = '.'; dir[1] = '\0';
    }
    int fd = open(dir, O_RDONLY
#ifdef O_DIRECTORY
                  | O_DIRECTORY
#endif
                  );
    if (fd < 0) return;
    fsync(fd);
    close(fd);
}

/* ----- listener -------------------------------------------------------- */

/* Create, bind and listen on port. With no bind_addr it binds the IPv6
 * wildcard with IPV6_V6ONLY disabled, so both IPv4 and IPv6 senders can
 * connect; with one, it resolves that address (IPv4 or IPv6). Returns the
 * listening fd (non-blocking) or -1. */
static int make_listener(const char *bind_addr, uint16_t port,
                         char *err, size_t errlen) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    const char *node = (bind_addr && *bind_addr) ? bind_addr : NULL;
    if (getaddrinfo(node, portstr, &hints, &res) != 0 || !res) {
        seterr(err, errlen, "Invalid bind address."); return -1;
    }
    int fd = -1;
    /* Prefer an IPv6 (dual-stack) socket when the wildcard is requested. */
    for (rp = res; rp; rp = rp->ai_next) {
        if (node == NULL && rp->ai_family != AF_INET6 && res->ai_next) continue;
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (rp->ai_family == AF_INET6) {
            int off = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        seterr(err, errlen, "Could not bind to the port (already in use?)."); return -1;
    }
    if (listen(fd, 1) != 0 || set_nonblocking(fd) != 0) {
        seterr(err, errlen, "Socket setup failed."); close(fd); return -1;
    }
    return fd;
}

/* Accept one connection, waiting (cancellably) and retrying transient races
 * where the peer disappears between poll() and accept(). Returns the fd, or
 * -1 with an IO result mapped onto err. */
static int accept_one(int lfd, volatile int *cancel, char *err, size_t errlen) {
    for (;;) {
        int w = wait_io(lfd, POLLIN, cancel);
        if (w != IO_OK) { io_fail(w, err, errlen, "Accept failed."); return -1; }
        int cfd = accept(lfd, NULL, NULL);
        if (cfd >= 0) return cfd;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED ||
            errno == EINTR) continue;                    /* transient, retry */
        seterr(err, errlen, "Accept failed."); return -1;
    }
}

/* ----- public: receive ------------------------------------------------- */

int pqx_receive(const char *bind_addr, uint16_t port,
                const char *out_dir, const char *passphrase,
                pqx_progress_cb cb, void *cb_user, volatile int *cancel,
                char *saved_path, size_t saved_len,
                char *err, size_t errlen) {
    ciphers_aead_t info;          /* cipher params, filled after handshake */
    int ret = -1, lfd = -1, cfd = -1;
    FILE *out = NULL;
    char tmp_path[4096 + 16] = {0};
    int have_tmp = 0;

    /* Hybrid keypair + CPace state (secret material pinned in locked memory). */
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t kyber_sk[HK_KYBER_SECRETKEYBYTES], x448_sk[HK_X448_PRIVKEY_LEN];
    uint8_t sid[SALT_LEN];
    uint8_t Yb[CPACE_MSG_LEN], Ya[CPACE_MSG_LEN], isk[CPACE_ISK_LEN];
    uint8_t shared[32], key[64];
    cpace_state cp;
    sodium_mlock(kyber_sk, sizeof(kyber_sk));
    sodium_mlock(x448_sk, sizeof(x448_sk));
    sodium_mlock(shared, sizeof(shared));
    sodium_mlock(key, sizeof(key));
    sodium_mlock(&cp, sizeof(cp));
    sodium_mlock(isk, sizeof(isk));

    if (hk_generate_keypair(kyber_pk, kyber_sk, x448_pk, x448_sk) != 0) {
        seterr(err, errlen, "Key generation failed."); goto done;
    }
    randombytes_buf(sid, sizeof(sid));
    if (cpace_start(&cp, Yb, passphrase, sid, sizeof(sid)) != 0) {
        seterr(err, errlen, "PAKE setup failed."); goto done;
    }

    /* Listen and accept one sender (both cancellable). */
    lfd = make_listener(bind_addr, port, err, errlen);
    if (lfd < 0) goto done;
    cfd = accept_one(lfd, cancel, err, errlen);
    if (cfd < 0) goto done;
    if (set_nonblocking(cfd) != 0) { seterr(err, errlen, "Socket setup failed."); goto done; }
    int yes = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    /* HELLO: MAGIC | sid | CPace Yb | hybrid public key. */
    {
        uint8_t hello[MAGIC_LEN + SALT_LEN + CPACE_MSG_LEN + HK_PK_LEN];
        uint8_t *p = hello;
        memcpy(p, TMAGIC, MAGIC_LEN);              p += MAGIC_LEN;
        memcpy(p, sid, SALT_LEN);                  p += SALT_LEN;
        memcpy(p, Yb, CPACE_MSG_LEN);              p += CPACE_MSG_LEN;
        memcpy(p, kyber_pk, HK_KYBER_PUBLICKEYBYTES); p += HK_KYBER_PUBLICKEYBYTES;
        memcpy(p, x448_pk, HK_X448_PUBKEY_LEN);
        int w = io_write_all(cfd, hello, sizeof(hello), cancel);
        if (w != IO_OK) { io_fail(w, err, errlen, "Handshake send failed."); goto done; }
    }

    /* Sender response: MAGIC | cipher_id | CPace Ya | kem_ct | base_nonce. */
    uint8_t rmagic[MAGIC_LEN], cidb;
    int w = io_read_all(cfd, rmagic, MAGIC_LEN, cancel);
    if (w != IO_OK) { io_fail(w, err, errlen, "Handshake receive failed."); goto done; }
    if (memcmp(rmagic, TMAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Peer is not PQ Transfer (or version mismatch)."); goto done;
    }
    w = io_read_all(cfd, &cidb, 1, cancel);
    if (w != IO_OK) { io_fail(w, err, errlen, "Handshake receive failed."); goto done; }
    cipher_id_t cipher = (cipher_id_t)cidb;
    if (ciphers_aead_info(cipher, &info) != 0) {
        seterr(err, errlen, "Peer chose an unknown cipher."); goto done;
    }
    if (!ciphers_cipher_available(cipher)) {
        seterr(err, errlen, "Peer's cipher is not supported on this CPU."); goto done;
    }

    uint8_t kem_ct[HK_KEM_CT_LEN];
    uint8_t base_nonce[MAX_NONCE];
    w = io_read_all(cfd, Ya, CPACE_MSG_LEN, cancel);
    if (w == IO_OK) w = io_read_all(cfd, kem_ct, HK_KEM_CT_LEN, cancel);
    if (w == IO_OK) w = io_read_all(cfd, base_nonce, info.nonce_len, cancel);
    if (w != IO_OK) { io_fail(w, err, errlen, "Handshake receive failed."); goto done; }

    if (hk_decapsulate(shared, kem_ct, kyber_sk, x448_sk) != 0) {
        seterr(err, errlen, "Key agreement failed."); goto done;
    }
    /* CPace: our message is Yb, the peer's is Ya. Transcript order is Ya|Yb. */
    if (cpace_finish(isk, &cp, Ya, Ya, Yb, sid, sizeof(sid)) != 0) {
        seterr(err, errlen, "PAKE failed (invalid peer message)."); goto done;
    }
    derive_final_key(key, isk, shared, Ya, Yb);

    /* Frame 0: metadata = u16 name_len | name | u64 filesize. */
    uint8_t  pt[CHUNK + MAX_TAG];
    size_t   ptlen = 0;
    int      final = 0;
    sodium_mlock(pt, sizeof(pt));
    int frc = recv_frame(cfd, cipher, base_nonce, info.nonce_len, info.tag_len,
                         key, 0, &final, pt, &ptlen, cancel);
    if (frc == IO_CANCEL) { seterr(err, errlen, "Cancelled."); goto done; }
    if (frc != IO_OK || ptlen < 2) {
        seterr(err, errlen, "Handshake failed: wrong passphrase or tampered stream.");
        goto done;
    }
    uint16_t name_len = (uint16_t)(pt[0] | (pt[1] << 8));
    if (name_len > MAX_NAME || (size_t)name_len + 2 + 8 != ptlen) {
        seterr(err, errlen, "Malformed metadata."); goto done;
    }
    char name[MAX_NAME + 1];
    memcpy(name, pt + 2, name_len); name[name_len] = '\0';
    uint64_t total = get_u64(pt + 2 + name_len);

    char out_path[4096];
    if (safe_output_path(out_dir, name, out_path, sizeof(out_path)) != 0) {
        seterr(err, errlen, "Output path is too long."); goto done;
    }
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s.pqx-tmp", out_path);
    if (tn < 0 || (size_t)tn >= sizeof(tmp_path)) {
        seterr(err, errlen, "Output path is too long."); goto done;
    }
    out = fopen(tmp_path, "wb");
    if (!out) { seterr(err, errlen, "Cannot create the output file."); goto done; }
    have_tmp = 1;

    /* Content frames (counter starts at 1). */
    uint64_t ctr = 1, done_bytes = 0;
    int saw_final = 0;
    if (cb && cb(0, total, cb_user) != 0) { seterr(err, errlen, "Cancelled."); goto done; }
    for (;;) {
        frc = recv_frame(cfd, cipher, base_nonce, info.nonce_len, info.tag_len,
                         key, ctr, &final, pt, &ptlen, cancel);
        if (frc == IO_CANCEL) { seterr(err, errlen, "Cancelled."); goto done; }
        if (frc != IO_OK) {
            seterr(err, errlen, "Transfer failed: connection lost or tampered stream.");
            goto done;
        }
        /* A zero-length content frame is only legitimate as the single final
         * frame (e.g. an empty file, or an exact-chunk-multiple tail). Reject
         * empty non-final frames so a peer cannot keep us looping forever
         * sending frames that never advance toward the declared size. */
        if (ptlen == 0 && !final) {
            seterr(err, errlen, "Malformed stream (empty frame)."); goto done;
        }
        /* The sender cannot stream more than the size it declared up front:
         * this bounds disk use and rejects a sender that lies small then keeps
         * sending. (The user also sees the declared size on the progress bar
         * and can cancel a suspiciously large transfer.) */
        if (done_bytes + ptlen > total) {
            seterr(err, errlen, "Transfer exceeds the declared size; aborted."); goto done;
        }
        if (ptlen && fwrite(pt, 1, ptlen, out) != ptlen) {
            seterr(err, errlen, "Write error (disk full?)."); goto done;
        }
        done_bytes += ptlen;
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) { saw_final = 1; break; }
    }
    if (!saw_final) { seterr(err, errlen, "Transfer truncated."); goto done; }

    /* Flush all the way to disk before the rename, so a crash or power loss
     * cannot publish a truncated/zero-length file as a completed transfer. */
    if (fflush(out) != 0 || ferror(out) || fsync(fileno(out)) != 0) {
        seterr(err, errlen, "Write error."); goto done;
    }
    fclose(out); out = NULL;
    if (rename(tmp_path, out_path) != 0) {
        seterr(err, errlen, "Could not finalize the output file."); goto done;
    }
    fsync_parent_dir(out_path);   /* make the rename durable */
    have_tmp = 0;
    if (saved_path && saved_len) snprintf(saved_path, saved_len, "%s", out_path);
    ret = 0;

done:
    sodium_munlock(pt, sizeof(pt));   /* zeroes; safe even if never locked */
    if (out) fclose(out);
    if (ret != 0 && have_tmp) remove(tmp_path);
    if (cfd >= 0) close(cfd);
    if (lfd >= 0) close(lfd);
    sodium_munlock(kyber_sk, sizeof(kyber_sk));
    sodium_munlock(x448_sk, sizeof(x448_sk));
    sodium_munlock(shared, sizeof(shared));
    sodium_munlock(key, sizeof(key));
    sodium_munlock(&cp, sizeof(cp));
    sodium_munlock(isk, sizeof(isk));
    return ret;
}

/* ----- public: send ---------------------------------------------------- */

/* Non-blocking connect to one resolved address, with a cancel-aware deadline
 * (~15 s). Returns the fd, or -1 (sets *cancelled if aborted by the user). */
static int connect_one(struct addrinfo *rp, volatile int *cancel, int *cancelled) {
    int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) return -1;
    if (set_nonblocking(fd) != 0) { close(fd); return -1; }
    int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
    if (rc == 0) return fd;                       /* immediate (loopback) */
    if (errno != EINPROGRESS) { close(fd); return -1; }
    int waited = 0;
    while (waited < 15000) {
        if (cancel && *cancel) { *cancelled = 1; close(fd); return -1; }
        struct pollfd pfd = { fd, POLLOUT, 0 };
        int r = poll(&pfd, 1, 200);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) { waited += 200; continue; }
        int soerr = 0; socklen_t sl = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr == 0) return fd;
        break;
    }
    close(fd);
    return -1;
}

/* Resolve host (IPv4 or IPv6) and connect to the first address that works. */
static int connect_to(const char *host, uint16_t port, volatile int *cancel,
                      char *err, size_t errlen) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        seterr(err, errlen, "Could not resolve the host."); return -1;
    }
    int cancelled = 0, fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = connect_one(rp, cancel, &cancelled);
        if (fd >= 0 || cancelled) break;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        seterr(err, errlen, cancelled ? "Cancelled."
                                      : "Could not connect to the receiver (timed out?).");
    }
    return fd;
}

int pqx_send(const char *host, uint16_t port,
             const char *in_path, cipher_id_t cipher, const char *passphrase,
             pqx_progress_cb cb, void *cb_user, volatile int *cancel,
             char *err, size_t errlen) {
    ciphers_aead_t info;
    if (ciphers_aead_info(cipher, &info) != 0) {
        seterr(err, errlen, "Unknown cipher."); return -1;
    }
    if (!ciphers_cipher_available(cipher)) {
        seterr(err, errlen, "Cipher not supported on this CPU (AES-256-GCM needs hardware AES).");
        return -1;
    }

    FILE *in = fopen(in_path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open the file to send."); return -1; }

    uint64_t total = 0;
    if (fseek(in, 0, SEEK_END) == 0) { long t = ftell(in); if (t > 0) total = (uint64_t)t; }
    rewind(in);

    /* Basename for the metadata frame. */
    const char *base = in_path;
    for (const char *p = in_path; *p; p++) if (*p == '/') base = p + 1;
    size_t name_len = strlen(base);
    if (name_len == 0 || name_len > MAX_NAME) name_len = 0;   /* receiver will fall back */

    int ret = -1, fd = -1;
    uint8_t shared[32], key[64];
    uint8_t Ya[CPACE_MSG_LEN], Yb[CPACE_MSG_LEN], isk[CPACE_ISK_LEN];
    cpace_state cp;
    sodium_mlock(shared, sizeof(shared));
    sodium_mlock(key, sizeof(key));
    sodium_mlock(&cp, sizeof(cp));
    sodium_mlock(isk, sizeof(isk));

    fd = connect_to(host, port, cancel, err, errlen);
    if (fd < 0) goto done;
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    /* Read HELLO: MAGIC | sid | CPace Yb | hybrid public key. */
    uint8_t hmagic[MAGIC_LEN], sid[SALT_LEN];
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    int w = io_read_all(fd, hmagic, MAGIC_LEN, cancel);
    if (w != IO_OK) { io_fail(w, err, errlen, "Handshake receive failed."); goto done; }
    if (memcmp(hmagic, TMAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Peer is not PQ Transfer (or version mismatch)."); goto done;
    }
    w = io_read_all(fd, sid, SALT_LEN, cancel);
    if (w == IO_OK) w = io_read_all(fd, Yb, CPACE_MSG_LEN, cancel);
    if (w == IO_OK) w = io_read_all(fd, kyber_pk, HK_KYBER_PUBLICKEYBYTES, cancel);
    if (w == IO_OK) w = io_read_all(fd, x448_pk, HK_X448_PUBKEY_LEN, cancel);
    if (w != IO_OK) { io_fail(w, err, errlen, "Handshake receive failed."); goto done; }

    /* Encapsulate to the receiver's key and run CPace (our message is Ya). */
    uint8_t kem_ct[HK_KEM_CT_LEN];
    if (hk_encapsulate(shared, kem_ct, kyber_pk, x448_pk) != 0) {
        seterr(err, errlen, "Key agreement failed."); goto done;
    }
    if (cpace_start(&cp, Ya, passphrase, sid, sizeof(sid)) != 0) {
        seterr(err, errlen, "PAKE setup failed."); goto done;
    }
    if (cpace_finish(isk, &cp, Yb, Ya, Yb, sid, sizeof(sid)) != 0) {
        seterr(err, errlen, "PAKE failed (invalid peer message)."); goto done;
    }
    derive_final_key(key, isk, shared, Ya, Yb);

    /* Response: MAGIC | cipher_id | CPace Ya | kem_ct | base_nonce. */
    uint8_t base_nonce[MAX_NONCE];
    randombytes_buf(base_nonce, info.nonce_len);
    {
        uint8_t resp[MAGIC_LEN + 1 + CPACE_MSG_LEN + HK_KEM_CT_LEN];
        uint8_t *p = resp;
        memcpy(p, TMAGIC, MAGIC_LEN);     p += MAGIC_LEN;
        *p++ = (uint8_t)cipher;
        memcpy(p, Ya, CPACE_MSG_LEN);     p += CPACE_MSG_LEN;
        memcpy(p, kem_ct, HK_KEM_CT_LEN);
        w = io_write_all(fd, resp, sizeof(resp), cancel);
        if (w == IO_OK) w = io_write_all(fd, base_nonce, info.nonce_len, cancel);
        if (w != IO_OK) { io_fail(w, err, errlen, "Handshake send failed."); goto done; }
    }

    /* Frame 0: metadata. */
    uint8_t pt[CHUNK + MAX_TAG];
    sodium_mlock(pt, sizeof(pt));
    {
        uint8_t meta[2 + MAX_NAME + 8];
        meta[0] = (uint8_t)(name_len & 0xff);
        meta[1] = (uint8_t)((name_len >> 8) & 0xff);
        if (name_len) memcpy(meta + 2, base, name_len);
        put_u64(meta + 2 + name_len, total);
        w = send_frame(fd, cipher, base_nonce, info.nonce_len, key,
                       0, 0, meta, 2 + name_len + 8, cancel);
        if (w != IO_OK) { io_fail(w, err, errlen, "Send failed."); goto done; }
    }

    /* Content frames (counter from 1). An empty file still sends one final,
     * zero-length frame so the receiver sees a clean end-of-stream. */
    uint64_t ctr = 1, done_bytes = 0;
    if (cb && cb(0, total, cb_user) != 0) { seterr(err, errlen, "Cancelled."); goto done; }
    for (;;) {
        size_t n = fread(pt, 1, CHUNK, in);
        if (n == 0 && ferror(in)) { seterr(err, errlen, "Read error."); goto done; }
        int final = feof(in) ? 1 : 0;
        w = send_frame(fd, cipher, base_nonce, info.nonce_len, key,
                       ctr, final, pt, n, cancel);
        if (w != IO_OK) { io_fail(w, err, errlen, "Send failed (connection lost?)."); goto done; }
        done_bytes += n;
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) break;
    }
    ret = 0;

done:
    sodium_munlock(pt, sizeof(pt));
    if (in) fclose(in);
    if (fd >= 0) close(fd);
    sodium_munlock(shared, sizeof(shared));
    sodium_munlock(key, sizeof(key));
    sodium_munlock(&cp, sizeof(cp));
    sodium_munlock(isk, sizeof(isk));
    return ret;
}
