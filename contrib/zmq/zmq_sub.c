// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * Example ZMQ subscriber (C23; replaces the former zmq_sub.py). Prints every
 * notification of a node started with, for example,
 *
 *   zclassicd -zmqpubhashblock=tcp://127.0.0.1:28332 -zmqpubhashtx=tcp://127.0.0.1:28332 \
 *             -zmqpubrawblock=tcp://127.0.0.1:28332 -zmqpubrawtx=tcp://127.0.0.1:28332
 *
 * Build against libzmq (the depends prefix has it):
 *
 *   cc -std=c2x -O2 -Wall -Wextra -I<prefix>/include contrib/zmq/zmq_sub.c -L<prefix>/lib -lzmq -o zmq_sub
 *   ./zmq_sub [endpoint]            default tcp://127.0.0.1:28332
 *
 * Each notification is a multipart message: topic, body, 4-byte little-endian
 * sequence number. See doc/zmq.md.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>

static const char *const TOPICS[] = {"hashblock", "hashtx", "rawblock", "rawtx", "checkedblock"};

static void print_hex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    putchar('\n');
}

// One frame of a multipart message; returns its size or -1, and sets *more.
static int recv_frame(void *sock, zmq_msg_t *m, int *more)
{
    zmq_msg_init(m);
    int n = zmq_msg_recv(m, sock, 0);
    if (n < 0)
        return -1;
    size_t sz = sizeof *more;
    *more = 0;
    zmq_getsockopt(sock, ZMQ_RCVMORE, more, &sz);
    return n;
}

int main(int argc, char **argv)
{
    const char *endpoint = argc > 1 ? argv[1] : "tcp://127.0.0.1:28332";
    void *ctx = zmq_ctx_new();
    void *sub = ctx ? zmq_socket(ctx, ZMQ_SUB) : NULL;
    if (!sub) {
        fprintf(stderr, "zmq_sub: cannot create a SUB socket: %s\n", zmq_strerror(zmq_errno()));
        return 1;
    }
    for (size_t i = 0; i < sizeof TOPICS / sizeof TOPICS[0]; i++)
        if (zmq_setsockopt(sub, ZMQ_SUBSCRIBE, TOPICS[i], strlen(TOPICS[i])) != 0) {
            fprintf(stderr, "zmq_sub: subscribe %s: %s\n", TOPICS[i], zmq_strerror(zmq_errno()));
            return 1;
        }
    if (zmq_connect(sub, endpoint) != 0) {
        fprintf(stderr, "zmq_sub: connect %s: %s\n", endpoint, zmq_strerror(zmq_errno()));
        return 1;
    }
    for (;;) {
        char topic[32] = "";
        uint8_t *body = NULL;
        size_t body_len = 0;
        char seq[16] = "Unknown";
        int frame = 0, more = 1;
        while (more) {
            zmq_msg_t m;
            int n = recv_frame(sub, &m, &more);
            if (n < 0) {
                free(body);
                zmq_msg_close(&m);
                fprintf(stderr, "zmq_sub: receive failed: %s\n", zmq_strerror(zmq_errno()));
                zmq_close(sub);
                zmq_ctx_destroy(ctx);
                return 1;
            }
            const uint8_t *d = zmq_msg_data(&m);
            if (frame == 0) {
                snprintf(topic, sizeof topic, "%.*s", n < 31 ? n : 31, (const char *)d);
            } else if (frame == 1) {
                body = malloc((size_t)n ? (size_t)n : 1);
                if (body) {
                    memcpy(body, d, (size_t)n);
                    body_len = (size_t)n;
                }
            } else if (!more && n == 4) {
                snprintf(seq, sizeof seq, "%u", (unsigned)(d[0] | d[1] << 8 | d[2] << 16 | (uint32_t)d[3] << 24));
            }
            zmq_msg_close(&m);
            frame++;
        }
        if (!body)
            continue;
        if (!strcmp(topic, "hashblock")) {
            printf("- HASH BLOCK (%s) -\n", seq);
            print_hex(body, body_len);
        } else if (!strcmp(topic, "hashtx")) {
            printf("- HASH TX  (%s) -\n", seq);
            print_hex(body, body_len);
        } else if (!strcmp(topic, "rawblock")) {
            printf("- RAW BLOCK HEADER (%s) -\n", seq);
            print_hex(body, body_len < 80 ? body_len : 80);
        } else if (!strcmp(topic, "rawtx")) {
            printf("- RAW TX (%s) -\n", seq);
            print_hex(body, body_len);
        } else if (!strcmp(topic, "checkedblock")) {
            printf("- CHECKED BLOCK (%s) -\n", seq);
            print_hex(body, body_len < 80 ? body_len : 80);
        }
        fflush(stdout);
        free(body);
    }
}
