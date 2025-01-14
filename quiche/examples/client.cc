// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <chrono>
#include <iostream>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ev.h>

#include <quiche.h>

#include "tmp_config.h"

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

ev_timer udp_timer;

int reliable_recvd = 0;
int unreliable_recvd = 0;
int total_recv = 0;
int start_time = 0;
int end_time = 0;
int end_time_tcp = 0;

struct conn_io {
    ev_timer timer;

    int sock;

    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;

    quiche_conn *conn;
};

int64_t get_current_time() {
    auto currentTime = std::chrono::system_clock::now();
    auto durationSinceEpoch = currentTime.time_since_epoch();
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(durationSinceEpoch);
    int64_t microsecondsCount = microseconds.count();
    return microsecondsCount;
}

// static void debug_log(const char *line, void *argp) {
//     fprintf(stderr, "%s\n", line);
// }

ssize_t send_using_txtime(int sock, uint8_t* out, ssize_t len, int flags, struct sockaddr * dst_addr, socklen_t dst_addr_len) {
    auto res = sendto(sock, out, len, flags, dst_addr, dst_addr_len);
    return res;
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_send_info send_info;

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE) {
            // fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = send_using_txtime(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &send_info.to,
                              send_info.to_len);

        if (sent != written) {
            perror("failed to send");
            return;
        }

        // fprintf(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    static bool req_sent = false;

    struct conn_io *conn_io = (struct conn_io *)w->data;

    static uint8_t buf[65535];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conn_io->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                // fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *) &peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conn_io->local_addr,
            conn_io->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet\n");
            continue;
        }

        // fprintf(stderr, "recv %zd bytes\n", done);
        total_recv += done;
    }

    // fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

        fprintf(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        const static uint8_t r[] = "GET /index.html\r\n";
        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), true) < 0) {
            fprintf(stderr, "failed to send HTTP request\n");
            return;
        }

        fprintf(stderr, "sent HTTP request\n");

        req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t s = 0;

        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s)) {
            // fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

            while (1) {
                bool fin = false;
                ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                        buf, sizeof(buf),
                                                        &fin);
                if (recv_len <= 0) {
                    break;
                }

                // std::cout << "Total Stream Bytes Received: " << recv_len << std::endl;
                reliable_recvd += recv_len;
                // printf("%.*s", (int) recv_len, buf);

                if (fin) {
                    end_time_tcp = get_current_time();
                }
            }
        }

        quiche_stream_iter_free(readable);

        while (1) {
            ssize_t recv_len = quiche_conn_dgram_recv(conn_io->conn, buf, sizeof(buf));
            if (recv_len < 0) {
                break;
            } else {
                // std::cout << "Total Dgram Bytes Received: " << recv_len << std::endl;
                unreliable_recvd += recv_len;
                if (unreliable_recvd >= UNRELIABLE_DATA_SIZE) {
                    end_time = get_current_time();
                    ev_timer_stop(loop, &udp_timer);
                    ev_break(EV_A_ EVBREAK_ONE);
                }
                if (start_time == 0) {
                    start_time = get_current_time();
                    ev_timer_start(loop, &udp_timer);
                }
            }
        }
    }

    flush_egress(loop, conn_io);
}

static void udp_timeout_cb(EV_P_ ev_timer *w, int revents) {
    end_time = get_current_time();
    ev_break(EV_A_ EVBREAK_ONE);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = (struct conn_io *)w->data;
    quiche_conn_on_timeout(conn_io->conn);

    // fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
                stats.recv, stats.sent, stats.lost, path_stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int main(int argc, char *argv[]) {
    const char *host = argv[1];
    const char *port = argv[2];

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    // quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_set_application_protos(config,
        (uint8_t *) "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);
    
    quiche_config_set_cc_algorithm(config, QUICHE_CC_CUBIC);
    quiche_config_set_initial_congestion_window_packets(config, 10);
    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 50000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 5000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 5000000);
    quiche_config_set_initial_max_stream_data_uni(config, 5000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);
    quiche_config_enable_dgram(config, true, 5000, 5000);
    quiche_config_verify_peer(config, false);
    quiche_config_enable_pacing(config, true);

    if (getenv("SSLKEYLOGFILE")) {
      quiche_config_log_keys(config);
    }

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return -1;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return -1;
    }

    struct conn_io *conn_io = (struct conn_io *)malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    conn_io->local_addr_len = sizeof(conn_io->local_addr);
    if (getsockname(sock, (struct sockaddr *)&conn_io->local_addr,
                    &conn_io->local_addr_len) != 0)
    {
        perror("failed to get local address of socket");
        return -1;
    };

    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid, sizeof(scid),
                                       (struct sockaddr *) &conn_io->local_addr,
                                       conn_io->local_addr_len,
                                       peer->ai_addr, peer->ai_addrlen, config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    conn_io->sock = sock;
    conn_io->conn = conn;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = conn_io;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    // ev_timer_init(&udp_timer, udp_timeout_cb, ev_time() - ev_now(loop) + 1, 0.0);
    ev_timer_init(&udp_timer, udp_timeout_cb, 0.4, 0.0);

    flush_egress(loop, conn_io);

    ev_loop(loop, 0);

    freeaddrinfo(peer);

    quiche_conn_free(conn);

    quiche_config_free(config);

    std::cout << "Reliably Received: " << (reliable_recvd*1.0/RELIABLE_DATA_SIZE) << " in " << end_time_tcp-start_time << " us." << std::endl;
    std::cout << "Unreliably Received: " << (unreliable_recvd*1.0/UNRELIABLE_DATA_SIZE) << " in " << end_time-start_time << " us."<< std::endl;
    std::cout << "Total Received: " << total_recv << std::endl;

    return 0;
}
