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
#include <iostream>
#include <vector>

#include <chrono>
#include <thread>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/net_tstamp.h>
#include <linux/ip.h>

#include <ev.h>
#include <uthash.h>

#include <quiche.h>

#include "tmp_config.h"

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350
#define MAX_PKT_SIZE 1200 // Used for sending unreliable datagrams

int total_flushed = 0;
std::string reliable_resp = "";
int processed = 0;

void make_chunks_and_send_as_dgrams(quiche_conn *conn, const uint8_t *buf, size_t buf_len) {
    int total_sent = 0;
    while (total_sent < buf_len) {
        auto bytes_sent = quiche_conn_dgram_send(conn, (uint8_t *) buf, std::min((unsigned long)MAX_PKT_SIZE, buf_len-total_sent));

        if (bytes_sent == -1) {
            std::cerr << "Could not send dgrams" << std::endl;
            return;
        }
        total_sent += bytes_sent;
    }

    std::cout << "Total Dgrams Data sent: " << total_sent << std::endl;

    return;
}

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

struct connections {
    int sock;

    struct sockaddr *local_addr;
    socklen_t local_addr_len;

    struct conn_io *h;
};

struct conn_io {
    ev_timer timer;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    UT_hash_handle hh;
};

static quiche_config *config = NULL;

static struct connections *conns = NULL;

static void timeout_cb(EV_P_ ev_timer *w, int revents);

// static void debug_log(const char *line, void *argp) {
//     fprintf(stderr, "%s\n", line);
// }

ssize_t send_using_txtime(int sock, uint8_t* out, ssize_t len, int flags, struct sockaddr * dst_addr, socklen_t dst_addr_len, timespec txtime) {
    // return sendto(sock, out, len, flags, dst_addr, dst_addr_len);
    struct iovec iov[1];
    iov[0].iov_base = out;
    iov[0].iov_len = len;

    // Create a control message with SCM_TXTIME
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = dst_addr;
    msg.msg_namelen = dst_addr_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    // Create a control message buffer
    char control_data[CMSG_SPACE(sizeof(struct timespec))];
    msg.msg_control = control_data;
    msg.msg_controllen = sizeof(control_data);

    // Set up the control message
    struct cmsghdr *cmsg;
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_TXTIME;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));
    uint64_t timestamp_ns = txtime.tv_sec *(1000ULL * 1000 * 1000) + txtime.tv_nsec;

    memcpy(CMSG_DATA(cmsg), &timestamp_ns, sizeof(uint64_t));

    // Send the message with control information
    ssize_t bytes_sent = sendmsg(sock, &msg, 0);
    if (bytes_sent == -1) {
        perror("sendmsg");
        close(sock);
        return -1;
    }
    return bytes_sent;
}

constexpr uint64_t NANOS_PER_SEC = 1'000'000'000;

uint64_t std_time_to_u64(const std::chrono::time_point<std::chrono::system_clock>& time) {
    const std::chrono::time_point<std::chrono::system_clock> UNIX_EPOCH;

    auto raw_time = time - UNIX_EPOCH;

    auto sec = std::chrono::duration_cast<std::chrono::seconds>(raw_time).count();
    auto nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(raw_time % std::chrono::seconds(1)).count();

    return static_cast<uint64_t>(sec) * NANOS_PER_SEC + static_cast<uint64_t>(nsec);
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
                              send_info.to_len, send_info.at);

        if (sent != written) {
            perror("failed to send");
            return;
        }

        total_flushed += sent;
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) {
    int rng = open("/dev/urandom", O_RDONLY);

    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    return cid;
}

static struct conn_io *create_conn(uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *local_addr,
                                   socklen_t local_addr_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len)
{
    total_flushed = 0;
    struct conn_io *conn_io = (struct conn_io *)calloc(1, sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    if (scid_len != LOCAL_CONN_ID_LEN) {
        fprintf(stderr, "failed, scid length too short\n");
    }

    memcpy(conn_io->cid, scid, LOCAL_CONN_ID_LEN);

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len,
                                      local_addr,
                                      local_addr_len,
                                      (struct sockaddr *) peer_addr,
                                      peer_addr_len,
                                      config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    fprintf(stderr, "new connection\n");

    return conn_io;
}

static void recv_cb(EV_P_ ev_io *w, int revents) {

    int tcp_data_size = RELIABLE_DATA_SIZE;
    std::vector<char> tcp_data_buffer(tcp_data_size, 'T');

    int udp_data_size = UNRELIABLE_DATA_SIZE;
    std::vector<char> udp_data_buffer(udp_data_size, 'U');
    udp_data_buffer[udp_data_size-1] = 'C';

    struct conn_io *tmp, *conn_io = NULL;

    uint8_t buf[65535];
    uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
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

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            fprintf(stderr, "failed to parse header: %d\n", rc);
            continue;
        }

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            if (!quiche_version_is_supported(version)) {
                fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create vneg packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            if (token_len == 0) {
                fprintf(stderr, "stateless retry\n");

                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len,
                           token, &token_len);

                uint8_t new_cid[LOCAL_CONN_ID_LEN];

                if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
                    continue;
                }

                ssize_t written = quiche_retry(scid, scid_len,
                                               dcid, dcid_len,
                                               new_cid, LOCAL_CONN_ID_LEN,
                                               token, token_len,
                                               version, out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create retry packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }


            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                fprintf(stderr, "invalid address validation token\n");
                continue;
            }

            conn_io = create_conn(dcid, dcid_len, odcid, odcid_len,
                                  conns->local_addr, conns->local_addr_len,
                                  &peer_addr, peer_addr_len);

            if (conn_io == NULL) {
                continue;
            }
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            conns->local_addr,
            conns->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }



        // fprintf(stderr, "recv %zd bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn)) {
            uint64_t ws = 0;
            quiche_stream_iter *writable = quiche_conn_writable(conn_io->conn);
            while (quiche_stream_iter_next(writable, &ws)) {
                if (processed < reliable_resp.size()) {
                    auto bytes_sent = quiche_conn_stream_send(conn_io->conn, ws, (uint8_t *) reliable_resp.data()+processed, reliable_resp.size()-processed, true);
                    processed += bytes_sent;
                }
            }
            quiche_stream_iter_free(writable);

            uint64_t s = 0;

            quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

            while (quiche_stream_iter_next(readable, &s)) {
                fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

                bool fin = false;
                ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                           buf, sizeof(buf),
                                                           &fin);
                if (recv_len < 0) {
                    break;
                }

                auto msg = "init";
                if (strncmp((char *)buf, "udp", 3)) {
                    msg = "udp";
                } else if (strncmp((char *)buf, "tcp", 3)) {
                    msg = "tcp";
                }

                msg = "udp";

                if (fin) {
                    reliable_resp = "byez\n";
                    std::string unreliable_resp = "";
                    if (strncmp((char *)msg, "tcp", 3) == 0) {
                        std::cout << "Sending Only Reliable Data" << std::endl;
                        reliable_resp = (std::string)tcp_data_buffer.data() + (std::string)udp_data_buffer.data();
                        unreliable_resp = "";
                    } else if (strncmp((char *)msg, "udp", 3) == 0) {
                        std::cout << "Sending Both Reliable (" << tcp_data_buffer.size() << ") & Unreliable Data (" << udp_data_buffer.size() << ")" << std::endl;
                        reliable_resp = (std::string)tcp_data_buffer.data();
                        unreliable_resp = (std::string)udp_data_buffer.data();
                    }

                    auto bytes_sent = quiche_conn_stream_send(conn_io->conn, s, (uint8_t *) reliable_resp.data(), reliable_resp.size(), true);
                    processed = bytes_sent;

                    if (unreliable_resp.size() > 1) {
                        make_chunks_and_send_as_dgrams(conn_io->conn, (uint8_t *) unreliable_resp.data(), unreliable_resp.size());
                    }
                }
            }

            quiche_stream_iter_free(readable);
        }
    }

    HASH_ITER(hh, conns->h, conn_io, tmp) {
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn)) {
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn_io->conn, &stats);
            quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

            fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                    stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = (struct conn_io *)w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);
        std::cout << "Total flushed: " << total_flushed << std::endl;
        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

        return;
    }
}

static void setsockopt_txtime(int sock)
{
    // Method from https://github.com/zephyrproject-rtos/zephyr/blob/main/samples/net/sockets/txtime/src/main.c
    // bool optval = true;
	// if (setsockopt(sock, SOL_SOCKET, SO_TXTIME, &optval, sizeof(optval))) {
    //     perror("setsockopt txtime (0)");
    // }

    // Method from https://unix.stackexchange.com/questions/718661/after-enabling-etf-qdisc-packets-are-only-sent-for-a-few-seconds
    struct sock_txtime so_txtime_val = { .clockid = CLOCK_MONOTONIC, .flags = 0 };
    so_txtime_val.flags = (SOF_TXTIME_REPORT_ERRORS);

    if (setsockopt(sock, SOL_SOCKET, SO_TXTIME, &so_txtime_val, sizeof(so_txtime_val))) {
        perror("setsockopt txtime::");
        exit(1);
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

    struct addrinfo *local;
    if (getaddrinfo(host, port, &hints, &local) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    setsockopt_txtime(sock);

    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, "./cert.crt");
    quiche_config_load_priv_key_from_pem_file(config, "./cert.key");

    quiche_config_set_application_protos(config,
        (uint8_t *) "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

    quiche_config_set_initial_congestion_window_packets(config, 10);
    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 50000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 5000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 5000000);
    quiche_config_set_initial_max_stream_data_uni(config, 5000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_CUBIC);
    quiche_config_verify_peer(config, false);
    quiche_config_enable_dgram(config, true, 5000, 5000);
    quiche_config_enable_pacing(config, true);

    struct connections c;
    c.sock = sock;
    c.h = NULL;
    c.local_addr = local->ai_addr;
    c.local_addr_len = local->ai_addrlen;

    conns = &c;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = &c;

    ev_loop(loop, 0);

    freeaddrinfo(local);

    quiche_config_free(config);

    return 0;
}

// Don't forget to run `sudo tc qdisc add dev lo root fq maxrate 2gbit`