/*
 * nfqueue.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
 *
 * Copyright (C) 2025  MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "nfqueue.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "globvar.h"
#include "ipv4pkt.h"
#include "logging.h"
#include "process.h"
#include "signals.h"

static int fd = -1;
static struct nfq_handle *h = NULL;
static struct nfq_q_handle *qh = NULL;

static void ipaddr_to_str(struct sockaddr *addr, char ipstr[INET6_ADDRSTRLEN])
{
    static const char invalid[] = "INVALID";

    const char *res;

    if (addr->sa_family == AF_INET) {
        res = inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                        ipstr, INET6_ADDRSTRLEN);
        if (!res) {
            goto invalid;
        }
        return;
    } else if (addr->sa_family == AF_INET6) {
        res = inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr,
                        ipstr, INET6_ADDRSTRLEN);
        if (!res) {
            goto invalid;
        }
        return;
    }

invalid:
    memcpy(ipstr, invalid, sizeof(invalid));
}


static int send_ack(struct sockaddr *saddr, struct sockaddr *daddr,
                    uint16_t sport_be, uint16_t dport_be, uint32_t seq_be,
                    uint32_t ackseq_be)
{
    int pkt_len, addr_len;
    ssize_t nbytes;
    char pkt_buff[1024];

    if (daddr->sa_family == AF_INET) {
        addr_len = sizeof(struct sockaddr_in);
        pkt_len = fh_pkt4_make(pkt_buff, sizeof(pkt_buff), saddr, daddr,
                               sport_be, dport_be, seq_be, ackseq_be, 0, NULL,
                               0);
        if (pkt_len < 0) {
            E(T(fh_pkt4_make));
            return -1;
        }
    } else if (daddr->sa_family == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
        /* TODO: NOT IMPLEMENTED */
        return -1;
    } else {
        E("ERROR: Unknown address family: %d", (int) daddr->sa_family);
        return -1;
    }

    nbytes = sendto(g_ctx.sockfd, pkt_buff, pkt_len, 0, daddr, addr_len);
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int send_http(struct sockaddr *saddr, struct sockaddr *daddr,
                     uint16_t sport_be, uint16_t dport_be, uint32_t seq_be,
                     uint32_t ackseq_be)
{
    static const char *http_fmt = "GET / HTTP/1.1\r\n"
                                  "Host: %s\r\n"
                                  "Accept: */*\r\n"
                                  "\r\n";

    int http_len, pkt_len, addr_len;
    ssize_t nbytes;
    char http_buff[512], pkt_buff[1024];

    http_len = snprintf(http_buff, sizeof(http_buff), http_fmt,
                        g_ctx.hostname);
    if (http_len < 0 || (size_t) http_len >= sizeof(http_buff)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    if (daddr->sa_family == AF_INET) {
        addr_len = sizeof(struct sockaddr_in);
        pkt_len = fh_pkt4_make(pkt_buff, sizeof(pkt_buff), saddr, daddr,
                               sport_be, dport_be, seq_be, ackseq_be, 1,
                               http_buff, http_len);
        if (pkt_len < 0) {
            E(T(fh_pkt4_make));
            return -1;
        }
    } else if (daddr->sa_family == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
        /* TODO: NOT IMPLEMENTED */
        return -1;
    } else {
        E("ERROR: Unknown address family: %d", (int) saddr->sa_family);
        return -1;
    }

    nbytes = sendto(g_ctx.sockfd, pkt_buff, pkt_len, 0, daddr, addr_len);
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    uint32_t pkt_id, ack_new;
    uint16_t ethertype;
    int res, i, pkt_len, tcp_payload_len;
    struct nfqnl_msg_packet_hdr *ph;
    struct tcphdr *tcph;
    unsigned char *pkt_data;
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    struct sockaddr_storage saddr_store, daddr_store;
    struct sockaddr *saddr, *daddr;

    (void) nfmsg;
    (void) data;

    saddr = (struct sockaddr *) &saddr_store;
    daddr = (struct sockaddr *) &daddr_store;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        EE("ERROR: nfq_get_msg_packet_hdr(): %s", "failure");
        return -1;
    }

    pkt_id = ntohl(ph->packet_id);
    ethertype = ntohs(ph->hw_protocol);
    pkt_data = NULL;
    pkt_len = nfq_get_payload(nfa, &pkt_data);
    if (pkt_len < 0 || !pkt_data) {
        EE("ERROR: nfq_get_payload(): %s", "failure");
        goto ret_accept;
    }

    if (ethertype == ETHERTYPE_IP) {
        res = fh_pkt4_parse(pkt_data, pkt_len, saddr, daddr, &tcph,
                            &tcp_payload_len);
        if (res < 0) {
            EE(T(fh_pkt4_parse));
            goto ret_accept;
        }
    } else if (ethertype == ETHERTYPE_IPV6) {
        /* TODO: NOT IMPLEMENTED */
        goto ret_accept;
    } else {
        EE("ERROR: unknown ethertype 0x%04x");
        goto ret_accept;
    }

    if (!g_ctx.silent) {
        ipaddr_to_str(saddr, src_ip);
        ipaddr_to_str(daddr, dst_ip);
    }

    if (tcp_payload_len > 0) {
        E_INFO("%s:%u ===PAYLOAD(?)===> %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));
        goto ret_mark_repeat;
    } else if (tcph->syn && tcph->ack) {
        E_INFO("%s:%u ===SYN-ACK===> %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        ack_new = ntohl(tcph->seq);
        ack_new++;
        ack_new = htonl(ack_new);

        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_ack(daddr, saddr, tcph->dest, tcph->source,
                           tcph->ack_seq, ack_new);
            if (res < 0) {
                EE(T(send_ack));
                goto ret_accept;
            }
        }
        E_INFO("%s:%u <===ACK(*)=== %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_http(daddr, saddr, tcph->dest, tcph->source,
                            tcph->ack_seq, ack_new);
            if (res < 0) {
                EE(T(send_http));
                goto ret_accept;
            }
        }
        E_INFO("%s:%u <===HTTP(*)=== %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        goto ret_mark_repeat;
    } else if (tcph->ack) {
        E_INFO("%s:%u ===ACK===> %s:%u", src_ip, ntohs(tcph->source), dst_ip,
               ntohs(tcph->dest));

        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_http(daddr, saddr, tcph->dest, tcph->source,
                            tcph->ack_seq, tcph->seq);
            if (res < 0) {
                EE(T(send_http));
                goto ret_accept;
            }
        }
        E_INFO("%s:%u <===HTTP(*)=== %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        goto ret_mark_repeat;
    } else {
        E_INFO("%s:%u ===(?)===> %s:%u", src_ip, ntohs(tcph->source), dst_ip,
               ntohs(tcph->dest));
        goto ret_accept;
    }

ret_accept:
    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);

ret_mark_repeat:
    return nfq_set_verdict2(qh, pkt_id, NF_REPEAT, g_ctx.fwmark, 0, NULL);
}


int fh_nfq_setup(void)
{
    int res, opt;
    char *err_hint;
    socklen_t opt_len;

    h = nfq_open();
    if (!h) {
        switch (errno) {
            case EPERM:
                err_hint = " (Are you root?)";
                break;
            case EINVAL:
                err_hint = " (Missing kernel module?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: nfq_open(): %s%s", strerror(errno), err_hint);
        return -1;
    }

    qh = nfq_create_queue(h, g_ctx.nfqnum, &callback, NULL);
    if (!qh) {
        switch (errno) {
            case EPERM:
                res = fh_kill_running(0);
                errno = EPERM;
                if (res < 0) {
                    err_hint = " (Another process is running / Are you root?)";
                } else {
                    err_hint = " (Another process is running)";
                }
                break;
            case EINVAL:
                err_hint = " (Missing kernel module?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: nfq_create_queue(): %s%s", strerror(errno), err_hint);
        goto close_nfq;
    }

    res = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    if (res < 0) {
        E("ERROR: nfq_set_mode(): NFQNL_COPY_PACKET: %s", strerror(errno));
        goto destroy_queue;
    }

    res = nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);
    if (res < 0) {
        E("ERROR: nfq_set_queue_flags(): NFQA_CFG_F_FAIL_OPEN: %s",
          strerror(errno));
        goto destroy_queue;
    }

    fd = nfq_fd(h);

    opt_len = sizeof(opt);
    res = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &opt_len);
    if (res < 0) {
        E("ERROR: getsockopt(): SO_RCVBUF: %s", strerror(errno));
        goto destroy_queue;
    }

    if (opt < 1048576 /* 1 MB */) {
        opt = 1048576;
        res = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, sizeof(opt));
        if (res < 0) {
            E("ERROR: setsockopt(): SO_RCVBUFFORCE: %s", strerror(errno));
            goto destroy_queue;
        }
    }

    return 0;

destroy_queue:
    nfq_destroy_queue(qh);

close_nfq:
    nfq_close(h);

    return -1;
}


void fh_nfq_cleanup(void)
{
    if (qh) {
        nfq_destroy_queue(qh);
        qh = NULL;
    }

    if (h) {
        nfq_close(h);
        h = NULL;
        fd = -1;
    }
}


int fh_nfq_loop(void)
{
    static const size_t buffsize = UINT16_MAX;

    int res, ret, err_cnt;
    ssize_t recv_len;
    char *buff;

    buff = malloc(buffsize);
    if (!buff) {
        E("ERROR: malloc(): %s", strerror(errno));
        return -1;
    }

    err_cnt = 0;

    while (!g_ctx.exit) {
        if (err_cnt >= 20) {
            E("too many errors, exiting...");
            ret = -1;
            goto free_buff;
        }

        recv_len = recv(fd, buff, buffsize, 0);
        if (recv_len < 0) {
            err_cnt++;
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                case ETIMEDOUT:
                case ENOBUFS:
                    E("ERROR: recv(): %s", strerror(errno));
                    continue;
                default:
                    E("ERROR: recv(): %s", strerror(errno));
                    ret = -1;
                    goto free_buff;
            }
        }

        res = nfq_handle_packet(h, buff, recv_len);
        if (res < 0) {
            err_cnt++;
            E("ERROR: nfq_handle_packet(): %s", "failure");
            continue;
        }

        err_cnt = 0;
    }

    ret = 0;

free_buff:
    free(buff);

    return ret;
}
