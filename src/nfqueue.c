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
#include <linux/if_packet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "globvar.h"
#include "logging.h"
#include "rawsend.h"
#include "signals.h"

static int fd = -1;
static struct nfq_handle *h = NULL;
static struct nfq_q_handle *qh = NULL;

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    uint32_t pkt_id, ifindex;
    int res, pkt_len;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkt_data;
    struct nfqnl_msg_packet_hw *hwph;
    struct sockaddr_ll sll;

    (void) nfmsg;
    (void) data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        EE("ERROR: nfq_get_msg_packet_hdr(): %s", "failure");
        return -1;
    }

    pkt_id = ntohl(ph->packet_id);

    ifindex = nfq_get_indev(nfa);
    if (!ifindex) {
        EE("ERROR: nfq_get_indev(): %s", "failure");
        goto ret_accept;
    }

    pkt_data = NULL;
    pkt_len = nfq_get_payload(nfa, &pkt_data);
    if (pkt_len < 0 || !pkt_data) {
        EE("ERROR: nfq_get_payload(): %s", "failure");
        goto ret_accept;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = ph->hw_protocol;
    sll.sll_ifindex = ifindex;
    sll.sll_pkttype = PACKET_HOST;

    /* hwph can be null on PPP interfaces */
    hwph = nfq_get_packet_hw(nfa);
    if (hwph) {
        sll.sll_halen = sizeof(hwph->hw_addr);
        memcpy(sll.sll_addr, hwph->hw_addr, sizeof(hwph->hw_addr));
    } else {
        sll.sll_halen = 0;
        memset(sll.sll_addr, 0, sizeof(sll.sll_addr));
    }

    res = fh_rawsend_handle(&sll, pkt_data, pkt_len);
    if (res < 0) {
        EE(T(fh_rawsend_handle));
        goto ret_accept;
    } else if (res) {
        goto ret_accept;
    }
    return nfq_set_verdict2(qh, pkt_id, NF_REPEAT, g_ctx.fwmark, 0, NULL);

ret_accept:
    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
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
