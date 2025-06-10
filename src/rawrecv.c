/*
 * rawrecv.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "rawrecv.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include "globvar.h"
#include "ipv4bpf.h"
#include "ipv4pkt.h"
#include "ipv6pkt.h"
#include "rawsend.h"
#include "logging.h"

static int sockfd = -1;

int fh_rawrecv_setup(void)
{
    int res;
    uint16_t ethertype;
    unsigned int ifindex;
    const char *err_hint;
    struct sockaddr_ll sll_bind;

    E("WARNING: Experimental feature!");

    if (g_ctx.use_ipv4 && !g_ctx.use_ipv6) {
        ethertype = ETH_P_IP;
    } else if (!g_ctx.use_ipv4 && g_ctx.use_ipv6) {
        ethertype = ETH_P_IPV6;
        E("ERROR: IPv6 is not implemented. please use -4.");
    } else {
        ethertype = ETH_P_ALL;
        E("ERROR: IPv6 is not implemented. please use -4.");
    }

    sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ethertype));
    if (sockfd < 0) {
        switch (errno) {
            case EPERM:
                err_hint = " (Are you root?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: socket(): %s%s", strerror(errno), err_hint);
        return -1;
    }

    ifindex = if_nametoindex(g_ctx.iface);
    if (!ifindex) {
        E("ERROR: if_nametoindex(): %s", strerror(errno));
        goto close_socket;
    }

    memset(&sll_bind, 0, sizeof(sll_bind));
    sll_bind.sll_family = AF_PACKET;
    sll_bind.sll_protocol = htons(ethertype);
    sll_bind.sll_ifindex = ifindex;

    res = bind(sockfd, (struct sockaddr *) &sll_bind, sizeof(sll_bind));
    if (res < 0) {
        E("ERROR: bind(): %s", strerror(errno));
        goto close_socket;
    }

    res = fh_bpf4_attach(sockfd);
    if (res < 0) {
        E(T(fh_bpf4_attach));
        goto close_socket;
    }

    return 0;

close_socket:
    close(sockfd);

    return -1;
}


void fh_rawrecv_cleanup(void)
{
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}


int fh_rawrecv_loop(void)
{
    static const size_t buffsize = UINT16_MAX;

    int res, ret, err_cnt;
    ssize_t recv_len;
    unsigned char *buff;
    socklen_t sock_len;
    struct sockaddr_ll sll_src;

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

        sock_len = sizeof(sll_src);
        recv_len = recvfrom(sockfd, buff, buffsize, 0,
                            (struct sockaddr *) &sll_src, &sock_len);
        if (recv_len < 0) {
            err_cnt++;
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                case ETIMEDOUT:
                case ENOBUFS:
                    E("ERROR: recvfrom(): %s", strerror(errno));
                    continue;
                default:
                    E("ERROR: recvfrom(): %s", strerror(errno));
                    ret = -1;
                    goto free_buff;
            }
        }

        res = fh_rawsend_handle(&sll_src, buff, recv_len);
        if (res < 0) {
            err_cnt++;
            E("ERROR: fh_rawsend_handle(): %s", "failure");
            continue;
        }

        err_cnt = 0;
    }

    ret = 0;

free_buff:
    free(buff);

    return ret;
}