/*
 * ipv6pkt.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "ipv6pkt.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include "globvar.h"
#include "logging.h"

int fh_pkt6_parse(void *pkt_data, int pkt_len, struct sockaddr *saddr,
                  struct sockaddr *daddr, uint8_t *ttl,
                  struct tcphdr **tcph_ptr, int *tcp_payload_len)
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    int ip6h_len, tcph_len;
    struct sockaddr_in6 *saddr_in6, *daddr_in6;

    saddr_in6 = (struct sockaddr_in6 *) saddr;
    daddr_in6 = (struct sockaddr_in6 *) daddr;

    ip6h_len = sizeof(*ip6h);

    if (pkt_len < ip6h_len) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    ip6h = (struct ip6_hdr *) pkt_data;

    if (ip6h->ip6_nxt != IPPROTO_TCP) {
        E("ERROR: not a TCP packet (next header %d)", (int) ip6h->ip6_nxt);
        return -1;
    }

    if ((size_t) pkt_len < ip6h_len + sizeof(*tcph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    tcph = (struct tcphdr *) ((uint8_t *) pkt_data + ip6h_len);
    tcph_len = tcph->doff * 4;
    if (pkt_len < ip6h_len + tcph_len) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    memset(saddr_in6, 0, sizeof(*saddr_in6));
    saddr_in6->sin6_family = AF_INET6;
    memcpy(&saddr_in6->sin6_addr, &ip6h->ip6_src, sizeof(struct in6_addr));

    memset(daddr_in6, 0, sizeof(*daddr_in6));
    daddr_in6->sin6_family = AF_INET6;
    memcpy(&daddr_in6->sin6_addr, &ip6h->ip6_dst, sizeof(struct in6_addr));

    *ttl = ip6h->ip6_hlim;
    *tcph_ptr = tcph;
    *tcp_payload_len = pkt_len - ip6h_len - tcph_len;

    return 0;
}


int fh_pkt6_make(uint8_t *buffer, size_t buffer_size, struct sockaddr *saddr,
                 struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                 uint16_t dport_be, uint32_t seq_be, uint32_t ackseq_be,
                 int psh, uint8_t *tcp_payload, size_t tcp_payload_size)
{
    size_t pkt_len;
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    uint8_t *tcppl;
    struct sockaddr_in6 *saddr_in6, *daddr_in6;

    if (saddr->sa_family != AF_INET6 || daddr->sa_family != AF_INET6) {
        E("ERROR: Invalid address family");
        return -1;
    }

    saddr_in6 = (struct sockaddr_in6 *) saddr;
    daddr_in6 = (struct sockaddr_in6 *) daddr;

    pkt_len = sizeof(*ip6h) + sizeof(*tcph) + tcp_payload_size;
    if (buffer_size < pkt_len + 1) {
        E("ERROR: %s", strerror(ENOBUFS));
        return -1;
    }

    ip6h = (struct ip6_hdr *) buffer;
    tcph = (struct tcphdr *) (buffer + sizeof(*ip6h));
    tcppl = buffer + sizeof(*ip6h) + sizeof(*tcph);

    memset(ip6h, 0, sizeof(*ip6h));
    ip6h->ip6_flow = htonl((6U << 28) /* version */ |
                           ((uint32_t) (g_ctx.dscp << 2) << 20) /* traffic */ |
                           0 /* flow */);
    ip6h->ip6_plen = htons(sizeof(*tcph) + tcp_payload_size);
    ip6h->ip6_nxt = IPPROTO_TCP;
    ip6h->ip6_hops = ttl;
    memcpy(&ip6h->ip6_src, &saddr_in6->sin6_addr, sizeof(struct in6_addr));
    memcpy(&ip6h->ip6_dst, &daddr_in6->sin6_addr, sizeof(struct in6_addr));

    memset(tcph, 0, sizeof(*tcph));
    tcph->source = sport_be;
    tcph->dest = dport_be;
    tcph->seq = seq_be;
    tcph->ack_seq = ackseq_be;
    tcph->doff = sizeof(*tcph) / 4;
    tcph->psh = psh;
    tcph->ack = 1;
    tcph->window = htons(0x0080);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    if (tcp_payload_size) {
        memcpy(tcppl, tcp_payload, tcp_payload_size);
    }

    nfq_tcp_compute_checksum_ipv6(tcph, ip6h);
    if (g_ctx.badsum) {
        tcph->check ^= htons(0x1234);
    }

    return pkt_len;
}
