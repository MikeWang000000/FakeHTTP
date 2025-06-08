/*
 * ipv4pkt.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "ipv4pkt.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include "globvar.h"
#include "logging.h"

int fh_pkt4_parse(void *pkt_data, int pkt_len, struct sockaddr *saddr,
                  struct sockaddr *daddr, struct tcphdr **tcph_ptr,
                  int *tcp_payload_len)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    int iph_len, tcph_len;
    struct sockaddr_in *saddr_in, *daddr_in;

    saddr_in = (struct sockaddr_in *) saddr;
    daddr_in = (struct sockaddr_in *) daddr;

    if ((size_t) pkt_len < sizeof(*iph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    iph = (struct iphdr *) pkt_data;
    iph_len = iph->ihl * 4;

    if ((size_t) iph_len < sizeof(*iph)) {
        E("ERROR: invalid IP header length: %d", iph_len);
        return -1;
    }

    if (iph->protocol != IPPROTO_TCP) {
        E("ERROR: not a TCP packet (protocol %d)", (int) iph->protocol);
        return -1;
    }

    if ((size_t) pkt_len < iph_len + sizeof(*tcph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    tcph = (struct tcphdr *) ((uint8_t *) pkt_data + iph_len);
    tcph_len = tcph->doff * 4;
    if ((size_t) pkt_len < iph_len + tcph_len) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    memset(saddr_in, 0, sizeof(*saddr_in));
    saddr_in->sin_family = AF_INET;
    saddr_in->sin_addr.s_addr = iph->saddr;

    memset(daddr_in, 0, sizeof(*daddr_in));
    daddr_in->sin_family = AF_INET;
    daddr_in->sin_addr.s_addr = iph->daddr;

    *tcph_ptr = tcph;
    *tcp_payload_len = pkt_len - iph_len - tcph_len;

    return 0;
}


int fh_pkt4_make(char *buffer, size_t buffer_size, struct sockaddr *saddr,
                 struct sockaddr *daddr, uint16_t sport_be, uint16_t dport_be,
                 uint32_t seq_be, uint32_t ackseq_be, int psh,
                 char *tcp_payload, size_t tcp_payload_size)
{
    size_t pkt_len;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *tcppl;
    struct sockaddr_in *saddr_in, *daddr_in;

    if (saddr->sa_family != AF_INET || daddr->sa_family != AF_INET) {
        E("ERROR: Invalid address family");
        return -1;
    }

    saddr_in = (struct sockaddr_in *) saddr;
    daddr_in = (struct sockaddr_in *) daddr;

    pkt_len = sizeof(*iph) + sizeof(*tcph) + tcp_payload_size;
    if (buffer_size < pkt_len + 1) {
        E("ERROR: %s", strerror(ENOBUFS));
        return -1;
    }

    iph = (struct iphdr *) buffer;
    tcph = (struct tcphdr *) (buffer + sizeof(*iph));
    tcppl = buffer + sizeof(*iph) + sizeof(*tcph);

    memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = sizeof(*iph) / 4;
    iph->tos = 0;
    iph->tot_len = htons(pkt_len);
    iph->id = ((rand() & 0xff) << 8) | (rand() & 0xff);
    iph->frag_off = htons(1 << 14 /* DF */);
    iph->ttl = g_ctx.ttl;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = saddr_in->sin_addr.s_addr;
    iph->daddr = daddr_in->sin_addr.s_addr;

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

    nfq_ip_set_checksum(iph);
    nfq_tcp_compute_checksum_ipv4(tcph, iph);

    return pkt_len;
}
