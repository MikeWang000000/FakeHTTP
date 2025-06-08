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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include "globvar.h"

/* TODO: NOT IMPLEMENTED */
int fh_pkt6_parse(void *pkt_data, int pkt_len, struct sockaddr *saddr,
                  struct sockaddr *daddr, struct tcphdr **tcph,
                  int *tcp_payload_len)
{
    (void) pkt_data;
    (void) pkt_len;
    (void) saddr;
    (void) daddr;
    (void) tcph;
    (void) tcp_payload_len;

    return -1;
}

/* TODO: NOT IMPLEMENTED */
int fh_pkt6_make(char *buffer, size_t buffer_size, struct sockaddr *saddr,
                 struct sockaddr *daddr, uint16_t sport_be, uint16_t dport_be,
                 uint32_t seq_be, uint32_t ackseq_be, int psh,
                 char *tcp_payload, size_t tcp_payload_size)
{
    (void) buffer;
    (void) buffer_size;
    (void) saddr;
    (void) daddr;
    (void) sport_be;
    (void) dport_be;
    (void) seq_be;
    (void) ackseq_be;
    (void) psh;
    (void) tcp_payload;
    (void) tcp_payload_size;

    return -1;
}
