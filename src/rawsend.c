/*
 * rawsend.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "rawsend.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include "globvar.h"
#include "ipv4pkt.h"
#include "ipv6pkt.h"
#include "logging.h"
#include "payload.h"
#include "srcinfo.h"

static uint8_t *payload = NULL;
static size_t payload_len = 0;
static int sockfd = -1;

static int hop_estimate(uint8_t ttl)
{
    if (ttl <= 64) {
        return 64 - ttl;
    } else if (ttl <= 128) {
        return 128 - ttl;
    } else {
        return 255 - ttl;
    }
}


static uint8_t calc_snd_ttl(int hops)
{
    int snd_ttl;

    if (!g_ctx.dynamic_pct) {
        return g_ctx.ttl;
    }

    snd_ttl = hops * g_ctx.dynamic_pct / 100;

    if (snd_ttl > g_ctx.ttl) {
        return snd_ttl;
    }

    return g_ctx.ttl;
}


static void ipaddr_to_str(struct sockaddr *addr, char ipstr[INET6_ADDRSTRLEN])
{
    static const char invalid[] = "INVALID";

    const char *res;

    if (addr->sa_family == AF_INET) {
        res = inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                        ipstr, INET_ADDRSTRLEN);
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


static int remove_tfo_cookie(uint16_t ethertype, uint8_t *pkt,
                             struct tcphdr *tcph)
{
    int not_found = 0;
    size_t i = 0, tcpopt_len;
    uint8_t *tcpopt_data, kind, len;

    not_found = 1;
    tcpopt_len = tcph->doff * 4 - sizeof(*tcph);
    tcpopt_data = (uint8_t *) tcph + sizeof(*tcph);

    while (i < tcpopt_len) {
        kind = tcpopt_data[i];
        if (kind == 0 || kind == 1) {
            i++;
            continue;
        }

        if (i + 1 >= tcpopt_len) {
            break;
        }

        len = tcpopt_data[i + 1];

        if (len < 2 || i + len > tcpopt_len) {
            break;
        }

        if (kind == 34 /* TCP Fast Open Cookie */) {
            not_found = 0;
            memset(&tcpopt_data[i], 0x01 /* NOP */, len);
        }
        i += len;
    }

    if (!not_found) {
        if (ethertype == ETHERTYPE_IP) {
            nfq_tcp_compute_checksum_ipv4(tcph, (struct iphdr *) pkt);
        } else if (ethertype == ETHERTYPE_IPV6) {
            nfq_tcp_compute_checksum_ipv6(tcph, (struct ip6_hdr *) pkt);
        }
    }

    return not_found;
}


/*
    This is a workaround for iptables since it does not allow us to intercept
    packets after POSTROUTING SNAT, which means the SNATed source address is
    unknown.
    Instead of using an AF_PACKET socket, we create a temporary AF_INET or
    AF_INET6 raw socket, so that the packet gets SNATed correctly.
*/
static int sendto_snat(struct sockaddr_ll *sll, struct sockaddr *daddr,
                       uint8_t *pkt_buff, int pkt_len)
{
    int res, ret, sock_fd;
    ssize_t nbytes;
    char *iface, iface_buf[IF_NAMESIZE];

    ret = -1;

    iface = if_indextoname(sll->sll_ifindex, iface_buf);
    if (!iface) {
        E("ERROR: if_indextoname(): %s", strerror(errno));
        return -1;
    }

    sock_fd = socket(daddr->sa_family, SOCK_RAW, IPPROTO_RAW);
    if (sock_fd < 0) {
        E("ERROR: socket(): %s", strerror(errno));
        return -1;
    }

    res = setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, iface,
                     strlen(iface));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_BINDTODEVICE: %s", strerror(errno));
        goto close_socket;
    }

    res = setsockopt(sock_fd, SOL_SOCKET, SO_MARK, &g_ctx.fwmark,
                     sizeof(g_ctx.fwmark));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_MARK: %s", strerror(errno));
        goto close_socket;
    }

    nbytes = sendto(sock_fd, pkt_buff, pkt_len, 0, daddr,
                    daddr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in));
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        goto close_socket;
    }

    ret = nbytes;

close_socket:
    close(sock_fd);

    return ret;
}


static int send_payload(struct sockaddr_ll *sll, struct sockaddr *saddr,
                        struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                        uint16_t dport_be, uint32_t seq_be, uint32_t ackseq_be,
                        int need_snat)
{
    int pkt_len;
    ssize_t nbytes;
    uint8_t pkt_buff[1600] __attribute__((aligned));

    if (daddr->sa_family == AF_INET) {
        pkt_len = fh_pkt4_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, seq_be, ackseq_be, 1,
                               payload, payload_len);
        if (pkt_len < 0) {
            E(T(fh_pkt4_make));
            return -1;
        }
    } else if (daddr->sa_family == AF_INET6) {
        pkt_len = fh_pkt6_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, seq_be, ackseq_be, 1,
                               payload, payload_len);
        if (pkt_len < 0) {
            E(T(fh_pkt6_make));
            return -1;
        }
    } else {
        E("ERROR: Unknown address family: %d", (int) saddr->sa_family);
        return -1;
    }

    if (need_snat) {
        nbytes = sendto_snat(sll, daddr, pkt_buff, pkt_len);
        if (nbytes < 0) {
            E(T(sendto_snat));
            return -1;
        }
    } else {
        nbytes = sendto(sockfd, pkt_buff, pkt_len, 0, (struct sockaddr *) sll,
                        sizeof(*sll));
        if (nbytes < 0) {
            E("ERROR: sendto(): %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}


int fh_rawsend_setup(void)
{
    int res, opt;
    const char *err_hint;

    sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
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

    res = setsockopt(sockfd, SOL_SOCKET, SO_MARK, &g_ctx.fwmark,
                     sizeof(g_ctx.fwmark));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_MARK: %s", strerror(errno));
        goto close_socket;
    }

    opt = 7;
    res = setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_PRIORITY: %s", strerror(errno));
        goto close_socket;
    }

    /*
        Set SO_RCVBUF to the minimum, since we never call recvfrom() on this
        socket.
    */
    opt = 128;
    res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_RCVBUF: %s", strerror(errno));
        goto close_socket;
    }

    return 0;

close_socket:
    close(sockfd);

    return -1;
}


void fh_rawsend_cleanup(void)
{
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}


int fh_rawsend_handle(struct sockaddr_ll *sll, uint8_t *pkt_data, int pkt_len,
                      int *modified)
{
    uint32_t seq_new, ack_new;
    uint16_t ethertype;
    int res, i, src_payload_len, hop, srcinfo_unavail;
    uint8_t src_ttl, snd_ttl;
    struct tcphdr *tcph;
    char src_ip_str[INET6_ADDRSTRLEN], dst_ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_storage saddr_store, daddr_store;
    struct sockaddr *saddr, *daddr;
    ssize_t nbytes;

    *modified = 0;

    saddr = (struct sockaddr *) &saddr_store;
    daddr = (struct sockaddr *) &daddr_store;

    ethertype = ntohs(sll->sll_protocol);
    if (g_ctx.use_ipv4 && ethertype == ETHERTYPE_IP) {
        res = fh_pkt4_parse(pkt_data, pkt_len, saddr, daddr, &src_ttl, &tcph,
                            &src_payload_len);
        if (res < 0) {
            E(T(fh_pkt4_parse));
            return -1;
        }
    } else if (g_ctx.use_ipv6 && ethertype == ETHERTYPE_IPV6) {
        res = fh_pkt6_parse(pkt_data, pkt_len, saddr, daddr, &src_ttl, &tcph,
                            &src_payload_len);
        if (res < 0) {
            E(T(fh_pkt6_parse));
            return -1;
        }
    } else {
        E("ERROR: unknown ethertype 0x%04x");
        return -1;
    }

    if (!g_ctx.silent) {
        ipaddr_to_str(saddr, src_ip_str);
        ipaddr_to_str(daddr, dst_ip_str);
    }

    if (sll->sll_pkttype == PACKET_HOST && tcph->syn && tcph->ack) {
        /*
            Outbound TCP connection. SYN-ACK received from peer.
        */
        sll->sll_pkttype = 0;

        if (!g_ctx.outbound) {
            E_INFO("%s:%u ===SYN-ACK(~)===> %s:%u", src_ip_str,
                   ntohs(tcph->source), dst_ip_str, ntohs(tcph->dest));
            return NF_ACCEPT;
        }

        E_INFO("%s:%u ===SYN-ACK===> %s:%u", src_ip_str, ntohs(tcph->source),
               dst_ip_str, ntohs(tcph->dest));

        ack_new = ntohl(tcph->seq);
        ack_new++;
        ack_new = htonl(ack_new);

        snd_ttl = g_ctx.ttl;

        if (!g_ctx.nohopest) {
            hop = hop_estimate(src_ttl);
            if (hop <= g_ctx.ttl) {
                E_INFO("%s:%u ===LOCAL(~)===> %s:%u", src_ip_str,
                       ntohs(tcph->source), dst_ip_str, ntohs(tcph->dest));
                return NF_ACCEPT;
            }
            snd_ttl = calc_snd_ttl(hop);
        }

        if (!g_ctx.promisc) {
            th_payload_get(&payload, &payload_len);
        }

        for (i = 0; i < g_ctx.repeat; i++) {
            if (g_ctx.promisc) {
                th_payload_get(&payload, &payload_len);
            }
            res = send_payload(sll, daddr, saddr, snd_ttl, tcph->dest,
                               tcph->source, tcph->ack_seq, ack_new, 0);
            if (res < 0) {
                E(T(send_payload));
                return -1;
            }
        }
        E_INFO("%s:%u <===FAKE(*)=== %s:%u", src_ip_str, ntohs(tcph->source),
               dst_ip_str, ntohs(tcph->dest));

        return NF_ACCEPT;
    } else if (sll->sll_pkttype == PACKET_OUTGOING && tcph->syn && tcph->ack) {
        /*
            Inbound TCP connection. SYN-ACK to be sent from local.
        */
        sll->sll_pkttype = 0;

        srcinfo_unavail = fh_srcinfo_get(daddr, &src_ttl, sll->sll_addr);

        if (!g_ctx.inbound || srcinfo_unavail) {
            E_INFO("%s:%u <===SYN-ACK(~)=== %s:%u", dst_ip_str,
                   ntohs(tcph->dest), src_ip_str, ntohs(tcph->source));
            return NF_ACCEPT;
        }

        seq_new = ntohl(tcph->seq);
        seq_new++;
        seq_new = htonl(seq_new);

        snd_ttl = g_ctx.ttl;

        if (!g_ctx.nohopest) {
            hop = hop_estimate(src_ttl);
            if (hop <= g_ctx.ttl) {
                E_INFO("%s:%u <===LOCAL(~)=== %s:%u", src_ip_str,
                       ntohs(tcph->source), dst_ip_str, ntohs(tcph->dest));
                return NF_ACCEPT;
            }
            snd_ttl = calc_snd_ttl(hop);
        }

        if (!g_ctx.promisc) {
            th_payload_get(&payload, &payload_len);
        }

        for (i = 0; i < g_ctx.repeat; i++) {
            if (g_ctx.promisc) {
                th_payload_get(&payload, &payload_len);
            }
            res = send_payload(sll, saddr, daddr, snd_ttl, tcph->source,
                               tcph->dest, seq_new, tcph->ack_seq,
                               g_ctx.use_iptables /* needs SNAT */);
            if (res < 0) {
                E(T(send_payload));
                return -1;
            }
        }
        E_INFO("%s:%u <===FAKE(*)=== %s:%u", dst_ip_str, ntohs(tcph->dest),
               src_ip_str, ntohs(tcph->source));

        /*
            We send the original packet using a raw socket and discard the
            current processing flow.
            This ensures that the SYN-ACK is transmitted after the payload.
            Although this deliberately causes a TCP out-of-order situation,
            it guarantees that our payload is always sent before the client's
            packet.
        */
        if (g_ctx.use_iptables) {
            nbytes = sendto_snat(sll, daddr, pkt_data, pkt_len);
            if (nbytes < 0) {
                E(T(sendto_snat));
                return -1;
            }
        } else {
            nbytes = sendto(sockfd, pkt_data, pkt_len, 0,
                            (struct sockaddr *) sll, sizeof(*sll));
            if (nbytes < 0) {
                E("ERROR: sendto(): %s", strerror(errno));
                return -1;
            }
        }

        E_INFO("%s:%u <===SYN-ACK=== %s:%u", dst_ip_str, ntohs(tcph->dest),
               src_ip_str, ntohs(tcph->source));

        return NF_DROP; /* Drop it! */
    } else if (sll->sll_pkttype == PACKET_HOST && tcph->syn) {
        /*
            Inbound TCP connection. SYN received from peer.
        */
        sll->sll_pkttype = 0;

        if (!g_ctx.inbound) {
            E_INFO("%s:%u ===SYN(~)===> %s:%u", src_ip_str,
                   ntohs(tcph->source), dst_ip_str, ntohs(tcph->dest));
            return NF_ACCEPT;
        }

        *modified = !remove_tfo_cookie(ethertype, pkt_data, tcph);
        if (*modified) {
            E_INFO("%s:%u ===SYN(#)===> %s:%u", src_ip_str,
                   ntohs(tcph->source), dst_ip_str, ntohs(tcph->dest));
        } else {
            E_INFO("%s:%u ===SYN===> %s:%u", src_ip_str, ntohs(tcph->source),
                   dst_ip_str, ntohs(tcph->dest));
        }

        res = fh_srcinfo_put(saddr, src_ttl, sll->sll_addr);
        if (res < 0) {
            E(T(fh_srcinfo_put));
            return -1;
        }

        return NF_ACCEPT;
    } else if (sll->sll_pkttype == PACKET_OUTGOING && tcph->syn) {
        /*
            Outbound TCP connection. SYN to be sent from local.
        */
        sll->sll_pkttype = 0;

        if (!g_ctx.outbound) {
            E_INFO("%s:%u <===SYN(~)=== %s:%u", dst_ip_str, ntohs(tcph->dest),
                   src_ip_str, ntohs(tcph->source));
            return NF_ACCEPT;
        }

        *modified = !remove_tfo_cookie(ethertype, pkt_data, tcph);
        if (*modified) {
            E_INFO("%s:%u <===SYN(#)=== %s:%u", dst_ip_str, ntohs(tcph->dest),
                   src_ip_str, ntohs(tcph->source));
        } else {
            E_INFO("%s:%u <===SYN=== %s:%u", dst_ip_str, ntohs(tcph->dest),
                   src_ip_str, ntohs(tcph->source));
        }

        return NF_ACCEPT;
    } else if (sll->sll_pkttype == PACKET_HOST) {
        E_INFO("%s:%u ===(~)===> %s:%u", src_ip_str, ntohs(tcph->source),
               dst_ip_str, ntohs(tcph->dest));
        return NF_ACCEPT;
    } else if (sll->sll_pkttype == PACKET_OUTGOING) {
        E_INFO("%s:%u <===(~)=== %s:%u", dst_ip_str, ntohs(tcph->dest),
               src_ip_str, ntohs(tcph->source));
        return NF_ACCEPT;
    } else {
        E_INFO("%s:%u ===(~)=== %s:%u", src_ip_str, ntohs(tcph->source),
               dst_ip_str, ntohs(tcph->dest));
        return NF_ACCEPT;
    }
}
