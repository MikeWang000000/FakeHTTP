#define _GNU_SOURCE
#include "ipv4bpf.h"

#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/in.h>

#include "logging.h"

#define IPH_OFFSET_VER_IHL  0
#define IPH_OFFSET_TOT_LEN  2
#define IPH_OFFSET_FRAG_OFF 6
#define IPH_OFFSET_PROTOCOL 9

#define TCPH_OFFSET_OFF   12
#define TCPH_OFFSET_FLAGS 13

#define ACC_INDEX 20 /* <- update this if bpf_code is updated */
#define REJ_INDEX 21 /* <- update this if bpf_code is updated */

#define TO_NEXT            0
#define TO_ACC(CURR_INDEX) (ACC_INDEX - (CURR_INDEX) - (1))
#define TO_REJ(CURR_INDEX) (REJ_INDEX - (CURR_INDEX) - (1))

static struct sock_filter bpf_code[] = {
    /*
        Reject if IP protocol is not TCP
    */
    /* (000) ldb [IPH_OFFSET_PROTOCOL] */
    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, IPH_OFFSET_PROTOCOL),

    /* (001) jeq IPPROTO_TCP jt NXT jf REJ */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, TO_NEXT, TO_REJ(1)),

    /*
        Reject if IP packet is fragmented
    */
    /* (002) ldh [IPH_OFFSET_FRAG_OFF] */
    BPF_STMT(BPF_LD | BPF_H | BPF_ABS, IPH_OFFSET_FRAG_OFF),

    /* (003) jset #0x1fff jt REJ jf NXT */
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, TO_REJ(3), TO_NEXT),

    /*
        Reject if SYN is not set
    */
    /* (004) ldxb 4 * ([IPH_OFFSET_VER_IHL] & 0x0f) : iphdr_len */
    BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, IPH_OFFSET_VER_IHL),

    /* (005) ldb [x + TCPH_OFFSET_FLAGS] : iphdr_len + TCPH_OFFSET_FLAGS */
    BPF_STMT(BPF_LD | BPF_B | BPF_IND, TCPH_OFFSET_FLAGS),

    /* (006) and TH_SYN */
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, TH_SYN),

    /* (007) jeq TH_SYN jt NXT jf REJ */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TH_SYN, TO_NEXT, TO_REJ(7)),

    /*
        Calculate TCP packet length:
            tcppkt_len = ippkt_len - iphdr_len
    */
    /* (008) ldh [IPH_OFFSET_TOT_LEN] : ippkt_len */
    BPF_STMT(BPF_LD | BPF_H | BPF_ABS, IPH_OFFSET_TOT_LEN),

    /* (009) ldxb 4 * ([IPH_OFFSET_VER_IHL] & 0x0f) : iphdr_len */
    BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, IPH_OFFSET_VER_IHL),

    /* (010) sub x : ippkt_len - iphdr_len */
    BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),

    /* (011) st M[0] */
    BPF_STMT(BPF_ST, 0),

    /*
        Calculate TCP payload length:
            tcppl_len = tcppkt_len - tcphdr_len
    */
    /* (012) ldxb 4 * ([IPH_OFFSET_VER_IHL] & 0x0f) : iphdr_len */
    BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, IPH_OFFSET_VER_IHL),

    /* (013) ldb [x + TCPH_OFFSET_OFF] : iphdr_len + TCPH_OFFSET_OFF */
    BPF_STMT(BPF_LD | BPF_B | BPF_IND, TCPH_OFFSET_OFF),

    /* (014) and #0xf0 */
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),

    /* (015) rsh #2 : tcphdr_len */
    BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 2),

    /* (016) tax */
    BPF_STMT(BPF_MISC | BPF_TAX, 0),

    /* (017) ld M[0] : tcppkt_len */
    BPF_STMT(BPF_LD | BPF_MEM, 0),

    /* (018) sub x : tcppkt_len - tcphdr_len */
    BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),

    /*
        Reject if TCP payload length != 0
    */
    /* (019) jeq 0 jt NXT jf REJ */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, TO_NEXT, TO_REJ(19)),

    /* (020) ret #65535 : ACC_INDEX */
    BPF_STMT(BPF_RET | BPF_K, 65535),

    /* (021) ret #0 : REJ_INDEX */
    BPF_STMT(BPF_RET | BPF_K, 0)};

static const struct sock_fprog bpf_prog = {
    .len = sizeof(bpf_code) / sizeof(bpf_code[0]), .filter = bpf_code};

int fh_bpf4_attach(int sockfd)
{
    int res;
    res = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog,
                     sizeof(bpf_prog));
    if (res < 0) {
        E("setsockopt(): SO_ATTACH_FILTER: %s", strerror(errno));
        return -1;
    };

    return 0;
}
