/*
 * payload.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "payload.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"
#include "globvar.h"

#define BUFFLEN 1200
#define SET_BE16(a, u16)         \
    do {                         \
        (a)[0] = (uint8_t) (((u16) >> 8) & 0xff);  \
        (a)[1] = (uint8_t) ((u16) & 0xff);         \
    } while (0)
#define SET_BE32(a, u32)          \
    do {                          \
        (a)[0] = (uint8_t) (((u32) >> 24) & 0xff); \
        (a)[1] = (uint8_t) (((u32) >> 16) & 0xff); \
        (a)[2] = (uint8_t) (((u32) >> 8) & 0xff);  \
        (a)[3] = (uint8_t) ((u32) & 0xff);         \
    } while (0)
#define SET_LE32(a, u32)          \
    do {                          \
        (a)[0] = (uint8_t) ((u32) & 0xff);         \
        (a)[1] = (uint8_t) (((u32) >> 8) & 0xff);  \
        (a)[2] = (uint8_t) (((u32) >> 16) & 0xff); \
        (a)[3] = (uint8_t) (((u32) >> 24) & 0xff); \
    } while (0)

struct payload_node {
    uint8_t payload[BUFFLEN];
    size_t payload_len;
    struct payload_node *next;
};

static const char *http_fmt =
    "GET / HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Accept: */*\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\r\n"
    "\r\n";

struct tls_ext_server_name_head {
    uint8_t type[2];
    uint8_t length[2];
    uint8_t server_name_list_length[2];
    uint8_t server_name_type;
    uint8_t server_name_length[2];
};

struct tls_ext_padding_head {
    uint8_t type[2];
    uint8_t length[2];
};

static const struct tls_client_hello {
    uint8_t data_01[11];
    uint8_t random[32];
    uint8_t session_id_length;
    uint8_t session_id[32];
    uint8_t data_02[39];
    uint8_t data_sni[275];
} cli_hello_tmpl = {
    .data_01 =
        {
            0x16,             /* handshake */
            0x03, 0x03,       /* tlsv1.2 */
            0x01, 0x81,       /* length */
            0x01,             /* client hello */
            0x00, 0x01, 0x7d, /* client hello length */
            0x03, 0x03        /* tlsv1.2 */
        },
    .session_id_length = 32,
    .data_02 =
        {
            0x00, 0x02, /* cipher suites length */
            0xc0, 0x2b, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
            0x01,       /* compression methods length */
            0x00,       /* null */
            0x01, 0x32, /* extensions length */
            0x00, 0x0a, /* ext. supported_groups */
            0x00, 0x04, /* ext. length */
            0x00, 0x02, /* list length */
            0x00, 0x17, /* secp256r1 */
            0x00, 0x0d, /* ext. signature_algorithms */
            0x00, 0x04, /* ext. length */
            0x00, 0x02, /* list length */
            0x04, 0x03, /* ecdsa_secp256r1_sha256 */
            0x00, 0x10, /* ext. alpn */
            0x00, 0x0b, /* ext. length */
            0x00, 0x09, /* alpn length */
            0x08,       /* alpn string length */
            'h',  't',  't', 'p', '/', '1', '.', '1' /* alpn string */
        },
};

static struct payload_node *current_node;
static struct payload_node **promisc_nodes;
static size_t promisc_node_count;

static int vformat_payload(uint8_t *buffer, size_t *len, const char *format,
                           va_list args)
{
    int written;
    size_t buffsize;

    buffsize = *len;
    written = vsnprintf((char *) buffer, buffsize, format, args);
    if (written < 0) {
        E("ERROR: vsnprintf(): %s", "failure");
        return -1;
    } else if ((size_t) written >= buffsize) {
        E("ERROR: payload buffer is too small");
        return -1;
    }

    *len = (size_t) written;

    return 0;
}


static int format_payload(uint8_t *buffer, size_t *len, const char *format, ...)
{
    int res;
    va_list args;

    va_start(args, format);
    res = vformat_payload(buffer, len, format, args);
    va_end(args);

    return res;
}


static void append_ring_node(struct payload_node **head, struct payload_node *node)
{
    if (*head) {
        node->next = (*head)->next;
        (*head)->next = node;
    } else {
        *head = node;
        node->next = node;
    }
}


static void free_ring(struct payload_node **head)
{
    struct payload_node *node, *next_node;

    if (!*head) {
        return;
    }

    node = *head;
    while (1) {
        next_node = node->next;
        free(node);
        if (next_node == *head) {
            break;
        }
        node = next_node;
    }

    *head = NULL;
}


static int set_node_payload(struct payload_node *node, const void *data, size_t len)
{
    if (len > sizeof(node->payload)) {
        E("ERROR: payload is too large");
        return -1;
    }

    memcpy(node->payload, data, len);
    node->payload_len = len;

    return 0;
}


static int add_promisc_payload(const void *data, size_t len)
{
    struct payload_node *node, **nodes;

    node = malloc(sizeof(*node));
    if (!node) {
        E("ERROR: malloc(): %s", strerror(errno));
        return -1;
    }

    if (set_node_payload(node, data, len) < 0) {
        free(node);
        return -1;
    }

    nodes = realloc(promisc_nodes,
                    (promisc_node_count + 1) * sizeof(*promisc_nodes));
    if (!nodes) {
        E("ERROR: realloc(): %s", strerror(errno));
        free(node);
        return -1;
    }

    promisc_nodes = nodes;
    promisc_nodes[promisc_node_count++] = node;

    return 0;
}


static int add_promisc_text(const char *payload)
{
    return add_promisc_payload(payload, strlen(payload));
}


static int add_promisc_printf(const char *format, ...)
{
    int res;
    size_t len;
    uint8_t buffer[BUFFLEN];
    va_list args;

    len = sizeof(buffer);
    va_start(args, format);
    res = vformat_payload(buffer, &len, format, args);
    va_end(args);
    if (res < 0) {
        return -1;
    }

    return add_promisc_payload(buffer, len);
}


static void cleanup_promisc_payloads(void)
{
    size_t i;

    for (i = 0; i < promisc_node_count; i++) {
        free(promisc_nodes[i]);
    }

    free(promisc_nodes);
    promisc_nodes = NULL;
    promisc_node_count = 0;
}


static const char *promisc_hostname(void)
{
    struct payload_info *pinfo;

    if (!g_ctx.plinfo) {
        return "example.com";
    }

    for (pinfo = g_ctx.plinfo; pinfo->type; pinfo++) {
        if ((pinfo->type == FH_PAYLOAD_HTTP ||
             pinfo->type == FH_PAYLOAD_HTTPS) &&
            pinfo->info && pinfo->info[0]) {
            return pinfo->info;
        }
    }

    return "example.com";
}

static int make_http_get(uint8_t *buffer, size_t *len, char *hostname)
{
    return format_payload(buffer, len, http_fmt, hostname);
}


static int make_tls_client_hello(uint8_t *buffer, size_t *len, char *hostname)
{
    int padding_len;
    size_t i, buffsize;
    struct tls_client_hello *tls_data;
    struct tls_ext_server_name_head *server_name_head;
    struct tls_ext_padding_head *padding_head;

    buffsize = *len;

    if (buffsize < (int) sizeof(*tls_data)) {
        E("ERROR: buffer is too small");
        return -1;
    }

    tls_data = (struct tls_client_hello *) buffer;
    memcpy(tls_data, &cli_hello_tmpl, sizeof(cli_hello_tmpl));

    for (i = 0; i < sizeof(tls_data->random); i++) {
        tls_data->random[i] = rand();
    }

    for (i = 0; i < sizeof(tls_data->session_id); i++) {
        tls_data->session_id[i] = rand();
    }

    size_t hostname_len = strlen(hostname);

    padding_len = sizeof(tls_data->data_sni) -
                  sizeof(struct tls_ext_server_name_head) - strlen(hostname) -
                  sizeof(struct tls_ext_padding_head);

    if (padding_len < 0) {
        E("ERROR: hostname is too long");
        return -1;
    }

    server_name_head = (struct tls_ext_server_name_head *) tls_data->data_sni;
    SET_BE16(server_name_head->type, 0);
    SET_BE16(server_name_head->length, hostname_len + 5);
    SET_BE16(server_name_head->server_name_list_length, hostname_len + 3);
    SET_BE16(server_name_head->server_name_length, hostname_len);
    memcpy((uint8_t *) server_name_head + sizeof(*server_name_head), hostname,
           hostname_len);

    padding_head = (struct tls_ext_padding_head *) (tls_data->data_sni +
                                                    sizeof(*server_name_head) +
                                                    hostname_len);
    SET_BE16(padding_head->type, 21);
    SET_BE16(padding_head->length, padding_len);
    memset((uint8_t *) padding_head + sizeof(*padding_head), 0, padding_len);

    *len = sizeof(*tls_data);

    return 0;
}


static int make_custom(uint8_t *buffer, size_t *len, char *filepath)
{
    int res, len_, buffsize;
    FILE *fp;

    len_ = 0;
    buffsize = *len;

    fp = fopen(filepath, "rb");
    if (!fp) {
        E("ERROR: fopen(): %s: %s", filepath, strerror(errno));
        return -1;
    }

    while (!feof(fp) && !ferror(fp) && len_ < buffsize) {
        len_ += fread(buffer + len_, 1, buffsize - len_, fp);
    }

    if (ferror(fp)) {
        E("ERROR: fread(): %s: %s", filepath, "failure");
        fclose(fp);
        return -1;
    }

    if (!feof(fp)) {
        E("ERROR: %s: Data too long. Maximum length is %d", filepath,
          buffsize);
        fclose(fp);
        return -1;
    }

    res = fclose(fp);
    if (res < 0) {
        E("ERROR: fclose(): %s", strerror(errno));
        return -1;
    }

    *len = len_;

    return 0;
}

static int add_promisc_dns(const char *hostname)
{
    size_t len, label_len;
    uint8_t buffer[BUFFLEN];
    const char *cur, *dot;

    if (!hostname || !hostname[0] || strchr(hostname, ' ')) {
        hostname = "example.com";
    }

    len = 0;

    buffer[len++] = 0x12;
    buffer[len++] = 0x34;
    buffer[len++] = 0x01;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x01;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;

    cur = hostname;
    while (*cur) {
        dot = strchr(cur, '.');
        label_len = dot ? (size_t) (dot - cur) : strlen(cur);
        if (!label_len || label_len > 63 || len + 1 + label_len + 5 > BUFFLEN) {
            return add_promisc_dns("example.com");
        }

        buffer[len++] = (uint8_t) label_len;
        memcpy(buffer + len, cur, label_len);
        len += label_len;

        if (!dot) {
            break;
        }
        cur = dot + 1;
    }

    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x01;
    buffer[len++] = 0x00;
    buffer[len++] = 0x01;

    return add_promisc_payload(buffer, len);
}


static size_t quic_varint(uint8_t *buffer, uint64_t value)
{
    if (value < (1ULL << 6)) {
        buffer[0] = (uint8_t) value;
        return 1;
    }

    if (value < (1ULL << 14)) {
        buffer[0] = 0x40 | ((value >> 8) & 0x3f);
        buffer[1] = value & 0xff;
        return 2;
    }

    if (value < (1ULL << 30)) {
        buffer[0] = 0x80 | ((value >> 24) & 0x3f);
        buffer[1] = (value >> 16) & 0xff;
        buffer[2] = (value >> 8) & 0xff;
        buffer[3] = value & 0xff;
        return 4;
    }

    buffer[0] = 0xc0 | ((value >> 56) & 0x3f);
    buffer[1] = (value >> 48) & 0xff;
    buffer[2] = (value >> 40) & 0xff;
    buffer[3] = (value >> 32) & 0xff;
    buffer[4] = (value >> 24) & 0xff;
    buffer[5] = (value >> 16) & 0xff;
    buffer[6] = (value >> 8) & 0xff;
    buffer[7] = value & 0xff;
    return 8;
}


static int add_promisc_quic_like(const void *payload, size_t payload_len)
{
    size_t len, varint_len;
    uint8_t buffer[BUFFLEN], varint[8];
    static const uint8_t dcid[] = {0x83, 0x94, 0xc8, 0xf0,
                                   0x3e, 0x51, 0x57, 0x08};
    static const uint8_t scid[] = {0x53, 0x46, 0xf7, 0x23,
                                   0x61, 0x91, 0xe0, 0x1f};

    len = 0;

    if (sizeof(buffer) < 1 + 4 + 1 + sizeof(dcid) + 1 + sizeof(scid) + 1 + 8 +
                           4 + payload_len) {
        E("ERROR: payload buffer is too small");
        return -1;
    }

    buffer[len++] = 0xc3;
    SET_BE32(buffer + len, 1);
    len += 4;

    buffer[len++] = sizeof(dcid);
    memcpy(buffer + len, dcid, sizeof(dcid));
    len += sizeof(dcid);

    buffer[len++] = sizeof(scid);
    memcpy(buffer + len, scid, sizeof(scid));
    len += sizeof(scid);

    varint_len = quic_varint(varint, 0);
    memcpy(buffer + len, varint, varint_len);
    len += varint_len;

    varint_len = quic_varint(varint, 4 + payload_len);
    memcpy(buffer + len, varint, varint_len);
    len += varint_len;

    SET_BE32(buffer + len, 1);
    len += 4;

    memcpy(buffer + len, payload, payload_len);
    len += payload_len;

    return add_promisc_payload(buffer, len);
}


static int add_promisc_tls(void)
{
    size_t len;
    uint8_t buffer[64];
    static const uint8_t client_random[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    len = 0;

    buffer[len++] = 0x16;
    buffer[len++] = 0x03;
    buffer[len++] = 0x03;
    buffer[len++] = 0x00;
    buffer[len++] = 0x2d;

    buffer[len++] = 0x01;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x29;

    buffer[len++] = 0x03;
    buffer[len++] = 0x03;
    memcpy(buffer + len, client_random, sizeof(client_random));
    len += sizeof(client_random);

    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x02;
    buffer[len++] = 0x00;
    buffer[len++] = 0x2f;
    buffer[len++] = 0x01;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;
    buffer[len++] = 0x00;

    return add_promisc_payload(buffer, len);
}


static int add_promisc_mqtt(void)
{
    size_t len;
    uint8_t buffer[32];

    len = 0;
    buffer[len++] = 0x10;
    buffer[len++] = 0x0d;
    buffer[len++] = 0x00;
    buffer[len++] = 0x04;
    memcpy(buffer + len, "MQTT", 4);
    len += 4;
    buffer[len++] = 0x04;
    buffer[len++] = 0x02;
    buffer[len++] = 0x00;
    buffer[len++] = 0x3c;
    buffer[len++] = 0x00;
    buffer[len++] = 0x01;
    buffer[len++] = 'c';

    return add_promisc_payload(buffer, len);
}


static int add_promisc_stomp(const char *hostname)
{
    size_t len;
    uint8_t buffer[BUFFLEN];

    len = sizeof(buffer);
    if (format_payload(buffer, &len,
                       "CONNECT\r\naccept-version:1.2\r\nhost:%s\r\n\r\n",
                       hostname) < 0) {
        return -1;
    }

    if (len + 1 > sizeof(buffer)) {
        E("ERROR: payload buffer is too small");
        return -1;
    }

    buffer[len++] = 0x00;

    return add_promisc_payload(buffer, len);
}


static int add_promisc_kcp(void)
{
    size_t len;
    uint8_t buffer[32];
    static const uint8_t data[] = {'p', 'i', 'n', 'g'};

    len = 0;
    SET_LE32(buffer + len, 0x11223344);
    len += 4;
    buffer[len++] = 0x51;
    buffer[len++] = 0x00;
    buffer[len++] = 0x20;
    buffer[len++] = 0x00;
    SET_LE32(buffer + len, 0x10203040);
    len += 4;
    SET_LE32(buffer + len, 1);
    len += 4;
    SET_LE32(buffer + len, 0);
    len += 4;
    SET_LE32(buffer + len, sizeof(data));
    len += 4;
    memcpy(buffer + len, data, sizeof(data));
    len += sizeof(data);

    return add_promisc_payload(buffer, len);
}


static int add_promisc_tftp_request(uint16_t opcode, size_t target_len)
{
    size_t len, filename_len;
    uint8_t buffer[BUFFLEN];

    if (!target_len) {
        filename_len = 4;
    } else {
        if (target_len < 9) {
            E("ERROR: invalid TFTP payload size");
            return -1;
        }
        filename_len = target_len - 9;
    }

    len = 2 + filename_len + 1 + 5 + 1;
    if (len > sizeof(buffer)) {
        E("ERROR: payload buffer is too small");
        return -1;
    }

    buffer[0] = 0x00;
    buffer[1] = opcode & 0xff;

    if (!target_len) {
        memcpy(buffer + 2, "test", 4);
    } else {
        memset(buffer + 2, 'a', filename_len);
    }

    buffer[2 + filename_len] = 0x00;
    memcpy(buffer + 2 + filename_len + 1, "octet", 5);
    buffer[len - 1] = 0x00;

    return add_promisc_payload(buffer, len);
}


static int add_promisc_ntp(void)
{
    uint8_t buffer[48];

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x1b;

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_dhcp(void)
{
    uint8_t buffer[244];

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x01;
    buffer[1] = 0x01;
    buffer[2] = 0x06;
    SET_BE32(buffer + 4, 0x3903f326);
    buffer[28] = 0x00;
    buffer[29] = 0x11;
    buffer[30] = 0x22;
    buffer[31] = 0x33;
    buffer[32] = 0x44;
    buffer[33] = 0x55;
    buffer[236] = 0x63;
    buffer[237] = 0x82;
    buffer[238] = 0x53;
    buffer[239] = 0x63;
    buffer[240] = 0x35;
    buffer[241] = 0x01;
    buffer[242] = 0x01;
    buffer[243] = 0xff;

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_stun(void)
{
    uint8_t buffer[20];
    static const uint8_t txid[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                   0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x00;
    buffer[1] = 0x01;
    buffer[4] = 0x21;
    buffer[5] = 0x12;
    buffer[6] = 0xa4;
    buffer[7] = 0x42;
    memcpy(buffer + 8, txid, sizeof(txid));

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_modbus(void)
{
    uint8_t buffer[12];

    memset(buffer, 0, sizeof(buffer));
    buffer[1] = 0x01;
    buffer[5] = 0x06;
    buffer[6] = 0x01;
    buffer[7] = 0x03;
    buffer[11] = 0x01;

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_opcua(void)
{
    uint8_t buffer[32];

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "HELF", 4);
    SET_LE32(buffer + 4, sizeof(buffer));
    SET_LE32(buffer + 12, 65535);
    SET_LE32(buffer + 16, 65535);
    SET_LE32(buffer + 20, 1 << 20);
    SET_LE32(buffer + 24, 16);

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_radius(void)
{
    uint8_t buffer[20];

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x01;
    buffer[2] = 0x00;
    buffer[3] = sizeof(buffer);

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_ikev2(void)
{
    uint8_t buffer[28];

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x01;
    buffer[1] = 0x02;
    buffer[2] = 0x03;
    buffer[3] = 0x04;
    buffer[4] = 0x05;
    buffer[5] = 0x06;
    buffer[6] = 0x07;
    buffer[7] = 0x08;
    buffer[16] = 0x21;
    buffer[17] = 0x20;
    buffer[18] = 0x22;
    buffer[19] = 0x08;
    buffer[27] = sizeof(buffer);

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_mysql(void)
{
    uint8_t buffer[36];

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 32;
    buffer[3] = 0x01;
    buffer[4] = 0x01;
    buffer[12] = 0x21;

    return add_promisc_payload(buffer, sizeof(buffer));
}


static int add_promisc_postgres(void)
{
    size_t len, params_len;
    uint8_t buffer[64];
    static const char params[] = "user\0user\0database\0db\0\0";

    params_len = sizeof(params) - 1;
    len = 0;

    SET_BE32(buffer + len, 8 + params_len);
    len += 4;
    SET_BE32(buffer + len, 196608);
    len += 4;
    memcpy(buffer + len, params, params_len);
    len += params_len;

    return add_promisc_payload(buffer, len);
}


static int add_promisc_mongo(void)
{
    size_t len;
    uint8_t buffer[64];

    len = 0;
    SET_LE32(buffer + len, 37);
    len += 4;
    SET_LE32(buffer + len, 1);
    len += 4;
    SET_LE32(buffer + len, 0);
    len += 4;
    SET_LE32(buffer + len, 2013);
    len += 4;
    SET_LE32(buffer + len, 0);
    len += 4;
    buffer[len++] = 0x00;

    SET_LE32(buffer + len, 16);
    len += 4;
    buffer[len++] = 0x10;
    memcpy(buffer + len, "ping", 4);
    len += 4;
    buffer[len++] = 0x00;
    SET_LE32(buffer + len, 1);
    len += 4;
    buffer[len++] = 0x00;

    return add_promisc_payload(buffer, len);
}


static int setup_promisc_payloads(void)
{
    const char *hostname, *webrtc_body;
    static const uint8_t amqp[] = {'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01};
    static const uint8_t ldap[] = {0x2f, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07,
                                   0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00};
    static const uint8_t snmp[] = {
        0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62,
        0x6c, 0x69, 0x63, 0xa0, 0x1c, 0x02, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
        0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
        0x00, 0x05, 0x00};
    static const uint8_t rtp[] = {0x7f, 0x60, 0x00, 0x01, 0x00, 0x00,
                                  0x00, 0x01, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t rtcp[] = {0x81, 0xc9, 0x00, 0x01,
                                   0x00, 0x00, 0x00, 0x01};
    static const uint8_t socks5[] = {0x05, 0x01, 0x00};
    static const uint8_t socks4[] = {0x04, 0x01, 0x00, 0x50, 0x7f,
                                     0x00, 0x00, 0x01, 0x00};
    static const uint8_t coap[] = {0x40, 0x01, 0x00, 0x01};
    static const uint8_t coap_ack[] = {0x60, 0x00, 0x00, 0x01};
    static const uint8_t bacnet[] = {0x81, 0x0a, 0x00, 0x0b, 0x01, 0x04,
                                     0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t knx[] = {0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, 0x08,
                                  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t telnet[] = {0xff, 0xfd, 0x18};

    hostname = promisc_hostname();
    webrtc_body = "{\"type\":\"offer\",\"sdp\":\"v=0\\r\\n\"}";

    if (add_promisc_printf("GET / HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n\r\n",
                           hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "GET /index.m3u8 HTTP/1.1\r\nHost: %s\r\nAccept: "
            "application/vnd.apple.mpegurl, application/x-mpegURL, */*\r\n\r\n",
            hostname) < 0) {
        return -1;
    }
    if (add_promisc_text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") < 0) {
        return -1;
    }
    if (add_promisc_quic_like("h3-control-stream",
                              sizeof("h3-control-stream") - 1) < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", hostname,
            hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "GET /chat HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
            hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "POST /signal HTTP/1.1\r\nHost: %s\r\nContent-Type: "
            "application/json\r\nContent-Length: %zu\r\n\r\n%s",
            hostname, strlen(webrtc_body), webrtc_body) < 0) {
        return -1;
    }
    if (add_promisc_text("SSH-2.0-OpenSSH_9.6\r\n") < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP 1.1.1.1;branch=z9\r\n"
            "From: <sip:a@%s>;tag=1\r\nTo: <sip:b@%s>\r\nCall-ID: 1@%s\r\n"
            "CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
            hostname, hostname, hostname, hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf("OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
                           hostname) < 0) {
        return -1;
    }
    if (add_promisc_payload(rtp, sizeof(rtp)) < 0) {
        return -1;
    }
    if (add_promisc_payload(rtcp, sizeof(rtcp)) < 0) {
        return -1;
    }
    if (add_promisc_text("USER anonymous\r\nPASS guest@\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("AUTH TLS\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("USER test\r\nPASS test\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("STLS\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("a1 CAPABILITY\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("a1 STARTTLS\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("MODE READER\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("NICK bot\r\nUSER bot 0 * :bot\r\n") < 0) {
        return -1;
    }
    if (add_promisc_printf("%s\r\n", hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "<stream:stream to='%s' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
            hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf("EHLO %s\r\n", hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf("EHLO %s\r\nSTARTTLS\r\n", hostname) < 0) {
        return -1;
    }
    if (add_promisc_printf(
            "<34>1 2020-01-01T00:00:00Z %s app - - - test\r\n", hostname) < 0) {
        return -1;
    }
    if (add_promisc_mqtt() < 0) {
        return -1;
    }
    if (add_promisc_stomp(hostname) < 0) {
        return -1;
    }
    if (add_promisc_text("PING\r\n") < 0) {
        return -1;
    }
    if (add_promisc_payload(amqp, sizeof(amqp)) < 0) {
        return -1;
    }
    if (add_promisc_text("*1\r\n$4\r\nPING\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("version\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("@RSYNCD: 31.0\n") < 0) {
        return -1;
    }
    if (add_promisc_text("ruok") < 0) {
        return -1;
    }
    if (add_promisc_payload(ldap, sizeof(ldap)) < 0) {
        return -1;
    }
    if (add_promisc_payload(snmp, sizeof(snmp)) < 0) {
        return -1;
    }
    if (add_promisc_dns(hostname) < 0) {
        return -1;
    }
    if (add_promisc_tls() < 0) {
        return -1;
    }
    if (add_promisc_quic_like("quic-example-payload",
                              sizeof("quic-example-payload") - 1) < 0) {
        return -1;
    }
    if (add_promisc_kcp() < 0) {
        return -1;
    }
    if (add_promisc_ntp() < 0) {
        return -1;
    }
    if (add_promisc_dhcp() < 0) {
        return -1;
    }
    if (add_promisc_tftp_request(0x0001, 0) < 0) {
        return -1;
    }
    if (add_promisc_tftp_request(0x0001, 20) < 0) {
        return -1;
    }
    if (add_promisc_tftp_request(0x0001, 100) < 0) {
        return -1;
    }
    if (add_promisc_tftp_request(0x0002, 0) < 0) {
        return -1;
    }
    if (add_promisc_stun() < 0) {
        return -1;
    }
    if (add_promisc_payload(socks5, sizeof(socks5)) < 0) {
        return -1;
    }
    if (add_promisc_payload(socks4, sizeof(socks4)) < 0) {
        return -1;
    }
    if (add_promisc_text("RFB 003.008\n") < 0) {
        return -1;
    }
    if (add_promisc_modbus() < 0) {
        return -1;
    }
    if (add_promisc_opcua() < 0) {
        return -1;
    }
    if (add_promisc_payload(coap, sizeof(coap)) < 0) {
        return -1;
    }
    if (add_promisc_payload(coap_ack, sizeof(coap_ack)) < 0) {
        return -1;
    }
    if (add_promisc_payload(bacnet, sizeof(bacnet)) < 0) {
        return -1;
    }
    if (add_promisc_payload(knx, sizeof(knx)) < 0) {
        return -1;
    }
    if (add_promisc_radius() < 0) {
        return -1;
    }
    if (add_promisc_ikev2() < 0) {
        return -1;
    }
    if (add_promisc_text(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n") < 0) {
        return -1;
    }
    if (add_promisc_text("/\r\n") < 0) {
        return -1;
    }
    if (add_promisc_payload(telnet, sizeof(telnet)) < 0) {
        return -1;
    }
    if (add_promisc_mysql() < 0) {
        return -1;
    }
    if (add_promisc_postgres() < 0) {
        return -1;
    }
    if (add_promisc_mongo() < 0) {
        return -1;
    }

    return 0;
}


int fh_payload_setup(void)
{
    int res;
    size_t len;
    struct payload_info *pinfo;
    struct payload_node *node;

    if (g_ctx.promisc) {
        res = setup_promisc_payloads();
        if (res < 0) {
            goto cleanup;
        }
    }

    for (pinfo = g_ctx.plinfo; pinfo->type; pinfo++) {
        node = malloc(sizeof(*node));
        if (!node) {
            E("ERROR: malloc(): %s", strerror(errno));
            goto cleanup;
        }

        append_ring_node(&current_node, node);

        switch (pinfo->type) {
            case FH_PAYLOAD_CUSTOM:
                len = sizeof(node->payload);
                res = make_custom(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_custom));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTP:
                len = sizeof(node->payload);
                res = make_http_get(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_http_get));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTPS:
                len = sizeof(node->payload);
                res = make_tls_client_hello(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_tls_client_hello));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            default:
                E("ERROR: Unknown payload type");
                goto cleanup;
        }
    }

    if (!current_node && !promisc_node_count) {
        E("ERROR: No payload is available");
        goto cleanup;
    }

    if (current_node) {
        current_node = current_node->next;
    }

    return 0;

cleanup:
    fh_payload_cleanup();

    return -1;
}


void fh_payload_cleanup(void)
{
    free_ring(&current_node);
    cleanup_promisc_payloads();
}


void th_payload_get(uint8_t **payload_ptr, size_t *payload_len)
{
    struct payload_node *node;

    if (g_ctx.promisc && promisc_node_count) {
        node = promisc_nodes[rand() % promisc_node_count];
        *payload_ptr = node->payload;
        *payload_len = node->payload_len;
        return;
    }

    *payload_ptr = current_node->payload;
    *payload_len = current_node->payload_len;
    current_node = current_node->next;
}
