/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020-2021 Nick Krylov.
 *
 * Author: Nick Krylov <krylovna@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */


#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>

#include "openconnect-internal.h"

#define FREE(ptr) do{free(ptr);ptr=NULL;}while(0)

enum PACKET_TYPE {
    CMD = 1,
    IP
};

/* SLIM protocol commands */
static const char client_hello[] = "(client_hello\n\
        :client_version (%d)\n\
        :protocol_version (%d)\n\
        :OM (\n\
                :ipaddr (%s)\n\
                :keep_address (%s)\n\
        )\n\
        :optional (\n\
                :client_type (4)\n\
        )\n\
        :cookie (%s)\n\
)";

static const char keepalive[] = "(keepalive\n\
        :id (0)\n\
)";

static const char disconnect[] = "(disconnect\n\
        :code (28)\n\
        :message (\"User has disconnected.\")\n\
)";

static struct pkt *build_packet(int type, const void *data, int len)
{
    char *buf;
    struct pkt *p = calloc(1, sizeof (struct pkt) +len);
    p->len = len;
    buf = (char *) p->cstp.hdr;
    store_be32(buf, p->len);
    store_be32(buf + sizeof (uint32_t), type);
    memcpy(p->data, data, len);
    return p;
}

static int snx_send(struct openconnect_info *vpninfo, int sync)
{
    struct pkt *p = vpninfo->current_ssl_pkt;
    char *buf = (char*) p->cstp.hdr;
    int buf_len = p->len + sizeof (p->cstp.hdr);
    int ptype = load_be32(buf + 4);
    int ret;

    if (ptype == IP) {
        vpn_progress(vpninfo, PRG_TRACE, _("Packet outgoing:\n"));
        dump_buf_hex(vpninfo, PRG_TRACE, '>', (void *) buf, buf_len);
    }

    if (sync)
        ret = vpninfo->ssl_write(vpninfo, buf, buf_len);
    else
        ret = ssl_nonblock_write(vpninfo, 0, buf, buf_len);
    /* Resend only if ret == 0! */
    if (ret != 0)
        FREE(vpninfo->current_ssl_pkt);

    if (ret > 0) {
        if (ret < buf_len) {
            vpn_progress(vpninfo, PRG_ERR,
                    _("SSL wrote too few bytes! Asked for %d, sent %d.\n"),
                    buf_len, ret);
            vpninfo->quit_reason = "Internal error";
            /* Should reconnect on error anyway. */
            ret = -EIO;
        }
    }
    return ret;
}

/* Special handling for commands: hide authentication-related fields */
static char *hide_auth_data(const char *data)
{
    static const char *excl_fields[] = {"username", "password", "cookie", "active_key", "session_id"};
    char *val_start, *val_end, *ret = strdup(data);
    const char *fld, *fld_start;
    int i;
    for (i = 0; i < sizeof (excl_fields) / sizeof (*excl_fields); i++) {
        fld = excl_fields[i];
        fld_start = ret;
        while ((fld_start = strstr(fld_start, fld))) {
            val_start = strstr(fld_start, "(");
            if (fld_start[strlen(fld)] == ' ') {
                val_end = strstr(fld_start, ")");
                if (val_end > (val_start + 1)) {
                    memmove(val_start + 2, val_end, strlen(val_end) + 1); /* include \0 */
                    val_start[1] = 'X'; /* Hide string, but mark as not empty*/
                }
            }
            fld_start++;
        }
    }
    return ret;
}

static int snx_send_command(struct openconnect_info *vpninfo, const char*cmd, int sync)
{
    int len = strlen(cmd) + 1;
    vpninfo->current_ssl_pkt = build_packet(CMD, cmd, len);
    if (vpninfo->verbose >= PRG_DEBUG) {
        char *cmd_print = hide_auth_data(cmd);
        vpn_progress(vpninfo, PRG_DEBUG, _("Command outgoing:\n%s\n"), cmd_print);
        free(cmd_print);
    }
    return snx_send(vpninfo, sync);
}

static int snx_send_packet(struct openconnect_info *vpninfo)
{
    return snx_send(vpninfo, 0);
}

static int snx_receive(struct openconnect_info *vpninfo, int*pkt_type, int sync)
{
    /* NOTE: static buffer here is safe as long as openconnect is single-threaded. */
    static char hdr[8];
    static const int hdr_len = sizeof (hdr);
    int len, pkt_len, payload_len, ret;
    uint8_t *buf;

    if (!vpninfo->cstp_pkt) {
        if (sync)
            len = vpninfo->ssl_read(vpninfo, hdr, sizeof (hdr));
        else {
            len = ssl_nonblock_read(vpninfo, 0, hdr, sizeof (hdr));
            if (len <= 0) {
                /* Exit immediately if no data or error in non-blocking mode. */
                return len;
            }
        }

        if (len != hdr_len) {
            vpn_progress(vpninfo, PRG_ERR, _("Received %d bytes instead of %d.\n"), len, hdr_len);
            vpninfo->quit_reason = "Short packet received";
            return -EIO;
        }
        pkt_len = load_be32(hdr);

        vpninfo->cstp_pkt = malloc(sizeof (struct pkt) +pkt_len);
        if (!vpninfo->cstp_pkt) {
            vpn_progress(vpninfo, PRG_ERR, _("Allocation failed.\n"));
            return -ENOMEM;
        }
        memcpy(vpninfo->cstp_pkt->cstp.hdr, hdr, hdr_len);
    }


    payload_len = vpninfo->cstp_pkt->len = load_be32(vpninfo->cstp_pkt->cstp.hdr);
    *pkt_type = load_be32(vpninfo->cstp_pkt->cstp.hdr + 4);
    buf = &(vpninfo->cstp_pkt->cstp.hdr[0]) + hdr_len;

    if (sync)
        ret = vpninfo->ssl_read(vpninfo, (char*) buf, payload_len);
    else
        ret = ssl_nonblock_read(vpninfo, 0, buf, payload_len);

    vpninfo->ssl_times.last_rx = time(NULL);

    if (ret != 0 && ret != payload_len)
        FREE(vpninfo->cstp_pkt);

    if (ret > 0) {
        if (ret != payload_len)
            return -EIO;

        if (vpninfo->verbose >= PRG_DEBUG) {
            if (*pkt_type == IP) {
                vpn_progress(vpninfo, PRG_TRACE, _("Received data packet of %d bytes.\n"),
                        payload_len);
                dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *) &vpninfo->cstp_pkt->cstp.hdr, payload_len + hdr_len);
            } else if (*pkt_type == CMD) {
                char*cmd_print = hide_auth_data((char*) vpninfo->cstp_pkt->data);
                vpn_progress(vpninfo, PRG_DEBUG, _("Command received:\n%s\n"), cmd_print);
                free(cmd_print);
            }
        }
    }
    return ret;
}

static int send_KA(struct openconnect_info *vpninfo, int sync)
{
    /* Update last_tx here only, because native client send KA messages constantly. */
    vpninfo->ssl_times.last_tx = time(NULL);
    return snx_send_command(vpninfo, keepalive, sync);
}

static int send_disconnect(struct openconnect_info *vpninfo)
{
    return snx_send_command(vpninfo, disconnect, 1);
}
/* NOTE: IPv4 versions */
static uint32_t strtoipv4(const char *ip)
{
    uint32_t ret = 0;
    struct in_addr buf;
    if (inet_pton(AF_INET, ip, &buf) == 1) {
        ret = ntohl(buf.s_addr);
    }
    return ret;
}

static char* ipv4tostr(uint32_t ip_int)
{
    static char ret[INET_ADDRSTRLEN] = {0};
    int32_t buf = htonl(ip_int);
    return inet_ntop(AF_INET, &buf, ret, INET_ADDRSTRLEN) ? ret : NULL;
}

/* Authentication-related helpers. */
static
int enc_dec_table[] = {
    0x2D, 0x4F, 0x44, 0x49, 0x46, 0x49, 0x45, 0x44, 0x26, 0x57, 0x30, 0x52, 0x4F, 0x50, 0x45, 0x52,
    0x54, 0x59, 0x33, 0x48, 0x45, 0x45, 0x54, 0x37, 0x49, 0x54, 0x48, 0x2F, 0x2B, 0x34, 0x48, 0x45,
    0x33, 0x48, 0x45, 0x45, 0x54, 0x29, 0x24, 0x33, 0x3F, 0x2C, 0x24, 0x21, 0x30, 0x3F, 0x21, 0x35,
    0x3F, 0x30, 0x32, 0x2F, 0x30, 0x25, 0x32, 0x34, 0x29, 0x25, 0x33, 0x2E, 0x35, 0x2C, 0x2C, 0x10,
    0x26, 0x37, 0x3F, 0x37, 0x30, 0x3F, 0x2F, 0x22, 0x2A, 0x25, 0x23, 0x34, 0x33, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Reverse string in-place. len is always even. */
static void strrv(char *data, int len)
{
    int i, j;
    char c;
    for (i = 0; i < len / 2; i++) {
        j = len - i - 1;
        c = data[j];
        data[j] = data[i];
        data[i] = c;
    }
}

static void bytes_from_hex(const char *hex, uint8_t *bytes)
{
    int len = strlen(hex);
    uint32_t off = 0, val;
    int i;
    for (i = 0; i < len / 2; i++) {
        off += 2 * sscanf(hex + off, "%2x", &val);
        bytes [i] = val & 0xff;
    }
}

static void hex_from_bytes(const uint8_t *bytes, int len, char *hex)
{
    int off = 0, i;
    for (i = 0; i < len; i++)
        off += sprintf(hex + off, "%02hx", (uint16_t) bytes[i]);
    hex[off] = '\0';
}

static
uint8_t enc_dec_ichr(int i, uint8_t ordc)
{
    int idx;
    uint8_t ret;
    uint64_t prod = (((uint64_t) i) * (0x3531DEC1));
    uint64_t high_bits = prod >> (32 + 4);
    int ofs1 = high_bits;
    int ofs2 = ofs1 + ofs1 * 8;
    ofs2 = ofs1 + ofs2 * 2;
    ofs2 = ofs1 + ofs2 * 4;
    idx = i - ofs2;

    if (ordc == 0xff) {
        ordc = 0;
    }

    ret = ((enc_dec_table[idx] ^ ordc));
    if (ret == 0) {
        ret = 0xff;
    }
    return ret;
}

static char *encode(const char *s)
{
    int i, slen = strlen(s);
    char *ret = calloc(1, 2 * slen + 1);
    char *tmp = strdup(s);

    for (i = 0; i < slen; i++)
        tmp[i] = enc_dec_ichr(i, (uint8_t) tmp[i]);

    strrv(tmp, slen);
    hex_from_bytes((uint8_t *) tmp, slen, ret);
    free_pass(&tmp);
    return ret;
}

static char *decode(const char *s)
{
    int i, slen = strlen(s), retlen = slen / 2;
    char *ret = calloc(retlen + 1, 1);
    bytes_from_hex(s, (uint8_t *) ret);
    strrv(ret, retlen);
    for (i = 0; i < retlen; i++)
        ret[i] = enc_dec_ichr(i, (uint8_t) ret[i]);
    ret[retlen] = 0;
    return ret;
}

/* Options handling helpers. Needed for server response processing.
 * Unfortunately, option syntax is not standard http/xml, but a special one.
 * Fortunately, it is not that complicated.*/

struct cp_option {
    char *key, *value;
    int parent;
};

typedef struct cp_option cp_option;

struct cp_options {
    char *rawdata;
    int len;
    cp_option elems[];
};

typedef struct cp_options cp_options;

static cp_options *cpo_init(int ne)
{
    cp_options *cfg = (cp_options *) calloc(1, sizeof (cp_options) + ne * sizeof (cp_option));
    cfg->len = ne;
    return cfg;
}

static void cpo_free(cp_options *cfg)
{
    if (!cfg) return;
    free_pass(&cfg->rawdata);
    free(cfg);
}

static int cpo_parse_elem(cp_options *cfg, char **input_ptr, int pidx, int *nextidx)
{
    char *nl = NULL, *strstart, *strend = NULL, *colon = NULL, *obrkt = NULL;
    char *cbrkt = NULL, *key;
    int idx, vlen, good, previdx;
    struct cp_option *cfge;
    char *input = *input_ptr;

    colon = strchr(input, ':');
    cbrkt = strchr(input, ')');
    if (colon && cbrkt > colon) {
        obrkt = strchr(colon, '(');
        strstart = strstr(colon, "(\"");

        if (strstart && strstart == obrkt) {
            /* Adjust nl */
            strend = strstr(colon, "\")");
            nl = strend + 2;
        } else {
            cbrkt = strchr(colon, ')');
            nl = strchr(colon, '\n');
            if (nl < cbrkt) {
                cbrkt = NULL;
            }
        }
    } else {
        colon = NULL;
        /* After last element */
        cbrkt = strchr(input, ')');
        if (cbrkt)
            nl = strchr(cbrkt, '\n');
    }
    if (!nl)
        return 0;
    nl[0] = 0;

    *input_ptr = nl + 1;

    idx = *nextidx;
    cfge = cfg->elems + idx;
    if (colon) {
        (*nextidx)++;
        key = colon + 1;
        /* Save non-empty keys only */
        if (key[0] != ' ') {
            cfge->key = key;
            key[obrkt - key - 1] = 0;
        }

        cfge->parent = pidx;
        if (obrkt) {
            if (cbrkt) {
                /* Single element. Save value. */
                cfge->value = obrkt + 1;
                vlen = cbrkt - cfge->value;
                cfge->value[vlen] = 0;

                /* Drop quotes if string is quoted */
                if (strstart && strend) {
                    cfge->value[vlen - 1] = 0;
                    cfge->value++;
                }
                return 1;
            } else {
                /* Container (list|map) */
                previdx = *nextidx;
                while ((good = cpo_parse_elem(cfg, input_ptr, idx, nextidx))&&(previdx<*nextidx))
                    previdx = *nextidx;
                return good;
            }
        }
    } else {
        if (cbrkt)
            /* Container end */
            return 1;
    }
    return 0;
}

static cp_options *cpo_parse(const char *input)
{
    char *key, *data = strdup(input);
    size_t full_len = strlen(input);
    const char *dataend = data + full_len - 1;

    /* Count number of elements in input data which is equal to the amount
     * of ':' characters in the input string.*/

    char *next = data;
    cp_options *cfg;
    int nelem, nextidx, ok;
    for (nelem = 0; (next = strchr(next, ':')); nelem++, next++);

    cfg = cpo_init(nelem + 1);
    cfg->rawdata = data;

    next = data;
    key = next + 1; /* Drop leading '(' */
    cfg->elems[0].key = key;
    next = strchr(key, '\n');
    nextidx = 1;
    ok = next != NULL;

    /* Do recursive parsing */
    if (ok) {
        key[next - key] = 0;
        next++;
        while ((ok = cpo_parse_elem(cfg, &next, 0, &nextidx))&&(next < dataend));
    }
    if (!ok) {
        cpo_free(cfg);
        cfg = 0;
    }
    return cfg;
}

static int cpo_find_child(const cp_options *cfg, int pidx, const char *key)
{
    int elemidx = -1;
    int ne = cfg->len;
    if (pidx >= 0) {
        for (int ie = pidx + 1; ie < ne; ie++) {
            const cp_option *elem = &cfg->elems[ie];
            if (elem->parent == pidx && elem->key && (0 == strcmp(key, elem->key))) {
                elemidx = ie;
                break;
            }
        }
    }
    return elemidx;
}

static int cpo_elem_iter(const cp_options *cfg, int iparent, int *i)
{

    int found = 0;
    if (*i < 0)
        *i = iparent;
    else
        ++(*i);

    for (; *i < cfg->len; ++(*i)) {
        const cp_option *nextelem = &cfg->elems[*i];
        if (nextelem->parent == iparent) {
            found = 1;
            break;
        }
    }
    return found;
}

static const cp_option *cpo_get(const cp_options *cfg, int i)
{
    return (i >= 0) ? &cfg->elems[i] : NULL;
}

static int cpo_get_index(const cp_options *cfg, const cp_option *opt)
{
    return opt - cfg->elems;
}

static struct oc_vpn_option *find_option(struct openconnect_info *vpninfo, const char *key)
{
    struct oc_vpn_option *opt = vpninfo->cstp_options;
    struct oc_vpn_option *next;
    for (; opt; opt = next) {
        if (0 == strcmp(key, opt->option))
            return opt;
        next = opt->next;
    }
    return NULL;
}

static const char *get_option(struct openconnect_info *vpninfo, const char *key)
{
    struct oc_vpn_option *opt = find_option(vpninfo, key);
    return opt ? opt->value : NULL;
}

static const char *add_option(struct openconnect_info *vpninfo, const char *key,
        const char *val)
{
    return val?add_option_dup(&vpninfo->cstp_options, key, val, -1):NULL;
}

static const char *set_option(struct openconnect_info *vpninfo, const char *key,
        const char *val)
{
    struct oc_vpn_option *opt = find_option(vpninfo, key);
    if (opt) {
        free(opt->value);
        opt->value = strdup(val);
    } else
        return add_option(vpninfo, key, val);
    return opt->value;
}

static void check_set_str(char **from, const char *to)
{
    char *fptr = *from;
    if (fptr == to)
        return;

    if (fptr && to && 0 == strcmp(fptr, to))
        return;

    free(fptr);
    *from = NULL;
    if (to)
        *from = strdup(to);
}

static void switch_to(struct openconnect_info *vpninfo, const char*host, int port,
        const char*path)
{
    const char *urlpath = path ? path : get_option(vpninfo, "org_urlpath");
    check_set_str(&vpninfo->hostname, host ? host : get_option(vpninfo, "org_hostname"));
    check_set_str(&vpninfo->urlpath, urlpath);
    vpninfo->port = (port > 0) ? port : atoi(get_option(vpninfo, "org_port"));
}

static int send_client_hello_command(struct openconnect_info *vpninfo)
{

    int ret, reconnect = vpninfo->ip_info.addr != NULL;
    char *request_body = NULL;
    int proto_ver = 1;
    int client_ver = 1;
    const char *cookie = get_option(vpninfo, "slim_cookie");

    if (asprintf(&request_body, client_hello, client_ver, proto_ver,
            (reconnect ? vpninfo->ip_info.addr : "0.0.0.0"),
            (reconnect ? "true" : "false"), cookie) < 0)
        return -ENOMEM;

    ret = snx_send_command(vpninfo, request_body, 1);
    free(request_body);
    return ret;
}

static int gen_ranges(struct openconnect_info *vpninfo, uint32_t ip_min,
        uint32_t ip_max, struct oc_text_buf *s)
{

    uint32_t ip = ip_min, imask, ip_low, ip_high;
    while (ip <= ip_max) {
        struct oc_split_include *inc;
        /* make mask that covers current ip range, but does not exceed it. */
        uint32_t mask = 0;
        for (imask = 0; imask < 32; imask++) {
            uint32_t curbit = 1 << imask;
            mask |= curbit;
            ip_low = ip & (~mask);
            ip_high = ip_low | mask;
            if (ip_low < ip || ip_high > ip_max) {
                mask &= ~curbit;
                break;
            }
        }
        buf_truncate(s);
        buf_append(s, "%s/%d", ipv4tostr(ip), 32 - imask);

        inc = malloc(sizeof (*inc));
        if (!inc)
            return 0;

        inc->route = add_option(vpninfo, "split-include", s->data);
        if (!inc->route)
            return 0;

        inc->next = vpninfo->ip_info.split_includes;
        vpninfo->ip_info.split_includes = inc;
        ip += mask + 1;
    }
    return 1;
}

static int handle_ip_ranges(struct openconnect_info *vpninfo, const cp_options *cpo, int range_idx)
{
    int ret = 1, ichild = -1;
    const cp_option*from_elem, *to_elem;
    struct oc_text_buf*s = buf_alloc();
    uint32_t from_ip_int, to_ip_int, gw_ip_int = strtoipv4(vpninfo->ip_info.gateway_addr);

    while (cpo_elem_iter(cpo, range_idx, &ichild)) {

        from_elem = cpo_get(cpo, cpo_find_child(cpo, ichild, "from"));
        to_elem = cpo_get(cpo, cpo_find_child(cpo, ichild, "to"));
        vpn_progress(vpninfo, PRG_DEBUG, _("Received IP address range %s:%s\n"),
                from_elem->value, to_elem->value);

        from_ip_int = strtoipv4(from_elem->value);
        to_ip_int = strtoipv4(to_elem->value);

        if (from_ip_int == gw_ip_int)
            continue;

        if (!gen_ranges(vpninfo, from_ip_int, to_ip_int, s)) {
            ret = 0;
            break;
        }
    }
    buf_free(s);
    return ret;
}

static int handle_hello_reply(const char *data, struct openconnect_info *vpninfo)
{
    int ichild = -1;
    int i, ret = 1, idx, OM_idx, range_idx;
    const cp_option *opt;
    cp_options *cpo = cpo_parse(data);

    if (!cpo) return 0;
    opt = cpo->elems;
    if (opt->key && strstr(opt->key, "hello_reply")) {

        /* Save versions, just in case */
        opt = cpo_get(cpo, cpo_find_child(cpo, 0, "version"));
        set_option(vpninfo, "slim_ver", opt->value);
        opt = cpo_get(cpo, cpo_find_child(cpo, 0, "protocol_version"));
        set_option(vpninfo, "slim_proto_ver", opt->value);

        /* Timeouts setup */
        idx = cpo_find_child(cpo, 0, "timeouts");
        opt = cpo_get(cpo, cpo_find_child(cpo, idx, "keepalive"));
        vpninfo->ssl_times.keepalive = MAX(10, atoi(opt->value));
        opt = cpo_get(cpo, cpo_find_child(cpo, idx, "authentication"));
        vpninfo->auth_expiration = time(NULL) + MAX(3600, atoi(opt->value));

        /* IP, NS, routing info */
        OM_idx = idx = cpo_find_child(cpo, 0, "OM");
        opt = cpo_get(cpo, cpo_find_child(cpo, idx, "ipaddr"));
        /* Check that ip is the same on reconnect.*/
        if (vpninfo->ip_info.addr && strcmp(vpninfo->ip_info.addr, opt->value)) {
            ret = 0;
            vpn_progress(vpninfo, PRG_ERR, _("Received different internal IP address %s (was %s)\n"),
                    opt->value, vpninfo->ip_info.addr);
        } else {
            vpninfo->ip_info.addr = set_option(vpninfo, "ipaddr", opt->value);
            vpn_progress(vpninfo, PRG_DEBUG, _("Received internal IP address %s\n"), opt->value);

            idx = cpo_find_child(cpo, OM_idx, "dns_servers");
            if (idx >= 0) {
                i = 0;
                while ((i < 3) && cpo_elem_iter(cpo, idx, &ichild)) {
                    opt = cpo_get(cpo, ichild);
                    vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), opt->value);
                    vpninfo->ip_info.dns[i++] = add_option(vpninfo, "dns_srv", opt->value);
                }
            }

            opt = cpo_get(cpo, cpo_find_child(cpo, OM_idx, "dns_suffix"));
            if (opt->value && strlen(opt->value))
                vpninfo->ip_info.domain = add_option(vpninfo, "dns_suff", opt->value);

            idx = cpo_find_child(cpo, OM_idx, "wins_servers");
            if (idx >= 0) {
                i = 0;
                ichild = -1;
                while ((i < 3) && cpo_elem_iter(cpo, idx, &ichild)) {
                    opt = cpo_get(cpo, ichild);
                    vpn_progress(vpninfo, PRG_DEBUG, _("Received WINS server %s\n"), opt->value);
                    vpninfo->ip_info.nbns[i++] = add_option(vpninfo, "wins_srv", opt->value);
                }
            }
            /* Note: optional.subnet not used. */

            range_idx = cpo_find_child(cpo, 0, "range");
            if (range_idx >= 0)
                ret = handle_ip_ranges(vpninfo, cpo, range_idx);
        }
    }
    cpo_free(cpo);
    return ret;
}

static int snx_start_tunnel(struct openconnect_info *vpninfo)
{
    int result, ptype;

    /* Try to open connection and send hello */
    switch_to(vpninfo, NULL, atoi(get_option(vpninfo, "ssl_port")), NULL);

    if (openconnect_open_https(vpninfo)) {
        vpninfo->quit_reason = "Failed to open HTTPS connection.";
        openconnect_close_https(vpninfo, 0);
        return -EIO;
    }

    result = send_client_hello_command(vpninfo);
    if (result < 0) {
        vpninfo->quit_reason = "Failed to send client_hello.";
        openconnect_close_https(vpninfo, 0);
        return -EIO;
    }

    /* Process hello reply */
    ptype = -1;
    snx_receive(vpninfo, &ptype, 1);

    if (ptype != CMD) {
        FREE(vpninfo->cstp_pkt);
        vpninfo->quit_reason = "Received packet with wrong type.";
        openconnect_close_https(vpninfo, 0);
        return -EIO;
    }

    result = handle_hello_reply((char*) vpninfo->cstp_pkt->data, vpninfo);
    FREE(vpninfo->cstp_pkt);

    if (!result) {
        vpninfo->quit_reason = "Error while processing hello_reply.";
        openconnect_close_https(vpninfo, 0);
        return -EIO;
    }

    if (send_KA(vpninfo, 1) < 0) {
        vpninfo->quit_reason = "Failed to send initial KA.";
        return -EIO;
    }

    vpninfo->ssl_times.last_rekey = vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);

    monitor_fd_new(vpninfo, ssl);
    monitor_read_fd(vpninfo, ssl);
    monitor_except_fd(vpninfo, ssl);
    return 0;
}

static int do_reconnect(struct openconnect_info *vpninfo)
{
    int result = ssl_reconnect(vpninfo);
    if (result) {
        vpninfo->quit_reason = "Server reconnect failed";
        return result;
    }
    return snx_start_tunnel(vpninfo);
}

static int snx_handle_command(struct openconnect_info *vpninfo)
{
    char *data = (char *) vpninfo->cstp_pkt->data;
    int ret = 0;

    if (strstr(data, "disconnect")) {
        vpninfo->quit_reason = "Disconnect on server request";
        ret = 1;
    }
    FREE(vpninfo->cstp_pkt);
    return ret;
}

int cp_obtain_cookie(struct openconnect_info *vpninfo)
{
    vpn_progress(vpninfo, PRG_ERR, "CP authentication not yet implemented\n");
    return -EOPNOTSUPP;
}

int cp_connect(struct openconnect_info *vpninfo)
{
    return 0;
}

int cp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
    int ret = 0, result;

    if (vpninfo->ssl_fd == -1)
        return do_reconnect(vpninfo);

    /* Service one incoming packet. */
    if (readable) {
        int ptype = -1;
        result = snx_receive(vpninfo, &ptype, 0);
        ret += result;
        if (result < 0)
            /* Try to reconnect on error */
            return do_reconnect(vpninfo);

        if (result != 0) {
            if (ptype == CMD) {
                if (snx_handle_command(vpninfo))
                    /* Server-side disconnect. Should exit. */
                    return -EPIPE;
            } else if (ptype == IP) {
                queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
                vpninfo->cstp_pkt = NULL;
            } else
                vpn_progress(vpninfo, PRG_INFO, _("Unknown packet of type %d, ignoring.\n"), ptype);
        }
    }

    /* Service one outgoing packet. */

    if (!vpninfo->current_ssl_pkt) {
        struct pkt *qpkt = dequeue_packet(&vpninfo->outgoing_queue);
        if (qpkt) {
            vpninfo->current_ssl_pkt = build_packet(IP, qpkt->data, qpkt->len);
            free(qpkt);
        }
    } else
        unmonitor_write_fd(vpninfo, ssl);

    if (vpninfo->current_ssl_pkt) {

        if ((result = snx_send_packet(vpninfo)) < 0)
            /* Try to reconnect on error */
            return do_reconnect(vpninfo);
        ret += result;
    }

    /* Send KA if previous packet was successfully sent. */
    if (!vpninfo->current_ssl_pkt) {
        switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
        case KA_DPD:
        case KA_KEEPALIVE:
        {
            if ((result = send_KA(vpninfo, 0)) < 0)
                /* Try to reconnect on error */
                return do_reconnect(vpninfo);
            ret += result;
            break;
        }
        case KA_DPD_DEAD:
        {
            return do_reconnect(vpninfo);
        }
        }
    }
    return ret;
}

int cp_bye(struct openconnect_info *vpninfo, const char *reason)
{
    if (vpninfo->ssl_fd != -1) {
        send_disconnect(vpninfo);
        openconnect_close_https(vpninfo, 0);
    }
    return 0;
}
