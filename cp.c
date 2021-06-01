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

static int snx_start_tunnel(struct openconnect_info *vpninfo)
{
    /* No-op */
    return -1;
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
