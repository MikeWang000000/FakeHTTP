/*
 * globvar.h - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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

#ifndef FH_GLOBVAR_H
#define FH_GLOBVAR_H

#include <stdint.h>
#include <stdio.h>

struct fh_context {
    int exit;
    FILE *logfp;

    /* -4 */ int use_ipv4;
    /* -6 */ int use_ipv6;
    /* -d */ int daemon;
    /* -f */ int skipfw;
    /* -h */ const char *hostname;
    /* -i */ const char *iface;
    /* -k */ int killproc;
    /* -m */ uint32_t fwmark;
    /* -n */ uint32_t nfqnum;
    /* -p */ int rawrecv;
    /* -r */ int repeat;
    /* -s */ int silent;
    /* -t */ uint8_t ttl;
    /* -w */ const char *logpath;
    /* -x */ uint32_t fwmask;
    /* -z */ int use_iptables;
};

extern struct fh_context g_ctx;

#endif /* FH_GLOBVAR_H */
