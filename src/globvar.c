/*
 * globvar.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "globvar.h"

#include <stdint.h>
#include <stdio.h>

struct fh_context g_ctx = {.exit = 0,
                           .logfp = NULL,

                           /* -4 */ .use_ipv4 = 0,
                           /* -6 */ .use_ipv6 = 0,
                           /* -d */ .daemon = 0,
                           /* -f */ .skipfw = 0,
                           /* -h */ .hostname = NULL,
                           /* -i */ .iface = NULL,
                           /* -k */ .killproc = 0,
                           /* -m */ .fwmark = 0x8000,
                           /* -n */ .nfqnum = 512,
                           /* -p */ .rawrecv = 0,
                           /* -r */ .repeat = 3,
                           /* -s */ .silent = 0,
                           /* -t */ .ttl = 3,
                           /* -w */ .logpath = NULL,
                           /* -x */ .fwmask = 0,
                           /* -z */ .use_iptables = 0};
