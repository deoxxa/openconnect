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
    return 0;
}

int cp_bye(struct openconnect_info *vpninfo, const char *reason)
{
    return -1;
}
