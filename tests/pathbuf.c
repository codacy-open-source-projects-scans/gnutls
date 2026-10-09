/*
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Daiki Ueno
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "config.h"

#include "../lib/pathbuf.h"
#include "utils.h"
#include <string.h>
#include <assert.h>

static char long_path[GNUTLS_PATH_MAX + 2];

void doit(void)
{
	struct gnutls_pathbuf_st pathbuf;
	int i;
	int ret;

	ret = _gnutls_pathbuf_init(&pathbuf, "./x509certs");
	assert(ret == 0);
	assert(streq(pathbuf.ptr, "./x509certs"));
	assert(pathbuf.len == sizeof("./x509certs") - 1);

	ret = _gnutls_pathbuf_append(&pathbuf, "cert.pem");
	assert(ret == 0);
	assert(streq(pathbuf.ptr, "./x509certs/cert.pem"));
	assert(pathbuf.len == sizeof("./x509certs/cert.pem") - 1);
	_gnutls_pathbuf_deinit(&pathbuf);

	for (i = -1; i <= 1; i++) {
		memset(long_path, 'a', GNUTLS_PATH_MAX + i);
		long_path[GNUTLS_PATH_MAX + i] = '\0';

		ret = _gnutls_pathbuf_init(&pathbuf, long_path);
		assert(ret == 0);
		assert(streq(pathbuf.ptr, long_path));
		assert(pathbuf.len == (size_t)GNUTLS_PATH_MAX + i);

		ret = _gnutls_pathbuf_append(&pathbuf, "cert.pem");
		assert(ret == 0);
		assert(memeq(pathbuf.ptr, long_path, GNUTLS_PATH_MAX + i));
		assert(streq(&pathbuf.ptr[GNUTLS_PATH_MAX + i], "/cert.pem"));
		assert(pathbuf.len ==
		       GNUTLS_PATH_MAX + i + sizeof("/cert.pem") - 1);
		_gnutls_pathbuf_deinit(&pathbuf);
	}
}
