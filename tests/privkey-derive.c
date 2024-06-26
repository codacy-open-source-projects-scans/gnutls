/*
 * Copyright (C) 2023 Red Hat, Inc.
 *
 * Author: Daiki Ueno
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

#include "config.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <stdint.h>

#include "utils.h"

/* Test vector from RFC7748, section 6.2 */
static uint8_t alice_priv[] = {
	0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0,
	0x4b, 0x58, 0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
	0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97,
	0x44, 0x89, 0x73, 0x91, 0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
	0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
};
static uint8_t alice_pub[] = {
	0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae,
	0xa1, 0x21, 0x07, 0x4a, 0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
	0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72,
	0x41, 0xd9, 0x53, 0xd4, 0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
	0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
};
#if 0
static uint8_t bob_priv[] = {
	0x1c, 0x30, 0x6a, 0x7a, 0xc2, 0xa0, 0xe2, 0xe0, 0x99, 0x0b, 0x29, 0x44, 0x70, 0xcb, 0xa3, 0x39, 0xe6, 0x45, 0x37, 0x72, 0xb0, 0x75, 0x81, 0x1d, 0x8f, 0xad, 0x0d, 0x1d,
	0x69, 0x27, 0xc1, 0x20, 0xbb, 0x5e, 0xe8, 0x97, 0x2b, 0x0d, 0x3e, 0x21, 0x37, 0x4c, 0x9c, 0x92, 0x1b, 0x09, 0xd1, 0xb0, 0x36, 0x6f, 0x10, 0xb6, 0x51, 0x73, 0x99, 0x2d,
};
#endif
static uint8_t bob_pub[] = {
	0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5, 0xbc, 0xfc, 0x0b, 0x59,
	0x9b, 0x6f, 0xec, 0xcf, 0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4,
	0xf3, 0x45, 0xb4, 0x30, 0x27, 0xd8, 0xb9, 0x72, 0xfc, 0x3e, 0x34, 0xfb,
	0x42, 0x32, 0xa1, 0x3c, 0xa7, 0x06, 0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae,
	0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09,
};
static uint8_t secret_expected[] = {
	0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95, 0xec, 0x1c, 0x16, 0xa9,
	0x4a, 0x0f, 0x74, 0xd1, 0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52,
	0x28, 0x1d, 0x28, 0x2b, 0xb6, 0x0c, 0x0b, 0x56, 0xfd, 0x24, 0x64, 0xc3,
	0x35, 0x54, 0x39, 0x36, 0x52, 0x1c, 0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a,
	0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d,
};

void doit(void)
{
	gnutls_privkey_t privkey;
	gnutls_pubkey_t pubkey;
	gnutls_datum_t x, y, k;
	gnutls_datum_t secret = { NULL, 0 };
	int ret;

	global_init();

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		fail("unable to init privkey: %s\n", gnutls_strerror(ret));
	}
	x.data = alice_pub;
	x.size = sizeof(alice_pub);
	k.data = alice_priv;
	k.size = sizeof(alice_priv);
	ret = gnutls_privkey_import_ecc_raw(privkey, GNUTLS_ECC_CURVE_X448, &x,
					    NULL, &k);
	if (ret < 0) {
		fail("unable to import privkey: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0) {
		fail("unable to init pubkey: %s\n", gnutls_strerror(ret));
	}
	y.data = bob_pub;
	y.size = sizeof(bob_pub);
	ret = gnutls_pubkey_import_ecc_raw(pubkey, GNUTLS_ECC_CURVE_X448, &y,
					   NULL);
	if (ret < 0) {
		fail("unable to import pubkey: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_privkey_derive_secret(privkey, pubkey, NULL, &secret, 0);
	if (ret < 0) {
		fail("unable to derive secret: %s\n", gnutls_strerror(ret));
	}

	if (secret.size != sizeof(secret_expected) ||
	    gnutls_memcmp(secret.data, secret_expected, secret.size)) {
		fail("derived secret is incorrect\n");
	}

	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);
	gnutls_free(secret.data);
	gnutls_global_deinit();
}
