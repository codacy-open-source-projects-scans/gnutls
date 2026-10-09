/*
 * Copyright © 2026 David Dudas
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
 * along with GnuTLS; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gnutls_int.h"

#include "cert-common.h"
#include "eagain-common.h"
#include "utils.h"

#define LONG_CHAIN_SIZE 102
#define CERTIFICATE_COUNT 103

const char *side;

#define CHECK_RET(call)                                                 \
	do {                                                            \
		int ret_ = (call);                                      \
		if (ret_ < 0)                                           \
			fail("%s: %s\n", #call, gnutls_strerror(ret_)); \
	} while (0)

static void create_chain(gnutls_x509_crt_t *certs, unsigned int chain_size,
			 gnutls_x509_privkey_t key)
{
	unsigned int i;
	time_t now = time(NULL);

	for (i = 0; i < chain_size; i++) {
		unsigned char serial[4] = { i >> 24, i >> 16, i >> 8, i + 1 };
		char dn[64];

		CHECK_RET(gnutls_x509_crt_init(&certs[i]));
		CHECK_RET(gnutls_x509_crt_set_version(certs[i], 3));
		CHECK_RET(gnutls_x509_crt_set_serial(certs[i], serial,
						     sizeof(serial)));
		CHECK_RET(gnutls_x509_crt_set_activation_time(certs[i],
							      now - 60));
		CHECK_RET(gnutls_x509_crt_set_expiration_time(certs[i],
							      now + 3600));
		CHECK_RET(gnutls_x509_crt_set_key(certs[i], key));

		snprintf(dn, sizeof(dn), "cn = verify-limit-%u", i);
		CHECK_RET(gnutls_x509_crt_set_dn(certs[i], dn, NULL));

		CHECK_RET(gnutls_x509_crt_set_basic_constraints(certs[i],
								i != 0, -1));
		CHECK_RET(gnutls_x509_crt_set_key_usage(
			certs[i], i == 0 ? GNUTLS_KEY_DIGITAL_SIGNATURE :
					   GNUTLS_KEY_KEY_CERT_SIGN));
	}

	for (i = 0; i < chain_size - 1; i++) {
		CHECK_RET(gnutls_x509_crt_sign2(certs[i], certs[i + 1], key,
						GNUTLS_DIG_SHA256, 0));
	}
	CHECK_RET(gnutls_x509_crt_sign2(certs[chain_size - 1],
					certs[chain_size - 1], key,
					GNUTLS_DIG_SHA256, 0));
}

static void verify_chain(gnutls_x509_crt_t *certs, gnutls_x509_privkey_t key,
			 unsigned int chain_size, unsigned int verify_limit,
			 int expected_ret)
{
	gnutls_certificate_credentials_t server_cred, client_cred;
	gnutls_pcert_st *pcerts;
	gnutls_privkey_t abstract_key;
	gnutls_session_t server, client;
	unsigned int i, peer_size, status = 0;
	int ret, sret, cret;

	CHECK_RET(gnutls_certificate_allocate_credentials(&server_cred));
	CHECK_RET(gnutls_certificate_allocate_credentials(&client_cred));

	pcerts = gnutls_calloc(chain_size, sizeof(*pcerts));
	if (pcerts == NULL)
		fail("gnutls_calloc\n");
	for (i = 0; i < chain_size; i++)
		CHECK_RET(gnutls_pcert_import_x509(&pcerts[i], certs[i], 0));

	CHECK_RET(gnutls_privkey_init(&abstract_key));
	CHECK_RET(gnutls_privkey_import_x509(abstract_key, key,
					     GNUTLS_PRIVKEY_IMPORT_COPY));
	CHECK_RET(gnutls_certificate_set_key(server_cred, NULL, 0, pcerts,
					     chain_size, abstract_key));
	gnutls_free(pcerts);

	ret = gnutls_certificate_set_x509_trust(client_cred, &certs[chain_size],
						1);
	if (ret != 1) {
		fail("gnutls_certificate_set_x509_trust: %s\n",
		     gnutls_strerror(ret));
	}

	if (verify_limit != UINT_MAX)
		gnutls_certificate_set_verify_limits(client_cred, 0,
						     verify_limit);

	reset_buffers();
	CHECK_RET(gnutls_init(&server, GNUTLS_SERVER));
	CHECK_RET(gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE,
					 server_cred));
	CHECK_RET(gnutls_priority_set_direct(server, "NORMAL", NULL));
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_ptr(server, server);

	CHECK_RET(gnutls_init(&client, GNUTLS_CLIENT));
	CHECK_RET(gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE,
					 client_cred));
	CHECK_RET(gnutls_priority_set_direct(client, "NORMAL", NULL));
	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_ptr(client, client);

	HANDSHAKE(client, server);

	gnutls_certificate_get_peers(client, &peer_size);
	if (peer_size != chain_size) {
		fail("received %u certificates, expected %u\n", peer_size,
		     chain_size);
	}

	ret = gnutls_certificate_verify_peers2(client, &status);
	if (ret != expected_ret) {
		fail("gnutls_certificate_verify_peers2: %s, expected %s\n",
		     gnutls_strerror(ret), gnutls_strerror(expected_ret));
	}
	if (ret == 0 && status != 0)
		fail("verification status: %x\n", status);

	gnutls_deinit(client);
	gnutls_deinit(server);
	gnutls_certificate_free_credentials(client_cred);
	gnutls_certificate_free_credentials(server_cred);
}

void doit(void)
{
	gnutls_x509_crt_t certs[CERTIFICATE_COUNT];
	gnutls_x509_privkey_t key;
	unsigned int i;

	CHECK_RET(global_init());
	CHECK_RET(gnutls_x509_privkey_init(&key));
	CHECK_RET(gnutls_x509_privkey_import(key, &server_ecc_key,
					     GNUTLS_X509_FMT_PEM));
	create_chain(certs, countof(certs), key);

	verify_chain(certs, key, DEFAULT_MAX_VERIFY_DEPTH, UINT_MAX,
		     GNUTLS_E_SUCCESS);
	verify_chain(certs, key, LONG_CHAIN_SIZE, UINT_MAX,
		     GNUTLS_E_CONSTRAINT_ERROR);
	verify_chain(certs, key, LONG_CHAIN_SIZE, LONG_CHAIN_SIZE,
		     GNUTLS_E_SUCCESS);
	verify_chain(certs, key, LONG_CHAIN_SIZE, 0, GNUTLS_E_SUCCESS);

	for (i = 0; i < countof(certs); i++)
		gnutls_x509_crt_deinit(certs[i]);
	gnutls_x509_privkey_deinit(key);
	gnutls_global_deinit();
}
