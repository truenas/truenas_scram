// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>


static
scram_resp_t scram_parse_str_u64(const char *str_in,
				 uint64_t min_val,
				 uint64_t max_val,
				 uint64_t *val_out,
				 scram_error_t *error)
{
	unsigned long long lval;
	char *end = NULL;

	if ((str_in == NULL) || (val_out == NULL)) {
		scram_set_error(error, "invalid initial parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	// strtoull requires explicitly setting errno to zero
	errno = 0;
	lval = strtoull(str_in, &end, 0);
	if (errno != 0) {
		scram_set_error(error, "%s: strtoull() failed: %s",
				str_in, strerror(errno));
		return SCRAM_E_FAULT;
	}

	/*
	 * If there were no digits at all then end == str_in
	 * If all characters were digits then *end will be '\0'
	 * Otherwise *end will be the first invalid character.
	 */
	if ((end == str_in) && (*end != '\0')) {
		scram_set_error(error, "%s: not an integer: %c",
				str_in, *end);
		return SCRAM_E_INVALID_REQUEST;
	}

	// Set some non-insane upper bound on count
	if (lval > max_val) {
		scram_set_error(error, "%llu: exceeds maximum of %llu", lval, max_val);
		return SCRAM_E_INVALID_REQUEST;
	}

	if (lval < min_val) {
		scram_set_error(error, "%llu: less than minimum value of %llu",
				lval, min_val);
		return SCRAM_E_INVALID_REQUEST;
	}

	*val_out = lval;
	return SCRAM_E_SUCCESS;
}

static
scram_resp_t scram_parse_b64_datum(const char *str_in,
				   size_t expected_sz,
				   crypto_datum_t *datum_out,
				   scram_error_t *error)
{
	crypto_datum_t b64_input;
	scram_resp_t ret;

	if ((str_in == NULL) || (datum_out == NULL)) {
		scram_set_error(error, "invalid initial parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	b64_input = (crypto_datum_t) {.data = (unsigned char *)str_in, .size = strlen(str_in)};

	ret = scram_base64_decode(&b64_input, datum_out, error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	if (expected_sz && (datum_out->size != expected_sz)) {
		crypto_datum_clear(datum_out, true);
		scram_set_error(error, "%zu: output size does not match expected %zu",
				datum_out->size, expected_sz);
		return SCRAM_E_INVALID_REQUEST;
	}

	return ret;
}

static
scram_resp_t scram_parse_digest(const char *str_in,
				crypto_datum_t *digest_out,
				scram_error_t *error)
{
	return scram_parse_b64_datum(str_in, SHA512_DIGEST_LENGTH, digest_out, error);
}

static
scram_resp_t scram_parse_nonce(const char *str_in,
			       crypto_datum_t *datum_out,
			       scram_error_t *error)
{
	scram_resp_t ret = SCRAM_E_FAULT;

	// initially set zero since nonce may be a client (32 byte) or server (64 byte) value
	ret = scram_parse_b64_datum(str_in, 0, datum_out, error);
	if ((ret == SCRAM_E_SUCCESS) && ((datum_out->size != SCRAM_NONCE_SIZE) &&
	    (datum_out->size != SCRAM_NONCE_SIZE * 2))) {
		scram_set_error(error, "%zu: unexpected nonce size", datum_out->size);
		crypto_datum_clear(datum_out, false);
		return SCRAM_E_INVALID_REQUEST;
	}

	return ret;
}

static
scram_resp_t scram_parse_iteration_cnt(const char *str_in,
				       uint64_t *iter_out,
				       scram_error_t *error)
{
	return scram_parse_str_u64(str_in,
				   SCRAM_MIN_ITERS,
				   SCRAM_MAX_ITERS,
				   iter_out,
				   error);
}

static
scram_resp_t scram_parse_principal(char *str_in,
				   scram_principal_t *principal_out,
				   scram_error_t *error)
{
	char *api_key_id_str = NULL;
	uint64_t api_key_id;
	scram_resp_t ret;

	if ((str_in == NULL) || (principal_out == NULL)) {
		scram_set_error(error, "invalid initial parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	api_key_id_str = strchr(str_in, ':');
	if (api_key_id_str != NULL) {
		*api_key_id_str++ = '\0';
		if (*api_key_id_str == '\0') {
			scram_set_error(error,
					"%s: expected value after separator (:)",
					str_in);
			return SCRAM_E_FAULT;
		}

		ret = scram_parse_str_u64(api_key_id_str,
					  1,
					  INT32_MAX,
					  &api_key_id,
					  error);
		if (ret != SCRAM_E_SUCCESS) {
			return ret;
		}

		principal_out->api_key_id = api_key_id;
	}

	// We need to SASLPREP the username str and verify that it
	// matches the raw str
	ret = scram_saslprep(str_in,
			     principal_out->username,
			     sizeof(principal_out->username) -1,
			     error);

	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	if (strcmp(str_in, principal_out->username) != 0) {
		scram_set_error(error, "%s: original string does not match "
				"scram_saslprep result: %s",
				str_in, principal_out->username);
		return SCRAM_E_FORMAT_ERROR;
	}

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_attr_parse(const char *str_in,
			      scram_attr_t *attr_out,
			      scram_error_t *error)
{
	char *attr_ident = NULL;
	char *attr_val = NULL;
	scram_resp_t ret;

	if ((str_in == NULL) || (attr_out == NULL)) {
		scram_set_error(error, "invalid initial parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	attr_ident = strdup(str_in);
	if (attr_ident == NULL) {
		scram_set_error(error, "%s: strdup() failed: %s", str_in, strerror(errno));
		return SCRAM_E_FAULT;
	}

	attr_val = strstr(attr_ident, "=");
	if (attr_val == NULL) {
		scram_set_error(error, "%s: attribute lacks expected separator", str_in);
		free(attr_ident);
		return SCRAM_E_PARSE_ERROR;
	}

	// advance attr value past the `=` character
	if (*attr_val++ == '\0') {
		scram_set_error(error, "%s: expected value after separator", str_in);
		free(attr_ident);
		return SCRAM_E_PARSE_ERROR;
	}

	switch (attr_ident[0]) {
	case SCRAM_ATTR_NONCE_CH:
		ret = scram_parse_nonce(attr_val,
					&attr_out->scram_val.datum,
					error);
		if (ret == SCRAM_E_SUCCESS) {
			attr_out->scram_type = ATTR_TYPE_CRYPTO_DATUM;
		}
		break;
	case SCRAM_ATTR_SALT_CH:
		ret = scram_parse_b64_datum(attr_val, SCRAM_DEFAULT_SALT_SZ,
					    &attr_out->scram_val.datum,
					    error);
		if (ret == SCRAM_E_SUCCESS) {
			attr_out->scram_type = ATTR_TYPE_CRYPTO_DATUM;
		}
		break;
	case SCRAM_ATTR_ITERATION_COUNT_CH:
		ret = scram_parse_iteration_cnt(attr_val,
						&attr_out->scram_val.number,
						error);
		if (ret == SCRAM_E_SUCCESS) {
			attr_out->scram_type = ATTR_TYPE_NUMBER;
		}
		break;
	case SCRAM_ATTR_CLIENT_PROOF_CH:
	case SCRAM_ATTR_SERVER_SIGNATURE_CH:
		ret = scram_parse_digest(attr_val,
					 &attr_out->scram_val.datum,
					 error);
		if (ret == SCRAM_E_SUCCESS) {
			attr_out->scram_type = ATTR_TYPE_CRYPTO_DATUM;
		}
		break;
	case SCRAM_ATTR_USERNAME_CH:
		ret = scram_parse_principal(attr_val,
					    &attr_out->scram_val.principal,
					    error);
		if (ret == SCRAM_E_SUCCESS) {
			attr_out->scram_type = ATTR_TYPE_PRINCIPAL;
		}
		break;
	default:
		scram_set_error(error, "%c: unsupported SCRAM attribute", *attr_ident);
		ret = SCRAM_E_PARSE_ERROR;
	}

	free(attr_ident);
	return ret;
}
