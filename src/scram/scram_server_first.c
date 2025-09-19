// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram.h"
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static scram_resp_t parse_iterations(const char *iter_str, uint64_t *iterations_out,
				     scram_error_t *error)
{
	char *endptr = NULL;
	unsigned long iterations = 0;

	if (!iter_str || !iterations_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	iterations = strtoul(iter_str, &endptr, 10);
	if (*endptr != '\0') {
		scram_set_error(error, "invalid iteration count format");
		return SCRAM_E_PARSE_ERROR;
	}

	if (iterations < SCRAM_MIN_ITERS || iterations > SCRAM_MAX_ITERS) {
		scram_set_error(error, "iteration count out of valid range");
		return SCRAM_E_INVALID_REQUEST;
	}

	*iterations_out = (uint64_t)iterations;
	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_create_server_first_message(const scram_client_first_t *client_msg,
					       const crypto_datum_t *salt,
					       uint64_t iterations,
					       scram_server_first_t **msg_out,
					       scram_error_t *error)
{
	scram_server_first_t *msg = NULL;
	crypto_datum_t server_nonce = {0};
	crypto_datum_t combined_nonce = {0};
	int ret = 0;

	if (!client_msg || !salt || !msg_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	if (iterations < SCRAM_MIN_ITERS || iterations > SCRAM_MAX_ITERS) {
		scram_set_error(error, "iteration count out of valid range");
		return SCRAM_E_INVALID_REQUEST;
	}

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Generate server nonce */
	ret = scram_generate_nonce(&server_nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		free(msg);
		return ret;
	}

	/* Combine client and server nonces */
	combined_nonce.size = client_msg->nonce.size + server_nonce.size;
	combined_nonce.data = malloc(combined_nonce.size);
	if (!combined_nonce.data) {
		scram_set_error(error, "malloc() failed for combined nonce");
		crypto_datum_clear(&server_nonce, false);
		free(msg);
		return SCRAM_E_MEMORY_ERROR;
	}

	memcpy(combined_nonce.data, client_msg->nonce.data,
	       client_msg->nonce.size);
	memcpy(combined_nonce.data + client_msg->nonce.size,
	       server_nonce.data, server_nonce.size);

	/* Copy salt and iterations */
	ret = dup_crypto_datum(salt, &msg->salt, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	msg->iterations = iterations;
	msg->nonce = combined_nonce;

	/* Transfer ownership to prevent double-free */
	memset(&combined_nonce, 0, sizeof(combined_nonce));

	*msg_out = msg;
	crypto_datum_clear(&server_nonce, false);
	return SCRAM_E_SUCCESS;

cleanup:
	crypto_datum_clear(&server_nonce, false);
	crypto_datum_clear(&combined_nonce, false);
	clear_scram_server_first_message(msg);
	free(msg);
	return ret;
}

scram_resp_t scram_serialize_server_first_message(const scram_server_first_t *msg,
						  char **scram_msg_str_out,
						  scram_error_t *error)
{
	crypto_datum_t salt_b64 = {0};
	crypto_datum_t nonce_b64 = {0};
	int ret = 0;

	if (!msg || !scram_msg_str_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Encode salt to base64 */
	ret = scram_base64_encode(&msg->salt, &salt_b64, error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	/* Encode nonce to base64 */
	ret = scram_base64_encode(&msg->nonce, &nonce_b64, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&salt_b64, false);
		return ret;
	}

	/* Format the server-first-message */
	if (asprintf(scram_msg_str_out,
		     SCRAM_ATTR_NONCE "=%.*s" SCRAM_SEP
		     SCRAM_ATTR_SALT "=%.*s" SCRAM_SEP
		     SCRAM_ATTR_ITERATION_COUNT "=%lu",
		     (int)nonce_b64.size, nonce_b64.data,
		     (int)salt_b64.size, salt_b64.data,
		     msg->iterations) < 0) {
		scram_set_error(error, "asprintf() failed");
		ret = SCRAM_E_MEMORY_ERROR;
	} else {
		ret = SCRAM_E_SUCCESS;
	}

	crypto_datum_clear(&salt_b64, false);
	crypto_datum_clear(&nonce_b64, false);

	return ret;
}

scram_resp_t scram_deserialize_server_first_message(const char *scram_msg_str,
						    scram_server_first_t **msg_out,
						    scram_error_t *error)
{
	scram_server_first_t *msg = NULL;
	char *msg_copy = NULL;
	char *token = NULL, *saveptr = NULL;
	char *nonce_str = NULL, *salt_str = NULL, *iter_str = NULL;
	crypto_datum_t b64_input;
	int token_index = 0;
	int ret = SCRAM_E_INVALID_REQUEST;

	if (!scram_msg_str || !msg_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	msg_copy = strdup(scram_msg_str);
	if (!msg_copy) {
		scram_set_error(error, "strdup() failed");
		ret = SCRAM_E_MEMORY_ERROR;
		goto cleanup;
	}

	/* Parse comma-separated attributes - RFC order: r,s,i */
	for (token = strtok_r(msg_copy, SCRAM_SEP, &saveptr);
	     token;
	     token = strtok_r(NULL, SCRAM_SEP, &saveptr), token_index++) {

		if (token_index == 0) {
			/* First attribute must be nonce (r) */
			if (strncmp(token, SCRAM_ATTR_NONCE "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
				nonce_str = token + SCRAM_ATTR_PREFIX_LEN;
			} else {
				scram_set_error(error, "expected nonce as first attribute");
				goto cleanup;
			}
		} else if (token_index == 1) {
			/* Second attribute must be salt (s) */
			if (strncmp(token, SCRAM_ATTR_SALT "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
				salt_str = token + SCRAM_ATTR_PREFIX_LEN;
			} else {
				scram_set_error(error, "expected salt as second attribute");
				goto cleanup;
			}
		} else if (token_index == 2) {
			/* Third attribute must be iteration count (i) */
			if (strncmp(token, SCRAM_ATTR_ITERATION_COUNT "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
				iter_str = token + SCRAM_ATTR_PREFIX_LEN;
			} else {
				scram_set_error(error, "expected iteration count as third attribute");
				goto cleanup;
			}
		} else {
			/* Additional attributes not expected in server-first-message */
			scram_set_error(error, "unexpected additional attributes");
			goto cleanup;
		}
	}

	if (!nonce_str || !salt_str || !iter_str) {
		scram_set_error(error, "missing required attributes");
		goto cleanup;
	}

	/* Parse iterations */
	ret = parse_iterations(iter_str, &msg->iterations, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Decode base64 nonce */
	b64_input.data = (unsigned char *)nonce_str;
	b64_input.size = strlen(nonce_str);
	ret = scram_base64_decode(&b64_input, &msg->nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Decode base64 salt */
	b64_input.data = (unsigned char *)salt_str;
	b64_input.size = strlen(salt_str);
	ret = scram_base64_decode(&b64_input, &msg->salt, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&msg->nonce, false);
		goto cleanup;
	}

	*msg_out = msg;
	free(msg_copy);
	return SCRAM_E_SUCCESS;

cleanup:
	free(msg_copy);
	clear_scram_server_first_message(msg);
	free(msg);
	return ret;
}
