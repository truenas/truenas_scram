// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

scram_resp_t scram_serialize_server_final_message(const scram_server_final_t *msg,
						  char **scram_msg_str_out,
						  scram_error_t *error)
{
	crypto_datum_t sig_b64 = {0};
	scram_resp_t ret = 0;

	if (!msg || !scram_msg_str_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Encode server signature to base64 */
	ret = scram_base64_encode(&msg->signature, &sig_b64, error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	/* Format the server-final-message: v=<signature> */
	if (asprintf(scram_msg_str_out, "v=%.*s",
		     (int)sig_b64.size, sig_b64.data) < 0) {
		scram_set_error(error, "asprintf() failed");
		ret = SCRAM_E_MEMORY_ERROR;
	} else {
		ret = SCRAM_E_SUCCESS;
	}

	crypto_datum_clear(&sig_b64, false);
	return ret;
}

scram_resp_t scram_deserialize_server_final_message(const char *scram_msg_str,
						    scram_server_final_t **msg_out,
						    scram_error_t *error)
{
	scram_server_final_t *msg = NULL;
	char *signature_str = NULL;
	crypto_datum_t b64_input;
	scram_resp_t ret = SCRAM_E_INVALID_REQUEST;

	if (!scram_msg_str || !msg_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Parse server signature attribute: v=<signature> */
	if (strncmp(scram_msg_str, SCRAM_ATTR_SERVER_SIGNATURE_EQ, SCRAM_ATTR_PREFIX_LEN) == 0) {
		signature_str = (char *)scram_msg_str + SCRAM_ATTR_PREFIX_LEN;
	} else {
		scram_set_error(error, "expected server signature attribute");
		ret = SCRAM_E_PARSE_ERROR;
		goto cleanup;
	}

	/* Check for any additional attributes after the signature */
	char *comma_pos = strchr(signature_str, ',');
	if (comma_pos) {
		/* Unexpected additional attributes */
		scram_set_error(error, "unexpected additional attributes");
		ret = SCRAM_E_PARSE_ERROR;
		goto cleanup;
	}

	/* Decode base64 server signature */
	b64_input.data = (unsigned char *)signature_str;
	b64_input.size = strlen(signature_str);
	ret = scram_base64_decode(&b64_input, &msg->signature, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	*msg_out = msg;
	return SCRAM_E_SUCCESS;

cleanup:
	clear_scram_server_final_message(msg);
	free(msg);
	return ret;
}

scram_resp_t scram_create_server_final_message(const scram_client_first_t *cfirst,
					      const scram_server_first_t *sfirst,
					      const scram_client_final_t *cfinal,
					      const crypto_datum_t *stored_key,
					      const crypto_datum_t *server_key,
					      scram_server_final_t **msg_out,
					      scram_error_t *error)
{
	scram_server_final_t *msg = NULL;
	crypto_datum_t auth_message = {0};
	char *client_first_bare = NULL;
	char *server_first_str = NULL;
	char *client_final_without_proof = NULL;
	scram_client_final_t temp_cfinal = {0};
	scram_resp_t ret = SCRAM_E_FAULT;

	if (!cfirst || !sfirst || !cfinal || !SCRAM_DATUM_IS_VALID(stored_key) ||
	    !SCRAM_DATUM_IS_VALID(server_key) || !msg_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Create client-first-message-bare for AuthMessage */
	ret = scram_serialize_client_first_message(cfirst, &client_first_bare, true, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create server-first-message string for AuthMessage */
	ret = scram_serialize_server_first_message(sfirst, &server_first_str, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create a copy of client final without the proof for AuthMessage */
	ret = dup_crypto_datum(&cfinal->nonce, &temp_cfinal.nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	if (cfinal->gs2_header) {
		temp_cfinal.gs2_header = strdup(cfinal->gs2_header);
		if (!temp_cfinal.gs2_header) {
			scram_set_error(error, "strdup() failed for GS2 header");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}
	}

	if (cfinal->channel_binding && SCRAM_DATUM_IS_VALID(cfinal->channel_binding)) {
		temp_cfinal.channel_binding = malloc(sizeof(crypto_datum_t));
		if (!temp_cfinal.channel_binding) {
			scram_set_error(error, "malloc() failed for channel binding");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}
		ret = dup_crypto_datum(cfinal->channel_binding, temp_cfinal.channel_binding, error);
		if (ret != SCRAM_E_SUCCESS) {
			free(temp_cfinal.channel_binding);
			temp_cfinal.channel_binding = NULL;
			goto cleanup;
		}
	}

	/* Serialize client final without proof (client_proof is not set in temp_cfinal) */
	ret = scram_serialize_client_final_message(&temp_cfinal, &client_final_without_proof, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create AuthMessage using the utility function */
	ret = scram_create_auth_message(client_first_bare, server_first_str,
					client_final_without_proof, &auth_message, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Calculate ServerSignature = HMAC(ServerKey, AuthMessage) */
	ret = scram_hmac_sha512(server_key, &auth_message, &msg->signature, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	*msg_out = msg;
	ret = SCRAM_E_SUCCESS;
	goto cleanup_resources;

cleanup:
	if (msg) {
		clear_scram_server_final_message(msg);
		free(msg);
	}

cleanup_resources:
	free(client_first_bare);
	free(server_first_str);
	free(client_final_without_proof);
	clear_scram_client_final_message(&temp_cfinal);
	crypto_datum_clear(&auth_message, true);

	return ret;
}

scram_resp_t scram_verify_server_signature(const scram_client_first_t *cfirst,
					   const scram_server_first_t *sfirst,
					   const scram_client_final_t *cfinal,
					   const scram_server_final_t *sfinal,
					   const crypto_datum_t *server_key,
					   scram_error_t *error)
{
	crypto_datum_t auth_message = {0};
	crypto_datum_t expected_signature = {0};
	char *client_first_bare = NULL;
	char *server_first_str = NULL;
	char *client_final_without_proof = NULL;
	scram_client_final_t temp_cfinal = {0};
	scram_resp_t ret = SCRAM_E_FAULT;

	if (!cfirst || !sfirst || !cfinal || !sfinal || !SCRAM_DATUM_IS_VALID(server_key)) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Create client-first-message-bare for AuthMessage */
	ret = scram_serialize_client_first_message(cfirst, &client_first_bare, true, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create server-first-message string for AuthMessage */
	ret = scram_serialize_server_first_message(sfirst, &server_first_str, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create a copy of client final without the proof for AuthMessage */
	ret = dup_crypto_datum(&cfinal->nonce, &temp_cfinal.nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	if (cfinal->gs2_header) {
		temp_cfinal.gs2_header = strdup(cfinal->gs2_header);
		if (!temp_cfinal.gs2_header) {
			scram_set_error(error, "strdup() failed for GS2 header");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}
	}

	if (cfinal->channel_binding && SCRAM_DATUM_IS_VALID(cfinal->channel_binding)) {
		temp_cfinal.channel_binding = malloc(sizeof(crypto_datum_t));
		if (!temp_cfinal.channel_binding) {
			scram_set_error(error, "malloc() failed for channel binding");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}
		ret = dup_crypto_datum(cfinal->channel_binding, temp_cfinal.channel_binding, error);
		if (ret != SCRAM_E_SUCCESS) {
			free(temp_cfinal.channel_binding);
			temp_cfinal.channel_binding = NULL;
			goto cleanup;
		}
	}

	/* Serialize client final without proof (client_proof is not set in temp_cfinal) */
	ret = scram_serialize_client_final_message(&temp_cfinal, &client_final_without_proof, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create AuthMessage using the utility function */
	ret = scram_create_auth_message(client_first_bare, server_first_str,
					client_final_without_proof, &auth_message, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Calculate expected ServerSignature = HMAC(ServerKey, AuthMessage) */
	ret = scram_hmac_sha512(server_key, &auth_message, &expected_signature, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Compare the expected signature with the received signature */
	bool signatures_match = false;
	ret = scram_constant_time_compare(&expected_signature, &sfinal->signature, &signatures_match, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}
	if (!signatures_match) {
		scram_set_error(error, "server signature verification failed");
		ret = SCRAM_E_AUTH_FAILED;
		goto cleanup;
	}

	ret = SCRAM_E_SUCCESS;

cleanup:
	free(client_first_bare);
	free(server_first_str);
	free(client_final_without_proof);
	clear_scram_client_final_message(&temp_cfinal);
	crypto_datum_clear(&auth_message, true);
	crypto_datum_clear(&expected_signature, true);

	return ret;
}
