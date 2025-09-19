// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram.h"
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static scram_resp_t extract_gs2_header(const crypto_datum_t *raw_data,
					char **gs2_header_out,
					size_t *gs2_header_len_out,
					scram_error_t *error)
{
	char *null_terminated_data = NULL;
	char *gs2_separator_pos = NULL;
	size_t gs2_header_len = 0;

	if (!raw_data || !gs2_header_out || !gs2_header_len_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Create null-terminated copy for string operations */
	null_terminated_data = malloc(raw_data->size + 1);
	if (!null_terminated_data) {
		scram_set_error(error, "malloc() failed for null-terminated data");
		return SCRAM_E_MEMORY_ERROR;
	}
	memcpy(null_terminated_data, raw_data->data, raw_data->size);
	null_terminated_data[raw_data->size] = '\0';

	/* Look for GS2 separator ",," */
	gs2_separator_pos = strstr(null_terminated_data, GS2_SEPARATOR);

	if (gs2_separator_pos) {
		/* Null-terminate at end of GS2 separator */
		gs2_separator_pos[strlen(GS2_SEPARATOR)] = '\0';
		gs2_header_len = gs2_separator_pos - null_terminated_data + strlen(GS2_SEPARATOR);
	} else {
		/* No GS2 separator found, treat entire data as GS2 header */
		gs2_header_len = raw_data->size;
	}

	*gs2_header_out = null_terminated_data;
	*gs2_header_len_out = gs2_header_len;

	return SCRAM_E_SUCCESS;
}

static scram_resp_t extract_channel_binding_data(const crypto_datum_t *raw_data,
						  size_t gs2_header_len,
						  crypto_datum_t **channel_binding_out,
						  scram_error_t *error)
{
	crypto_datum_t *channel_binding = NULL;
	size_t channel_data_len = 0;

	if (!raw_data || !channel_binding_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Calculate channel binding data length */
	if (gs2_header_len >= raw_data->size) {
		/* No channel binding data */
		*channel_binding_out = NULL;
		return SCRAM_E_SUCCESS;
	}

	channel_data_len = raw_data->size - gs2_header_len;
	if (channel_data_len == 0) {
		*channel_binding_out = NULL;
		return SCRAM_E_SUCCESS;
	}

	/* Allocate channel binding structure */
	channel_binding = malloc(sizeof(crypto_datum_t));
	if (!channel_binding) {
		scram_set_error(error, "malloc() failed for channel binding");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Allocate and copy channel binding data */
	channel_binding->data = malloc(channel_data_len);
	if (!channel_binding->data) {
		scram_set_error(error, "malloc() failed for channel binding data");
		free(channel_binding);
		return SCRAM_E_MEMORY_ERROR;
	}

	memcpy(channel_binding->data, raw_data->data + gs2_header_len, channel_data_len);
	channel_binding->size = channel_data_len;

	*channel_binding_out = channel_binding;
	return SCRAM_E_SUCCESS;
}

static scram_resp_t extract_channel_binding_info(const char *channel_binding_str,
						  scram_client_final_t *msg,
						  scram_error_t *error)
{
	crypto_datum_t b64_input;
	crypto_datum_t channel_binding_raw = {0};
	char *gs2_header_temp = NULL;
	size_t gs2_header_len = 0;
	scram_resp_t ret = SCRAM_E_FAULT;

	if (!channel_binding_str || !msg) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Decode base64 channel binding data */
	b64_input.data = (unsigned char *)channel_binding_str;
	b64_input.size = strlen(channel_binding_str);
	ret = scram_base64_decode(&b64_input, &channel_binding_raw, error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	/* Extract GS2 header */
	ret = extract_gs2_header(&channel_binding_raw, &gs2_header_temp, &gs2_header_len, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&channel_binding_raw, false);
		return ret;
	}

	/* Transfer ownership of GS2 header to message structure */
	msg->gs2_header = gs2_header_temp;

	/* Extract channel binding data */
	ret = extract_channel_binding_data(&channel_binding_raw, gs2_header_len,
					   &msg->channel_binding, error);
	if (ret != SCRAM_E_SUCCESS) {
		free(msg->gs2_header);
		msg->gs2_header = NULL;
	}

	crypto_datum_clear(&channel_binding_raw, false);
	return ret;
}

scram_resp_t scram_serialize_client_final_message(scram_client_final_t *msg,
						  char **scram_msg_str_out,
						  scram_error_t *error)
{
	crypto_datum_t nonce_b64 = {0};
	crypto_datum_t proof_b64 = {0};
	crypto_datum_t channel_binding_data = {0};
	crypto_datum_t channel_binding_b64 = {0};
	const char *gs2_header_to_use = NULL;
	size_t gs2_header_len = 0;
	int ret = 0;

	if (!msg || !scram_msg_str_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Use provided GS2 header or default to no channel binding */
	gs2_header_to_use = msg->gs2_header ? msg->gs2_header :
					    GS2_FLAG_NO_CB_SUPPORT GS2_SEPARATOR;
	gs2_header_len = strlen(gs2_header_to_use);

	/* Create channel binding data: GS2 header + channel binding data */
	channel_binding_data.size = gs2_header_len +
				   (msg->channel_binding ? msg->channel_binding->size : 0);
	channel_binding_data.data = malloc(channel_binding_data.size);
	if (!channel_binding_data.data) {
		scram_set_error(error, "malloc() failed for channel binding data");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Copy GS2 header */
	memcpy(channel_binding_data.data, gs2_header_to_use, gs2_header_len);

	/* Append channel binding data if present */
	if (msg->channel_binding && msg->channel_binding->size > 0) {
		memcpy(channel_binding_data.data + gs2_header_len,
		       msg->channel_binding->data,
		       msg->channel_binding->size);
	}

	/* Encode combined channel binding data to base64 */
	ret = scram_base64_encode(&channel_binding_data, &channel_binding_b64, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&channel_binding_data, false);
		return ret;
	}

	/* Encode nonce to base64 */
	ret = scram_base64_encode(&msg->nonce, &nonce_b64, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&channel_binding_data, false);
		crypto_datum_clear(&channel_binding_b64, false);
		return ret;
	}

	/* Encode client proof to base64 if present */
	if (SCRAM_DATUM_IS_VALID(&msg->client_proof)) {
		ret = scram_base64_encode(&msg->client_proof, &proof_b64, error);
		if (ret != SCRAM_E_SUCCESS) {
			crypto_datum_clear(&channel_binding_data, false);
			crypto_datum_clear(&channel_binding_b64, false);
			crypto_datum_clear(&nonce_b64, false);
			return ret;
		}

		/* Format the client-final-message with proof: c=<channel_binding>,r=<nonce>,p=<proof> */
		if (asprintf(scram_msg_str_out,
			     SCRAM_ATTR_CHANNEL_BINDING "=%.*s" SCRAM_SEP
			     SCRAM_ATTR_NONCE "=%.*s" SCRAM_SEP
			     SCRAM_ATTR_CLIENT_PROOF "=%.*s",
			     (int)channel_binding_b64.size, channel_binding_b64.data,
			     (int)nonce_b64.size, nonce_b64.data,
			     (int)proof_b64.size, proof_b64.data) < 0) {
			scram_set_error(error, "asprintf() failed");
			ret = SCRAM_E_MEMORY_ERROR;
		} else {
			ret = SCRAM_E_SUCCESS;
		}
	} else {
		/* Format the client-final-message without proof: c=<channel_binding>,r=<nonce> */
		if (asprintf(scram_msg_str_out,
			     SCRAM_ATTR_CHANNEL_BINDING "=%.*s" SCRAM_SEP
			     SCRAM_ATTR_NONCE "=%.*s",
			     (int)channel_binding_b64.size, channel_binding_b64.data,
			     (int)nonce_b64.size, nonce_b64.data) < 0) {
			scram_set_error(error, "asprintf() failed");
			ret = SCRAM_E_MEMORY_ERROR;
		} else {
			ret = SCRAM_E_SUCCESS;
		}
	}

	crypto_datum_clear(&channel_binding_data, false);
	crypto_datum_clear(&channel_binding_b64, false);
	crypto_datum_clear(&nonce_b64, false);
	crypto_datum_clear(&proof_b64, false);

	return ret;
}

scram_resp_t scram_deserialize_client_final_message(const char *scram_msg_str,
						    scram_client_final_t **msg_out,
						    scram_error_t *error)
{
	scram_client_final_t *msg = NULL;
	char *msg_copy = NULL;
	char *token = NULL, *saveptr = NULL;
	char *channel_binding_str = NULL, *nonce_str = NULL, *proof_str = NULL;
	crypto_datum_t b64_input;
	int token_index = 0;
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

	msg_copy = strdup(scram_msg_str);
	if (!msg_copy) {
		scram_set_error(error, "strdup() failed");
		ret = SCRAM_E_MEMORY_ERROR;
		goto cleanup;
	}

	/* Parse comma-separated attributes - expected order: c,r,p */
	for (token = strtok_r(msg_copy, SCRAM_SEP, &saveptr);
	     token;
	     token = strtok_r(NULL, SCRAM_SEP, &saveptr), token_index++) {

		if (token_index == 0) {
			/* First attribute must be channel binding (c) */
			if (strncmp(token, SCRAM_ATTR_CHANNEL_BINDING "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
				channel_binding_str = token + SCRAM_ATTR_PREFIX_LEN;
			} else {
				scram_set_error(error, "expected channel binding as first attribute");
				goto cleanup;
			}
		} else if (token_index == 1) {
			/* Second attribute must be nonce (r) */
			if (strncmp(token, SCRAM_ATTR_NONCE "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
				nonce_str = token + SCRAM_ATTR_PREFIX_LEN;
			} else {
				scram_set_error(error, "expected nonce as second attribute");
				goto cleanup;
			}
		} else if (token_index == 2) {
			/* Third attribute must be client proof (p) */
			if (strncmp(token, SCRAM_ATTR_CLIENT_PROOF "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
				proof_str = token + SCRAM_ATTR_PREFIX_LEN;
			} else {
				scram_set_error(error, "expected client proof as third attribute");
				goto cleanup;
			}
		} else {
			/* Additional attributes not expected in client-final-message */
			scram_set_error(error, "unexpected additional attributes");
			goto cleanup;
		}
	}

	if (!channel_binding_str || !nonce_str || !proof_str) {
		scram_set_error(error, "missing required attributes");
		goto cleanup;
	}

	/* Extract channel binding information */
	if (strlen(channel_binding_str) > 0) {
		ret = extract_channel_binding_info(channel_binding_str, msg, error);
		if (ret != SCRAM_E_SUCCESS) {
			goto cleanup;
		}
	}

	/* Decode base64 nonce */
	b64_input.data = (unsigned char *)nonce_str;
	b64_input.size = strlen(nonce_str);
	ret = scram_base64_decode(&b64_input, &msg->nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Decode base64 client proof */
	b64_input.data = (unsigned char *)proof_str;
	b64_input.size = strlen(proof_str);
	ret = scram_base64_decode(&b64_input, &msg->client_proof, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&msg->nonce, false);
		goto cleanup;
	}

	*msg_out = msg;
	free(msg_copy);
	return SCRAM_E_SUCCESS;

cleanup:
	free(msg_copy);
	clear_scram_client_final_message(msg);
	free(msg);
	return ret;
}

scram_resp_t scram_create_client_final_message(const crypto_datum_t *channel_binding_data,
					      const crypto_datum_t *client_key,
					      const crypto_datum_t *stored_key,
					      const scram_client_first_t *client,
					      const scram_server_first_t *server,
					      scram_client_final_t **msg_out,
					      scram_error_t *error)
{
	scram_client_final_t *msg = NULL;
	crypto_datum_t auth_message = {0};
	crypto_datum_t client_signature = {0};
	char *client_first_bare = NULL;
	char *server_first_str = NULL;
	char *client_final_without_proof = NULL;
	scram_resp_t ret = SCRAM_E_FAULT;

	if (!SCRAM_DATUM_IS_VALID(client_key) || !SCRAM_DATUM_IS_VALID(stored_key) ||
	    !client || !server || !msg_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Copy nonce from server first message (contains combined client+server nonce) */
	ret = dup_crypto_datum(&server->nonce, &msg->nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Set up channel binding data and GS2 header */
	if (client->gs2_header) {
		msg->gs2_header = strdup(client->gs2_header);
		if (!msg->gs2_header) {
			scram_set_error(error, "strdup() failed for GS2 header");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}
	}

	/* Copy channel binding data if provided */
	if (channel_binding_data && SCRAM_DATUM_IS_VALID(channel_binding_data)) {
		msg->channel_binding = malloc(sizeof(crypto_datum_t));
		if (!msg->channel_binding) {
			scram_set_error(error, "malloc() failed for channel binding");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}
		ret = dup_crypto_datum(channel_binding_data, msg->channel_binding, error);
		if (ret != SCRAM_E_SUCCESS) {
			free(msg->channel_binding);
			msg->channel_binding = NULL;
			goto cleanup;
		}
	}

	/* Create client-first-message-bare for AuthMessage */
	ret = scram_serialize_client_first_message(client, &client_first_bare, true, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create server-first-message string for AuthMessage */
	ret = scram_serialize_server_first_message(server, &server_first_str, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create client-final-without-proof for AuthMessage (serialize without setting client_proof) */
	ret = scram_serialize_client_final_message(msg, &client_final_without_proof, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Create AuthMessage using the utility function */
	ret = scram_create_auth_message(client_first_bare, server_first_str,
					client_final_without_proof, &auth_message, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Calculate ClientSignature = HMAC(StoredKey, AuthMessage) */
	ret = scram_hmac_sha512(stored_key, &auth_message, &client_signature, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Calculate ClientProof = ClientKey XOR ClientSignature */
	ret = scram_xor_bytes(client_key, &client_signature, &msg->client_proof, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	*msg_out = msg;
	ret = SCRAM_E_SUCCESS;
	goto cleanup_resources;

cleanup:
	if (msg) {
		clear_scram_client_final_message(msg);
		free(msg);
	}

cleanup_resources:
	free(client_first_bare);
	free(server_first_str);
	free(client_final_without_proof);
	crypto_datum_clear(&auth_message, true);
	crypto_datum_clear(&client_signature, true);

	return ret;
}

scram_resp_t scram_verify_client_final_message(const scram_client_first_t *cfirst,
					      const scram_server_first_t *sfirst,
					      const scram_client_final_t *cfinal,
					      const crypto_datum_t *stored_key,
					      scram_error_t *error)
{
	crypto_datum_t auth_message = {0};
	crypto_datum_t client_signature = {0};
	crypto_datum_t expected_client_key = {0};
	crypto_datum_t received_client_key = {0};
	char *client_first_bare = NULL;
	char *server_first_str = NULL;
	char *client_final_without_proof = NULL;
	scram_client_final_t temp_cfinal = {0};
	scram_resp_t ret = SCRAM_E_FAULT;

	if (!cfirst || !sfirst || !cfinal || !SCRAM_DATUM_IS_VALID(stored_key)) {
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

	/* Calculate expected ClientSignature = HMAC(StoredKey, AuthMessage) */
	ret = scram_hmac_sha512(stored_key, &auth_message, &client_signature, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Calculate received ClientKey = ClientProof XOR ClientSignature */
	ret = scram_xor_bytes(&cfinal->client_proof, &client_signature, &received_client_key, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Calculate expected ClientKey by hashing the StoredKey back to ClientKey */
	/* Note: We can't reverse the hash, so we compare StoredKeys instead */
	/* Calculate StoredKey from received ClientKey: StoredKey = H(ClientKey) */
	ret = scram_h(&received_client_key, &expected_client_key, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Compare the expected StoredKey with the provided StoredKey */
	bool keys_match = false;
	ret = scram_constant_time_compare(&expected_client_key, stored_key, &keys_match, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}
	if (!keys_match) {
		scram_set_error(error, "client proof verification failed");
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
	crypto_datum_clear(&client_signature, true);
	crypto_datum_clear(&expected_client_key, true);
	crypto_datum_clear(&received_client_key, true);

	return ret;
}
