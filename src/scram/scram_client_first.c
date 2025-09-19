// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static int parse_username_and_api_key(const char *username_str,
				       scram_principal_t *principal,
				       scram_error_t *error)
{
	char *username_copy = NULL;
	char *colon_pos = NULL;
	int ret = SCRAM_E_SUCCESS;

	if (!username_str || !principal) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	username_copy = strdup(username_str);
	if (!username_copy) {
		scram_set_error(error, "strdup() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Parse username and optional API key ID */
	colon_pos = strchr(username_copy, ':');
	if (colon_pos) {
		*colon_pos = '\0';
		char *endptr = NULL;
		unsigned long api_key_id = strtoul(colon_pos + 1, &endptr, 10);
		if (*endptr != '\0' || api_key_id > UINT32_MAX) {
			scram_set_error(error, "invalid API key ID format");
			ret = SCRAM_E_PARSE_ERROR;
			goto cleanup;
		}
		principal->api_key_id = (uint32_t)api_key_id;
	} else {
		principal->api_key_id = 0;
	}

	if (strlcpy(principal->username, username_copy,
		    sizeof(principal->username)) >= sizeof(principal->username)) {
		scram_set_error(error, "username too long");
		ret = SCRAM_E_FORMAT_ERROR;
		goto cleanup;
	}

cleanup:
	free(username_copy);
	return ret;
}

scram_resp_t scram_serialize_client_first_message(const scram_client_first_t *msg,
						  char **scram_msg_str_out,
						  bool bare,
						  scram_error_t *error)
{
	crypto_datum_t nonce_b64 = {0};
	char *username_with_api_key = NULL;
	int ret = 0;

	if (!msg || !scram_msg_str_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Encode nonce to base64 */
	ret = scram_base64_encode(&msg->nonce, &nonce_b64, error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	/* Create username with API key ID if present */
	if (msg->principal.api_key_id != 0) {
		if (asprintf(&username_with_api_key, "%s:%u",
			     msg->principal.username,
			     msg->principal.api_key_id) < 0) {
			scram_set_error(error, "asprintf() failed");
			crypto_datum_clear(&nonce_b64, false);
			return SCRAM_E_MEMORY_ERROR;
		}
	} else {
		username_with_api_key = strdup(msg->principal.username);
		if (!username_with_api_key) {
			scram_set_error(error, "strdup() failed");
			crypto_datum_clear(&nonce_b64, false);
			return SCRAM_E_MEMORY_ERROR;
		}
	}

	/* Format the message */
	if (bare) {
		/* client-first-message-bare */
		if (asprintf(scram_msg_str_out,
			     SCRAM_ATTR_USERNAME "=%s" SCRAM_SEP
			     SCRAM_ATTR_NONCE "=%.*s",
			     username_with_api_key,
			     (int)nonce_b64.size, nonce_b64.data) < 0) {
			ret = SCRAM_E_MEMORY_ERROR;
		}
	} else {
		/* full client-first-message */
		if (msg->gs2_header) {
			if (asprintf(scram_msg_str_out,
				     "%s" GS2_SEPARATOR SCRAM_ATTR_USERNAME "=%s" SCRAM_SEP
				     SCRAM_ATTR_NONCE "=%.*s",
				     msg->gs2_header,
				     username_with_api_key,
				     (int)nonce_b64.size, nonce_b64.data) < 0) {
				ret = SCRAM_E_MEMORY_ERROR;
			}
		} else {
			if (asprintf(scram_msg_str_out,
				     GS2_FLAG_NO_CB_SUPPORT GS2_SEPARATOR SCRAM_ATTR_USERNAME "=%s" SCRAM_SEP
				     SCRAM_ATTR_NONCE "=%.*s",
				     username_with_api_key,
				     (int)nonce_b64.size, nonce_b64.data) < 0) {
				ret = SCRAM_E_MEMORY_ERROR;
			}
		}
	}

	if (ret != SCRAM_E_SUCCESS) {
		scram_set_error(error, "asprintf() failed");
	}

	free(username_with_api_key);
	crypto_datum_clear(&nonce_b64, false);

	return (ret == SCRAM_E_SUCCESS) ? SCRAM_E_SUCCESS :
		SCRAM_E_MEMORY_ERROR;
}

scram_resp_t scram_deserialize_client_first_message(const char *scram_msg_str,
						    scram_client_first_t **msg_out,
						    scram_error_t *error)
{
	scram_client_first_t *msg = NULL;
	char *msg_copy = NULL;
	char *gs2_header_end = NULL;
	char *token = NULL, *saveptr = NULL;
	char *username_str = NULL, *nonce_str = NULL;
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

	/* Check for GS2 header (look for ",," separator) */
	gs2_header_end = strstr(msg_copy, GS2_SEPARATOR);
	if (gs2_header_end) {
		/* Extract and store GS2 header */
		*gs2_header_end = '\0';
		msg->gs2_header = strdup(msg_copy);
		if (!msg->gs2_header) {
			scram_set_error(error, "strdup() failed");
			ret = SCRAM_E_MEMORY_ERROR;
			goto cleanup;
		}

		/* Move to start of SCRAM attributes */
		token = gs2_header_end + strlen(GS2_SEPARATOR);
	} else {
		/* No GS2 header, start from beginning */
		token = msg_copy;
	}

	/* Parse SCRAM attributes */
	for (token = strtok_r(token, SCRAM_SEP, &saveptr);
	     token;
	     token = strtok_r(NULL, SCRAM_SEP, &saveptr), token_index++) {

		if (strncmp(token, SCRAM_ATTR_USERNAME "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
			username_str = token + SCRAM_ATTR_PREFIX_LEN;
		} else if (strncmp(token, SCRAM_ATTR_NONCE "=", SCRAM_ATTR_PREFIX_LEN) == 0) {
			nonce_str = token + SCRAM_ATTR_PREFIX_LEN;
		} else {
			/* Unknown attribute - could be extensions */
			if (token_index > 10) {
				scram_set_error(error,
					"Unsupported extensions in message");
				goto cleanup;
			}
		}
	}

	if (!username_str || !nonce_str) {
		scram_set_error(error, "missing required attributes");
		goto cleanup;
	}

	/* Parse username and API key ID using helper function */
	ret = parse_username_and_api_key(username_str, &msg->principal,
					 error);
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

	*msg_out = msg;
	free(msg_copy);
	return SCRAM_E_SUCCESS;

cleanup:
	free(msg_copy);
	clear_scram_client_first_message(msg);
	free(msg);
	return ret;
}

scram_resp_t scram_create_client_first_message(const char *username,
					       uint32_t api_key_id,
					       const char *gs2_header,
					       scram_client_first_t **msg_out,
					       scram_error_t *error)
{
	scram_client_first_t *msg = NULL;
	int ret = 0;

	if (!username || !msg_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	/* Set API key ID and username */
	msg->principal.api_key_id = api_key_id;
	if (strlcpy(msg->principal.username, username,
		    sizeof(msg->principal.username)) >=
	    sizeof(msg->principal.username)) {
		scram_set_error(error, "username too long");
		free(msg);
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Generate client nonce */
	ret = scram_generate_nonce(&msg->nonce, error);
	if (ret != SCRAM_E_SUCCESS) {
		free(msg);
		return ret;
	}

	/* Set GS2 header - NULL means no channel binding */
	if (gs2_header) {
		msg->gs2_header = strdup(gs2_header);
		if (!msg->gs2_header) {
			scram_set_error(error, "strdup() failed for GS2 header");
			crypto_datum_clear(&msg->nonce, false);
			free(msg);
			return SCRAM_E_MEMORY_ERROR;
		}
	}

	*msg_out = msg;
	return SCRAM_E_SUCCESS;
}
