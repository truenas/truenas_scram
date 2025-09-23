// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#define CLIENT_FIRST_BARE_FMT "n=%s" SCRAM_SEP "r=%.*s"
#define CLIENT_FIRST_FMT "%s" GS2_SEPARATOR CLIENT_FIRST_BARE_FMT

scram_resp_t scram_serialize_client_first_message(const scram_client_first_t *msg,
						  char **scram_msg_str_out,
						  bool bare,
						  scram_error_t *error)
{
	crypto_datum_t nonce_b64 = {0};
	char *username_with_api_key = NULL;
	scram_resp_t ret = 0;

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
		if (asprintf(scram_msg_str_out, CLIENT_FIRST_BARE_FMT,
			     username_with_api_key,
			     (int)nonce_b64.size, nonce_b64.data) < 0) {
			ret = SCRAM_E_MEMORY_ERROR;
		}
	} else {
		/* full client-first-message */
		if (msg->gs2_header) {
			if (asprintf(scram_msg_str_out, CLIENT_FIRST_FMT,
				     msg->gs2_header,
				     username_with_api_key,
				     (int)nonce_b64.size, nonce_b64.data) < 0) {
				ret = SCRAM_E_MEMORY_ERROR;
			}
		} else {
			if (asprintf(scram_msg_str_out, CLIENT_FIRST_FMT,
				     GS2_FLAG_NO_CB_SUPPORT,
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

enum first_message_parts {
	// MSG_PART_GS2_HEADER,  // parsed separately
	MSG_PART_USERNAME,
	MSG_PART_NONCE,
};
#define LAST_MSG_PART MSG_PART_NONCE

scram_resp_t scram_deserialize_message_part(char *token,
					    int token_index,
					    scram_client_first_t *msg,
					    scram_error_t *error)
{
	scram_resp_t ret = SCRAM_E_PARSE_ERROR;
	scram_attr_t attr = {0};

	switch(token_index) {
	case MSG_PART_USERNAME:
		if (*token != SCRAM_ATTR_USERNAME_CH) {
			scram_set_error(error, "expected username as second attribute");
			return ret;
		}

		ret = scram_attr_parse(token, &attr, error);
		if ((ret != SCRAM_E_SUCCESS) || (attr.scram_type != ATTR_TYPE_PRINCIPAL)) {
			return ret;
		}
		msg->principal.api_key_id = attr.scram_val.principal.api_key_id;
		strlcpy(msg->principal.username,
			attr.scram_val.principal.username,
			sizeof(msg->principal.username)
		);
		break;
	case MSG_PART_NONCE:
		if (*token != SCRAM_ATTR_NONCE_CH) {
			scram_set_error(error, "expected username as second attribute");
			return ret;
		}

		ret = scram_attr_parse(token, &attr, error);
		if ((ret != SCRAM_E_SUCCESS) || (attr.scram_type != ATTR_TYPE_CRYPTO_DATUM)) {
			return ret;
		}

		msg->nonce = attr.scram_val.datum;
		break;
	default:
		scram_set_error(error, "%s: unexpected attribute.", token);
	};

	return ret;
}

scram_resp_t scram_deserialize_client_first_message(const char *scram_msg_str,
						    scram_client_first_t **msg_out,
						    scram_error_t *error)
{
	scram_client_first_t *msg = NULL;
	char *msg_copy = NULL;
	char *gs2_header_end = NULL;
	char *token = NULL, *saveptr = NULL;
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
	if (msg_copy == NULL) {
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
	for (token = strtok_r(token, SCRAM_SEP, &saveptr); token;
	     token = strtok_r(NULL, SCRAM_SEP, &saveptr), token_index++) {
		ret = scram_deserialize_message_part(token, token_index, msg, error);
		if (ret != SCRAM_E_SUCCESS) {
			goto cleanup;
		}
	}

	if ((*msg->principal.username == '\0') || (msg->nonce.size == 0)) {
		scram_set_error(error, "missing required attributes");
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
	scram_resp_t ret = 0;

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
	ret = scram_saslprep(username, msg->principal.username,
			     sizeof(msg->principal.username),
			     error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
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
