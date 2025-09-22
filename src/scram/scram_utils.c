// SPDX-License-Identifier: LGPL-3.0-or-later
#include "scram_private.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <idna.h>
#include <stringprep.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

void crypto_datum_clear(crypto_datum_t *datum, bool zero_data)
{
	if (!datum) {
		return;
	}

	if (datum->data && datum->size > 0) {
		if (zero_data) {
			explicit_bzero(datum->data, datum->size);
		}
		free(datum->data);
	}

	explicit_bzero(datum, sizeof(*datum));
}

static int scram_alloc_sha512_digest_datum(crypto_datum_t *datum)
{
	if (!datum) {
		return SCRAM_E_INVALID_REQUEST;
	}

	datum->data = calloc(1, EVP_MAX_MD_SIZE);
	if (!datum->data) {
		return SCRAM_E_MEMORY_ERROR;
	}
	datum->size = EVP_MAX_MD_SIZE;

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_generate_nonce(crypto_datum_t *nonce_out, scram_error_t *error)
{
	if (!nonce_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	nonce_out->data = malloc(SCRAM_NONCE_SIZE);
	if (!nonce_out->data) {
		scram_set_error(error, "malloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}
	nonce_out->size = SCRAM_NONCE_SIZE;

	if (RAND_bytes(nonce_out->data, SCRAM_NONCE_SIZE) != 1) {
		free(nonce_out->data);
		nonce_out->data = NULL;
		nonce_out->size = 0;
		scram_set_ssl_error(error, "RAND_bytes() failed");
		return SCRAM_E_CRYPTO_ERROR;
	}

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_hi(const crypto_datum_t *key, const crypto_datum_t *salt,
                      uint64_t iterations, crypto_datum_t *result, scram_error_t *error)
{
	if (!SCRAM_DATUM_IS_VALID(key) || !SCRAM_DATUM_IS_VALID(salt) || !result ||
	    iterations < SCRAM_MIN_ITERS || iterations > SCRAM_MAX_ITERS) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Check for maximum data size to prevent integer overflow */
	if (key->size > SCRAM_MAX_DATA_SIZE || salt->size > SCRAM_MAX_DATA_SIZE) {
		scram_set_error(error, "input data too large (max %d bytes)", SCRAM_MAX_DATA_SIZE);
		return SCRAM_E_INVALID_REQUEST;
	}

	if (scram_alloc_sha512_digest_datum(result) != SCRAM_E_SUCCESS) {
		scram_set_error(error, "failed to allocate digest datum");
		return SCRAM_E_MEMORY_ERROR;
	}

	if (PKCS5_PBKDF2_HMAC((const char *)key->data, (int)key->size,
			      salt->data, (int)salt->size,
			      (int)iterations,
			      EVP_sha512(),
			      (int)result->size, result->data) != 1) {
		crypto_datum_clear(result, true);
		scram_set_ssl_error(error, "PKCS5_PBKDF2_HMAC() failed");
		return SCRAM_E_CRYPTO_ERROR;
	}

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_h(const crypto_datum_t *data, crypto_datum_t *result, scram_error_t *error)
{
	EVP_MD_CTX *ctx = NULL;
	unsigned int digest_len = 0;

	if (!SCRAM_DATUM_IS_VALID(data) || !result) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Check for maximum data size to prevent integer overflow */
	if (data->size > SCRAM_MAX_DATA_SIZE) {
		scram_set_error(error, "input data too large (max %d bytes)", SCRAM_MAX_DATA_SIZE);
		return SCRAM_E_INVALID_REQUEST;
	}

	if (scram_alloc_sha512_digest_datum(result) != SCRAM_E_SUCCESS) {
		scram_set_error(error, "failed to allocate digest datum");
		return SCRAM_E_MEMORY_ERROR;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		crypto_datum_clear(result, true);
		scram_set_ssl_error(error, "EVP_MD_CTX_new() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, data->data, data->size) != 1 ||
	    EVP_DigestFinal_ex(ctx, result->data, &digest_len) != 1) {
		EVP_MD_CTX_free(ctx);
		crypto_datum_clear(result, true);
		scram_set_ssl_error(error, "digest operation failed");
		return SCRAM_E_CRYPTO_ERROR;
	}

	EVP_MD_CTX_free(ctx);
	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_hmac_sha512(const crypto_datum_t *key, const crypto_datum_t *data,
                               crypto_datum_t *result, scram_error_t *error)
{
	unsigned int result_len = 0;

	if (!SCRAM_DATUM_IS_VALID(key) || !SCRAM_DATUM_IS_VALID(data) || !result) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Check for maximum data size to prevent integer overflow */
	if (key->size > SCRAM_MAX_DATA_SIZE || data->size > SCRAM_MAX_DATA_SIZE) {
		scram_set_error(error, "input data too large (max %d bytes)", SCRAM_MAX_DATA_SIZE);
		return SCRAM_E_INVALID_REQUEST;
	}

	if (scram_alloc_sha512_digest_datum(result) != SCRAM_E_SUCCESS) {
		scram_set_error(error, "failed to allocate digest datum");
		return SCRAM_E_MEMORY_ERROR;
	}

	if (!HMAC(EVP_sha512(), key->data, (int)key->size,
		  data->data, (int)data->size,
		  result->data, &result_len)) {
		crypto_datum_clear(result, true);
		scram_set_ssl_error(error, "HMAC() failed");
		return SCRAM_E_CRYPTO_ERROR;
	}

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_create_client_key(const crypto_datum_t *salted_password,
                                     crypto_datum_t *client_key, scram_error_t *error)
{
	crypto_datum_t client_key_string = {
		.data = (unsigned char *)"Client Key",
		.size = 10
	};

	return scram_hmac_sha512(salted_password, &client_key_string, client_key, error);
}

scram_resp_t scram_create_server_key(const crypto_datum_t *salted_password,
                                     crypto_datum_t *server_key, scram_error_t *error)
{
	crypto_datum_t server_key_string = {
		.data = (unsigned char *)"Server Key",
		.size = 10
	};

	return scram_hmac_sha512(salted_password, &server_key_string, server_key, error);
}

scram_resp_t scram_create_stored_key(const crypto_datum_t *client_key,
                                     crypto_datum_t *stored_key, scram_error_t *error)
{
	return scram_h(client_key, stored_key, error);
}

scram_resp_t scram_create_auth_message(const char *client_first_bare,
                                      const char *server_first_msg,
                                      const char *client_final_without_proof,
                                      crypto_datum_t *auth_message,
                                      scram_error_t *error)
{
	char *auth_msg_str = NULL;

	if (!client_first_bare || !server_first_msg || !client_final_without_proof || !auth_message) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Create AuthMessage: client-first-message-bare + "," + server-first-message + "," + client-final-without-proof */
	if (asprintf(&auth_msg_str, "%s,%s,%s",
		     client_first_bare, server_first_msg, client_final_without_proof) < 0) {
		scram_set_error(error, "asprintf() failed for AuthMessage");
		return SCRAM_E_MEMORY_ERROR;
	}

	auth_message->data = (unsigned char *)auth_msg_str;
	auth_message->size = strlen(auth_msg_str);

	return SCRAM_E_SUCCESS;
}

scram_resp_t dup_crypto_datum(const crypto_datum_t *in, crypto_datum_t *out, scram_error_t *error)
{
	if (!in || !out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	if (!SCRAM_DATUM_IS_VALID(in)) {
		scram_set_error(error, "invalid source crypto_datum_t");
		return SCRAM_E_INVALID_REQUEST;
	}

	out->data = malloc(in->size);
	if (!out->data) {
		scram_set_error(error, "malloc() failed for crypto_datum_t data");
		return SCRAM_E_MEMORY_ERROR;
	}

	out->size = in->size;
	memcpy(out->data, in->data, in->size);

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_xor_bytes(const crypto_datum_t *a, const crypto_datum_t *b,
                             crypto_datum_t *result, scram_error_t *error)
{
	size_t i = 0;

	if (!SCRAM_DATUM_IS_VALID(a) || !SCRAM_DATUM_IS_VALID(b) || !result) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	if (a->size != b->size) {
		scram_set_error(error, "crypto_datum_t sizes do not match");
		return SCRAM_E_INVALID_REQUEST;
	}

	result->data = malloc(a->size);
	if (!result->data) {
		scram_set_error(error, "malloc() failed for XOR result");
		return SCRAM_E_MEMORY_ERROR;
	}
	result->size = a->size;

	for (i = 0; i < a->size; i++) {
		result->data[i] = a->data[i] ^ b->data[i];
	}

	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_constant_time_compare(const crypto_datum_t *a, const crypto_datum_t *b,
					bool *match, scram_error_t *error)
{
	bool size_mismatch = false;
	int result = 0;

	if (!SCRAM_DATUM_IS_VALID(a) || !SCRAM_DATUM_IS_VALID(b) || !match) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Check if sizes differ, but don't return early to maintain constant time */
	size_mismatch = (a->size != b->size);

	/* Use OpenSSL's constant-time memory comparison */
	if (size_mismatch) {
		/* Compare a with itself to maintain constant time */
		result = CRYPTO_memcmp(a->data, a->data, a->size);
	} else {
		result = CRYPTO_memcmp(a->data, b->data, a->size);
	}

	/* Result is false if sizes differ OR if comparison failed */
	*match = !size_mismatch && (result == 0);

	return SCRAM_E_SUCCESS;
}

int raw_api_key_to_scram_data(const char *api_key, const crypto_datum_t *salt,
                              uint64_t iterations, crypto_datum_t *client_key_out,
                              crypto_datum_t *stored_key_out, crypto_datum_t *server_key_out)
{
	crypto_datum_t api_key_datum;
	crypto_datum_t salted_password = {0};
	scram_error_t error = {0};
	int ret = 0;

	if (!api_key || !SCRAM_DATUM_IS_VALID(salt) ||
	    !client_key_out || !stored_key_out || !server_key_out) {
		return SCRAM_E_INVALID_REQUEST;
	}

	api_key_datum.data = (unsigned char *)api_key;
	api_key_datum.size = strlen(api_key);

	/* Generate salted password using PBKDF2 */
	ret = scram_hi(&api_key_datum, salt, iterations, &salted_password, &error);
	if (ret != SCRAM_E_SUCCESS) {
		return ret;
	}

	/* Generate client key */
	ret = scram_create_client_key(&salted_password, client_key_out, &error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&salted_password, true);
		return ret;
	}

	/* Generate stored key */
	ret = scram_create_stored_key(client_key_out, stored_key_out, &error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&salted_password, true);
		crypto_datum_clear(client_key_out, true);
		return ret;
	}

	/* Generate server key */
	ret = scram_create_server_key(&salted_password, server_key_out, &error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&salted_password, true);
		crypto_datum_clear(client_key_out, true);
		crypto_datum_clear(stored_key_out, true);
		return ret;
	}

	crypto_datum_clear(&salted_password, true);
	return SCRAM_E_SUCCESS;
}

static scram_resp_t generate_random_password(crypto_datum_t *password_out, scram_error_t *error)
{
	if (!password_out) {
		scram_set_error(error, "invalid output parameter");
		return SCRAM_E_INVALID_REQUEST;
	}

	password_out->data = malloc(SCRAM_DEFAULT_PWD_SZ);
	if (!password_out->data) {
		scram_set_error(error, "malloc() failed for random password");
		return SCRAM_E_MEMORY_ERROR;
	}
	password_out->size = SCRAM_DEFAULT_PWD_SZ;

	if (RAND_bytes(password_out->data, SCRAM_DEFAULT_PWD_SZ) != 1) {
		crypto_datum_clear(password_out, true);
		scram_set_ssl_error(error, "RAND_bytes() failed for password");
		return SCRAM_E_CRYPTO_ERROR;
	}

	return SCRAM_E_SUCCESS;
}

static scram_resp_t generate_random_salt(crypto_datum_t *salt_out, scram_error_t *error)
{
	if (!salt_out) {
		scram_set_error(error, "invalid output parameter");
		return SCRAM_E_INVALID_REQUEST;
	}

	salt_out->data = malloc(SCRAM_DEFAULT_SALT_SZ);
	if (!salt_out->data) {
		scram_set_error(error, "malloc() failed for random salt");
		return SCRAM_E_MEMORY_ERROR;
	}
	salt_out->size = SCRAM_DEFAULT_SALT_SZ;

	if (RAND_bytes(salt_out->data, SCRAM_DEFAULT_SALT_SZ) != 1) {
		crypto_datum_clear(salt_out, false);
		scram_set_ssl_error(error, "RAND_bytes() failed for salt");
		return SCRAM_E_CRYPTO_ERROR;
	}

	return SCRAM_E_SUCCESS;
}

static scram_resp_t generate_missing_auth_components(const crypto_datum_t *salt,
                                                    uint64_t iterations,
                                                    crypto_datum_t *generated_salt,
                                                    crypto_datum_t *generated_password,
                                                    const crypto_datum_t **final_salt,
                                                    uint64_t *final_iterations,
                                                    const crypto_datum_t **final_password,
                                                    scram_error_t *error)
{
	crypto_datum_t raw_password = {0};
	scram_resp_t ret = SCRAM_E_FAULT;

	/* Generate random password */
	ret = generate_random_password(&raw_password, error);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(&raw_password, true);
		return ret;
	}

	/* Generate salt if needed */
	if (!salt) {
		ret = generate_random_salt(generated_salt, error);
		if (ret != SCRAM_E_SUCCESS) {
			crypto_datum_clear(&raw_password, true);
			return ret;
		}
		*final_salt = generated_salt;
	} else {
		*final_salt = salt;
	}

	/* Set default iterations if needed */
	if (iterations == 0) {
		*final_iterations = SCRAM_DEFAULT_ITERS;
	} else {
		*final_iterations = iterations;
	}

	/* Generate salted password from raw password */
	ret = scram_hi(&raw_password, *final_salt, *final_iterations, generated_password, error);
	crypto_datum_clear(&raw_password, true);
	if (ret != SCRAM_E_SUCCESS) {
		crypto_datum_clear(generated_salt, false);
		return ret;
	}
	*final_password = generated_password;

	return SCRAM_E_SUCCESS;
}

scram_resp_t generate_scram_auth_data(const crypto_datum_t *salted_password,
                                     const crypto_datum_t *salt,
                                     uint64_t iterations,
                                     scram_auth_data_t *auth_data_out,
                                     scram_error_t *error)
{
	crypto_datum_t generated_salt = {0};
	crypto_datum_t generated_password = {0};
	const crypto_datum_t *final_salt = salt;
	const crypto_datum_t *final_password = salted_password;
	uint64_t final_iterations = iterations;
	scram_resp_t ret = SCRAM_E_FAULT;

	if (!auth_data_out) {
		scram_set_error(error, "invalid output parameter");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Initialize output structure */
	memset(auth_data_out, 0, sizeof(*auth_data_out));

	/* Validate input combinations */
	if (salted_password && (!salt || iterations == 0)) {
		scram_set_error(error, "salted_password provided without matching salt and iterations");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Generate components if needed */
	if (!salted_password) {
		ret = generate_missing_auth_components(salt, iterations,
		                                       &generated_salt, &generated_password,
		                                       &final_salt, &final_iterations, &final_password,
		                                       error);
		if (ret != SCRAM_E_SUCCESS) {
			return ret;
		}
	}

	/* Copy salt, iterations, and salted_password to output */
	ret = dup_crypto_datum(final_salt, &auth_data_out->salt, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}
	auth_data_out->iterations = final_iterations;

	ret = dup_crypto_datum(final_password, &auth_data_out->salted_password, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Generate client key */
	ret = scram_create_client_key(final_password, &auth_data_out->client_key, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Generate stored key */
	ret = scram_create_stored_key(&auth_data_out->client_key, &auth_data_out->stored_key, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Generate server key */
	ret = scram_create_server_key(final_password, &auth_data_out->server_key, error);
	if (ret != SCRAM_E_SUCCESS) {
		goto cleanup;
	}

	/* Success - cleanup temporary data */
	crypto_datum_clear(&generated_salt, false);
	crypto_datum_clear(&generated_password, true);
	return SCRAM_E_SUCCESS;

cleanup:
	/* Error - cleanup everything */
	clear_scram_auth_data(auth_data_out);
	crypto_datum_clear(&generated_salt, false);
	crypto_datum_clear(&generated_password, true);
	return ret;
}

/* Memory management functions */

/*
 * Frees memory inside the struct and zeros it out, but does not free the msg itself.
 * Caller is responsible for freeing the struct if it was dynamically allocated.
 */
void clear_scram_auth_data(scram_auth_data_t *auth_data)
{
	if (!auth_data) {
		return;
	}

	crypto_datum_clear(&auth_data->salt, false);
	crypto_datum_clear(&auth_data->salted_password, true);
	crypto_datum_clear(&auth_data->client_key, true);
	crypto_datum_clear(&auth_data->stored_key, true);
	crypto_datum_clear(&auth_data->server_key, true);
}

/*
 * Frees memory inside the struct and zeros it out, but does not free the msg itself.
 * Caller is responsible for freeing the struct if it was dynamically allocated.
 */
void clear_scram_client_first_message(struct scram_client_first_message *msg)
{
	if (!msg) {
		return;
	}

	crypto_datum_clear(&msg->nonce, false);
	free(msg->gs2_header);
	memset(msg, 0, sizeof(*msg));
}

/*
 * Frees memory inside the struct and zeros it out, but does not free the msg itself.
 * Caller is responsible for freeing the struct if it was dynamically allocated.
 */
void clear_scram_server_first_message(struct scram_server_first_message *msg)
{
	if (!msg) {
		return;
	}

	crypto_datum_clear(&msg->salt, false);
	crypto_datum_clear(&msg->nonce, false);
	memset(msg, 0, sizeof(*msg));
}

/*
 * Frees memory inside the struct and zeros it out, but does not free the msg itself.
 * Caller is responsible for freeing the struct if it was dynamically allocated.
 */
void clear_scram_client_final_message(scram_client_final_t *msg)
{
	if (!msg) {
		return;
	}

	free(msg->gs2_header);
	crypto_datum_clear(msg->channel_binding, true);
	free(msg->channel_binding);
	crypto_datum_clear(&msg->nonce, false);
	crypto_datum_clear(&msg->client_proof, true);
	memset(msg, 0, sizeof(*msg));
}

/*
 * Frees memory inside the struct and zeros it out, but does not free the msg itself.
 * Caller is responsible for freeing the struct if it was dynamically allocated.
 */
void clear_scram_server_final_message(scram_server_final_t *msg)
{
	if (!msg) {
		return;
	}

	crypto_datum_clear(&msg->signature, true);
	memset(msg, 0, sizeof(*msg));
}

/* Error handling implementation */
void _scram_set_error(scram_error_t *error, unsigned long ssl_err_code,
                     const char *fmt, const char *location, ...)
{
	va_list args;
	int offset = 0;
	char ssl_err_buf[256];

	if (!error || !fmt) {
		return;
	}

	va_start(args, location);
	offset = vsnprintf(error->message, sizeof(error->message), fmt, args);
	va_end(args);

	/* Append SSL error string if ssl_err_code is non-zero */
	if (ssl_err_code != 0 && offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
		ERR_error_string(ssl_err_code, ssl_err_buf);
		offset += snprintf(error->message + offset, sizeof(error->message) - offset,
			": %s", ssl_err_buf);
	}

	if (offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
		snprintf(error->message + offset, sizeof(error->message) - offset,
			" [%s]", location);
	}
}

/* Base64 encoding function */
scram_resp_t scram_base64_encode(const crypto_datum_t *data_in,
				 crypto_datum_t *data_out, scram_error_t *error)
{
	char *encoded = NULL;
	size_t encoded_len = 0;
	int ret = 0;

	if (!SCRAM_DATUM_IS_VALID(data_in) || !data_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Check for maximum data size to prevent integer overflow */
	if (data_in->size > SCRAM_MAX_DATA_SIZE) {
		scram_set_error(error, "input data too large (max %d bytes)", SCRAM_MAX_DATA_SIZE);
		return SCRAM_E_INVALID_REQUEST;
	}

	encoded_len = 4 * ((data_in->size + 2) / 3) + 1;
	encoded = calloc(1, encoded_len);
	if (!encoded) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	ret = EVP_EncodeBlock((unsigned char *)encoded, data_in->data, (int)data_in->size);
	if (ret < 0) {
		scram_set_ssl_error(error, "EVP_EncodeBlock() failed");
		free(encoded);
		return SCRAM_E_BASE64_ERROR;
	}

	data_out->data = (unsigned char *)encoded;
	data_out->size = ret;

	return SCRAM_E_SUCCESS;
}

/* Base64 decoding function */
scram_resp_t scram_base64_decode(const crypto_datum_t *data_in,
				 crypto_datum_t *data_out, scram_error_t *error)
{
	unsigned char *decoded = NULL;
	int decoded_len = 0;

	if (!SCRAM_DATUM_IS_VALID(data_in) || !data_out) {
		scram_set_error(error, "invalid input parameters");
		return SCRAM_E_INVALID_REQUEST;
	}

	/* Check for maximum data size to prevent integer overflow */
	if (data_in->size > SCRAM_MAX_DATA_SIZE) {
		scram_set_error(error, "input data too large (max %d bytes)", SCRAM_MAX_DATA_SIZE);
		return SCRAM_E_INVALID_REQUEST;
	}

	decoded = calloc(1, ((data_in->size * 3) / 4) + 3);
	if (!decoded) {
		scram_set_error(error, "calloc() failed");
		return SCRAM_E_MEMORY_ERROR;
	}

	decoded_len = EVP_DecodeBlock(decoded, data_in->data, (int)data_in->size);
	if (decoded_len < 0) {
		scram_set_ssl_error(error, "EVP_DecodeBlock() failed");
		free(decoded);
		return SCRAM_E_BASE64_ERROR;
	}

	/* Adjust for base64 padding */
	if (data_in->size > 0 && data_in->data[data_in->size - 1] == '=') {
		decoded_len--;
		if (data_in->size > 1 && data_in->data[data_in->size - 2] == '=') {
			decoded_len--;
		}
	}

	data_out->data = decoded;
	data_out->size = decoded_len;
	return SCRAM_E_SUCCESS;
}

scram_resp_t scram_saslprep(const char *str_in, char *buf, size_t bufsz, scram_error_t *error)
{
	int rc;

	if (strlen(str_in) >= bufsz) {
		scram_set_error(error, "buffer size too small for provided string");
		return SCRAM_E_INVALID_REQUEST;
	}

	// first copy str_in to the output buffer because the stringprep API is awesome

	strlcpy(buf, str_in, bufsz);
	rc = stringprep(buf, bufsz, 0, stringprep_saslprep);
	if (rc != STRINGPREP_OK) {
		scram_set_error(error, "%d: stringprep_saslprep failed", rc);
		return SCRAM_E_FAULT;
	}

	return SCRAM_E_SUCCESS;
}
