// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _SCRAM_PRIVATE_H_
#define _SCRAM_PRIVATE_H_

#include "scram.h"
#include <stdarg.h>

/* Error handling macros */
#define __stringify(x) #x
#define __stringify2(x) __stringify(x)
#define __location__ __FILE__ ":" __stringify2(__LINE__)

/* Internal error setting function */
void _scram_set_error(scram_error_t *error, unsigned long ssl_err_code,
                     const char *fmt, const char *location, ...);

#define scram_set_error(error, fmt, ...) \
    _scram_set_error(error, 0, fmt, __location__, ##__VA_ARGS__)

#define scram_set_ssl_error(error, fmt, ...) \
    _scram_set_error(error, ERR_get_error(), fmt, __location__, ##__VA_ARGS__)

/* SCRAM attribute names from RFC 5802 section 5.1 */
#define SCRAM_ATTR_USERNAME "n"
#define SCRAM_ATTR_RESERVED_MEXT "m"
#define SCRAM_ATTR_NONCE "r"
#define SCRAM_ATTR_SALT "s"
#define SCRAM_ATTR_ITERATION_COUNT "i"
#define SCRAM_ATTR_CHANNEL_BINDING "c"
#define SCRAM_ATTR_CLIENT_PROOF "p"
#define SCRAM_ATTR_SERVER_SIGNATURE "v"
#define SCRAM_ATTR_ERROR "e"

/* GS2 flags from RFC 5801 */
#define GS2_FLAG_NO_CB_SUPPORT "n"
#define GS2_FLAG_CB_SUPPORT_NOT_USED "y"
#define GS2_FLAG_CB_USED "p"

/* GS2 separator between GS2 header and SCRAM data */
#define GS2_SEPARATOR ",,"

/* SCRAM attribute separator */
#define SCRAM_SEP ","

/* Length of SCRAM attribute prefix (e.g., "r=", "s=", "i=") */
#define SCRAM_ATTR_PREFIX_LEN 2

/*
 * Maximum size for any crypto_datum_t data (64 KiB)
 * This validated during b64encode / b64decode to guard against
 * overflow.
 */
#define SCRAM_MAX_DATA_SIZE ((size_t)(64 * 1024))

#define SCRAM_DEFAULT_SALT_SZ 16
#define SCRAM_DEFAULT_PWD_SZ 64

/* Internal base64 functions */

/**
 * @brief encode binary data to base64 string
 *
 * This function encodes binary data from a crypto_datum_t structure
 * into a base64-encoded string stored in another crypto_datum_t.
 *
 * @param[in]		data_in - input binary data to encode
 * @param[out]		data_out - output base64 string (caller must free with crypto_datum_clear)
 * @param[in,out]	error - error buffer for detailed error information
 * @return		SCRAM_E_SUCCESS on success, error code on failure
 */
scram_resp_t scram_base64_encode(const crypto_datum_t *data_in,
				 crypto_datum_t *data_out, scram_error_t *error);

/**
 * @brief decode base64 string to binary data
 *
 * This function decodes a base64-encoded string from a crypto_datum_t
 * structure into binary data stored in another crypto_datum_t.
 *
 * @param[in]		data_in - input base64 string to decode
 * @param[out]		data_out - output binary data (caller must free with crypto_datum_clear)
 * @param[in,out]	error - error buffer for detailed error information
 * @return		SCRAM_E_SUCCESS on success, error code on failure
 */
scram_resp_t scram_base64_decode(const crypto_datum_t *data_in,
				 crypto_datum_t *data_out, scram_error_t *error);

#endif /* _SCRAM_PRIVATE_H_ */
