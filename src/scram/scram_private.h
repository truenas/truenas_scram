// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _SCRAM_PRIVATE_H_
#define _SCRAM_PRIVATE_H_

#include "truenas_scram.h"
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
#define SCRAM_ATTR(name, ch) \
	static const char SCRAM_ATTR_##name##_STR[] = { ch, '\0' }; \
	static const char SCRAM_ATTR_##name##_EQ[] = { ch, '=', '\0' }; \
	static const char SCRAM_ATTR_##name##_CH = ch;

SCRAM_ATTR(USERNAME, 'n')
SCRAM_ATTR(NONCE, 'r')
SCRAM_ATTR(SALT, 's')
SCRAM_ATTR(ITERATION_COUNT, 'i')
SCRAM_ATTR(CHANNEL_BINDING, 'c')
SCRAM_ATTR(CLIENT_PROOF, 'p')
SCRAM_ATTR(SERVER_SIGNATURE, 'v')
SCRAM_ATTR(ERROR, 'e')
SCRAM_ATTR(RESERVED_MEXT, 'm')

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

enum scram_attr_type {
	ATTR_TYPE_NUMBER,
	ATTR_TYPE_CRYPTO_DATUM,
	ATTR_TYPE_PRINCIPAL,
};

typedef union scram_attr_val {
	uint64_t number;
	crypto_datum_t datum;
	scram_principal_t principal;
} scram_attr_val_t;

typedef struct scram_attr {
	enum scram_attr_type scram_type;
	scram_attr_val_t scram_val;
} scram_attr_t;

scram_resp_t scram_attr_parse(const char *str_in,
			      scram_attr_t *attr_out,
			      scram_error_t *error);
#endif /* _SCRAM_PRIVATE_H_ */
