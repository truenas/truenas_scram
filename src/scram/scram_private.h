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

#endif /* _SCRAM_PRIVATE_H_ */
