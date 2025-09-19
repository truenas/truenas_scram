// SPDX-License-Identifier: LGPL-3.0-or-later
#ifndef TRUENAS_PYSCRAM_H
#define TRUENAS_PYSCRAM_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../scram/scram.h"

#define MODULE_NAME "truenas_pyscram"

/**
 * @brief Module state for the truenas_pyscram Python extension
 *
 * This structure holds the global state for the Python module,
 * including custom exception objects that are used throughout
 * the module for error reporting.
 */
typedef struct {
	PyObject *scram_error;  /**< Custom exception object for SCRAM errors */
} tnscram_module_state_t;

/**
 * @brief Python wrapper for crypto_datum_t structure
 */
typedef struct {
	PyObject_HEAD
	crypto_datum_t datum;
} py_crypto_datum_t;

/**
 * @brief Python wrapper for SCRAM authentication data
 *
 * This type provides a Python interface to the complete set of SCRAM
 * authentication data including salted password, client key, stored key,
 * server key, salt, and iteration count. Used for storing and managing
 * authentication credentials in SCRAM protocol implementations.
 */
typedef struct {
	PyObject_HEAD
	scram_auth_data_t auth_data;
} py_scram_auth_data_t;

/**
 * @brief Python wrapper for SCRAM client first message
 *
 * This type represents the initial message in SCRAM authentication sent
 * from client to server. Contains the client nonce, username/principal,
 * and GS2 header for channel binding support. Implements RFC 5802
 * client-first-message format.
 */
typedef struct {
	PyObject_HEAD
	scram_client_first_t *msg;
	PyObject *rfc_string;  /**< Cached RFC 5802 formatted message string */
} py_client_first_t;

/**
 * @brief Python wrapper for SCRAM server first message
 *
 * This type represents the server's response to the client first message
 * in SCRAM authentication. Contains the combined client+server nonce,
 * base64-encoded salt, and iteration count. Implements RFC 5802
 * server-first-message format.
 */
typedef struct {
	PyObject_HEAD
	scram_server_first_t *msg;
	PyObject *rfc_string;  /**< Cached RFC 5802 formatted message string */
} py_server_first_t;

/**
 * @brief Python wrapper for SCRAM client final message
 *
 * This type represents the client's final message in SCRAM authentication
 * containing the authentication proof. Includes channel binding data,
 * cryptographic data buffers.
 * nonce confirmation, and the client proof that demonstrates knowledge
 * of the password. Implements RFC 5802 client-final-message format.
 */
typedef struct {
	PyObject_HEAD
	scram_client_final_t *msg;
	PyObject *rfc_string;  /**< Cached RFC 5802 formatted message string */
} py_client_final_t;

/**
 * @brief Python wrapper for SCRAM server final message
 *
 * This type represents the server's final message in SCRAM authentication
 * containing the server signature that proves the server also knows the
 * user's authentication information. Implements RFC 5802
 * server-final-message format.
 */
typedef struct {
	PyObject_HEAD
	scram_server_final_t *msg;
	PyObject *rfc_string;  /**< Cached RFC 5802 formatted message string */
} py_server_final_t;

/**
 * @brief External Python type object declarations
 */
extern PyTypeObject PyCryptoDatum_Type;
extern PyTypeObject PyScramAuthData_Type;
extern PyTypeObject PyClientFirstMessage_Type;
extern PyTypeObject PyServerFirstMessage_Type;
extern PyTypeObject PyClientFinalMessage_Type;
extern PyTypeObject PyServerFinalMessage_Type;

/**
 * @brief Convert crypto_datum_t to Python CryptoDatum object
 *
 * @param[in] datum - source crypto_datum_t structure to convert
 * @return new Python CryptoDatum object, or NULL on error
 */
PyObject *crypto_datum_to_pycrypto_datum(const crypto_datum_t *datum);

/**
 * @brief Create and setup the SCRAM exception type
 *
 * Creates a new Python exception type derived from RuntimeError for
 * SCRAM-specific errors. This exception type is used throughout the
 * module for consistent error reporting.
 *
 * @return new exception type object, or NULL on error
 */
PyObject *setup_scram_exception(void);

/**
 * @brief Convert SCRAM error code to string representation
 *
 * @param[in] code - SCRAM error code to convert
 * @return string name of the error code, or "UNKNOWN_ERROR" if not found
 */
const char *scram_error_code_to_string(scram_resp_t code);

/**
 * @brief Set Python exception from SCRAM error information
 *
 * Creates and sets a Python exception using SCRAM error codes and messages.
 * This function gets the current module state and uses the module's custom
 * exception type for consistent error reporting across the extension.
 *
 * @param[in] code - SCRAM error code
 * @param[in] scram_err - detailed error information (can be NULL)
 * @param[in] additional_info - additional context information (can be NULL)
 */
void set_exc_from_scram(scram_resp_t code, scram_error_t *scram_err, const char *additional_info);

/**
 * @brief Create dictionary mapping error codes to names
 *
 * Creates a Python dictionary that maps SCRAM error code integers
 * to their corresponding string names. Used for error code introspection
 * and debugging from Python code.
 *
 * @return new dictionary object mapping codes to names, or NULL on error
 */
PyObject *create_errorcode_dict(void);

/**
 * @brief Python wrapper for SCRAM client final message verification
 *
 * Verifies a client final message against stored authentication data.
 * This function implements the server-side verification logic as specified
 * in RFC 5802 Section 3.
 *
 * @param[in] self - unused (module-level function)
 * @param[in] args - positional arguments tuple
 * @param[in] kwds - keyword arguments dictionary
 * @return Py_True if verification succeeds, Py_False if fails, NULL on error
 */
PyObject *py_verify_client_final_message(PyObject *self, PyObject *args, PyObject *kwds);

/**
 * @brief Python wrapper for SCRAM server signature verification
 *
 * Verifies a server signature against expected authentication data.
 * This function implements the client-side verification logic as specified
 * in RFC 5802 Section 3.
 *
 * @param[in] self - unused (module-level function)
 * @param[in] args - positional arguments tuple
 * @param[in] kwds - keyword arguments dictionary
 * @return Py_True if verification succeeds, Py_False if fails, NULL on error
 */
PyObject *py_verify_server_signature(PyObject *self, PyObject *args, PyObject *kwds);

#endif
