// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

PyDoc_STRVAR(generate_nonce__doc__,
"generate_nonce() -> truenas_pyscram.CryptoDatum\n"
"----------------------------------------------\n\n"
"Generate a cryptographically secure random nonce for SCRAM authentication.\n\n"
"Returns\n"
"-------\n"
"truenas_pyscram.CryptoDatum\n"
"    A 32-byte random nonce suitable for SCRAM authentication.\n"
);

static PyObject *
generate_nonce(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	crypto_datum_t nonce_datum = {0};
	scram_error_t error = {0};
	scram_resp_t ret;
	PyObject *result;

	Py_BEGIN_ALLOW_THREADS
	ret = scram_generate_nonce(&nonce_datum, &error);
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error, "Failed to generate nonce");
		return NULL;
	}

	/* Create CryptoDatum from the nonce data */
	result = crypto_datum_to_pycrypto_datum(&nonce_datum);
	crypto_datum_clear(&nonce_datum, false);

	return result;
}

PyDoc_STRVAR(generate_scram_auth_data__doc__,
"generate_scram_auth_data(*, salted_password=None, salt=None, iterations=0) -> ScramAuthData\n"
"-----------------------------------------------------------------------------------------\n\n"
"Generate SCRAM authentication data from optional inputs.\n\n"
"This function generates complete SCRAM authentication data including client key,\n"
"stored key, and server key. It can generate missing components automatically:\n"
"- If salted_password is None, generates from 64 random bytes\n"
"- If salt is None and salted_password is None, generates 16 random bytes for salt\n"
"- If iterations is 0 and salted_password is None, defaults to 500000\n\n"
"Important constraints:\n"
"- If salted_password is provided, salt and iterations MUST match what was used to generate it\n"
"- salted_password provided without salt or iterations is invalid\n\n"
"Parameters\n"
"----------\n"
"salted_password : CryptoDatum, optional\n"
"    Pre-computed salted password (default=None)\n"
"salt : CryptoDatum, optional\n"
"    Salt used for PBKDF2 (required if salted_password provided, default=None)\n"
"iterations : int, optional\n"
"    PBKDF2 iterations (required if salted_password provided, 0 for default, default=0)\n\n"
"Returns\n"
"-------\n"
"ScramAuthData\n"
"    Object containing salt, iterations, salted_password, client_key, stored_key, server_key\n"
);

PyDoc_STRVAR(py_verify_client_final_message__doc__,
"verify_client_final_message(client_first, server_first, client_final, stored_key) -> None\n"
"----------------------------------------------------------------------------------------\n\n"
"Server-side verification of SCRAM client final message as specified in RFC 5802.\n\n"
"This function is used by the server to verify the client-final-message proof\n"
"for SCRAM authentication as defined in RFC 5802 Section 3. It reconstructs\n"
"the AuthMessage and verifies that the client proof was generated using the\n"
"correct stored key.\n\n"
"Parameters\n"
"----------\n"
"client_first : ClientFirstMessage\n"
"    The original client first message\n"
"server_first : ServerFirstMessage\n"
"    The server first message that was sent\n"
"client_final : ClientFinalMessage\n"
"    The client final message to verify\n"
"stored_key : CryptoDatum\n"
"    The stored key derived from the user's credentials\n\n"
"Raises\n"
"------\n"
"RuntimeError\n"
"    If verification fails or if any message is invalid\n"
"TypeError\n"
"    If parameters are not of the expected types\n"
);

PyDoc_STRVAR(py_verify_server_signature__doc__,
"verify_server_signature(client_first, server_first, client_final, server_final, server_key) -> None\n"
"--------------------------------------------------------------------------------------------------\n\n"
"Client-side verification of SCRAM server signature as specified in RFC 5802.\n\n"
"This function is used by the client to verify the server-final-message signature\n"
"for SCRAM authentication as defined in RFC 5802 Section 3. It reconstructs the\n"
"AuthMessage and verifies that the server signature was generated using the correct\n"
"server key. This verification is optional but recommended to ensure mutual\n"
"authentication and prevent server impersonation.\n\n"
"Parameters\n"
"----------\n"
"client_first : ClientFirstMessage\n"
"    The original client first message\n"
"server_first : ServerFirstMessage\n"
"    The server first message that was sent\n"
"client_final : ClientFinalMessage\n"
"    The client final message that was received\n"
"server_final : ServerFinalMessage\n"
"    The server final message to verify\n"
"server_key : CryptoDatum\n"
"    The server key derived from the user's credentials\n\n"
"Raises\n"
"------\n"
"RuntimeError\n"
"    If verification fails or if any message is invalid\n"
"TypeError\n"
"    If parameters are not of the expected types\n"
);

static PyObject *
py_generate_scram_auth_data(PyObject *self, PyObject *args, PyObject *kwds)
{
	PyObject *salted_password_obj = NULL;
	PyObject *salt_obj = NULL;
	uint64_t iterations = 0;
	py_crypto_datum_t *salted_password_datum = NULL;
	py_crypto_datum_t *salt_datum = NULL;
	scram_auth_data_t auth_data = {0};
	scram_error_t error = {0};
	scram_resp_t ret;
	py_scram_auth_data_t *result = NULL;

	static char *kwlist[] = {"salted_password", "salt", "iterations", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOK", kwlist,
					 &salted_password_obj, &salt_obj, &iterations)) {
		return NULL;
	}

	/* Validate and extract salted_password if provided */
	if (salted_password_obj && salted_password_obj != Py_None) {
		if (!PyObject_IsInstance(salted_password_obj, (PyObject *)&PyCryptoDatum_Type)) {
			PyErr_SetString(PyExc_TypeError, "salted_password must be a CryptoDatum");
			return NULL;
		}
		salted_password_datum = (py_crypto_datum_t *)salted_password_obj;
	}

	/* Validate and extract salt if provided */
	if (salt_obj && salt_obj != Py_None) {
		if (!PyObject_IsInstance(salt_obj, (PyObject *)&PyCryptoDatum_Type)) {
			PyErr_SetString(PyExc_TypeError, "salt must be a CryptoDatum");
			return NULL;
		}
		salt_datum = (py_crypto_datum_t *)salt_obj;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = generate_scram_auth_data(
		salted_password_datum ? &salted_password_datum->datum : NULL,
		salt_datum ? &salt_datum->datum : NULL,
		iterations,
		&auth_data,
		&error
	);
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error, "Failed to generate SCRAM auth data");
		clear_scram_auth_data(&auth_data);
		return NULL;
	}

	/* Create ScramAuthData object */
	result = (py_scram_auth_data_t *)PyObject_CallObject((PyObject *)&PyScramAuthData_Type, NULL);
	if (!result) {
		clear_scram_auth_data(&auth_data);
		return NULL;
	}

	/* Transfer ownership of auth_data to the Python object */
	result->auth_data = auth_data;

	return (PyObject *)result;
}

static PyMethodDef truenas_pyscram_methods[] = {
	{
		.ml_name = "generate_nonce",
		.ml_meth = (PyCFunction)generate_nonce,
		.ml_flags = METH_NOARGS,
		.ml_doc = generate_nonce__doc__
	},
	{
		.ml_name = "generate_scram_auth_data",
		.ml_meth = (PyCFunction)py_generate_scram_auth_data,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = generate_scram_auth_data__doc__
	},
	{
		.ml_name = "verify_client_final_message",
		.ml_meth = (PyCFunction)py_verify_client_final_message,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_verify_client_final_message__doc__
	},
	{
		.ml_name = "verify_server_signature",
		.ml_meth = (PyCFunction)py_verify_server_signature,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_verify_server_signature__doc__
	},
	{NULL, NULL, 0, NULL}
};

static int
truenas_pyscram_module_clear(PyObject *m)
{
	tnscram_module_state_t *state = (tnscram_module_state_t *)PyModule_GetState(m);
	if (state) {
		Py_CLEAR(state->scram_error);
	}
	return 0;
}

static void
truenas_pyscram_module_free(void *m)
{
	truenas_pyscram_module_clear((PyObject *)m);
}

PyModuleDef truenas_pyscram_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = MODULE_NAME,
	.m_doc = "TrueNAS SCRAM library",
	.m_size = sizeof(tnscram_module_state_t),
	.m_methods = truenas_pyscram_methods,
	.m_clear = truenas_pyscram_module_clear,
	.m_free = truenas_pyscram_module_free,
};

PyMODINIT_FUNC
PyInit_truenas_pyscram(void)
{
	PyObject *m = NULL;
	tnscram_module_state_t *state = NULL;

	if (PyType_Ready(&PyCryptoDatum_Type) < 0) {
		return NULL;
	}

	if (PyType_Ready(&PyScramAuthData_Type) < 0) {
		return NULL;
	}

	if (PyType_Ready(&PyClientFirstMessage_Type) < 0) {
		return NULL;
	}

	if (PyType_Ready(&PyServerFirstMessage_Type) < 0) {
		return NULL;
	}

	if (PyType_Ready(&PyClientFinalMessage_Type) < 0) {
		return NULL;
	}

	if (PyType_Ready(&PyServerFinalMessage_Type) < 0) {
		return NULL;
	}

	m = PyModule_Create(&truenas_pyscram_module);
	if (m == NULL) {
		return NULL;
	}

	state = (tnscram_module_state_t *)PyModule_GetState(m);
	if (state == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	/* Create ScramError exception */
	state->scram_error = setup_scram_exception();
	if (state->scram_error == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddObjectRef(m, "ScramError", state->scram_error) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add CryptoDatum type */
	if (PyModule_AddObjectRef(m, "CryptoDatum", (PyObject *)&PyCryptoDatum_Type) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add ClientFirstMessage type */
	if (PyModule_AddObjectRef(m, "ClientFirstMessage", (PyObject *)&PyClientFirstMessage_Type) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add ServerFirstMessage type */
	if (PyModule_AddObjectRef(m, "ServerFirstMessage", (PyObject *)&PyServerFirstMessage_Type) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add ClientFinalMessage type */
	if (PyModule_AddObjectRef(m, "ClientFinalMessage", (PyObject *)&PyClientFinalMessage_Type) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add ServerFinalMessage type */
	if (PyModule_AddObjectRef(m, "ServerFinalMessage", (PyObject *)&PyServerFinalMessage_Type) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add SCRAM constants */
	if (PyModule_AddIntConstant(m, "SCRAM_E_SUCCESS", SCRAM_E_SUCCESS) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_INVALID_REQUEST", SCRAM_E_INVALID_REQUEST) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_MEMORY_ERROR", SCRAM_E_MEMORY_ERROR) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_CRYPTO_ERROR", SCRAM_E_CRYPTO_ERROR) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_BASE64_ERROR", SCRAM_E_BASE64_ERROR) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_PARSE_ERROR", SCRAM_E_PARSE_ERROR) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_FORMAT_ERROR", SCRAM_E_FORMAT_ERROR) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_E_AUTH_FAILED", SCRAM_E_AUTH_FAILED) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add SCRAM limits and defaults */
	if (PyModule_AddIntConstant(m, "SCRAM_DEFAULT_ITERS", SCRAM_DEFAULT_ITERS) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_MIN_ITERS", SCRAM_MIN_ITERS) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_MAX_ITERS", SCRAM_MAX_ITERS) < 0 ||
	    PyModule_AddIntConstant(m, "SCRAM_MAX_USERNAME_LEN", SCRAM_MAX_USERNAME_LEN) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add errorcode dictionary */
	PyObject *errorcode_dict = create_errorcode_dict();
	if (!errorcode_dict) {
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddObjectRef(m, "errorcode", errorcode_dict) < 0) {
		Py_DECREF(errorcode_dict);
		Py_DECREF(m);
		return NULL;
	}
	Py_DECREF(errorcode_dict);

	return m;
}
