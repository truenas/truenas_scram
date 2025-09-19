// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

typedef struct {
	py_client_first_t *client_first;
	py_server_first_t *server_first;
	py_client_final_t *client_final;
	py_crypto_datum_t *stored_key;
} client_final_verify_params_t;

typedef struct {
	py_client_first_t *client_first;
	py_server_first_t *server_first;
	py_client_final_t *client_final;
	py_server_final_t *server_final;
	py_crypto_datum_t *server_key;
} server_signature_verify_params_t;

static int
parse_client_final_verify_params(PyObject *args, PyObject *kwds,
				 client_final_verify_params_t *params)
{
	PyObject *client_first_obj = NULL;
	PyObject *server_first_obj = NULL;
	PyObject *client_final_obj = NULL;
	PyObject *stored_key_obj = NULL;
	static char *kwlist[] = {"client_first", "server_first", "client_final",
				 "stored_key", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOO", kwlist,
					 &client_first_obj, &server_first_obj,
					 &client_final_obj, &stored_key_obj)) {
		return -1;
	}

	/* Validate client_first parameter */
	if (!PyObject_IsInstance(client_first_obj,
				 (PyObject *)&PyClientFirstMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"client_first must be a ClientFirstMessage instance");
		return -1;
	}
	params->client_first = (py_client_first_t *)client_first_obj;

	/* Validate server_first parameter */
	if (!PyObject_IsInstance(server_first_obj,
				 (PyObject *)&PyServerFirstMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"server_first must be a ServerFirstMessage instance");
		return -1;
	}
	params->server_first = (py_server_first_t *)server_first_obj;

	/* Validate client_final parameter */
	if (!PyObject_IsInstance(client_final_obj,
				 (PyObject *)&PyClientFinalMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"client_final must be a ClientFinalMessage instance");
		return -1;
	}
	params->client_final = (py_client_final_t *)client_final_obj;

	/* Validate stored_key parameter */
	if (!PyObject_IsInstance(stored_key_obj,
				 (PyObject *)&PyCryptoDatum_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"stored_key must be a CryptoDatum instance");
		return -1;
	}
	params->stored_key = (py_crypto_datum_t *)stored_key_obj;

	/* Validate that all required objects are initialized */
	if (!params->client_first->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFirstMessage not initialized");
		return -1;
	}

	if (!params->server_first->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFirstMessage not initialized");
		return -1;
	}

	if (!params->client_final->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return -1;
	}

	if (!SCRAM_DATUM_IS_VALID(&params->stored_key->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"stored_key CryptoDatum not initialized");
		return -1;
	}

	return 0;
}

static int
parse_server_signature_verify_params(PyObject *args, PyObject *kwds,
				      server_signature_verify_params_t *params)
{
	PyObject *client_first_obj = NULL;
	PyObject *server_first_obj = NULL;
	PyObject *client_final_obj = NULL;
	PyObject *server_final_obj = NULL;
	PyObject *server_key_obj = NULL;
	static char *kwlist[] = {"client_first", "server_first", "client_final",
				 "server_final", "server_key", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOOO", kwlist,
					 &client_first_obj, &server_first_obj,
					 &client_final_obj, &server_final_obj,
					 &server_key_obj)) {
		return -1;
	}

	/* Validate client_first parameter */
	if (!PyObject_IsInstance(client_first_obj,
				 (PyObject *)&PyClientFirstMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"client_first must be a ClientFirstMessage instance");
		return -1;
	}
	params->client_first = (py_client_first_t *)client_first_obj;

	/* Validate server_first parameter */
	if (!PyObject_IsInstance(server_first_obj,
				 (PyObject *)&PyServerFirstMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"server_first must be a ServerFirstMessage instance");
		return -1;
	}
	params->server_first = (py_server_first_t *)server_first_obj;

	/* Validate client_final parameter */
	if (!PyObject_IsInstance(client_final_obj,
				 (PyObject *)&PyClientFinalMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"client_final must be a ClientFinalMessage instance");
		return -1;
	}
	params->client_final = (py_client_final_t *)client_final_obj;

	/* Validate server_final parameter */
	if (!PyObject_IsInstance(server_final_obj,
				 (PyObject *)&PyServerFinalMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"server_final must be a ServerFinalMessage instance");
		return -1;
	}
	params->server_final = (py_server_final_t *)server_final_obj;

	/* Validate server_key parameter */
	if (!PyObject_IsInstance(server_key_obj,
				 (PyObject *)&PyCryptoDatum_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"server_key must be a CryptoDatum instance");
		return -1;
	}
	params->server_key = (py_crypto_datum_t *)server_key_obj;

	/* Validate that all required objects are initialized */
	if (!params->client_first->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFirstMessage not initialized");
		return -1;
	}

	if (!params->server_first->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFirstMessage not initialized");
		return -1;
	}

	if (!params->client_final->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return -1;
	}

	if (!params->server_final->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFinalMessage not initialized");
		return -1;
	}

	if (!SCRAM_DATUM_IS_VALID(&params->server_key->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"server_key CryptoDatum not initialized");
		return -1;
	}

	return 0;
}


PyObject *
py_verify_client_final_message(PyObject *self, PyObject *args, PyObject *kwds)
{
	client_final_verify_params_t params = {0};
	scram_error_t error = {0};
	scram_resp_t ret;

	if (parse_client_final_verify_params(args, kwds, &params) < 0) {
		return NULL;
	}

	/* Perform verification under GIL drop */
	Py_BEGIN_ALLOW_THREADS
	ret = scram_verify_client_final_message(
		params.client_first->msg,
		params.server_first->msg,
		params.client_final->msg,
		&params.stored_key->datum,
		&error);
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error,
				   "Client final message verification failed");
		return NULL;
	}

	Py_RETURN_NONE;
}


PyObject *
py_verify_server_signature(PyObject *self, PyObject *args, PyObject *kwds)
{
	server_signature_verify_params_t params = {0};
	scram_error_t error = {0};
	scram_resp_t ret;

	if (parse_server_signature_verify_params(args, kwds, &params) < 0) {
		return NULL;
	}

	/* Perform verification under GIL drop */
	Py_BEGIN_ALLOW_THREADS
	ret = scram_verify_server_signature(
		params.client_first->msg,
		params.server_first->msg,
		params.client_final->msg,
		params.server_final->msg,
		&params.server_key->datum,
		&error);
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error,
				   "Server signature verification failed");
		return NULL;
	}

	Py_RETURN_NONE;
}
