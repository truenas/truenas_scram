// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

typedef struct {
	py_client_first_t *client_first;
	py_server_first_t *server_first;
	py_client_final_t *client_final;
	py_crypto_datum_t *stored_key;
	py_crypto_datum_t *server_key;
} server_final_params_t;

static int
parse_server_final_params(PyObject *args, PyObject *kwds,
			  server_final_params_t *params, const char **rfc_string)
{
	PyObject *client_first_obj = NULL;
	PyObject *server_first_obj = NULL;
	PyObject *client_final_obj = NULL;
	PyObject *stored_key_obj = NULL;
	PyObject *server_key_obj = NULL;
	static char *kwlist[] = {"client_first", "server_first", "client_final",
				 "stored_key", "server_key", "rfc_string", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$OOOOOs", kwlist,
					 &client_first_obj, &server_first_obj,
					 &client_final_obj, &stored_key_obj,
					 &server_key_obj, rfc_string)) {
		return -1;
	}

	/* Check for mutually exclusive parameters */
	if (*rfc_string && client_first_obj) {
		PyErr_SetString(PyExc_ValueError,
				"Cannot specify both rfc_string and other parameters");
		return -1;
	}

	if (!*rfc_string && !client_first_obj) {
		PyErr_SetString(PyExc_ValueError,
				"Must specify either rfc_string or message parameters");
		return -1;
	}

	/* If rfc_string is provided, we're done parsing */
	if (*rfc_string) {
		return 0;
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

	if (!SCRAM_DATUM_IS_VALID(&params->stored_key->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"stored_key CryptoDatum not initialized");
		return -1;
	}

	if (!SCRAM_DATUM_IS_VALID(&params->server_key->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"server_key CryptoDatum not initialized");
		return -1;
	}

	return 0;
}

static int
py_server_final_init(py_server_final_t *self, PyObject *args, PyObject *kwds)
{
	server_final_params_t params = {0};
	const char *rfc_string = NULL;
	char *serialized = NULL;
	scram_error_t error = {0};
	scram_resp_t ret;

	if (parse_server_final_params(args, kwds, &params, &rfc_string) < 0) {
		return -1;
	}

	if (rfc_string) {
		/* Parse from RFC string */
		Py_BEGIN_ALLOW_THREADS
		ret = scram_deserialize_server_final_message(rfc_string, &self->msg, &error);
		if (ret == SCRAM_E_SUCCESS) {
			/* Re-serialize to get a clean RFC string */
			ret = scram_serialize_server_final_message(self->msg,
								   &serialized, &error);
		}
		Py_END_ALLOW_THREADS

		if (ret != SCRAM_E_SUCCESS) {
			set_exc_from_scram(ret, &error,
					   "Failed to parse server final message");
			return -1;
		}

		self->rfc_string = PyUnicode_FromString(serialized);
		free(serialized);
		if (!self->rfc_string) {
			return -1;
		}

		return 0;
	}

	/* Create server final message and serialize in single GIL drop */
	Py_BEGIN_ALLOW_THREADS
	ret = scram_create_server_final_message(
		params.client_first->msg,
		params.server_first->msg,
		params.client_final->msg,
		&params.stored_key->datum,
		&params.server_key->datum,
		&self->msg,
		&error);
	if (ret == SCRAM_E_SUCCESS) {
		ret = scram_serialize_server_final_message(self->msg,
							   &serialized, &error);
	}
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error,
				   "Failed to create/serialize server final message");
		return -1;
	}

	self->rfc_string = PyUnicode_FromString(serialized);
	free(serialized);
	if (!self->rfc_string) {
		return -1;
	}

	return 0;
}

static void
py_server_final_dealloc(py_server_final_t *self)
{
	clear_scram_server_final_message(self->msg);
	free(self->msg);
	Py_XDECREF(self->rfc_string);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(py_server_final_signature__doc__,
"Server signature for client verification.\n\n"
"This attribute contains the server signature used by the client\n"
"to verify that the server has access to the user's authentication\n"
"information, as specified in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_server_final_get_signature(py_server_final_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFinalMessage not initialized");
		return NULL;
	}

	return crypto_datum_to_pycrypto_datum(&self->msg->signature);
}

static PyGetSetDef py_server_final_getsetters[] = {
	{
		.name = "signature",
		.get = (getter)py_server_final_get_signature,
		.set = NULL,
		.doc = py_server_final_signature__doc__,
		.closure = NULL
	},
	{NULL}
};

static PyObject *
py_server_final_str(py_server_final_t *self)
{
	if (!self->rfc_string) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFinalMessage not initialized");
		return NULL;
	}
	return Py_NewRef(self->rfc_string);
}

PyDoc_STRVAR(py_server_final__doc__,
"ServerFinalMessage(client_first=None, server_first=None, client_final=None, stored_key=None, server_key=None, rfc_string=None)\n"
"-------------------------------------------------------------------------------------------------------------------------------\n\n"
"SCRAM server final message as specified in RFC 5802 Section 5.1.\n\n"
"This message contains the server signature that allows the client to verify\n"
"that the server has access to the user's authentication information.\n"
"It is sent by the server as the final step in the SCRAM authentication flow.\n\n"
"Parameters\n"
"----------\n"
"client_first : ClientFirstMessage, optional\n"
"    The original client first message.\n"
"    Required if rfc_string is not provided.\n"
"server_first : ServerFirstMessage, optional\n"
"    The server first message that was sent.\n"
"    Required if rfc_string is not provided.\n"
"client_final : ClientFinalMessage, optional\n"
"    The client final message that was received.\n"
"    Required if rfc_string is not provided.\n"
"stored_key : CryptoDatum, optional\n"
"    The stored key derived from the user's credentials.\n"
"    Required if rfc_string is not provided.\n"
"server_key : CryptoDatum, optional\n"
"    The server key derived from the user's credentials.\n"
"    Required if rfc_string is not provided.\n"
"rfc_string : str, optional\n"
"    RFC 5802 formatted server-final-message string to parse.\n"
"    If provided, all other parameters must not be specified.\n\n"
"Notes\n"
"-----\n"
"Either all message parameters or 'rfc_string' must be provided, but not both.\n"
);

PyTypeObject PyServerFinalMessage_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".ServerFinalMessage",
	.tp_doc = py_server_final__doc__,
	.tp_basicsize = sizeof(py_server_final_t),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_server_final_init,
	.tp_dealloc = (destructor)py_server_final_dealloc,
	.tp_str = (reprfunc)py_server_final_str,
	.tp_getset = py_server_final_getsetters,
};
