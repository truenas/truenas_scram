// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

typedef struct {
	py_client_first_t *client_first;
	py_server_first_t *server_first;
	py_crypto_datum_t *client_key;
	py_crypto_datum_t *stored_key;
	py_crypto_datum_t *channel_binding;
} client_final_params_t;

static int
parse_client_final_params(PyObject *args, PyObject *kwds,
			  client_final_params_t *params)
{
	PyObject *client_first_obj = NULL;
	PyObject *server_first_obj = NULL;
	PyObject *client_key_obj = NULL;
	PyObject *stored_key_obj = NULL;
	PyObject *channel_binding_obj = NULL;
	static char *kwlist[] = {"client_first", "server_first", "client_key",
				 "stored_key", "channel_binding", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOO|O", kwlist,
					 &client_first_obj, &server_first_obj,
					 &client_key_obj, &stored_key_obj,
					 &channel_binding_obj)) {
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

	/* Validate client_key parameter */
	if (!PyObject_IsInstance(client_key_obj,
				 (PyObject *)&PyCryptoDatum_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"client_key must be a CryptoDatum instance");
		return -1;
	}
	params->client_key = (py_crypto_datum_t *)client_key_obj;

	/* Validate stored_key parameter */
	if (!PyObject_IsInstance(stored_key_obj,
				 (PyObject *)&PyCryptoDatum_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"stored_key must be a CryptoDatum instance");
		return -1;
	}
	params->stored_key = (py_crypto_datum_t *)stored_key_obj;

	/* Validate optional channel_binding parameter */
	if (channel_binding_obj && channel_binding_obj != Py_None) {
		if (!PyObject_IsInstance(channel_binding_obj,
					 (PyObject *)&PyCryptoDatum_Type)) {
			PyErr_SetString(PyExc_TypeError,
					"channel_binding must be a CryptoDatum instance or None");
			return -1;
		}
		params->channel_binding = (py_crypto_datum_t *)channel_binding_obj;
	} else {
		params->channel_binding = NULL;
	}

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

	if (!SCRAM_DATUM_IS_VALID(&params->client_key->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"client_key CryptoDatum not initialized");
		return -1;
	}

	if (!SCRAM_DATUM_IS_VALID(&params->stored_key->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"stored_key CryptoDatum not initialized");
		return -1;
	}

	if (params->channel_binding &&
	    !SCRAM_DATUM_IS_VALID(&params->channel_binding->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"channel_binding CryptoDatum not initialized");
		return -1;
	}

	return 0;
}

static int
py_client_final_init(py_client_final_t *self, PyObject *args, PyObject *kwds)
{
	client_final_params_t params = {0};
	char *serialized = NULL;
	scram_error_t error = {0};
	scram_resp_t ret;

	if (parse_client_final_params(args, kwds, &params) < 0) {
		return -1;
	}

	/* Create client final message and serialize in single GIL drop */
	Py_BEGIN_ALLOW_THREADS
	ret = scram_create_client_final_message(
		params.channel_binding ? &params.channel_binding->datum : NULL,
		&params.client_key->datum,
		&params.stored_key->datum,
		params.client_first->msg,
		params.server_first->msg,
		&self->msg,
		&error);
	if (ret == SCRAM_E_SUCCESS) {
		ret = scram_serialize_client_final_message(self->msg,
							   &serialized, &error);
	}
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error,
				   "Failed to create/serialize client final message");
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
py_client_final_dealloc(py_client_final_t *self)
{
	clear_scram_client_final_message(self->msg);
	free(self->msg);
	Py_XDECREF(self->rfc_string);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(py_client_final_nonce__doc__,
"Combined client and server nonce.\n\n"
"This attribute contains the concatenated client nonce and server nonce\n"
"as specified in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_client_final_get_nonce(py_client_final_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return NULL;
	}

	return crypto_datum_to_pycrypto_datum(&self->msg->nonce);
}

PyDoc_STRVAR(py_client_final_client_proof__doc__,
"Client proof for authentication.\n\n"
"This attribute contains the base64-encoded client proof\n"
"as specified in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_client_final_get_client_proof(py_client_final_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return NULL;
	}

	return crypto_datum_to_pycrypto_datum(&self->msg->client_proof);
}

PyDoc_STRVAR(py_client_final_gs2_header__doc__,
"GS2 header for channel binding support.\n\n"
"This attribute contains the GS2 header string from the client-first-message\n"
"as specified in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_client_final_get_gs2_header(py_client_final_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return NULL;
	}
	if (self->msg->gs2_header) {
		return PyUnicode_FromString(self->msg->gs2_header);
	}
	Py_RETURN_NONE;
}

PyDoc_STRVAR(py_client_final_channel_binding__doc__,
"Channel binding data from the SSL transport.\n\n"
"This attribute contains the raw channel binding data obtained from\n"
"the SSL object for the encrypted transport connection, as specified\n"
"in RFC 5802 Section 5.1. Returns None if no channel binding is used.\n"
);

static PyObject *
py_client_final_get_channel_binding(py_client_final_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return NULL;
	}
	if (self->msg->channel_binding &&
	    SCRAM_DATUM_IS_VALID(self->msg->channel_binding)) {
		return crypto_datum_to_pycrypto_datum(self->msg->channel_binding);
	}
	Py_RETURN_NONE;
}

static PyGetSetDef py_client_final_getsetters[] = {
	{
		.name = "nonce",
		.get = (getter)py_client_final_get_nonce,
		.set = NULL,
		.doc = py_client_final_nonce__doc__,
		.closure = NULL
	},
	{
		.name = "client_proof",
		.get = (getter)py_client_final_get_client_proof,
		.set = NULL,
		.doc = py_client_final_client_proof__doc__,
		.closure = NULL
	},
	{
		.name = "gs2_header",
		.get = (getter)py_client_final_get_gs2_header,
		.set = NULL,
		.doc = py_client_final_gs2_header__doc__,
		.closure = NULL
	},
	{
		.name = "channel_binding",
		.get = (getter)py_client_final_get_channel_binding,
		.set = NULL,
		.doc = py_client_final_channel_binding__doc__,
		.closure = NULL
	},
	{NULL}
};

static PyObject *
py_client_final_str(py_client_final_t *self)
{
	if (!self->rfc_string) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFinalMessage not initialized");
		return NULL;
	}
	return Py_NewRef(self->rfc_string);
}

PyDoc_STRVAR(py_client_final__doc__,
"ClientFinalMessage(client_first, server_first, client_key, stored_key, channel_binding=None)\n"
"-------------------------------------------------------------------------------------------\n\n"
"SCRAM client final message as specified in RFC 5802 Section 5.1.\n\n"
"This message contains the combined nonce, channel binding data (if any),\n"
"and client proof for authentication. It is sent by the client in response\n"
"to the server-first-message to prove knowledge of the password.\n\n"
"Parameters\n"
"----------\n"
"client_first : ClientFirstMessage\n"
"    The original client first message\n"
"server_first : ServerFirstMessage\n"
"    The server first message being responded to\n"
"client_key : CryptoDatum\n"
"    The client key derived from the user's credentials\n"
"stored_key : CryptoDatum\n"
"    The stored key derived from the client key\n"
"channel_binding : CryptoDatum, optional\n"
"    Channel binding data obtained from the SSL object for the encrypted\n"
"    transport connection (None for no channel binding)\n"
);

PyTypeObject PyClientFinalMessage_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".ClientFinalMessage",
	.tp_doc = py_client_final__doc__,
	.tp_basicsize = sizeof(py_client_final_t),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_client_final_init,
	.tp_dealloc = (destructor)py_client_final_dealloc,
	.tp_str = (reprfunc)py_client_final_str,
	.tp_getset = py_client_final_getsetters,
};
