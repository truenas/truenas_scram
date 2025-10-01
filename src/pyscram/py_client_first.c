// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

static int
py_client_first_init(py_client_first_t *self, PyObject *args, PyObject *kwds)
{
	const char *username = NULL;
	uint32_t api_key_id = 0;
	const char *gs2_header = NULL;
	const char *rfc_string = NULL;
	char *serialized = NULL;
	scram_error_t error = {0};
	scram_resp_t ret;
	static char *kwlist[] = {"username", "api_key_id", "gs2_header", "rfc_string", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$sIss", kwlist,
					 &username, &api_key_id, &gs2_header, &rfc_string)) {
		return -1;
	}

	/* Check for mutually exclusive parameters */
	if (rfc_string && username) {
		PyErr_SetString(PyExc_ValueError,
				"Cannot specify both rfc_string and username parameters");
		return -1;
	}

	if (!rfc_string && !username) {
		PyErr_SetString(PyExc_ValueError,
				"Must specify either rfc_string or username parameter");
		return -1;
	}

	if (rfc_string) {
		/* Parse from RFC string */
		Py_BEGIN_ALLOW_THREADS
		ret = scram_deserialize_client_first_message(rfc_string, &self->msg, &error);
		if (ret == SCRAM_E_SUCCESS) {
			/* Re-serialize to get a clean RFC string */
			ret = scram_serialize_client_first_message(self->msg,
								   &serialized, false,
								   &error);
		}
		Py_END_ALLOW_THREADS
	} else {
		/* Create new message from parameters */
		Py_BEGIN_ALLOW_THREADS
		ret = scram_create_client_first_message(username, api_key_id, gs2_header,
							&self->msg, &error);
		if (ret == SCRAM_E_SUCCESS) {
			ret = scram_serialize_client_first_message(self->msg,
								   &serialized, false,
								   &error);
		}
		Py_END_ALLOW_THREADS
	}

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error,
				   rfc_string ? "Failed to parse client first message" :
				   "Failed to create/serialize client first message");
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
py_client_first_dealloc(py_client_first_t *self)
{
	clear_scram_client_first_message(self->msg);
	free(self->msg);
	Py_XDECREF(self->rfc_string);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(py_client_first_username__doc__,
"Username for authentication (authentication identity).\n\n"
"This attribute specifies the name of the user whose password is\n"
"used for authentication as defined in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_client_first_get_username(py_client_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError, "ClientFirstMessage not initialized");
		return NULL;
	}
	return PyUnicode_FromString(self->msg->principal.username);
}

PyDoc_STRVAR(py_client_first_api_key_id__doc__,
"API key identifier.\n\n"
"Optional API key identifier stored in the principal structure.\n"
"When non-zero, it will be encoded using a colon delimiter after\n"
"the username when the message is serialized.\n"
);

static PyObject *
py_client_first_get_api_key_id(py_client_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError, "ClientFirstMessage not initialized");
		return NULL;
	}
	return PyLong_FromUnsignedLong(self->msg->principal.api_key_id);
}

PyDoc_STRVAR(py_client_first_nonce__doc__,
"Client nonce for authentication.\n\n"
"This attribute specifies a sequence of random printable ASCII\n"
"characters excluding ',' which forms the nonce used by the client\n"
"as defined in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_client_first_get_nonce(py_client_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError, "ClientFirstMessage not initialized");
		return NULL;
	}
	return crypto_datum_to_pycrypto_datum(&self->msg->nonce);
}

PyDoc_STRVAR(py_client_first_gs2_header__doc__,
"GS2 header for channel binding support.\n\n"
"Channel binding support and authzid information as specified\n"
"in the SCRAM protocol. None indicates no channel binding.\n"
);

static PyObject *
py_client_first_get_gs2_header(py_client_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError, "ClientFirstMessage not initialized");
		return NULL;
	}
	if (self->msg->gs2_header) {
		return PyUnicode_FromString(self->msg->gs2_header);
	}
	Py_RETURN_NONE;
}

static PyGetSetDef py_client_first_getsetters[] = {
	{"username", (getter)py_client_first_get_username, NULL, py_client_first_username__doc__, NULL},
	{"api_key_id", (getter)py_client_first_get_api_key_id, NULL, py_client_first_api_key_id__doc__, NULL},
	{"nonce", (getter)py_client_first_get_nonce, NULL, py_client_first_nonce__doc__, NULL},
	{"gs2_header", (getter)py_client_first_get_gs2_header, NULL, py_client_first_gs2_header__doc__, NULL},
	{NULL}
};

static PyObject *
py_client_first_str(py_client_first_t *self)
{
	if (!self->rfc_string) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFirstMessage not initialized");
		return NULL;
	}
	return Py_NewRef(self->rfc_string);
}

static PyObject *
py_client_first_repr(py_client_first_t *self)
{
	if (!self->msg) {
		return PyUnicode_FromFormat("ClientFirstMessage(<uninitialized>)");
	}

	return PyUnicode_FromFormat("ClientFirstMessage(username='%s', api_key_id=%u)",
	                            self->msg->principal.username,
	                            self->msg->principal.api_key_id);
}

PyDoc_STRVAR(py_client_first__doc__,
"ClientFirstMessage(username=None, api_key_id=0, gs2_header=None, rfc_string=None)\n"
"----------------------------------------------------------------------------------\n\n"
"SCRAM client first message as specified in RFC 5802 Section 5.1.\n\n"
"This message contains the username (with optional API key ID),\n"
"client nonce, and GS2 header for channel binding support.\n"
"A random client nonce is automatically generated during initialization.\n\n"
"Parameters\n"
"----------\n"
"username : str, optional\n"
"    Username for authentication (authentication identity).\n"
"    Required if rfc_string is not provided.\n"
"api_key_id : int, optional\n"
"    API key identifier (0 if not used).\n"
"    Only used when creating a new message (not with rfc_string).\n"
"gs2_header : str, optional\n"
"    GS2 header string (None for no channel binding).\n"
"    Only used when creating a new message (not with rfc_string).\n"
"rfc_string : str, optional\n"
"    RFC 5802 formatted client-first-message string to parse.\n"
"    If provided, username, api_key_id, and gs2_header must not be specified.\n\n"
"Notes\n"
"-----\n"
"Either 'username' or 'rfc_string' must be provided, but not both.\n"
);

PyTypeObject PyClientFirstMessage_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".ClientFirstMessage",
	.tp_doc = py_client_first__doc__,
	.tp_basicsize = sizeof(py_client_first_t),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_client_first_init,
	.tp_dealloc = (destructor)py_client_first_dealloc,
	.tp_repr = (reprfunc)py_client_first_repr,
	.tp_str = (reprfunc)py_client_first_str,
	.tp_getset = py_client_first_getsetters,
};
