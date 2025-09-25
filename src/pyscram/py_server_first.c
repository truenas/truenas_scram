// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

static int
py_server_first_init(py_server_first_t *self, PyObject *args, PyObject *kwds)
{
	PyObject *client_first_obj = NULL;
	PyObject *salt_obj = NULL;
	uint64_t iterations = 0;
	const char *rfc_string = NULL;
	py_client_first_t *client_first = NULL;
	py_crypto_datum_t *salt = NULL;
	char *serialized = NULL;
	scram_error_t error = {0};
	scram_resp_t ret;
	static char *kwlist[] = {"client_first", "salt", "iterations", "rfc_string", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$OOKs", kwlist,
					 &client_first_obj, &salt_obj,
					 &iterations, &rfc_string)) {
		return -1;
	}

	/* Check for mutually exclusive parameters */
	if (rfc_string && client_first_obj) {
		PyErr_SetString(PyExc_ValueError,
				"Cannot specify both rfc_string and client_first parameters");
		return -1;
	}

	if (!rfc_string && !client_first_obj) {
		PyErr_SetString(PyExc_ValueError,
				"Must specify either rfc_string or client_first parameter");
		return -1;
	}

	if (rfc_string) {
		/* Parse from RFC string */
		Py_BEGIN_ALLOW_THREADS
		ret = scram_deserialize_server_first_message(rfc_string, &self->msg, &error);
		if (ret == SCRAM_E_SUCCESS) {
			/* Re-serialize to get a clean RFC string */
			ret = scram_serialize_server_first_message(self->msg,
								   &serialized, &error);
		}
		Py_END_ALLOW_THREADS

		if (ret != SCRAM_E_SUCCESS) {
			set_exc_from_scram(ret, &error,
					   "Failed to parse server first message");
			return -1;
		}

		self->rfc_string = PyUnicode_FromString(serialized);
		free(serialized);
		if (!self->rfc_string) {
			return -1;
		}

		return 0;
	}

	/* Create new message from parameters */
	if (!PyObject_IsInstance(client_first_obj,
				 (PyObject *)&PyClientFirstMessage_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"client_first must be a ClientFirstMessage instance");
		return -1;
	}

	if (!PyObject_IsInstance(salt_obj, (PyObject *)&PyCryptoDatum_Type)) {
		PyErr_SetString(PyExc_TypeError,
				"salt must be a CryptoDatum instance");
		return -1;
	}

	client_first = (py_client_first_t *)client_first_obj;
	salt = (py_crypto_datum_t *)salt_obj;

	if (!client_first->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ClientFirstMessage not initialized");
		return -1;
	}

	if (!SCRAM_DATUM_IS_VALID(&salt->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"Salt CryptoDatum not initialized");
		return -1;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = scram_create_server_first_message(client_first->msg, &salt->datum,
						iterations, &self->msg, &error);
	if (ret == SCRAM_E_SUCCESS) {
		ret = scram_serialize_server_first_message(self->msg,
							   &serialized, &error);
	}
	Py_END_ALLOW_THREADS

	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error,
				   "Failed to create/serialize server first message");
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
py_server_first_dealloc(py_server_first_t *self)
{
	clear_scram_server_first_message(self->msg);
	free(self->msg);
	Py_XDECREF(self->rfc_string);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(py_server_first_salt__doc__,
"Salt value used for password derivation.\n\n"
"This attribute contains the salt value as specified in RFC 5802 Section 5.1.\n"
"The salt is used with PBKDF2 for password-based key derivation.\n"
);

static PyObject *
py_server_first_get_salt(py_server_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFirstMessage not initialized");
		return NULL;
	}

	return crypto_datum_to_pycrypto_datum(&self->msg->salt);
}

PyDoc_STRVAR(py_server_first_iterations__doc__,
"Iteration count for PBKDF2 password derivation.\n\n"
"This attribute specifies the iteration count as defined in RFC 5802 Section 5.1.\n"
"Higher values increase security but require more computation time.\n"
);

static PyObject *
py_server_first_get_iterations(py_server_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFirstMessage not initialized");
		return NULL;
	}
	return PyLong_FromUnsignedLongLong(self->msg->iterations);
}

PyDoc_STRVAR(py_server_first_nonce__doc__,
"Combined client and server nonce.\n\n"
"This attribute contains the concatenated client nonce (from client-first-message)\n"
"and server nonce as specified in RFC 5802 Section 5.1.\n"
);

static PyObject *
py_server_first_get_nonce(py_server_first_t *self, void *closure)
{
	if (!self->msg) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFirstMessage not initialized");
		return NULL;
	}

	return crypto_datum_to_pycrypto_datum(&self->msg->nonce);
}

static PyGetSetDef py_server_first_getsetters[] = {
	{
		.name = "salt",
		.get = (getter)py_server_first_get_salt,
		.set = NULL,
		.doc = py_server_first_salt__doc__,
		.closure = NULL
	},
	{
		.name = "iterations",
		.get = (getter)py_server_first_get_iterations,
		.set = NULL,
		.doc = py_server_first_iterations__doc__,
		.closure = NULL
	},
	{
		.name = "nonce",
		.get = (getter)py_server_first_get_nonce,
		.set = NULL,
		.doc = py_server_first_nonce__doc__,
		.closure = NULL
	},
	{NULL}
};

static PyObject *
py_server_first_str(py_server_first_t *self)
{
	if (!self->rfc_string) {
		PyErr_SetString(PyExc_RuntimeError,
				"ServerFirstMessage not initialized");
		return NULL;
	}
	return Py_NewRef(self->rfc_string);
}

PyDoc_STRVAR(py_server_first__doc__,
"ServerFirstMessage(client_first=None, salt=None, iterations=None, rfc_string=None)\n"
"-----------------------------------------------------------------------------------\n\n"
"SCRAM server first message as specified in RFC 5802 Section 5.1.\n\n"
"This message contains the combined nonce (client + server nonces),\n"
"salt value, and iteration count for PBKDF2 password derivation.\n"
"A random server nonce is automatically generated and combined with\n"
"the client nonce during initialization.\n\n"
"Parameters\n"
"----------\n"
"client_first : ClientFirstMessage, optional\n"
"    The client first message to respond to.\n"
"    Required if rfc_string is not provided.\n"
"salt : CryptoDatum, optional\n"
"    Salt value for password derivation.\n"
"    Required if rfc_string is not provided.\n"
"iterations : int, optional\n"
"    Iteration count for PBKDF2 (must be within valid range).\n"
"    Required if rfc_string is not provided.\n"
"rfc_string : str, optional\n"
"    RFC 5802 formatted server-first-message string to parse.\n"
"    If provided, client_first, salt, and iterations must not be specified.\n\n"
"Notes\n"
"-----\n"
"Either 'client_first' (with salt and iterations) or 'rfc_string' must be provided, but not both.\n"
);

PyTypeObject PyServerFirstMessage_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".ServerFirstMessage",
	.tp_doc = py_server_first__doc__,
	.tp_basicsize = sizeof(py_server_first_t),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_server_first_init,
	.tp_dealloc = (destructor)py_server_first_dealloc,
	.tp_str = (reprfunc)py_server_first_str,
	.tp_getset = py_server_first_getsetters,
};
