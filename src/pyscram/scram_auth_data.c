// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pyscram.h"

static void
py_scram_auth_data_dealloc(py_scram_auth_data_t *self)
{
	clear_scram_auth_data(&self->auth_data);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(py_scram_auth_data_salt__doc__,
"Base64-encoded salt used by the server for this user as specified in RFC 5802.\n"
"This attribute corresponds to the 's:' attribute in server-first-message."
);

static PyObject *
py_scram_auth_data_get_salt(py_scram_auth_data_t *self, void *closure)
{
	return crypto_datum_to_pycrypto_datum(&self->auth_data.salt);
}

PyDoc_STRVAR(py_scram_auth_data_iterations__doc__,
"Iteration count for the selected hash function and user as specified in RFC 5802.\n"
"This attribute corresponds to the 'i:' attribute in server-first-message.\n"
"Must be between 50000 and 5000000 iterations."
);

static PyObject *
py_scram_auth_data_get_iterations(py_scram_auth_data_t *self, void *closure)
{
	return PyLong_FromUnsignedLongLong(self->auth_data.iterations);
}

PyDoc_STRVAR(py_scram_auth_data_salted_password__doc__,
"SaltedPassword := Hi(Normalize(password), salt, i) as defined in RFC 5802 Section 3.\n"
"This is the result of PBKDF2 key derivation using HMAC-SHA-512 with the user's password,\n"
"salt, and iteration count. Used as the basis for generating client and server keys."
);

static PyObject *
py_scram_auth_data_get_salted_password(py_scram_auth_data_t *self, void *closure)
{
	return crypto_datum_to_pycrypto_datum(&self->auth_data.salted_password);
}

PyDoc_STRVAR(py_scram_auth_data_client_key__doc__,
"ClientKey := HMAC(SaltedPassword, \"Client Key\") as defined in RFC 5802 Section 3.\n"
"Used by the client to generate the client proof during SCRAM authentication.\n"
"This key is derived from the salted password and never transmitted directly."
);

static PyObject *
py_scram_auth_data_get_client_key(py_scram_auth_data_t *self, void *closure)
{
	return crypto_datum_to_pycrypto_datum(&self->auth_data.client_key);
}

PyDoc_STRVAR(py_scram_auth_data_stored_key__doc__,
"StoredKey := H(ClientKey) as defined in RFC 5802 Section 3.\n"
"This is the SHA-512 hash of the client key and is what the server stores\n"
"instead of the plaintext password for authentication verification.\n"
"Used to verify the client proof in the client-final-message."
);

static PyObject *
py_scram_auth_data_get_stored_key(py_scram_auth_data_t *self, void *closure)
{
	return crypto_datum_to_pycrypto_datum(&self->auth_data.stored_key);
}

PyDoc_STRVAR(py_scram_auth_data_server_key__doc__,
"ServerKey := HMAC(SaltedPassword, \"Server Key\") as defined in RFC 5802 Section 3.\n"
"Used by the server to generate the server signature in the server-final-message.\n"
"This proves to the client that the server has access to the user's authentication information."
);

static PyObject *
py_scram_auth_data_get_server_key(py_scram_auth_data_t *self, void *closure)
{
	return crypto_datum_to_pycrypto_datum(&self->auth_data.server_key);
}

static PyObject *
py_scram_auth_data_repr(py_scram_auth_data_t *self)
{
	return PyUnicode_FromFormat("ScramAuthData(iterations=%llu)",
		(unsigned long long)self->auth_data.iterations);
}

static PyGetSetDef py_scram_auth_data_getsetters[] = {
	{
		.name = "salt",
		.get = (getter)py_scram_auth_data_get_salt,
		.doc = py_scram_auth_data_salt__doc__
	},
	{
		.name = "iterations",
		.get = (getter)py_scram_auth_data_get_iterations,
		.doc = py_scram_auth_data_iterations__doc__
	},
	{
		.name = "salted_password",
		.get = (getter)py_scram_auth_data_get_salted_password,
		.doc = py_scram_auth_data_salted_password__doc__
	},
	{
		.name = "client_key",
		.get = (getter)py_scram_auth_data_get_client_key,
		.doc = py_scram_auth_data_client_key__doc__
	},
	{
		.name = "stored_key",
		.get = (getter)py_scram_auth_data_get_stored_key,
		.doc = py_scram_auth_data_stored_key__doc__
	},
	{
		.name = "server_key",
		.get = (getter)py_scram_auth_data_get_server_key,
		.doc = py_scram_auth_data_server_key__doc__
	},
	{NULL}
};

PyDoc_STRVAR(ScramAuthDataType__doc__,
"ScramAuthData\n"
"-------------\n\n"
"SCRAM authentication data containing all keys and parameters as defined in RFC 5802.\n\n"
"This object provides access to the complete SCRAM authentication data including:\n"
"- Salt and iteration count for PBKDF2 key derivation\n"
"- SaltedPassword derived using Hi(password, salt, iterations)\n"
"- ClientKey and StoredKey for client authentication verification\n"
"- ServerKey for server signature generation\n\n"
"All cryptographic operations use HMAC-SHA-512 as specified for SCRAM-SHA-512.\n"
"Use truenas_pyscram.generate_scram_auth_data() to create instances.\n\n"
"This corresponds to the session authentication data structure used internally\n"
"by the SCRAM implementation for managing authentication state.\n"
);

PyTypeObject PyScramAuthData_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".ScramAuthData",
	.tp_doc = ScramAuthDataType__doc__,
	.tp_basicsize = sizeof(py_scram_auth_data_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_dealloc = (destructor)py_scram_auth_data_dealloc,
	.tp_repr = (reprfunc)py_scram_auth_data_repr,
	.tp_getset = py_scram_auth_data_getsetters,
};
