// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/crypto.h>
#include "truenas_pyscram.h"

static int
py_crypto_datum_init(py_crypto_datum_t *self, PyObject *args, PyObject *kwds)
{
	const char *data;
	Py_ssize_t data_len;
	crypto_datum_t source_datum;
	scram_error_t error = {0};
	scram_resp_t ret;

	/*
	 * A CryptoDatum wraps a single secret value and is immutable once
	 * initialized; re-initialization is rejected.
	 */
	if (SCRAM_DATUM_IS_VALID(&self->datum)) {
		PyErr_SetString(PyExc_RuntimeError,
				"CryptoDatum is immutable and cannot be "
				"re-initialized");
		return -1;
	}

	if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) {
		return -1;
	}

	if (data_len == 0) {
		return 0;
	}

	source_datum.data = (unsigned char *)data;
	source_datum.size = (size_t)data_len;

	ret = dup_crypto_datum(&source_datum, &self->datum, &error);
	if (ret != SCRAM_E_SUCCESS) {
		set_exc_from_scram(ret, &error, "Failed to copy crypto data");
		return -1;
	}

	return 0;
}

static void
py_crypto_datum_dealloc(py_crypto_datum_t *self)
{
	/*
	 * Free on the data pointer directly rather than via crypto_datum_clear():
	 * clear() zeroes the buffer and sets size to 0 while keeping it allocated,
	 * and crypto_datum_clear() skips the free() when size is 0.
	 */
	if (self->datum.data) {
		if (self->datum.size > 0) {
			explicit_bzero(self->datum.data, self->datum.size);
		}
		free(self->datum.data);
	}
	explicit_bzero(&self->datum, sizeof(self->datum));
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int
py_crypto_datum_getbuffer(py_crypto_datum_t *self, Py_buffer *view, int flags)
{
	return PyBuffer_FillInfo(view, (PyObject *)self,
	                         self->datum.data, self->datum.size,
	                         1, flags);  /* readonly=1 */
}

static PyBufferProcs py_crypto_datum_as_buffer = {
	.bf_getbuffer = (getbufferproc)py_crypto_datum_getbuffer,
};

static Py_ssize_t
py_crypto_datum_length(py_crypto_datum_t *self)
{
	return (Py_ssize_t)self->datum.size;
}

static PyObject *
py_crypto_datum_getitem(py_crypto_datum_t *self, PyObject *key)
{
	Py_ssize_t len = (Py_ssize_t)self->datum.size;

	if (PyLong_Check(key)) {
		Py_ssize_t index = PyLong_AsSsize_t(key);
		if (index == -1 && PyErr_Occurred()) {
			return NULL;
		}

		/* Handle negative indices */
		if (index < 0) {
			index += len;
		}

		if (index < 0 || index >= len) {
			PyErr_SetString(PyExc_IndexError, "index out of range");
			return NULL;
		}
		return PyLong_FromLong(self->datum.data[index]);
	}
	else if (PySlice_Check(key)) {
		Py_ssize_t start, stop, step, slice_len;

		if (PySlice_Unpack(key, &start, &stop, &step) < 0) {
			return NULL;
		}

		slice_len = PySlice_AdjustIndices(len, &start, &stop, step);

		if (step == 1) {
			return PyBytes_FromStringAndSize((char *)self->datum.data + start, slice_len);
		} else {
			/* Handle step != 1 */
			char *result_data = malloc(slice_len);
			if (!result_data) {
				PyErr_NoMemory();
				return NULL;
			}

			for (Py_ssize_t i = 0; i < slice_len; i++) {
				result_data[i] = self->datum.data[start + i * step];
			}

			PyObject *result = PyBytes_FromStringAndSize(result_data, slice_len);
			free(result_data);
			return result;
		}
	}
	else {
		PyErr_SetString(PyExc_TypeError, "indices must be integers or slices");
		return NULL;
	}
}

static PyMappingMethods py_crypto_datum_as_mapping = {
	.mp_length = (lenfunc)py_crypto_datum_length,
	.mp_subscript = (binaryfunc)py_crypto_datum_getitem,
};

static PyObject *
py_crypto_datum_richcompare(py_crypto_datum_t *self, PyObject *other, int op)
{
	py_crypto_datum_t *other_datum;
	int result;

	if (op != Py_EQ && op != Py_NE) {
		Py_RETURN_NOTIMPLEMENTED;
	}

	/* Only CryptoDatum instances compare equal; anything else is unequal. */
	if (!PyObject_TypeCheck(other, &PyCryptoDatum_Type)) {
		if (op == Py_EQ) {
			Py_RETURN_FALSE;
		} else {
			Py_RETURN_TRUE;
		}
	}

	other_datum = (py_crypto_datum_t *)other;

	if (self->datum.size != other_datum->datum.size) {
		result = 0;
	} else if (self->datum.size == 0) {
		result = 1;
	} else {
		/* Constant-time compare: these datums hold secrets. */
		result = (CRYPTO_memcmp(self->datum.data,
					other_datum->datum.data,
					self->datum.size) == 0);
	}

	if (op == Py_EQ) {
		return PyBool_FromLong(result);
	} else {
		return PyBool_FromLong(!result);
	}
}


PyDoc_STRVAR(py_crypto_datum_clear__doc__,
"clear() -> None\n"
"-------------\n\n"
"Securely zero the cryptographic data in place.\n\n"
"Overwrites the underlying buffer with zeros using explicit_bzero()\n"
"and resets the length to zero. The buffer itself is released when the\n"
"object is destroyed. After clear() the datum is empty and must not be\n"
"used for cryptographic operations.\n"
);

static PyObject *
py_crypto_datum_clear(py_crypto_datum_t *self, PyObject *Py_UNUSED(ignored))
{
	if (self->datum.data && self->datum.size > 0) {
		explicit_bzero(self->datum.data, self->datum.size);
		self->datum.size = 0;
	}
	Py_RETURN_NONE;
}

static Py_hash_t
py_crypto_datum_hash(py_crypto_datum_t *self)
{
	return PyHash_GetFuncDef()->hash(self->datum.data, self->datum.size);
}

static PyMethodDef py_crypto_datum_methods[] = {
	{"clear", (PyCFunction)py_crypto_datum_clear, METH_NOARGS, py_crypto_datum_clear__doc__},
	{NULL, NULL, 0, NULL}
};

PyDoc_STRVAR(py_crypto_datum__doc__,
"CryptoDatum(data)\n"
"-----------------\n\n"
"Immutable wrapper around a crypto_datum_t holding secret bytes.\n"
"Supports len(), indexing and slicing, the buffer protocol (e.g.\n"
"bytes(d)), hashing, and equality against other CryptoDatum instances\n"
"(constant-time). Call clear() to zero the contents when done.\n\n"
"Parameters\n"
"----------\n"
"data : bytes-like\n"
"    Binary data to wrap\n"
);

PyTypeObject PyCryptoDatum_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".CryptoDatum",
	.tp_doc = py_crypto_datum__doc__,
	.tp_basicsize = sizeof(py_crypto_datum_t),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_crypto_datum_init,
	.tp_dealloc = (destructor)py_crypto_datum_dealloc,
	.tp_richcompare = (richcmpfunc)py_crypto_datum_richcompare,
	.tp_hash = (hashfunc)py_crypto_datum_hash,
	.tp_as_buffer = &py_crypto_datum_as_buffer,
	.tp_as_mapping = &py_crypto_datum_as_mapping,
	.tp_methods = py_crypto_datum_methods,
};

PyObject *
crypto_datum_to_pycrypto_datum(const crypto_datum_t *datum)
{
	py_crypto_datum_t *result;
	scram_error_t error = {0};
	scram_resp_t ret;

	if (!SCRAM_DATUM_IS_VALID(datum)) {
		PyErr_SetString(PyExc_ValueError, "invalid crypto_datum_t");
		return NULL;
	}

	result = (py_crypto_datum_t *)PyCryptoDatum_Type.tp_new(&PyCryptoDatum_Type, NULL, NULL);
	if (!result) {
		return NULL;
	}

	ret = dup_crypto_datum(datum, &result->datum, &error);
	if (ret != SCRAM_E_SUCCESS) {
		Py_DECREF(result);
		set_exc_from_scram(ret, &error, "Failed to copy crypto data");
		return NULL;
	}

	return (PyObject *)result;
}
