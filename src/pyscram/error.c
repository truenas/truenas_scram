// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pyscram.h"

/* Forward declaration of module definition from truenas_pyscram.c */
extern PyModuleDef truenas_pyscram_module;


static const struct {
	scram_resp_t code;
	const char *name;
} scram_error_table[] = {
	{ SCRAM_E_SUCCESS, "SCRAM_E_SUCCESS" },
	{ SCRAM_E_INVALID_REQUEST, "SCRAM_E_INVALID_REQUEST" },
	{ SCRAM_E_MEMORY_ERROR, "SCRAM_E_MEMORY_ERROR" },
	{ SCRAM_E_CRYPTO_ERROR, "SCRAM_E_CRYPTO_ERROR" },
	{ SCRAM_E_BASE64_ERROR, "SCRAM_E_BASE64_ERROR" },
	{ SCRAM_E_PARSE_ERROR, "SCRAM_E_PARSE_ERROR" },
	{ SCRAM_E_FORMAT_ERROR, "SCRAM_E_FORMAT_ERROR" },
	{ SCRAM_E_AUTH_FAILED, "SCRAM_E_AUTH_FAILED" },
	{ SCRAM_E_FAULT, "SCRAM_E_FAULT" },
};

_Static_assert(
	SCRAM_E_LAST == SCRAM_E_FAULT,
	"Error lookup table needs updating - last enum value changed"
);

const char *scram_error_code_to_string(scram_resp_t code)
{
	for (size_t i = 0; i < sizeof(scram_error_table) / sizeof(scram_error_table[0]); i++) {
		if (scram_error_table[i].code == code) {
			return scram_error_table[i].name;
		}
	}
	return "UNKNOWN_ERROR";
}

PyObject *
create_errorcode_dict(void)
{
	PyObject *errorcode_dict = PyDict_New();
	if (!errorcode_dict) {
		return NULL;
	}

	for (size_t i = 0; i < sizeof(scram_error_table) / sizeof(scram_error_table[0]); i++) {
		PyObject *code_obj = PyLong_FromLong(scram_error_table[i].code);
		PyObject *name_obj = PyUnicode_FromString(scram_error_table[i].name);

		if (!code_obj || !name_obj) {
			Py_XDECREF(code_obj);
			Py_XDECREF(name_obj);
			Py_DECREF(errorcode_dict);
			return NULL;
		}

		if (PyDict_SetItem(errorcode_dict, code_obj, name_obj) < 0) {
			Py_DECREF(code_obj);
			Py_DECREF(name_obj);
			Py_DECREF(errorcode_dict);
			return NULL;
		}

		Py_DECREF(code_obj);
		Py_DECREF(name_obj);
	}

	return errorcode_dict;
}

PyObject *
setup_scram_exception(void)
{
	PyObject *scram_error = PyErr_NewException(MODULE_NAME ".ScramError", PyExc_RuntimeError, NULL);
	return scram_error;
}

void
set_exc_from_scram(scram_resp_t code, scram_error_t *scram_err, const char *additional_info)
{
	PyObject *exc_args;
	PyObject *message_obj;
	const char *error_str;
	PyObject *scram_error_type;

	/* Get the module and extract the exception type from module state */
	PyObject *module = PyState_FindModule(&truenas_pyscram_module);
	if (module == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "SCRAM module not found");
		return;
	}

	tnscram_module_state_t *state = (tnscram_module_state_t *)PyModule_GetState(module);
	if (state == NULL || state->scram_error == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "SCRAM error type not initialized");
		return;
	}

	scram_error_type = state->scram_error;

	error_str = scram_error_code_to_string(code);

	if (scram_err != NULL && scram_err->message[0] != '\0') {
		if (additional_info != NULL) {
			message_obj = PyUnicode_FromFormat("%s: %s (%s)",
							   error_str, scram_err->message, additional_info);
		} else {
			message_obj = PyUnicode_FromFormat("%s: %s", error_str, scram_err->message);
		}
	} else {
		if (additional_info != NULL) {
			message_obj = PyUnicode_FromFormat("%s (%s)", error_str, additional_info);
		} else {
			message_obj = PyUnicode_FromString(error_str);
		}
	}

	if (message_obj == NULL) {
		return;
	}

	/* Create the exception instance */
	exc_args = PyTuple_Pack(1, message_obj);
	if (exc_args == NULL) {
		Py_DECREF(message_obj);
		return;
	}

	PyObject *exc_instance = PyObject_CallObject(scram_error_type, exc_args);
	if (exc_instance == NULL) {
		Py_DECREF(exc_args);
		Py_DECREF(message_obj);
		return;
	}

	/* Set custom attributes on the exception instance */
	PyObject *code_obj = PyLong_FromLong(code);
	if (code_obj != NULL) {
		PyObject_SetAttrString(exc_instance, "code", code_obj);
		Py_DECREF(code_obj);
	}

	/* Set the exception */
	PyErr_SetObject(scram_error_type, exc_instance);

	Py_DECREF(exc_instance);
	Py_DECREF(exc_args);
	Py_DECREF(message_obj);
}
