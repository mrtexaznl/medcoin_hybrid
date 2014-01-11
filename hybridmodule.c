#include <Python.h>

#include "hybrid.h"

static PyObject *hybrid_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
    PyStringObject *input;
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);

    hybridScryptHash256((char *)PyString_AsString((PyObject*) input), output);

    Py_DECREF(input);
    value = Py_BuildValue("s#", output, 32);
    PyMem_Free(output);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "getPoWHash", hybrid_getpowhash, METH_VARARGS, "Returns the proof of work hash using HybridScriptHash256" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initmedcoin_hybrid(void) {
    (void) Py_InitModule("medcoin_hybrid", ScryptMethods);
}
