#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "simpledll.h"

static PyObject *simpleext_helloworld(PyObject *self, PyObject *args)
{
   helloworld();
   Py_RETURN_NONE;
}

static PyMethodDef SimpleExtMethods[] = {
    {"helloworld", simpleext_helloworld, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef simpleextmodule = {
    PyModuleDef_HEAD_INIT,
    "simpleext",
    NULL,
    -1,
    SimpleExtMethods
};

PyMODINIT_FUNC PyInit_simpleext(void)
{
    return PyModule_Create(&simpleextmodule);
}
