#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "simpledll.h"

#ifndef SIMPLEEXT_INIT
#define SIMPLEEXT_INIT PyInit_simpleext
#endif
#ifndef SIMPLEEXT_MODNAME
#define SIMPLEEXT_MODNAME "simpleext"
#endif

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
    SIMPLEEXT_MODNAME,
    NULL,
    -1,
    SimpleExtMethods
};

PyMODINIT_FUNC SIMPLEEXT_INIT(void)
{
    return PyModule_Create(&simpleextmodule);
}
