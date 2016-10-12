#include <Python.h>
#include <stdbool.h>
#if __APPLE__
#include <sys/types.h>
#endif
#include <sys/ptrace.h>

#define UNUSED(arg) arg __attribute__((unused))

char python_ptrace_DOCSTR[] =
"ptrace(command: int, pid: int, arg1=0, arg2=0, check_errno=False): call ptrace syscall.\r\n"
"Raise a ValueError on error.\r\n"
"Returns an unsigned integer.\r\n";

static bool cpython_cptrace(
    unsigned int request,
    pid_t pid,
    void *arg1,
    void *arg2,
    bool check_errno,
    unsigned long *result)
{
    unsigned long ret;
    errno = 0;
    ret = ptrace(request, pid, arg1, arg2);
    if ((long)ret == -1) {
        /**
         * peek operations may returns -1 with errno=0: it's not an error.
         * For other operations, -1 is always an error
         */
        if (!check_errno || errno) {
            PyErr_Format(
                PyExc_ValueError,
                "ptrace(request=%u, pid=%i, %p, %p) "
                "error #%i: %s",
                request, pid, arg1, arg2,
                errno, strerror(errno));
            return false;
        }
    }
    if (result)
        *result = ret;
    return true;
}

static PyObject* cpython_ptrace(PyObject* UNUSED(self), PyObject *args, PyObject *keywds)
{
    unsigned long result;
    unsigned int request;
    pid_t pid;
    unsigned long arg1 = 0;
    unsigned long arg2 = 0;
    bool check_errno = false;
    PyObject* check_errno_p = NULL;
    static char *kwlist[] = {"request", "pid", "arg1", "arg2", "check_errno", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds,
        "Ii|LLO", kwlist,
        &request, &pid, &arg1, &arg2, &check_errno_p
    ))
    {
        return NULL;
    }

    if (check_errno_p) {
        check_errno = PyObject_IsTrue(check_errno_p);
    }

    if (cpython_cptrace(request, pid, (void*)arg1, (void*)arg2, check_errno, &result))
        return PyLong_FromUnsignedLong(result);
    else
        return NULL;
}

static PyMethodDef module_methods[] = {
    {"ptrace", (PyCFunction)cpython_ptrace, METH_VARARGS | METH_KEYWORDS, python_ptrace_DOCSTR},
    {NULL, NULL, 0, NULL}
};

PyDoc_STRVAR(module_doc,
"ptrace module written in C");

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "cptrace",
    module_doc,
    0,
    module_methods,
    NULL
};
#endif

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit_cptrace(void)
#else
initcptrace(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    return PyModule_Create(&module_def);
#else
    (void)Py_InitModule3("cptrace", module_methods, module_doc);
#endif
}

