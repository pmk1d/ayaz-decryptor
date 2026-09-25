#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>
#include <string.h>


static uint32_t load32_le(const unsigned char *data)
{
    return (uint32_t)data[0]
        | ((uint32_t)data[1] << 8)
        | ((uint32_t)data[2] << 16)
        | ((uint32_t)data[3] << 24);
}


static void store32_le(unsigned char *data, uint32_t value)
{
    data[0] = (unsigned char)value;
    data[1] = (unsigned char)(value >> 8);
    data[2] = (unsigned char)(value >> 16);
    data[3] = (unsigned char)(value >> 24);
}


static uint32_t rotate32(uint32_t value, unsigned int shift)
{
    return (value << shift) | (value >> (32 - shift));
}


static void quarter_round(uint32_t x[16], unsigned int a, unsigned int b,
                          unsigned int c, unsigned int d)
{
    x[b] ^= rotate32(x[a] + x[d], 7);
    x[c] ^= rotate32(x[b] + x[a], 9);
    x[d] ^= rotate32(x[c] + x[b], 13);
    x[a] ^= rotate32(x[d] + x[c], 18);
}


static void salsa20_block(const uint32_t state[16], unsigned char output[64])
{
    uint32_t x[16];
    memcpy(x, state, sizeof(x));
    for (unsigned int round = 0; round < 10; ++round) {
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 5, 9, 13, 1);
        quarter_round(x, 10, 14, 2, 6);
        quarter_round(x, 15, 3, 7, 11);
        quarter_round(x, 0, 1, 2, 3);
        quarter_round(x, 5, 6, 7, 4);
        quarter_round(x, 10, 11, 8, 9);
        quarter_round(x, 15, 12, 13, 14);
    }
    for (unsigned int index = 0; index < 16; ++index) {
        store32_le(output + index * 4, x[index] + state[index]);
    }
}


static void salsa20_xor(const unsigned char *data, unsigned char *output,
                        Py_ssize_t length, uint32_t state[16])
{
    unsigned char stream[64];
    Py_ssize_t position = 0;
    while (position < length) {
        Py_ssize_t chunk = length - position;
        if (chunk > 64) {
            chunk = 64;
        }
        salsa20_block(state, stream);
        for (Py_ssize_t index = 0; index < chunk; ++index) {
            output[position + index] = data[position + index] ^ stream[index];
        }
        state[8] += 1;
        if (state[8] == 0) {
            state[9] += 1;
        }
        position += chunk;
    }
}


static PyObject *native_salsa_crypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"data", "state", "block_offset", NULL};
    PyObject *data = NULL;
    PyObject *state_object = NULL;
    PyObject *offset_object = NULL;
    uint64_t offset = 0;
    uint32_t state[16];
    (void)self;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|$O:salsa_crypt", keywords,
                                     &data, &state_object, &offset_object)) {
        return NULL;
    }
    if (!PyBytes_Check(data) || !PyBytes_Check(state_object)) {
        PyErr_SetString(PyExc_TypeError, "data и state должны быть bytes");
        return NULL;
    }
    if (PyBytes_GET_SIZE(state_object) != 64) {
        PyErr_SetString(PyExc_ValueError, "Состояние Salsa20 должно содержать 64 байта");
        return NULL;
    }
    if (offset_object != NULL) {
        if (!PyLong_Check(offset_object)) {
            PyErr_SetString(PyExc_ValueError,
                            "Смещение блока должно быть беззнаковым 64-битным числом");
            return NULL;
        }
        offset = PyLong_AsUnsignedLongLong(offset_object);
        if (PyErr_Occurred()) {
            if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
                PyErr_Clear();
                PyErr_SetString(PyExc_ValueError,
                                "Смещение блока должно быть беззнаковым 64-битным числом");
            }
            return NULL;
        }
    }

    const unsigned char *state_bytes = (const unsigned char *)PyBytes_AS_STRING(state_object);
    for (unsigned int index = 0; index < 16; ++index) {
        state[index] = load32_le(state_bytes + index * 4);
    }
    uint64_t counter = (uint64_t)state[8] | ((uint64_t)state[9] << 32);
    if (offset > UINT64_MAX - counter) {
        PyErr_SetString(PyExc_ValueError, "Переполнение счетчика Salsa20");
        return NULL;
    }
    counter += offset;
    Py_ssize_t length = PyBytes_GET_SIZE(data);
    uint64_t blocks = (uint64_t)(length / 64) + (length % 64 != 0);
    if (blocks != 0 && blocks - 1 > UINT64_MAX - counter) {
        PyErr_SetString(PyExc_ValueError, "Переполнение счетчика Salsa20");
        return NULL;
    }
    state[8] = (uint32_t)counter;
    state[9] = (uint32_t)(counter >> 32);

    PyObject *result = PyBytes_FromStringAndSize(NULL, length);
    if (result == NULL) {
        return NULL;
    }
    const unsigned char *input = (const unsigned char *)PyBytes_AS_STRING(data);
    unsigned char *output = (unsigned char *)PyBytes_AS_STRING(result);
    /* Без GIL читаются только bytes и локальная копия состояния. */
    if (length >= 16384) {
        Py_BEGIN_ALLOW_THREADS
        salsa20_xor(input, output, length, state);
        Py_END_ALLOW_THREADS
    } else {
        salsa20_xor(input, output, length, state);
    }
    return result;
}


PyDoc_STRVAR(salsa_crypt_doc,
             "salsa_crypt(data, state, *, block_offset=0)\n--\n\n"
             "Применяет Salsa20/20 из полного состояния длиной 64 байта.");

static PyMethodDef native_methods[] = {
    {"salsa_crypt", (PyCFunction)(void (*)(void))native_salsa_crypt,
     METH_VARARGS | METH_KEYWORDS, salsa_crypt_doc},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "Необязательное ускорение Salsa20 для восстановления файлов.",
    -1,
    native_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC PyInit__native(void)
{
    return PyModule_Create(&native_module);
}
