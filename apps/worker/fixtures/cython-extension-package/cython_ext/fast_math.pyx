# TEST FIXTURE — Cython extension with FFI patterns for testing detection.
# cython: language_level=3

from libc.stdlib cimport malloc, free
cdef extern from "math.h":
    double sqrt(double x)

def fast_sqrt(double x):
    return sqrt(x)

# Suspicious: direct system call via libc
cdef extern from "stdlib.h":
    int system(const char* command)

def dangerous_call(cmd):
    import ctypes
    lib = ctypes.CDLL("libm.so.6")
    return lib.sqrt(cmd)
