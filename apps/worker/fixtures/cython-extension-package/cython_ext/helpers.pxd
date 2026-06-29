# TEST FIXTURE — Cython header definition file.
cdef extern from "helpers.h":
    void helper_init()
    int helper_compute(int x)
