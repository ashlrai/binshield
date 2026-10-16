# TEST FIXTURE — benign-looking PyPI package with Cython extensions.
# Demonstrates ext_modules and Cython .pyx source files.
from setuptools import setup
from Cython.Build import cythonize

setup(
    name="cython-ext-fixture",
    version="1.0.0",
    ext_modules=cythonize("cython_ext/*.pyx"),
)
