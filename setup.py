from setuptools import setup
from Cython.Build import cythonize

#cython: language_level=3

setup(
    name='Zero-knowledge memory',
    ext_modules=cythonize("cython_bdhash.pyx"),
    zip_safe=False,
)