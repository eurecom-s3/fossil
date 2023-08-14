from setuptools import setup
from Cython.Build import cythonize

#cython: language_level=3str

setup(
    name='Zero-knowledge memory',
    ext_modules=cythonize("cython_bdhash.pyx", language_level="3str"),
    zip_safe=False,
)
