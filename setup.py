from setuptools import setup
from Cython.Build import cythonize

#cython: language_level=3str

setup(
    name='Zero-knowledge memory',
    ext_modules=cythonize('cython_bidirectional_hashes.pyx', language_level='3str'),
    zip_safe=False,
)
