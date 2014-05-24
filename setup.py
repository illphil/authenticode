import os

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

libs = ["crypto"]
if os.name == "nt":
    libs.append("gdi32")

setup(
    version='0.1',
    description='PE Authenticode verification package',
    name='authenticode',
    author='illphil',
    cmdclass = {'build_ext': build_ext},
    ext_modules = [Extension(
        "authenticode._authenticode",
        libraries=libs,
        sources=["src/authenticode.pyx", "src/osslsigncode.c", "src/osslsigncode_ex.c"])
    ],
)
