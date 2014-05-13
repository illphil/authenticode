from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    version='0.1',
    description='PE Authenticode verification package',
    name='authenticode',
    author='illphil',
    email_address='phil@ruxcon.org.au',
    install_requires=[ 'pefile' ],
    packages=['authenticode'],
    cmdclass = {'build_ext': build_ext},
    ext_modules = [Extension(
        "authenticode._authenticode",
        libraries=["crypto"],
        sources=["src/authenticode.pyx", "src/osslsigncode.c", "src/osslsigncode_ex.c"])
    ]
)
