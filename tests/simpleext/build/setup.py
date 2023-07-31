import sys
from setuptools import setup, Extension

if sys.maxsize > 2**32:
    library_dirs = ['simpledll/x64/Release']
else:
    library_dirs = ['simpledll/Release']

n = ''  # change to build different module name

setup(
    name='simpleext',
    version='0.0.1',
    url='https://github.com/adang1345/delvewheel',
    author='Aohan Dang',
    author_email='adang1345@gmail.com',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: Microsoft :: Windows',
    ],
    license='MIT',
    description='Simple extension module',
    platforms='Windows',
    python_requires='==3.10.*',
    zip_safe=False,
    ext_modules=[Extension(
        f'simpleext{n}', [f'simpleext.c'],
        include_dirs=['simpledll'],
        libraries=['simpledll'],
        library_dirs=library_dirs,
        define_macros=[('SIMPLEEXT_INIT', f'PyInit_simpleext{n}'), ('SIMPLEEXT_MODNAME', f'"simpleext{n}"')],
    )]
)
