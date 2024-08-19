import sys
from setuptools import setup, Extension

n = ''  # change to build different module name
py_limited_api = False  # set to True and add --py-limited-api=cp3__ to command line to build with Python limited API
dependent_load_flag = '0'  # change to set a different /DEPENDENTLOADFLAG linker option
header_checksum = False  # change to True to set the PE header checksum

if sys.maxsize > 2**32:
    library_dirs = ['simpledll/x64/Release']
else:
    library_dirs = ['simpledll/Release']

py_major, py_minor = sys.version_info[:2]
if n:
    define_macros = [('SIMPLEEXT_INIT', f'PyInit_simpleext{n}'), ('SIMPLEEXT_MODNAME', f'"simpleext{n}"')]
else:
    define_macros = []
if py_limited_api:
    define_macros.append(('Py_LIMITED_API', f'0x{py_major:02X}{py_minor:02X}0000'))
    python_requires = f">={py_major}.{py_minor}"
else:
    python_requires = f"=={py_major}.{py_minor}.*"
extra_link_args = [f'/DEPENDENTLOADFLAG:{dependent_load_flag}']
if header_checksum:
    extra_link_args.append('/RELEASE')

setup(
    name='simpleext',
    version='0.0.1',
    url='https://github.com/adang1345/delvewheel',
    author='Aohan Dang',
    author_email='adang1345@gmail.com',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: Microsoft :: Windows',
    ],
    license='MIT',
    description='Simple extension module',
    platforms='Windows',
    python_requires=python_requires,
    zip_safe=False,
    ext_modules=[Extension(
        f'simpleext{n}', [f'simpleext.c'],
        include_dirs=['simpledll'],
        extra_link_args=extra_link_args,
        libraries=['simpledll'],
        library_dirs=library_dirs,
        define_macros=define_macros,
        py_limited_api=py_limited_api,
    )]
)
