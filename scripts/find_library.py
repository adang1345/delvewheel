"""Find all instances of a given DLL in PATH and output information about
each."""

import os
import pefile

dll_name = 'msvcp140.dll'

for d in os.environ['PATH'].split(os.pathsep):
    if os.path.isfile(path := os.path.join(d, dll_name)):
        print(path, end=': ')
        with pefile.PE(path) as pe:
            print((pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion))
