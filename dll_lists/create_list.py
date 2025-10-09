"""For a given folder, find the .dll and .drv files that match the given
architecture and contain an export directory table. Write the list to an
output file."""

import os
import pefile
import sys

pefile.fast_load = True
source_folder = sys.argv[1]
out_filename = sys.argv[2]
arch = sys.argv[3]

if arch  == 'x86':
    machine = 0x14C
elif arch == 'x64':
    machine = 0x8664
elif arch == 'arm64':
    machine = 0xAA64
else:
    raise ValueError('Invalid architecture ' + arch)

with open(out_filename, 'w') as f:
    for filename in os.listdir(source_folder):
        filename_lower = filename.lower()
        if filename_lower.endswith('.dll') or filename_lower.endswith('.drv'):
            try:
                with pefile.PE(os.path.join(source_folder, filename)) as pe:
                    pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.FILE_HEADER.Machine == machine:
                        f.write(filename)
                        f.write('\n')
            except pefile.PEFormatError:
                print('Invalid PE file ' + filename)
