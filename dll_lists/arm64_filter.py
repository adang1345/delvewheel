"""For a given folder, list only the .dll and .drv files that are arm64"""

import os
import pefile

pefile.fast_load = True
folder = r'F:\Windows\System32'
out_filename = r'10-arm64\System32-arm64.txt'

with open(out_filename, 'w') as f:
    for filename in os.listdir(folder):
        if filename.lower().endswith('.dll') or filename.lower().endswith('.drv'):
            with pefile.PE(os.path.join(folder, filename)) as pe:
                if pe.FILE_HEADER.Machine == 0xAA64:
                    f.write(filename)
                    f.write('\n')
