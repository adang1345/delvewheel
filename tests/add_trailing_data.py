"""Usage: python add_trailing_data.py OLD_DLL_PATH NEW_DLL_PATH

Add trailing data to a DLL."""

import shutil
import sys

with open(shutil.copy2(sys.argv[1], sys.argv[2]), 'ab') as f:
    f.write(b'extra data')
