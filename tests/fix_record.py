"""Given the path to a wheel, fix the RECORD file. This is useful when a wheel
is modified manually for testing purposes."""

import base64
import hashlib
import os
import sys
import tempfile
import typing
import zipfile


def _rehash(file_path: str) -> typing.Tuple[str, int]:
    """Return (hash, size) for a file with path file_path. The hash and size
    are used by pip to verify the integrity of the contents of a wheel."""
    with open(file_path, 'rb') as file:
        contents = file.read()
        hash = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode('latin1').rstrip('=')
        size = len(contents)
        return hash, size


# extract wheel to temp directory
whl_path = sys.argv[1]
whl_name = os.path.basename(whl_path)
td = tempfile.TemporaryDirectory()
extract_dir = td.name
with zipfile.ZipFile(sys.argv[1]) as whl_file:
    whl_file.extractall(extract_dir)

# fix the RECORD file
dist_info_foldername = '-'.join(whl_name.split('-')[:2]) + '.dist-info'
record_filepath = os.path.join(extract_dir, dist_info_foldername, 'RECORD')
filepath_list = []
for root, _, files in os.walk(extract_dir):
    for file in files:
        filepath_list.append(os.path.join(root, file))
with open(record_filepath, 'w') as record_file:
    for file_path in filepath_list:
        if file_path == record_filepath:
            record_file.write(os.path.relpath(record_filepath, extract_dir).replace('\\', '/'))
            record_file.write(',,\n')
        else:
            record_line = '{},sha256={},{}\n'.format(os.path.relpath(file_path, extract_dir).replace('\\', '/'), *_rehash(file_path))
            record_file.write(record_line)

# repackage wheel
with zipfile.ZipFile(whl_path, 'w', zipfile.ZIP_DEFLATED) as whl_file:
    for file_path in filepath_list:
        relpath = os.path.relpath(file_path, extract_dir)
        whl_file.write(file_path, relpath)
