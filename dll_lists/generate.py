import os
import sys

if len(sys.argv) < 2 or sys.argv[1] not in ('x86', 'x64', 'arm64'):
    raise ValueError('must specify 32 or 64 as first argument')
if sys.argv[1] == 'x86':
    input_filename = 'SysWOW64.txt'
    output_varname = 'ignore_names_x86'
elif sys.argv[1] == 'x64':
    input_filename = 'System32.txt'
    output_varname = 'ignore_names_x64'
else:
    input_filename = 'System32-arm64.txt'
    output_varname = 'ignore_names_arm64'

dll_sets = []
for folder in os.listdir('.'):
    if not os.path.isdir(folder):
        continue
    filepath = os.path.join(folder, input_filename)
    if not os.path.isfile(filepath):
        continue
    with open(filepath) as f:
        print(f'Reading {filepath}')
        dll_sets.append(set(x.lower() for x in f.read().split()))
dll_intersection = set.intersection(*dll_sets)

with open(f'{output_varname}.txt', 'w') as f:
    f.write(f'{output_varname} = {{\n')
    for dll in sorted(dll_intersection):
        f.write(f'    {dll!r},\n')
    f.write('}\n')

print(f'{len(dll_intersection)} DLLs will be ignored')
