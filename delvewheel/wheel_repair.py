"""Functions for repairing a wheel."""

import ast
import base64
import hashlib
import os
import pprint
import random
import shutil
import tempfile
import typing
import zipfile
from . import patch_dll
from . import dll_list


# Template for patching __init__.py so that the vendored-in DLLs are loaded at
# runtime. An empty triple-quoted string is placed at the beginning so that the
# comment "start delvewheel patch" does not show up when the built-in help
# system help() is invoked on the package.
_patch_init_template = """

\"\"\"\"\"\"  # start delvewheel patch
def _delvewheel_init_patch_{0}():
    import os
    import sys
    libs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), {1!r}))
    if sys.version_info[:2] >= (3, 8):
        os.add_dll_directory(libs_dir)
    else:
        from ctypes import WinDLL
        for lib in os.listdir(libs_dir):
            WinDLL(os.path.join(libs_dir, lib))


_delvewheel_init_patch_{0}()
del _delvewheel_init_patch_{0}
# end delvewheel patch

"""

pp = pprint.PrettyPrinter(indent=4)


class WheelRepair:
    """An instance represents a wheel that can be repaired."""

    def __init__(self,
                 whl_path: str,
                 extract_dir: typing.Optional[str] = None,
                 add_dlls: typing.Optional[set[str]] = None,
                 no_dlls: typing.Optional[set[str]] = None,
                 verbose: int = 0) -> None:
        """Initialize a wheel repair object.
        whl_path: Path to the wheel to repair
        extract_dir: Directory where intermediate files are created in the
            process of repairing the wheel. If None, a temporary directory is
            created.
        dest_dir: Directory to place the repaired wheel. If None, it defaults to
            wheelhouse, relative to the current working directory.
        add_dlls: Set of lowercase DLL names to force inclusion into the wheel
        no_dlls: Set of lowercase DLL names to force exclusion from wheel
            (cannot overlap with add_dlls)
        no_mangles: Set of lowercase DLL names not to mangle
        verbose: verbosity level, 0 to 3"""
        if not os.path.isfile(whl_path):
            raise FileNotFoundError(f'{whl_path} not found')
        self._whl_path = whl_path
        self._whl_name = os.path.basename(whl_path)
        if extract_dir is None:
            # need to assign temp directory object to an attribute to prevent it
            # from being destructed
            self._extract_dir_obj = tempfile.TemporaryDirectory()
            self._extract_dir = self._extract_dir_obj.name
        else:
            self._extract_dir_obj = None
            self._extract_dir = extract_dir
        self._add_dlls = set() if add_dlls is None else add_dlls
        self._no_dlls = set() if no_dlls is None else no_dlls
        self._verbose = verbose

    @staticmethod
    def _rehash(file_path: str) -> tuple[str, int]:
        """Return (hash, size) for a file with path file_path. The hash and size
        are used by pip to verify the integrity of the contents of a wheel."""
        with open(file_path, 'rb') as file:
            contents = file.read()
            hash = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode('latin1').rstrip('=')
            size = len(contents)
            return hash, size

    @staticmethod
    def _hashfile(afile: typing.BinaryIO, blocksize: int = 65536, length: int = 8) -> str:
        """Hash the contents of an open file handle with SHA256. Return the
        first length characters of the hash."""
        hasher = hashlib.sha256()
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        return hasher.hexdigest()[:length]

    def show(self) -> None:
        """Show the dependencies that the wheel has."""
        print(f'Analyzing {self._whl_name}\n')

        # extract wheel
        try:
            shutil.rmtree(self._extract_dir)
        except FileNotFoundError:
            pass
        os.makedirs(self._extract_dir)
        if self._verbose >= 1:
            print(f'extracting {self._whl_name} to {self._extract_dir}')
        with zipfile.ZipFile(self._whl_path) as whl_file:
            whl_file.extractall(self._extract_dir)

        # find dependencies
        dependency_paths = set()
        ignored_dll_names = set()
        not_found_dll_names = set()
        extension_module_paths = []
        for root, _, filenames in os.walk(self._extract_dir):
            for filename in filenames:
                if filename.endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    extension_module_paths.append(extension_module_path)
                    discovered, ignored, not_found = patch_dll.get_all_needed(extension_module_path, self._add_dlls, self._no_dlls, 'ignore')
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored
                    not_found_dll_names |= not_found

        dependency_paths = list(dependency_paths)
        dependency_paths.sort()
        print('The following dependent DLLs will be copied into the wheel.')
        if dependency_paths:
            for dependency_path in dependency_paths:
                print(f'    {os.path.basename(dependency_path)} ({dependency_path})')
            for not_found_dll_name in not_found_dll_names:
                print(f'    {not_found_dll_name} (Error: Not Found)')
        else:
            print('    None')

        ignored_dll_names = list(ignored_dll_names)
        ignored_dll_names.sort()
        print('\nThe following dependent DLLs will not be copied into the wheel.')
        if ignored_dll_names:
            for ignored_dll_name in ignored_dll_names:
                print(f'    {ignored_dll_name}')
        else:
            print('    None')
        if not_found_dll_names:
            print('\nWarning: At least one dependent DLL needs to be copied into the wheel but was not found.\n\n')

    def repair(self, target: str, no_mangles: set, lib_sdir: str) -> None:
        """Repair the wheel in a manner similar to auditwheel.
        target is the target directory for storing the repaired wheel
        no_mangles is a set of lowercase DLL names that will not be mangled"""
        print(f'repairing {self._whl_path}')

        # extract wheel
        try:
            shutil.rmtree(self._extract_dir)
        except FileNotFoundError:
            pass
        os.makedirs(self._extract_dir)
        if self._verbose >= 1:
            print(f'extracting {self._whl_name} to {self._extract_dir}')
        with zipfile.ZipFile(self._whl_path) as whl_file:
            whl_file.extractall(self._extract_dir)

        # find dependencies and copy them into wheel
        print('finding DLL dependencies')
        dependency_paths = set()
        ignored_dll_names = set()
        extension_module_paths = []
        for root, _, filenames in os.walk(self._extract_dir):
            for filename in filenames:
                if filename.lower().endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    extension_module_paths.append(extension_module_path)
                    discovered, ignored = patch_dll.get_all_needed(extension_module_path, self._add_dlls, self._no_dlls)[:2]
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored
        if not dependency_paths:
            print('no external dependencies are needed')
            return
        if self._verbose >= 1:
            print(f'External dependencies to copy into the wheel are\n{pp.pformat(set(os.path.basename(p) for p in dependency_paths))}')
            print(f'External dependencies not to copy into the wheel are\n{pp.pformat(ignored_dll_names)}')
        distribution_name = self._whl_name[:self._whl_name.index('-')]
        libs_dir = os.path.join(self._extract_dir, distribution_name, lib_sdir)
        os.makedirs(libs_dir, exist_ok=True)
        if os.listdir(libs_dir):
            raise FileExistsError(f'The {os.path.join(distribution_name, lib_sdir)} directory already exists and is nonempty')
        print(f'copying DLLs into {os.path.join(distribution_name, lib_sdir)}')
        for dependency_path in dependency_paths:
            if self._verbose >= 1:
                print(f'copying {dependency_path} -> {os.path.join(libs_dir, os.path.basename(dependency_path))}')
            shutil.copy2(dependency_path, libs_dir)

        # mangle library names
        print('mangling DLL names')
        name_mangler = {}  # dict from old name to new name
        for lib_name in os.listdir(libs_dir):
            if not any(lib_name.startswith(prefix) for prefix in dll_list.no_mangle_prefixes) and \
                    lib_name not in no_mangles:
                root, ext = os.path.splitext(lib_name)
                with open(os.path.join(libs_dir, lib_name), 'rb') as lib_file:
                    root = f'{root}-{self._hashfile(lib_file)}'
                name_mangler[lib_name] = root + ext
        for extension_module_path in extension_module_paths:
            extension_module_name = os.path.basename(extension_module_path)
            if self._verbose >= 1:
                print(f'repairing {extension_module_name} -> {extension_module_name}')
            needed = patch_dll.get_direct_mangleable_needed(extension_module_path, self._no_dlls, no_mangles)
            patch_dll.replace_needed(extension_module_path, needed, name_mangler)
        for lib_name in os.listdir(libs_dir):
            if self._verbose >= 1:
                if lib_name in name_mangler:
                    print(f'repairing {lib_name} -> {name_mangler[lib_name]}')
                else:
                    print(f'repairing {lib_name} -> {lib_name}')
            lib_path = os.path.join(libs_dir, lib_name)
            needed = patch_dll.get_direct_mangleable_needed(lib_path, self._no_dlls, no_mangles)
            patch_dll.replace_needed(lib_path, needed, name_mangler)
            if lib_name in name_mangler:
                os.rename(lib_path, os.path.join(libs_dir, name_mangler[lib_name]))

        # create or patch __init__.py to load dependent DLLs
        print(f'patching {os.path.join(distribution_name, "__init__.py")}')
        init_path = os.path.join(self._extract_dir, distribution_name, '__init__.py')
        open(init_path, 'a+').close()
        with open(init_path) as file:
            init_contents = file.read()
        node = ast.parse(init_contents)
        docstring = ast.get_docstring(node)

        rand_num = random.randint(10**10, 10**11-1)
        patch_init_contents = _patch_init_template.format(rand_num, lib_sdir)

        if docstring is None:
            # prepend patch
            with open(init_path, 'w') as file:
                file.write(patch_init_contents)
                file.write(init_contents)
        else:
            # insert patch after docstring
            children = list(ast.iter_child_nodes(node))
            if len(children) == 0 or not isinstance(children[0], ast.Expr) or \
                    not isinstance(children[0].value, ast.Constant) or \
                    children[0].value.value != docstring:
                raise ValueError('Error parsing __init__.py: docstring exists but is not the first element of the parse tree')
            elif len(children) == 1:
                with open(init_path, 'a') as file:
                    file.write(patch_init_contents)
            else:
                if not init_contents.lstrip().startswith('"""'):
                    raise ValueError('Error parsing __init__.py: docstring exists but is not a triple-quoted string at the start of the file')
                docstring_start_index = init_contents.index('"""')
                docstring_end_index = init_contents.find('"""', docstring_start_index + 1) + 3
                if docstring_end_index == -1:
                    raise ValueError('Error parsing __init__.py: docstring exists but does not end with triple quotes')
                docstring_end_line = init_contents.find('\n', docstring_end_index)
                if docstring_end_line == -1:
                    docstring_end_line = len(init_contents)
                extra_text = init_contents[docstring_end_index: docstring_end_line]
                if extra_text and not extra_text.isspace():
                    raise ValueError(f'Error parsing __init__.py: extra text {extra_text!r} is on the line where the docstring ends')
                with open(init_path, 'w') as file:
                    file.write(init_contents[:docstring_end_index])
                    file.write('\n')
                    file.write(patch_init_contents)
                    file.write(init_contents[docstring_end_index:])

        # update record file, which tracks wheel contents and their checksums
        dist_info_foldername = '-'.join(self._whl_name.split('-')[:2]) + '.dist-info'
        record_filepath = os.path.join(self._extract_dir, dist_info_foldername, 'RECORD')
        print(f'updating {os.path.join(dist_info_foldername, "RECORD")}')
        filepath_list = []
        for root, _, files in os.walk(self._extract_dir):
            for file in files:
                filepath_list.append(os.path.join(root, file))
        with open(record_filepath, 'w') as record_file:
            for file_path in filepath_list:
                if file_path == record_filepath:
                    record_file.write(os.path.relpath(record_filepath, self._extract_dir).replace('\\', '/'))
                    record_file.write(',,\n')
                else:
                    record_line = '{},sha256={},{}\n'.format(os.path.relpath(file_path, self._extract_dir).replace('\\', '/'), *self._rehash(file_path))
                    record_file.write(record_line)

        # repackage wheel
        print('repackaging wheel')
        os.makedirs(target, exist_ok=True)
        whl_dest_path = os.path.join(target, self._whl_name)
        with zipfile.ZipFile(whl_dest_path, 'w', zipfile.ZIP_DEFLATED) as whl_file:
            for file_path in filepath_list:
                relpath = os.path.relpath(file_path, self._extract_dir)
                if self._verbose >= 1:
                    print(f'adding {relpath}')
                whl_file.write(file_path, relpath)
        print(f'fixed wheel written to {os.path.abspath(whl_dest_path)}\n')
