"""Functions for repairing a wheel."""

import ast
import base64
import hashlib
import itertools
import os
import pprint
import shutil
import tempfile
import typing
import zipfile
from . import patch_dll
from . import dll_list
from . import version


# Template for patching __init__.py so that the vendored DLLs are loaded at
# runtime. An empty triple-quoted string is placed at the beginning so that the
# comment "start delvewheel patch" does not show up when the built-in help
# system help() is invoked on the package. For Python >=3.8, we use the
# os.add_dll_directory() function so that the folder containing the vendored
# DLLs is added to the DLL search path. For Python 3.7 or lower, this function
# is unavailable, so we preload the DLLs. Whenever Python needs a vendored DLL,
# it will use the already-loaded DLL instead of searching for it.
#
# To use the template, call str.format(), passing in an identifying string, the
# name of the directory containing the vendored DLLs, and the name of the file
# containing the DLL load order.
_patch_init_template = """

""\"""\"  # start delvewheel patch
def _delvewheel_init_patch_{0}():
    import os
    import sys
    libs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, {1!r}))
    if sys.version_info[:2] >= (3, 8):
        os.add_dll_directory(libs_dir)
    else:
        from ctypes import WinDLL
        with open(os.path.join(libs_dir, {2!r})) as file:
            load_order = file.read().split()
        for lib in load_order:
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
                 add_dlls: typing.Optional[typing.Set[str]] = None,
                 no_dlls: typing.Optional[typing.Set[str]] = None,
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
        if not self._whl_name.endswith('.whl'):
            raise ValueError(f'{self._whl_name} is not a valid wheel name')
        whl_name_split = os.path.splitext(self._whl_name)[0].split('-')
        if len(whl_name_split) not in (5, 6):
            raise ValueError(f'{self._whl_name} is not a valid wheel name')
        self._distribution_name = whl_name_split[0]
        self._version = whl_name_split[1]

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

        # Modify self._no_dlls to include those that are already part of every
        # Python distribution the wheel targets.
        abi_tags = whl_name_split[-2].split('.')
        platform_tags = whl_name_split[-1].split('.')
        ignore_by_distribution = set().union(*dll_list.ignore_by_distribution.values())
        for abi_platform in itertools.product(abi_tags, platform_tags):
            abi_platform = '-'.join(abi_platform)
            if abi_platform in dll_list.ignore_by_distribution:
                ignore_by_distribution &= dll_list.ignore_by_distribution[abi_platform]
            else:
                ignore_by_distribution = set()
                break
        self._no_dlls |= ignore_by_distribution

        self._verbose = verbose

    @staticmethod
    def _rehash(file_path: str) -> typing.Tuple[str, int]:
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

    def _patch_init(self, init_path: str, libs_dir: str, load_order_filename: str) -> None:
        """Given the path to __init__.py, create or patch the file so that
        vendored-in DLLs can be loaded at runtime. The patch is placed at the
        topmost location after the docstring (if any) and any
        "from __future__ import" statements.
        libs_dir is the name of the directory where DLLs are stored."""
        print(f'patching {os.path.relpath(init_path, self._extract_dir)}')

        patch_init_contents = _patch_init_template.format(version.__version__.replace('.', '_'), libs_dir, load_order_filename)

        open(init_path, 'a+').close()
        with open(init_path) as file:
            init_contents = file.read()
        node = ast.parse(init_contents)
        docstring = ast.get_docstring(node, False)
        children = list(ast.iter_child_nodes(node))
        for child in reversed(children):
            if isinstance(child, ast.ImportFrom) and child.module == '__future__':
                future_import_lineno = child.lineno
                break
        else:
            future_import_lineno = 0  # no "from __future__ import" statement found

        if future_import_lineno > 0:
            init_contents_split = init_contents.splitlines(True)
            with open(init_path, 'w') as file:
                file.write(''.join(init_contents_split[:future_import_lineno]))
                file.write('\n')
                file.write(patch_init_contents)
                file.write(''.join(init_contents_split[future_import_lineno:]))
        elif docstring is None:
            # prepend patch
            with open(init_path, 'w') as file:
                file.write(patch_init_contents)
                file.write(init_contents)
        else:
            # insert patch after docstring
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

        # verify that __init__.py can be parsed properly
        with open(init_path) as file:
            try:
                ast.parse(file.read())
            except SyntaxError:
                raise ValueError('Error parsing __init__.py: Patch failed. This might occur if a node is split across multiple lines.')

    def _is_top_level_ext_module(self, path: str) -> bool:
        """Return True if `path` refers to a top-level extension module. That
        is, when the wheel is installed, the module is placed directly into the
        site-packages directory and not inside a package. Otherwise, return
        False.

        Precondition: path must end with .pyd"""
        top_level_dirs = [
            self._extract_dir,
            os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data', 'purelib'),
            os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data', 'platlib'),
        ]
        return any(os.path.samefile(os.path.dirname(path), p) for p in top_level_dirs if os.path.isdir(p))

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

    def repair(self, target: str, no_mangles: set, no_mangle_all: bool, lib_sdir: str) -> None:
        """Repair the wheel in a manner similar to auditwheel.
        target is the target directory for storing the repaired wheel
        no_mangles is a set of lowercase DLL names that will not be mangled
        no_mangle_all is True if no DLL name mangling should happen at all
        lib_sdir is the suffix for the directory to store the DLLs"""
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
        has_top_level_ext_module = False
        for root, _, filenames in os.walk(self._extract_dir):
            for filename in filenames:
                if filename.lower().endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    if self._is_top_level_ext_module(extension_module_path):
                        if self._verbose >= 1:
                            print(f'analyzing top-level extension module {os.path.relpath(extension_module_path, self._extract_dir)}')
                        has_top_level_ext_module = True
                    elif self._verbose >= 1:
                        print(f'analyzing package-level extension module {os.path.relpath(extension_module_path, self._extract_dir)}')
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
        if has_top_level_ext_module:
            # Extension module is top-level, so we cannot use __init__.py to
            # insert the DLL search path at runtime. In this case, DLLs are
            # instead copied into the platlib folder, whose contents are
            # installed directly into site-packages during installation.
            libs_dir_name = '.'
            libs_dir = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data', 'platlib')
        else:
            libs_dir_name = self._distribution_name + lib_sdir
            libs_dir = os.path.join(self._extract_dir, libs_dir_name)
        os.makedirs(libs_dir, exist_ok=True)
        print(f'copying DLLs into {os.path.relpath(libs_dir, self._extract_dir)}')
        for dependency_path in dependency_paths:
            if self._verbose >= 1:
                print(f'copying {dependency_path} -> {os.path.join(libs_dir, os.path.basename(dependency_path))}')
            shutil.copy2(dependency_path, libs_dir)

        # mangle library names
        dependency_names = {os.path.basename(p) for p in dependency_paths}
        name_mangler = {}  # dict from old name to new name
        if no_mangle_all:
            print('skip mangling DLL names')
        else:
            print('mangling DLL names')
            for lib_name in dependency_names:
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
            for lib_name in dependency_names:
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

        # Perform topological sort to determine the order that DLLs must be
        # loaded at runtime. We first construct a directed graph where the
        # vertices are the vendored DLLs and an edge represents a "depends-on"
        # relationship. We perform a topological sort of this graph. The reverse
        # of this topological sort then tells us what order we need to load the
        # DLLs so that all dependencies of a DLL are loaded before that DLL is
        # loaded.
        print('calculating DLL load order')
        for dependency_name in dependency_names.copy():
            if dependency_name in name_mangler:
                dependency_names.remove(dependency_name)
                dependency_names.add(name_mangler[dependency_name])
        graph = {}  # map each DLL to a set of its vendored direct dependencies
        for dll_name in dependency_names:
            dll_path = os.path.join(libs_dir, dll_name)
            # In this context, delay-loaded DLL dependencies are not true
            # dependencies because they are not necessary to get the DLL to load
            # initially. More importantly, we may get circular dependencies if
            # were were to consider delay-loaded DLLs as true dependencies.
            # For example, concrt140.dll lists msvcp140.dll in its import table,
            # while msvcp140.dll lists concrt140.dll in its delay import table.
            graph[dll_name] = patch_dll.get_direct_needed(dll_path, False) & dependency_names
        rev_dll_load_order = []
        no_incoming_edge = {dll_name for dll_name in dependency_names if not any(dll_name in value for value in graph.values())}
        while no_incoming_edge:
            dll_name = no_incoming_edge.pop()
            rev_dll_load_order.append(dll_name)
            while graph[dll_name]:
                dependent_dll_name = graph[dll_name].pop()
                if not any(dependent_dll_name in value for value in graph.values()):
                    no_incoming_edge.add(dependent_dll_name)
        if any(graph.values()):
            graph_leftover = {k: v for k, v in graph.items() if v}
            raise RuntimeError(f'Dependent DLLs have a circular dependency: {graph_leftover}')
        load_order_filename = f'.load-order-{self._distribution_name}-{self._version}'
        load_order_filepath = os.path.join(libs_dir, load_order_filename)
        if os.path.exists(load_order_filepath):
            raise FileExistsError(f'{os.path.relpath(load_order_filepath, self._extract_dir)} already exists')
        with open(os.path.join(libs_dir, load_order_filename), 'w') as file:
            file.write('\n'.join(reversed(rev_dll_load_order)))
            file.write('\n')

        # create or patch top-level __init__.py in each package to load
        # dependent DLLs from correct location at runtime
        for item in os.listdir(self._extract_dir):
            if os.path.isdir(os.path.join(self._extract_dir, item)) and \
                    item != f'{self._distribution_name}-{self._version}.dist-info' and \
                    item != f'{self._distribution_name}-{self._version}.data' and \
                    item != libs_dir_name:
                self._patch_init(os.path.join(self._extract_dir, item, '__init__.py'), libs_dir_name, load_order_filename)
        for extra_dir_name in ('purelib', 'platlib'):
            extra_dir = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data', extra_dir_name)
            if os.path.isdir(extra_dir):
                for item in os.listdir(extra_dir):
                    if os.path.isdir(os.path.join(extra_dir, item)):
                        self._patch_init(os.path.join(extra_dir, item, '__init__.py'), libs_dir_name, load_order_filename)

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
