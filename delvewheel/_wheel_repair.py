"""Functions for repairing a wheel."""

import ast
import base64
import hashlib
import itertools
import os
import pathlib
import pprint
import re
import shutil
import sys
import tempfile
import typing
import zipfile
from . import _patch_dll
from . import _dll_list
from . import _version


# Template for patching __init__.py so that the vendored DLLs are loaded at
# runtime. If the patch would be placed at the beginning of the file, an empty
# triple-quoted string is placed at the beginning so that the comment
# "start delvewheel patch" does not show up when the built-in help system help()
# is invoked on the package. For non-Anaconda Python >= 3.8, we use the
# os.add_dll_directory() function so that the folder containing the vendored
# DLLs is added to the DLL search path. For Python 3.7 or lower, this function
# is unavailable, so we preload the DLLs. Whenever Python needs a vendored DLL,
# it will use the already-loaded DLL instead of searching for it. We also
# preload the DLLs for Anaconda Python < 3.10, which has a bug where
# os.add_dll_directory() does not always take effect.
#
# To use the template, call str.format(), passing in
# 0. '""""""' if the patch would be at the start of the file else ''
# 1. an identifying string such as the delvewheel version
# 2. the name of the directory containing the vendored DLLs
# 3. the name of the file containing the DLL load order.
_patch_init_template = """

{0}# start delvewheel patch
def _delvewheel_init_patch_{1}():
    import os
    import sys
    libs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, {2!r}))
    if sys.version_info[:2] >= (3, 8) and not os.path.exists(os.path.join(sys.base_prefix, 'conda-meta')) or sys.version_info[:2] >= (3, 10):
        os.add_dll_directory(libs_dir)
    else:
        from ctypes import WinDLL
        with open(os.path.join(libs_dir, {3!r})) as file:
            load_order = file.read().split()
        for lib in load_order:
            WinDLL(os.path.join(libs_dir, lib))


_delvewheel_init_patch_{1}()
del _delvewheel_init_patch_{1}
# end delvewheel patch

"""

# Template for patching __init__.py for Python 3.10 and above. For these Python
# versions, os.add_dll_directory() is used as the exclusive strategy.
#
# To use the template, call str.format(), passing in
# 0. '""""""' if the patch would be at the start of the file else ''
# 1. an identifying string such as the delvewheel version
# 2. the name of the directory containing the vendored DLLs
_patch_init_template_v2 = """

{0}# start delvewheel patch
def _delvewheel_init_patch_{1}():
    import os
    libs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, {2!r}))
    os.add_dll_directory(libs_dir)


_delvewheel_init_patch_{1}()
del _delvewheel_init_patch_{1}
# end delvewheel patch

"""

pp = pprint.PrettyPrinter(indent=4)


class WheelRepair:
    """An instance represents a wheel that can be repaired."""

    _verbose: int  # verbosity level, 0 to 2
    _whl_path: str  # path to wheel
    _whl_name: str  # name of wheel
    _distribution_name: str
    _version: str  # wheel version
    _extract_dir_obj: typing.Optional[tempfile.TemporaryDirectory]  # wheel extraction directory object
    _extract_dir: str  # wheel extraction directory
    _add_dlls: typing.Set[str]  # additional DLLs to addd
    _no_dlls: typing.Set[str]  # DLLs to exclude
    _wheel_dirs: typing.Optional[typing.List[str]]  # extracted directories from inside wheel
    _ignore_in_wheel: bool  # whether to ignore DLLs that are already inside wheel
    _arch: str  # CPU architecture of wheel: 'x86', 'x64', 'arm64'
    _min_supported_python: typing.Optional[typing.Tuple[int, int]]
        # minimum supported Python version based on Python tags (ignoring the
        # Python-Requires metadatum), None if unknown

    def __init__(self,
                 whl_path: str,
                 extract_dir: typing.Optional[str] = None,
                 add_dlls: typing.Optional[typing.Set[str]] = None,
                 no_dlls: typing.Optional[typing.Set[str]] = None,
                 ignore_in_wheel: bool = False,
                 verbose: int = 0) -> None:
        """Initialize a wheel repair object.
        whl_path: Path to the wheel to repair
        extract_dir: Directory where wheel is extracted. If None, a temporary
            directory is created.
        dest_dir: Directory to place the repaired wheel. If None, it defaults to
            wheelhouse, relative to the current working directory.
        add_dlls: Set of lowercase DLL names to force inclusion into the wheel
        no_dlls: Set of lowercase DLL names to force exclusion from wheel
            (cannot overlap with add_dlls)
        no_mangles: Set of lowercase DLL names not to mangle
        ignore_in_wheel: whether to ignore DLLs that are already in the wheel
        verbose: verbosity level, 0 to 2"""
        if not os.path.isfile(whl_path):
            raise FileNotFoundError(f'{whl_path} not found')

        self._verbose = verbose
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
        try:
            shutil.rmtree(self._extract_dir)
        except FileNotFoundError:
            pass
        os.makedirs(self._extract_dir)
        if self._verbose >= 1:
            print(f'extracting {self._whl_name} to {self._extract_dir}')
        with zipfile.ZipFile(self._whl_path) as whl_file:
            whl_file.extractall(self._extract_dir)

        self._add_dlls = set() if add_dlls is None else add_dlls
        self._no_dlls = set() if no_dlls is None else no_dlls

        # Modify self._no_dlls to include those that are already part of every
        # Python distribution the wheel targets.
        abi_tags = whl_name_split[-2].split('.')
        platform_tags = whl_name_split[-1].split('.')
        if len(set(platform_tags) & {'win32', 'win_amd64', 'win_arm64'}) > 1:
            raise NotImplementedError('Wheels targeting multiple CPU architectures are not supported')
        ignore_by_distribution = set().union(*_dll_list.ignore_by_distribution.values())
        for abi_platform in itertools.product(abi_tags, platform_tags):
            abi_platform = '-'.join(abi_platform)
            if abi_platform in _dll_list.ignore_by_distribution:
                ignore_by_distribution &= _dll_list.ignore_by_distribution[abi_platform]
            else:
                ignore_by_distribution = set()
                break
        self._no_dlls |= ignore_by_distribution

        # If ignore_in_wheel is True, save list of all directories in the wheel.
        # These directories will be used to search for DLLs that are already in
        # the wheel.
        if ignore_in_wheel:
            self._wheel_dirs = [self._extract_dir]
            for root, dirnames, _ in os.walk(self._extract_dir):
                for dirname in dirnames:
                    self._wheel_dirs.append(os.path.join(root, dirname))
        else:
            self._wheel_dirs = None
        self._ignore_in_wheel = ignore_in_wheel

        # determine the CPU architecture of the wheel
        self._arch = ''
        if 'win32' in platform_tags:
            self._arch = 'x86'
        elif 'win_amd64' in platform_tags:
            self._arch = 'x64'
        elif 'win_arm64' in platform_tags:
            self._arch = 'arm64'
        else:
            for root, _, filenames in os.walk(self._extract_dir):
                for filename in filenames:
                    if filename.lower().endswith('.pyd'):
                        arch = _patch_dll.get_arch(os.path.join(root, filename))
                        if not arch:
                            raise NotImplementedError('Wheels for architectures other than x86, x64, and arm64 are not supported')
                        elif self._arch and self._arch != arch:
                            raise NotImplementedError('Wheels targeting multiple CPU architectures are not supported')
                        self._arch = arch
            self._arch = 'x64'  # set default value for safety; this shouldn't be used

        # get minimum supported Python version
        python_tags = whl_name_split[-3].split('.')
        if python_tags:
            unknown = False
            python_versions = []
            for python_tag in python_tags:
                match = re.fullmatch(r'^[A-Za-z]+([0-9])([0-9]*)$', python_tag)
                if not match:
                    unknown = True
                    break
                python_versions.append((int(match[1]), int(match[2]) if match[2] else 0))
            self._min_supported_python = None if unknown else min(python_versions)
        else:
            self._min_supported_python = None

    @staticmethod
    def _rehash(file_path: str) -> typing.Tuple[str, int]:
        """Return (hash, size) for a file with path file_path. The hash and size
        can be used to verify the integrity of the contents of a wheel."""
        with open(file_path, 'rb') as file:
            contents = file.read()
            hash = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode('latin1').rstrip('=')
            size = len(contents)
            return hash, size

    @staticmethod
    def _hashfile(afile: typing.BinaryIO, blocksize: int = 65536, length: int = 32) -> str:
        """Hash the contents of an open file handle with SHA256. Return the
        first length characters of the hash."""
        hasher = hashlib.sha256()
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        return hasher.hexdigest()[:length]

    def _patch_init_contents(self, at_start: bool, libs_dir: str, load_order_filename: typing.Optional[str]) -> str:
        """Return the contents of the patch to place in __init__.py.

        at_start is whether the contents are placed at the beginning of
            __init__.py
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used"""
        if self._min_supported_python is None or self._min_supported_python < (3, 10):
            if load_order_filename is None:
                raise ValueError('load_order_filename cannot be None')
            return _patch_init_template.format('""""""' if at_start else '', _version.__version__.replace('.', '_'), libs_dir, load_order_filename)
        else:
            return _patch_init_template_v2.format('""""""' if at_start else '', _version.__version__.replace('.', '_'), libs_dir)

    def _patch_init(self, init_path: str, libs_dir: str, load_order_filename: typing.Optional[str]) -> None:
        """Given the path to __init__.py, create or patch the file so that
        vendored-in DLLs can be loaded at runtime. The patch is placed at the
        topmost location after the docstring (if any) and any
        "from __future__ import" statements.

        init_path is the path to the __init__.py file to patch
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used"""
        print(f'patching {os.path.relpath(init_path, self._extract_dir)}')

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
            # insert patch after the last __future__ import
            patch_init_contents = self._patch_init_contents(False, libs_dir, load_order_filename)
            init_contents_split = init_contents.splitlines(True)
            with open(init_path, 'w') as file:
                file.write(''.join(init_contents_split[:future_import_lineno]))
                file.write('\n')
                file.write(patch_init_contents)
                file.write(''.join(init_contents_split[future_import_lineno:]))
        elif docstring is None:
            # prepend patch
            patch_init_contents = self._patch_init_contents(True, libs_dir, load_order_filename)
            with open(init_path, 'w') as file:
                file.write(patch_init_contents)
                file.write(init_contents)
        else:
            # place patch just after docstring
            patch_init_contents = self._patch_init_contents(False, libs_dir, load_order_filename)
            if len(children) == 0 or not isinstance(children[0], ast.Expr) or ast.literal_eval(children[0].value) != docstring:
                # verify that the first child node is the docstring
                raise ValueError('Error parsing __init__.py: docstring exists but is not the first element of the parse tree')
            if len(children) == 1:
                # append patch
                with open(init_path, 'a') as file:
                    file.write(patch_init_contents)
            else:
                # insert patch after docstring
                init_contents = '\n'.join(init_contents.splitlines())  # normalize line endings
                docstring_search_start_index = 0
                for line in init_contents.splitlines(True):
                    if line.lstrip().startswith('#'):
                        # ignore comments at start of file
                        docstring_search_start_index += len(line)
                    else:
                        break
                double_quotes_index = init_contents.find('"""', docstring_search_start_index)
                single_quotes_index = init_contents.find("'''", docstring_search_start_index)
                if double_quotes_index == -1 and single_quotes_index == -1:
                    raise ValueError('Error parsing __init__.py: docstring exists but does not start with triple quotes')
                elif double_quotes_index == -1 or single_quotes_index != -1 and single_quotes_index < double_quotes_index:
                    docstring_start_index = single_quotes_index
                    quotes = "'''"
                else:
                    docstring_start_index = double_quotes_index
                    quotes = '"""'
                docstring_end_index = init_contents.find(quotes, docstring_start_index + 3)
                if docstring_end_index == -1:
                    raise ValueError('Error parsing __init__.py: docstring exists but does not end with triple quotes')
                docstring_end_index += 3
                docstring_end_line = init_contents.find('\n', docstring_end_index)
                if docstring_end_line == -1:
                    docstring_end_line = len(init_contents)
                extra_text = init_contents[docstring_end_index: docstring_end_line]
                if extra_text and not extra_text.isspace():
                    raise ValueError(f'Error parsing __init__.py: extra text {extra_text!r} is on the line where the docstring ends. Move the extra text to a new line and try again.')
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
            pathlib.Path(self._extract_dir),
            pathlib.Path(self._extract_dir) / f'{self._distribution_name}-{self._version}.data' / 'purelib',
            pathlib.Path(self._extract_dir) / f'{self._distribution_name}-{self._version}.data' / 'platlib',
        ]
        return pathlib.Path(os.path.dirname(path)) in top_level_dirs

    def _get_repair_version(self) -> str:
        """If this wheel has already been repaired, return the delvewheel
        version that performed the repair. Otherwise, return the empty
        string."""
        filename = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.dist-info', 'DELVEWHEEL')
        if os.path.isfile(filename):
            with open(filename) as file:
                return file.readline().strip()
        return ''

    def _split_dependency_paths(self, dependency_paths: typing.Iterable) -> typing.Tuple[typing.Set, typing.Set]:
        """Given an iterable of DLL paths, partition the contents into a tuple
        of sets
        (dependency_paths_in_wheel, dependency_paths_outside_wheel).
        dependency_paths_in_wheel contains the paths to DLLs that are already in
        the wheel, and dependency_paths_outside_wheel contains the paths to DLLs
        that are not in the wheel."""
        dependency_paths_in_wheel = set()
        dependency_paths_outside_wheel = set()
        for dependency_path in dependency_paths:
            if pathlib.Path(self._extract_dir) in pathlib.Path(dependency_path).parents:
                dependency_paths_in_wheel.add(dependency_path)
            else:
                dependency_paths_outside_wheel.add(dependency_path)
        return dependency_paths_in_wheel, dependency_paths_outside_wheel

    def show(self) -> None:
        """Show the dependencies that the wheel has."""
        print(f'Analyzing {self._whl_name}\n')

        # check whether wheel has already been repaired
        repair_version = self._get_repair_version()
        if repair_version:
            print(f'Delvewheel {repair_version} has already repaired this wheel.')
            return

        # find dependencies
        dependency_paths = set()
        ignored_dll_names = set()
        not_found_dll_names = set()
        extension_module_paths = []
        for root, _, filenames in os.walk(self._extract_dir):
            for filename in filenames:
                if filename.lower().endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    extension_module_paths.append(extension_module_path)
                    discovered, ignored, not_found = _patch_dll.get_all_needed(extension_module_path, self._no_dlls, self._wheel_dirs, 'ignore', self._verbose)
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored
                    not_found_dll_names |= not_found

        # find extra dependencies specified with --add-dll
        extra_dependency_paths = set()
        for dll_name in self._add_dlls:
            path = _patch_dll.find_library(dll_name, None, self._arch)
            if path:
                extra_dependency_paths.add(path)
            else:
                not_found_dll_names.add(dll_name)

        if self._ignore_in_wheel:
            dependency_paths_in_wheel, dependency_paths_outside_wheel = self._split_dependency_paths(dependency_paths)
            for path in dependency_paths_in_wheel.copy():
                if os.path.basename(path).lower() in self._add_dlls:
                    dependency_paths_in_wheel.remove(path)
            dependency_paths_in_wheel = list(dependency_paths_in_wheel)
            dependency_paths_in_wheel.sort()
            dependency_paths_outside_wheel |= extra_dependency_paths
            dependency_paths_outside_wheel = list(dependency_paths_outside_wheel)
            dependency_paths_outside_wheel.sort()
        else:
            dependency_paths_in_wheel = None
            dependency_paths_outside_wheel = list(dependency_paths | extra_dependency_paths)
            dependency_paths_outside_wheel.sort()
        print('The following DLLs will be copied into the wheel.')
        if dependency_paths_outside_wheel or not_found_dll_names:
            for dependency_path in dependency_paths_outside_wheel:
                print(f'    {os.path.basename(dependency_path)} ({dependency_path})')
            for not_found_dll_name in not_found_dll_names:
                print(f'    {not_found_dll_name} (Error: Not Found)')
        else:
            print('    None')

        if self._ignore_in_wheel:
            print('\nThe following DLLs are already in the wheel and will not be copied.')
            if dependency_paths_in_wheel:
                for dependency_path in dependency_paths_in_wheel:
                    print(f'    {os.path.basename(dependency_path)} ({os.path.join(self._whl_name, os.path.relpath(dependency_path, self._extract_dir))})')
            else:
                print('    None')

        ignored_dll_names -= {os.path.basename(p).lower() for p in dependency_paths_outside_wheel}
        ignored_dll_names = list(ignored_dll_names)
        ignored_dll_names.sort()
        print("\nThe following DLLs are assumed to be present in the end user's environment and will not be copied into the wheel.")
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

        # check whether wheel has already been repaired
        repair_version = self._get_repair_version()
        if repair_version:
            print(f'Delvewheel {repair_version} has already repaired this wheel.')
            return

        # find dependencies
        print('finding DLL dependencies')
        dependency_paths = set()
        ignored_dll_names = set()
        extension_module_paths = []
        top_level_ext_module_names = set()
        for root, _, filenames in os.walk(self._extract_dir):
            for filename in filenames:
                if filename.lower().endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    dll_arch = _patch_dll.get_arch(extension_module_path)
                    if dll_arch != self._arch:
                        raise RuntimeError(f'{os.path.relpath(extension_module_path, self._extract_dir)} is {dll_arch}, which is not allowed in a {self._arch} wheel')
                    if self._is_top_level_ext_module(extension_module_path):
                        if self._verbose >= 1:
                            print(f'analyzing top-level extension module {os.path.relpath(extension_module_path, self._extract_dir)}')
                        top_level_ext_module_names.add(filename[:filename.index('.')])
                    elif self._verbose >= 1:
                        print(f'analyzing package-level extension module {os.path.relpath(extension_module_path, self._extract_dir)}')
                    extension_module_paths.append(extension_module_path)
                    discovered, ignored = _patch_dll.get_all_needed(extension_module_path, self._no_dlls, self._wheel_dirs, 'raise', self._verbose)[:2]
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored

        # if --ignore-in-wheel is specified, ignore DLLs that were found inside
        # the wheel unless they are specified with --add-dll
        if self._ignore_in_wheel:
            dependency_paths_in_wheel, dependency_paths_outside_wheel = self._split_dependency_paths(dependency_paths)
            for p in dependency_paths_in_wheel:
                name_lower = os.path.basename(p).lower()
                no_mangles.add(name_lower)
                no_mangles.update(_patch_dll.get_direct_mangleable_needed(p, self._no_dlls, no_mangles, self._verbose))
                if name_lower not in self._add_dlls:
                    ignored_dll_names.add(name_lower)
            dependency_paths = dependency_paths_outside_wheel

        # find extra dependencies specified with --add-dll that have not yet
        # been found
        dependency_names = {os.path.basename(p) for p in dependency_paths}  # this is NOT lowercased
        dependency_names_lower = {name.lower() for name in dependency_names}
        extra_dependency_paths = set()
        for dll_name in self._add_dlls:
            if dll_name in dependency_names_lower:
                continue
            path = _patch_dll.find_library(dll_name, None, self._arch)
            if path:
                extra_dependency_paths.add(path)
            else:
                raise FileNotFoundError(f'{dll_name} not found')

        if not dependency_paths and not extra_dependency_paths:
            print('no external dependencies are needed')
            return
        if self._verbose >= 1:
            to_copy = set(os.path.basename(p) for p in dependency_paths | extra_dependency_paths)
            ignored_dll_names -= {name.lower() for name in to_copy}
            print(f'External dependencies to copy into the wheel are\n{pp.pformat(to_copy)}')
            print(f'External dependencies not to copy into the wheel are\n{pp.pformat(ignored_dll_names)}')
        if top_level_ext_module_names:
            # At least 1 extension module is top-level, so we cannot use
            # __init__.py to insert the DLL search path at runtime. In this
            # case, DLLs are instead copied into the platlib folder, whose
            # contents are installed directly into site-packages during
            # installation.
            libs_dir_name = '.'
            libs_dir = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data', 'platlib')
        else:
            libs_dir_name = self._distribution_name + lib_sdir
            libs_dir = os.path.join(self._extract_dir, libs_dir_name)
        os.makedirs(libs_dir, exist_ok=True)
        print(f'copying DLLs into {os.path.relpath(libs_dir, self._extract_dir)}')
        for dependency_path in dependency_paths | extra_dependency_paths:
            if self._verbose >= 1:
                print(f'copying {dependency_path} -> {os.path.join(libs_dir, os.path.basename(dependency_path))}')
            shutil.copy2(dependency_path, libs_dir)

        # mangle library names
        name_mangler = {}  # dict from lowercased old name to new name
        if no_mangle_all:
            print('skip mangling DLL names')
        else:
            print('mangling DLL names')
            for lib_name in dependency_names:
                # lib_name is NOT lowercased
                if not any(lib_name.lower().startswith(prefix) for prefix in _dll_list.no_mangle_prefixes) and \
                        lib_name.lower() not in no_mangles:
                    root, ext = os.path.splitext(lib_name)
                    with open(os.path.join(libs_dir, lib_name), 'rb') as lib_file:
                        root = f'{root}-{self._hashfile(lib_file)}'
                    name_mangler[lib_name.lower()] = root + ext
            for extension_module_path in extension_module_paths:
                extension_module_name = os.path.basename(extension_module_path)
                if self._verbose >= 1:
                    print(f'repairing {extension_module_name} -> {extension_module_name}')
                needed = _patch_dll.get_direct_mangleable_needed(extension_module_path, self._no_dlls, no_mangles, self._verbose)
                _patch_dll.replace_needed(extension_module_path, needed, name_mangler, self._verbose)
            for lib_name in dependency_names:
                # lib_name is NOT lowercased
                if self._verbose >= 1:
                    if lib_name.lower() in name_mangler:
                        print(f'repairing {lib_name} -> {name_mangler[lib_name.lower()]}')
                    else:
                        print(f'repairing {lib_name} -> {lib_name}')
                lib_path = os.path.join(libs_dir, lib_name)
                needed = _patch_dll.get_direct_mangleable_needed(lib_path, self._no_dlls, no_mangles, self._verbose)
                _patch_dll.replace_needed(lib_path, needed, name_mangler, self._verbose)
                if lib_name.lower() in name_mangler:
                    os.rename(lib_path, os.path.join(libs_dir, name_mangler[lib_name.lower()]))

        if self._min_supported_python is None or self._min_supported_python < (3, 10):
            # Perform topological sort to determine the order that DLLs must be
            # loaded at runtime. We first construct a directed graph where the
            # vertices are the vendored DLLs and an edge represents a "depends-
            # on" relationship. We perform a topological sort of this graph. The
            # reverse of this topological sort then tells us what order we need
            # to load the DLLs so that all dependencies of a DLL are loaded
            # before that DLL is loaded.
            print('calculating DLL load order')
            for dependency_name in dependency_names.copy():
                # dependency_name is NOT lowercased
                if dependency_name.lower() in name_mangler:
                    dependency_names.remove(dependency_name)
                    dependency_names.add(name_mangler[dependency_name.lower()])

            # map from lowercased DLL name to its original case
            dependency_name_casemap = {dependency_name.lower(): dependency_name for dependency_name in dependency_names}

            graph = {}  # map each lowercased DLL name to a lowercased set of its vendored direct dependencies
            for dll_name in dependency_names:
                # dll_name is NOT lowercased
                dll_path = os.path.join(libs_dir, dll_name)
                # In this context, delay-loaded DLL dependencies are not true
                # dependencies because they are not necessary to get the DLL to load
                # initially. More importantly, we may get circular dependencies if
                # we were to consider delay-loaded DLLs as true dependencies. For
                # example, there exist versions of concrt140.dll and msvcp140.dll
                # such that concrt140.dll lists msvcp140.dll in its import table,
                # while msvcp140.dll lists concrt140.dll in its delay import table.
                graph[dll_name.lower()] = _patch_dll.get_direct_needed(dll_path, False, True, self._verbose) & set(dependency_name_casemap.keys())
            rev_dll_load_order = []
            no_incoming_edge = {dll_name_lower for dll_name_lower in dependency_name_casemap.keys() if not any(dll_name_lower in value for value in graph.values())}
            while no_incoming_edge:
                dll_name_lower = no_incoming_edge.pop()
                rev_dll_load_order.append(dependency_name_casemap[dll_name_lower])
                while graph[dll_name_lower]:
                    dependent_dll_name = graph[dll_name_lower].pop()
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
        else:
            load_order_filename = None

        # Create or patch top-level __init__.py in each package to load
        # dependent DLLs from correct location at runtime.
        #
        # This may cause problems for namespace packages where __init__.py must
        # be absent for proper functionality. However, without __init__.py, we
        # cannot load the dependent DLLs. For now, we do not handle this edge
        # case and create __init__.py anyway.
        #
        # An exception is that if a top-level module and a top-level namespace
        # package have the same name, do not create __init__.py in the package.
        # Otherwise, the import resolution order of the module and the package
        # would be swapped.
        for item in os.listdir(self._extract_dir):
            init_path = os.path.join(self._extract_dir, item, '__init__.py')
            if os.path.isdir(os.path.join(self._extract_dir, item)) and \
                    item != f'{self._distribution_name}-{self._version}.dist-info' and \
                    item != f'{self._distribution_name}-{self._version}.data' and \
                    item != libs_dir_name and \
                    (item not in top_level_ext_module_names or os.path.isfile(init_path)):
                self._patch_init(init_path, libs_dir_name, load_order_filename)
        for extra_dir_name in ('purelib', 'platlib'):
            extra_dir = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data', extra_dir_name)
            if os.path.isdir(extra_dir):
                for item in os.listdir(extra_dir):
                    init_path = os.path.join(extra_dir, item, '__init__.py')
                    if os.path.isdir(os.path.join(extra_dir, item)) and \
                            (item not in top_level_ext_module_names or os.path.isfile(init_path)):
                        self._patch_init(init_path, libs_dir_name, load_order_filename)

        # create .dist-info/DELVEWHEEL file to indicate that the wheel has been
        # repaired
        filename = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.dist-info', 'DELVEWHEEL')
        with open(filename, 'w') as file:
            file.write(f'{_version.__version__}\n\n{sys.argv}')

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
        print(f'fixed wheel written to {os.path.abspath(whl_dest_path)}')
