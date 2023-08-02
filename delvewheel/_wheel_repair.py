"""Functions for repairing a wheel."""

import ast
import base64
import hashlib
import os
import pathlib
import pprint
import re
import shutil
import sys
import tempfile
import typing
import warnings
import zipfile
from . import _dll_utils
from . import _dll_list
from . import _version


# Template for patching a .py file so that the vendored DLLs are loaded at
# runtime. If the patch would be placed at the beginning of the file, an empty
# triple-quoted string is placed at the beginning so that the comment
# "start delvewheel patch" does not show up when the built-in help system
# help() is invoked on the package or file. For non-Anaconda Python >= 3.8, we
# use the os.add_dll_directory() function so that the folder containing the
# vendored DLLs is added to the DLL search path. For Python 3.7 or lower, this
# function is unavailable, so we preload the DLLs. Whenever Python needs a
# vendored DLL, it will use the already-loaded DLL instead of searching for it.
# We also preload the DLLs for Anaconda Python < 3.10, which has a bug where
# os.add_dll_directory() does not always take effect.
#
# The template must produce Python code that is compatible with Python 2.6, the
# oldest supported target Python version.
#
# To use the template, call str.format(), passing in
# 0. '"""""" ' if the patch would be at the start of the file else ''
# 1. an identifying string such as the delvewheel version
# 2. a number of repeats of 'os.pardir, ' corresponding to the path depth of
#    the file in site-packages upon wheel installation
# 3. the name of the directory containing the vendored DLLs
# 4. the name of the file containing the DLL load order.
_patch_py_template = """\
{0}# start delvewheel patch
def _delvewheel_patch_{1}():
    import ctypes
    import os
    import platform
    import sys
    libs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), {2}{3!r}))
    is_conda_cpython = platform.python_implementation() == 'CPython' and (hasattr(ctypes.pythonapi, 'Anaconda_GetVersion') or 'packaged by conda-forge' in sys.version)
    if sys.version_info[:2] >= (3, 8) and not is_conda_cpython or sys.version_info[:2] >= (3, 10):
        if os.path.isdir(libs_dir):
            os.add_dll_directory(libs_dir)
    else:
        load_order_filepath = os.path.join(libs_dir, {4!r})
        if os.path.isfile(load_order_filepath):
            with open(os.path.join(libs_dir, {4!r})) as file:
                load_order = file.read().split()
            for lib in load_order:
                lib_path = os.path.join(os.path.join(libs_dir, lib))
                if os.path.isfile(lib_path) and not ctypes.windll.kernel32.LoadLibraryExW(ctypes.c_wchar_p(lib_path), None, 0x00000008):
                    raise OSError('Error loading {{}}; {{}}'.format(lib, ctypes.FormatError()))


_delvewheel_patch_{1}()
del _delvewheel_patch_{1}
# end delvewheel patch
"""

# Template for patching a .py file for Python 3.10 and above. For these Python
# versions, os.add_dll_directory() is used as the exclusive strategy.
#
# The template must produce Python code that is compatible with Python 2.6, the
# oldest supported target Python version.
#
# To use the template, call str.format(), passing in
# 0. '"""""" ' if the patch would be at the start of the file else ''
# 1. an identifying string such as the delvewheel version
# 2. a number of repeats of 'os.pardir, ' corresponding to the path depth of
#    the file in site-packages upon wheel installation
# 3. the name of the directory containing the vendored DLLs
_patch_py_template_v2 = """\
{0}# start delvewheel patch
def _delvewheel_patch_{1}():
    import os
    libs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), {2}{3!r}))
    if os.path.isdir(libs_dir):
        os.add_dll_directory(libs_dir)


_delvewheel_patch_{1}()
del _delvewheel_patch_{1}
# end delvewheel patch
"""

pp = pprint.PrettyPrinter(indent=4)


class WheelRepair:
    """An instance represents a wheel that can be repaired."""

    _verbose: int  # verbosity level, 0 to 2
    _test: typing.List[str]  # testing options for internal use
    _whl_path: str  # path to wheel
    _whl_name: str  # name of wheel
    _distribution_name: str
    _version: str  # wheel version
    _extract_dir_obj: typing.Optional[tempfile.TemporaryDirectory]  # wheel extraction directory object
    _extract_dir: str  # wheel extraction directory
    _data_dir: str  # extracted path to .data directory, is set even if directory does not exist
    _purelib_dir: str  # extracted path to .data/purelib directory, is set even if directory does not exist
    _platlib_dir: str  # extracted path to .data/platlib directory, is set even if directory does not exist
    _add_dlls: typing.Set[str]  # additional DLLs to addd
    _no_dlls: typing.Set[str]  # DLLs to exclude
    _wheel_dirs: typing.Optional[typing.List[str]]  # extracted directories from inside wheel
    _ignore_in_wheel: bool  # whether to ignore DLLs that are already inside wheel
    _arch: _dll_list.MachineType  # CPU architecture of wheel
    _min_supported_python: typing.Optional[typing.Tuple[int, int]]
        # minimum supported Python version based on Python tags (ignoring the
        # Python-Requires metadatum), None if unknown

    def __init__(self,
                 whl_path: str,
                 extract_dir: typing.Optional[str],
                 add_dlls: typing.Optional[typing.Set[str]],
                 no_dlls: typing.Optional[typing.Set[str]],
                 ignore_in_wheel: bool,
                 verbose: int,
                 test: typing.List[str]) -> None:
        """Initialize a wheel repair object.
        whl_path: Path to the wheel to repair
        extract_dir: Directory where wheel is extracted. If None, a temporary
            directory is created.
        add_dlls: Set of lowercase DLL names to force inclusion into the wheel
        no_dlls: Set of lowercase DLL names to force exclusion from wheel
            (cannot overlap with add_dlls)
        ignore_in_wheel: whether to ignore DLLs that are already in the wheel
        verbose: verbosity level, 0 to 2
        test: testing options for internal use"""
        if not os.path.isfile(whl_path):
            raise FileNotFoundError(f'{whl_path} not found')

        self._verbose = verbose
        self._test = test
        self._whl_path = whl_path
        self._whl_name = os.path.basename(whl_path)
        if not self._whl_name.endswith('.whl'):
            raise ValueError(f'{self._whl_name} is not a valid wheel name')
        whl_name_split = os.path.splitext(self._whl_name)[0].split('-')
        if len(whl_name_split) not in (5, 6) or not all(whl_name_split):
            raise ValueError(f'{self._whl_name} is not a valid wheel name')
        self._distribution_name = whl_name_split[0]
        self._version = whl_name_split[1]

        if extract_dir is None:
            # need to assign temp directory object to an attribute to prevent
            # it from being destructed
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

        self._data_dir = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data')
        self._purelib_dir = os.path.join(self._data_dir, 'purelib')
        self._platlib_dir = os.path.join(self._data_dir, 'platlib')

        self._add_dlls = set() if add_dlls is None else add_dlls
        self._no_dlls = set() if no_dlls is None else no_dlls

        # Modify self._no_dlls to include those that are already part of every
        # Python distribution the wheel targets.
        abi_tags = whl_name_split[-2].split('.')
        platform_tag = whl_name_split[-1]
        if '.' in platform_tag:
            raise NotImplementedError('Wheels targeting multiple CPU architectures are not supported')
        ignore_by_abi_platform = set().union(*_dll_list.ignore_by_abi_platform.values())
        for abi_tag in abi_tags:
            abi_platform = f'{abi_tag}-{platform_tag}'
            if abi_platform in _dll_list.ignore_by_abi_platform:
                ignore_by_abi_platform &= _dll_list.ignore_by_abi_platform[abi_platform]
            else:
                ignore_by_abi_platform = set()
                break
        self._no_dlls |= ignore_by_abi_platform

        python_tags = whl_name_split[-3].split('.')
        if abi_tags == ['abi3']:
            ignore_abi3 = set().union(*_dll_list.ignore_abi3.values())
            for python_tag in python_tags:
                python_platform = f'{python_tag}-{platform_tag}'
                if python_platform in _dll_list.ignore_abi3:
                    ignore_abi3 &= _dll_list.ignore_abi3[python_platform]
                else:
                    ignore_abi3 = set()
                    break
            self._no_dlls |= ignore_abi3

        # If ignore_in_wheel is True, save list of all directories in the
        # wheel. These directories will be used to search for DLLs that are
        # already in the wheel.
        if ignore_in_wheel:
            self._wheel_dirs = [self._extract_dir]
            for root, dirnames, _ in os.walk(self._extract_dir):
                for dirname in dirnames:
                    self._wheel_dirs.append(os.path.join(root, dirname))
        else:
            self._wheel_dirs = None
        self._ignore_in_wheel = ignore_in_wheel

        # determine the CPU architecture of the wheel
        self._arch = _dll_list.MachineType.platform_tag_to_type(platform_tag)
        if not self._arch:
            for root, dirnames, filenames in os.walk(self._extract_dir):
                if root == self._data_dir:
                    dirnames[:] = set(dirnames) & {'platlib', 'purelib'}
                for filename in filenames:
                    if filename.lower().endswith('.pyd'):
                        arch = _dll_utils.get_arch(os.path.join(root, filename))
                        if not arch:
                            raise NotImplementedError('Wheels for architectures other than x86, x64, and arm64 are not supported')
                        elif self._arch and self._arch is not arch:
                            raise NotImplementedError('Wheels targeting multiple CPU architectures are not supported')
                        self._arch = arch
            self._arch = _dll_list.MachineType.AMD64  # set default value for safety; this shouldn't be used

        # get minimum supported Python version
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
        """Return (hash, size) for a file with path file_path. The hash and
        size can be used to verify the integrity of the contents of a wheel."""
        with open(file_path, 'rb') as file:
            contents = file.read()
            hash = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode('latin1').rstrip('=')
            size = len(contents)
            return hash, size

    def _hashfile(self, afile: typing.BinaryIO, blocksize: int = 65536, length: int = 32) -> str:
        """Hash the contents of an open file handle with SHA256. Return the
        first length characters of the hash."""
        hasher = hashlib.sha256(self._distribution_name.encode())
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        return hasher.hexdigest()[:length]

    def _patch_py_contents(self, at_start: bool, libs_dir: str, load_order_filename: typing.Optional[str], depth: int) -> str:
        """Return the contents of the patch to place in a .py file.

        at_start is whether the contents are placed at the beginning of the file
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used
        depth is the number of parent directories to traverse to reach the
            site-packages directory at runtime starting from the directory
            containing the .py file"""
        if self._min_supported_python is None or self._min_supported_python < (3, 10):
            if load_order_filename is None:
                raise ValueError('load_order_filename cannot be None')
            return _patch_py_template.format('"""""" ' if at_start else '', _version.__version__.replace('.', '_'), 'os.pardir, ' * depth, libs_dir, load_order_filename)
        else:
            return _patch_py_template_v2.format('"""""" ' if at_start else '', _version.__version__.replace('.', '_'), 'os.pardir, ' * depth, libs_dir)

    def _patch_py_file(self, py_path: str, libs_dir: str, load_order_filename: typing.Optional[str], depth: int) -> None:
        """Given the path to a .py file, create or patch the file so that
        vendored DLLs can be loaded at runtime. The patch is placed at the
        topmost location after the docstring (if any) and any
        "from __future__ import" statements.

        py_path is the path to the .py file to create or patch
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used
        depth is the number of parent directories to traverse to reach the
            site-packages directory at runtime starting from the directory
            containing the .py file"""
        print(f'patching {os.path.relpath(py_path, self._extract_dir)}')

        py_name = os.path.basename(py_path)
        open(py_path, 'a+').close()  # create file if it doesn't exist
        with open(py_path, newline='') as file:
            line = file.readline()
        for newline in ('\r\n', '\r', '\n'):
            if line.endswith(newline):
                break
        else:
            newline = '\r\n'

        with open(py_path) as file:
            py_contents = file.read()
        node = ast.parse(py_contents)
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
            patch_py_contents = self._patch_py_contents(False, libs_dir, load_order_filename, depth)
            py_contents_split = py_contents.splitlines(True)
            with open(py_path, 'w', newline=newline) as file:
                file.write(''.join(py_contents_split[:future_import_lineno]).rstrip())
                file.write('\n\n\n')
                file.write(patch_py_contents)
                remainder = ''.join(py_contents_split[future_import_lineno:]).lstrip()
                if remainder:
                    file.write('\n')
                    file.write(remainder)
        elif docstring is None:
            # prepend patch
            patch_py_contents = self._patch_py_contents(True, libs_dir, load_order_filename, depth)
            with open(py_path, 'w', newline=newline) as file:
                file.write(patch_py_contents)
                remainder = py_contents.lstrip()
                if remainder:
                    file.write('\n')
                    file.write(remainder)
        else:
            # place patch just after docstring
            patch_py_contents = self._patch_py_contents(False, libs_dir, load_order_filename, depth)
            if len(children) == 0 or not isinstance(children[0], ast.Expr) or ast.literal_eval(children[0].value) != docstring:
                # verify that the first child node is the docstring
                raise ValueError(f'Error parsing {py_name}: docstring exists but is not the first element of the parse tree')
            if len(children) == 1:
                # append patch
                with open(py_path, 'w', newline=newline) as file:
                    file.write(py_contents.rstrip())
                    file.write('\n\n\n')
                    file.write(patch_py_contents)
            else:
                # insert patch after docstring
                py_contents = '\n'.join(py_contents.splitlines())  # normalize line endings
                docstring_search_start_index = 0
                for line in py_contents.splitlines(True):
                    if line.lstrip().startswith('#'):
                        # ignore comments at start of file
                        docstring_search_start_index += len(line)
                    else:
                        break
                double_quotes_index = py_contents.find('"""', docstring_search_start_index)
                single_quotes_index = py_contents.find("'''", docstring_search_start_index)
                if double_quotes_index == single_quotes_index == -1:
                    raise ValueError(f'Error parsing {py_name}: docstring exists but does not start with triple quotes')
                elif double_quotes_index == -1 or single_quotes_index != -1 and single_quotes_index < double_quotes_index:
                    docstring_start_index = single_quotes_index
                    quotes = "'''"
                else:
                    docstring_start_index = double_quotes_index
                    quotes = '"""'
                docstring_end_index = py_contents.find(quotes, docstring_start_index + 3)
                if docstring_end_index == -1:
                    raise ValueError(f'Error parsing {py_name}: docstring exists but does not end with triple quotes')
                docstring_end_index += 3
                docstring_end_line = py_contents.find('\n', docstring_end_index)
                if docstring_end_line == -1:
                    docstring_end_line = len(py_contents)
                extra_text = py_contents[docstring_end_index: docstring_end_line]
                if extra_text and not extra_text.isspace():
                    raise ValueError(f'Error parsing {py_name}: extra text {extra_text!r} is on the line where the docstring ends. Move the extra text to a new line and try again.')
                with open(py_path, 'w', newline=newline) as file:
                    file.write(py_contents[:docstring_end_index].rstrip())
                    file.write('\n\n\n')
                    file.write(patch_py_contents)
                    file.write('\n')
                    file.write(py_contents[docstring_end_index:].lstrip())

        # verify that the file can be parsed properly
        with open(py_path) as file:
            try:
                ast.parse(file.read())
            except SyntaxError:
                raise ValueError(f'Error parsing {py_name}: Patch failed. This might occur if a node is split across multiple lines.')

    @staticmethod
    def _get_init(dir: str) -> typing.Optional[str]:
        """If directory dir contains any case variation of the __init__.py file,
        then return the path to that file. Otherwise, return None.

        Precondition: dir is an existing directory"""
        for item in os.listdir(dir):
            path = os.path.join(dir, item)
            if item.lower() == '__init__.py' and os.path.isfile(path):
                return path
        return None

    def _patch_package(self, package_dir: str, namespace_pkgs: typing.Set[typing.Tuple[str]], libs_dir: str, load_order_filename: str, depth: int) -> typing.Set[str]:
        """Patch a package so that vendored DLLs can be found at runtime.
        Return a set containing the absolute extracted paths of all .pyd
        extension modules that are at the root of a namespace package within
        the package.

        package_dir is the absolute path to the extracted package
        namespace_pkgs is a set of paths, relative to the parent of
            package_dir, corresponding to the namespace packages. Each path is
            represented as a tuple of path components.
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used
        depth is the number of parent directories to traverse to reach the
            site-packages directory at runtime starting from package_dir"""
        package_name = os.path.basename(package_dir)
        namespace_root_ext_modules = set()
        if any(x[0] == package_name for x in namespace_pkgs):
            for item in os.listdir(package_dir):
                item_path = os.path.join(package_dir, item)
                if os.path.isfile(item_path):
                    item_lower = item.lower()
                    if item_lower.endswith('.py') and item_lower != '__init__.py':
                        self._patch_py_file(item_path, libs_dir, load_order_filename, depth)
                    elif item_lower.endswith('.pyd'):
                        namespace_root_ext_modules.add(item_path)
                elif os.path.isdir(item_path) and \
                        (item not in self._root_level_module_names(package_dir) or self._get_init(item_path)):
                    namespace_root_ext_modules.update(self._patch_package(item_path, set(x[1:] for x in namespace_pkgs if x[0] == package_name and len(x) > 1), libs_dir, load_order_filename, depth + 1))
        else:
            self._patch_py_file(self._get_init(package_dir) or os.path.join(package_dir, '__init__.py'), libs_dir, load_order_filename, depth)
        return namespace_root_ext_modules

    def _get_repair_version(self) -> str:
        """If this wheel has already been repaired, return the delvewheel
        version that performed the repair or '(unknown version)' if the version
        could not be determined. Return the empty string if the wheel has not
        been repaired."""
        filename = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.dist-info', 'DELVEWHEEL')
        if os.path.isfile(filename):
            with open(filename) as file:
                line = file.readline()
                if line.startswith('Version: '):
                    return line[len('Version: '):].rstrip()
            return '(unknown version)'
        return ''

    def _split_dependency_paths(self, dependency_paths: typing.Iterable) -> typing.Tuple[typing.Set, typing.Set]:
        """Given an iterable of DLL paths, partition the contents into a tuple
        of sets
        (dependency_paths_in_wheel, dependency_paths_outside_wheel).
        dependency_paths_in_wheel contains the paths to DLLs that are already
        in the wheel, and dependency_paths_outside_wheel contains the paths to
        DLLs that are not in the wheel."""
        dependency_paths_in_wheel = set()
        dependency_paths_outside_wheel = set()
        for dependency_path in dependency_paths:
            if pathlib.Path(self._extract_dir) in pathlib.Path(dependency_path).parents:
                dependency_paths_in_wheel.add(dependency_path)
            else:
                dependency_paths_outside_wheel.add(dependency_path)
        return dependency_paths_in_wheel, dependency_paths_outside_wheel

    def _get_site_packages_relpath(self, path: str) -> str:
        """Given the path to a file or folder in the extracted wheel contents,
        return the path relative to site-packages when the wheel is
        installed."""
        purelib_dir_obj = pathlib.Path(self._purelib_dir)
        platlib_dir_obj = pathlib.Path(self._platlib_dir)
        path_obj = pathlib.Path(path)
        if path_obj == purelib_dir_obj or purelib_dir_obj in path_obj.parents:
            return os.path.relpath(path, self._purelib_dir)
        elif path_obj == platlib_dir_obj or platlib_dir_obj in path_obj.parents:
            return os.path.relpath(path, self._platlib_dir)
        else:
            return os.path.relpath(path, self._extract_dir)

    def _root_level_module_names(self, path: str) -> typing.Set[str]:
        """Given the absolute path to the extracted wheel contents or to an
        extracted package, return a set of original-case names of the Python
        modules at the root of the wheel or package. A name does not include
        the file extension or compatibility tag.

        Precondition: path is to a folder that exists"""
        module_names = set()
        for top_level in (self._extract_dir, self._purelib_dir, self._platlib_dir):
            search_dir = os.path.join(top_level, self._get_site_packages_relpath(path))
            if os.path.isdir(search_dir):
                filenames = os.listdir(search_dir)
                for filename in filenames:
                    if os.path.isfile(os.path.join(search_dir, filename)) and \
                            (filename.lower().endswith('.py') or filename.lower().endswith('.pyd')):
                        module_names.add(filename[:filename.index('.')])
        return module_names

    @staticmethod
    def _isdir_case(root: str, remainder: typing.Tuple[str]) -> bool:
        """Return True if remainder is an existing directory relative to root.
        Regardless of the case sensitivity of the file system, treat remainder
        as case-sensitive. Treat root using the file system's case sensitivity.

        remainder is represented as a tuple of path components. If root is not
        an existing directory, return False."""
        if not os.path.isdir(root):
            return False
        for component in remainder:
            new_root = os.path.join(root, component)
            if component not in os.listdir(root) or not os.path.isdir(new_root):
                return False
            root = new_root
        return True

    def _namespace_pkg_sortkey(self, path: str) -> int:
        """Given the path to a file or folder in the extracted wheel contents,
        return an int that can be used to sort the path.

        Return 3 if the path is in the purelib directory.
        Return 2 if the path is in the platlib directory.
        Return 1 otherwise."""
        purelib_dir_obj = pathlib.Path(self._purelib_dir)
        platlib_dir_obj = pathlib.Path(self._platlib_dir)
        path_obj = pathlib.Path(path)
        if path_obj == purelib_dir_obj or purelib_dir_obj in path_obj.parents:
            return 3
        elif path_obj == platlib_dir_obj or platlib_dir_obj in path_obj.parents:
            return 2
        else:
            return 1

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
        for root, dirnames, filenames in os.walk(self._extract_dir):
            if root == self._data_dir:
                dirnames[:] = set(dirnames) & {'platlib', 'purelib'}
            for filename in filenames:
                if filename.lower().endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    extension_module_paths.append(extension_module_path)
                    discovered, ignored, not_found = _dll_utils.get_all_needed(extension_module_path, self._no_dlls, self._wheel_dirs, 'ignore', self._verbose)
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored
                    not_found_dll_names |= not_found

        # find extra dependencies specified with --add-dll
        extra_dependency_paths = set()
        for dll_name in self._add_dlls:
            path = _dll_utils.find_library(dll_name, None, self._arch)
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
            print('\nWarning: At least one dependent DLL needs to be copied into the wheel but was not found.')

    def repair(self, target: str, no_mangles: set, no_mangle_all: bool, strip: bool, lib_sdir: str, no_diagnostic: bool, namespace_pkgs: typing.Set[typing.Tuple[str]]) -> None:
        """Repair the wheel in a manner similar to auditwheel.
        target is the target directory for storing the repaired wheel
        no_mangles is a set of lowercase DLL names that will not be mangled
        no_mangle_all is True if no DLL name mangling should happen at all
        strip is True if we should strip DLLs that contain trailing data when
            name-mangling
        lib_sdir is the suffix for the directory to store the DLLs
        no_diagnostic is True if no diagnostic information is written to the
            DELVEWHEEL metadata file
        namespace_pkgs is a set of paths, relative to the wheel root,
            corresponding to the namespace packages. Each path is represented
            as a tuple of path components"""
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
        has_top_level_ext_module = False
        for root, dirnames, filenames in os.walk(self._extract_dir):
            if root == self._data_dir:
                dirnames[:] = set(dirnames) & {'platlib', 'purelib'}
            for filename in filenames:
                if filename.lower().endswith('.pyd'):
                    extension_module_path = os.path.join(root, filename)
                    dll_arch = _dll_utils.get_arch(extension_module_path)
                    if dll_arch != self._arch:
                        raise RuntimeError(f'{os.path.relpath(extension_module_path, self._extract_dir)} has a CPU architecture that is not compatible with this wheel')
                    if self._get_site_packages_relpath(root) == os.curdir:
                        if self._verbose >= 1:
                            print(f'analyzing top-level extension module {os.path.relpath(extension_module_path, self._extract_dir)}')
                        has_top_level_ext_module = True
                    elif self._verbose >= 1:
                        print(f'analyzing package-level extension module {os.path.relpath(extension_module_path, self._extract_dir)}')
                    extension_module_paths.append(extension_module_path)
                    discovered, ignored = _dll_utils.get_all_needed(extension_module_path, self._no_dlls, self._wheel_dirs, 'raise', self._verbose)[:2]
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored

        # if --ignore-in-wheel is specified, ignore DLLs that were found inside
        # the wheel unless they are specified with --add-dll
        if self._ignore_in_wheel:
            dependency_paths_in_wheel, dependency_paths_outside_wheel = self._split_dependency_paths(dependency_paths)
            for p in dependency_paths_in_wheel:
                name_lower = os.path.basename(p).lower()
                no_mangles.add(name_lower)
                no_mangles.update(_dll_utils.get_direct_mangleable_needed(p, self._no_dlls, no_mangles, self._verbose))
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
            path = _dll_utils.find_library(dll_name, None, self._arch)
            if path:
                extra_dependency_paths.add(path)
            else:
                raise FileNotFoundError(f'{dll_name} not found')
        if not dependency_paths and not extra_dependency_paths:
            print('no external dependencies are needed')
            return

        # Warn if namespace package does not exist
        not_found_namespace_pkgs = set()
        for namespace_pkg in namespace_pkgs:
            if not any(self._isdir_case(root, namespace_pkg) for root in (self._extract_dir, self._purelib_dir, self._platlib_dir)):
                not_found_namespace_pkgs.add('.'.join(namespace_pkg))
        if not_found_namespace_pkgs:
            warnings.warn(
                'Namespace package'
                f'{"s" if len(not_found_namespace_pkgs) > 1 else ""} '
                f'{not_found_namespace_pkgs} w'
                f'{"as" if len(not_found_namespace_pkgs) == 1 else "ere"} '
                f'not found', UserWarning)

        if self._verbose >= 1:
            to_copy = set(os.path.basename(p) for p in dependency_paths | extra_dependency_paths)
            ignored_dll_names -= {name.lower() for name in to_copy}
            print(f'External dependencies to copy into the wheel are\n{pp.pformat(to_copy)}')
            print(f'External dependencies not to copy into the wheel are\n{pp.pformat(ignored_dll_names)}')
        if has_top_level_ext_module:
            # At least 1 extension module is top-level, so we cannot use
            # __init__.py to insert the DLL search path at runtime. In this
            # case, DLLs are instead copied into the platlib folder, whose
            # contents are installed directly into site-packages during
            # installation.
            libs_dir_name = '.'
            libs_dir = self._platlib_dir
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
                if not any(r.fullmatch(lib_name.lower()) for r in _dll_list.no_mangle_regexes) and \
                        lib_name.lower() not in no_mangles:
                    root, ext = os.path.splitext(lib_name)
                    with open(os.path.join(libs_dir, lib_name), 'rb') as lib_file:
                        root = f'{root}-{self._hashfile(lib_file)}'
                    name_mangler[lib_name.lower()] = root + ext
            for extension_module_path in extension_module_paths:
                extension_module_name = os.path.basename(extension_module_path)
                if self._verbose >= 1:
                    print(f'repairing {extension_module_name} -> {extension_module_name}')
                needed = _dll_utils.get_direct_mangleable_needed(extension_module_path, self._no_dlls, no_mangles, self._verbose)
                _dll_utils.replace_needed(extension_module_path, needed, name_mangler, strip, self._verbose, self._test)
            for lib_name in dependency_names:
                # lib_name is NOT lowercased
                if self._verbose >= 1:
                    if lib_name.lower() in name_mangler:
                        print(f'repairing {lib_name} -> {name_mangler[lib_name.lower()]}')
                    else:
                        print(f'repairing {lib_name} -> {lib_name}')
                lib_path = os.path.join(libs_dir, lib_name)
                needed = _dll_utils.get_direct_mangleable_needed(lib_path, self._no_dlls, no_mangles, self._verbose)
                _dll_utils.replace_needed(lib_path, needed, name_mangler, strip, self._verbose, self._test)
                if lib_name.lower() in name_mangler:
                    os.rename(lib_path, os.path.join(libs_dir, name_mangler[lib_name.lower()]))

        if self._min_supported_python is None or self._min_supported_python < (3, 10):
            load_order_filename = f'.load-order-{self._distribution_name}-{self._version}'
        else:
            load_order_filename = None

        # Patch each package to load dependent DLLs from correct location at
        # runtime.
        #
        # However, if a module and a folder are next to each other and have the
        # same name and case,
        # - If the folder does not contain __init__.py, do not patch
        #   the folder. Otherwise, the import resolution order of the module
        #   and the folder may be swapped.
        # - If the folder contains __init__.py, patch the module (if it is pure
        #   Python) and the folder.
        dist_info_foldername = f'{self._distribution_name}-{self._version}.dist-info'
        namespace_root_ext_modules = set()
        for item in os.listdir(self._extract_dir):
            package_dir = os.path.join(self._extract_dir, item)
            if os.path.isdir(package_dir) and \
                    item != dist_info_foldername and \
                    item != os.path.basename(self._data_dir) and \
                    item != libs_dir_name and \
                    (item not in self._root_level_module_names(self._extract_dir) or self._get_init(package_dir)):
                namespace_root_ext_modules.update(self._patch_package(package_dir, namespace_pkgs, libs_dir_name, load_order_filename, 1))
        for extra_dir in (self._purelib_dir, self._platlib_dir):
            if os.path.isdir(extra_dir):
                for item in os.listdir(extra_dir):
                    package_dir = os.path.join(extra_dir, item)
                    if os.path.isdir(package_dir) and \
                            (item not in self._root_level_module_names(self._extract_dir) or self._get_init(package_dir)):
                        namespace_root_ext_modules.update(self._patch_package(package_dir, namespace_pkgs, libs_dir_name, load_order_filename, 1))

        # Copy libraries next to all extension modules that are at the root of
        # a namespace package. If a namespace package contains extension
        # modules that are split across at least 2 of the following:
        # 1. the wheel root,
        # 2. the platlib directory,
        # 3. the purelib directory,
        # then copy the libraries to the first in the above list containing
        # this namespace package.
        if namespace_root_ext_modules:
            dirnames = set(self._get_site_packages_relpath(os.path.dirname(x)) for x in namespace_root_ext_modules)
            filenames = set(map(os.path.basename, namespace_root_ext_modules))
            warnings.warn(
                f'Namespace package{"s" if len(dirnames) > 1 else ""} '
                f'{os.pathsep.join(dirnames)} contain'
                f'{"s" if len(dirnames) == 1 else ""} root-level extension '
                f'module{"s" if len(filenames) > 1 else ""} '
                f'{os.pathsep.join(filenames)} and need'
                f'{"s" if len(dirnames) == 1 else ""} '
                f'{"an " if len(dirnames) == 1 else ""}extra '
                f'cop{"ies" if len(dirnames) > 1 else "y"} of the '
                'vendored DLLs. To avoid duplicate DLLs, move extension '
                'modules into regular (non-namespace) packages.', UserWarning)
            dirnames = list(set(map(os.path.dirname, namespace_root_ext_modules)))
            dirnames.sort(key=self._namespace_pkg_sortkey)
            seen_relative = set()
            for dirname in dirnames:
                dirname_relative = self._get_site_packages_relpath(dirname)
                if dirname_relative not in seen_relative:
                    for lib_name in os.listdir(libs_dir):
                        lib_path = os.path.join(libs_dir, lib_name)
                        if self._verbose >= 1:
                            print(f'copying {lib_path} -> {os.path.join(dirname, lib_name)}')
                        shutil.copy2(lib_path, dirname)
                    seen_relative.add(dirname_relative)

        if load_order_filename is not None:
            # Create .load-order file containing list of DLLs to load during
            # import. Contrary to what the filename suggests, the DLLs are not
            # listed in any particular order. In an older version of
            # delvewheel, the DLLs needed to be listed in a particular order,
            # and the old filename has been kept to maintain backward
            # compatibility with re-bundling tools such as PyInstaller.
            for dependency_name in dependency_names.copy():
                # dependency_name is NOT lowercased
                if dependency_name.lower() in name_mangler:
                    dependency_names.remove(dependency_name)
                    dependency_names.add(name_mangler[dependency_name.lower()])
            # If the wheel contains a top-level extension module, then the
            # load-order file will be installed directly into site-packages. To
            # avoid conflicts with load-order files from other distributions,
            # include the distribution name and version in the load-order
            # filename. Do this regardless of whether the wheel actually
            # contains a top-level extension module.
            load_order_filepath = os.path.join(libs_dir, load_order_filename)
            if os.path.exists(load_order_filepath):
                raise FileExistsError(f'{os.path.relpath(load_order_filepath, self._extract_dir)} already exists')
            with open(os.path.join(libs_dir, load_order_filename), 'w', newline='\n') as file:
                file.write('\n'.join(dependency_names))
                file.write('\n')

        # Create .dist-info/DELVEWHEEL file to log repair information. The
        # first line of the file must be 'Version: ' followed by the delvewheel
        # version. Further lines are for information purposes only and are
        # subject to change without notice between delvewheel versions.
        filename = os.path.join(self._extract_dir, dist_info_foldername, 'DELVEWHEEL')
        with open(filename, 'w', newline='\n') as file:
            file.write(f'Version: {_version.__version__}\n')
            if not no_diagnostic:
                file.write(f'Arguments: {sys.argv}\n')

        # update record file, which tracks wheel contents and their checksums
        record_filepath = os.path.join(self._extract_dir, dist_info_foldername, 'RECORD')
        if self._verbose >= 1:
            print(f'updating {os.path.join(dist_info_foldername, "RECORD")}')
        filepath_list = []
        for root, _, files in os.walk(self._extract_dir):
            for file in files:
                filepath_list.append(os.path.join(root, file))
        with open(record_filepath, 'w', newline='\n') as record_file:
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
