"""Functions for repairing a wheel."""

import ast
import base64
import collections.abc
import csv
import datetime
import graphlib
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
from . import _Config
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
# We also preload the DLLs for the versions of Anaconda CPython < 3.10 that
# have a bug where os.add_dll_directory() does not always take effect
# (https://github.com/conda/conda/issues/10897).
#
# Strictly speaking, the is_conda_cpython variable in the patch does not always
# correctly detect whether Anaconda CPython is in use because newer versions of
# Anaconda CPython 3.8 and 3.9 no longer define the Anaconda_GetVersion()
# function. However, these versions do not have the os.add_dll_directory() bug,
# so we are still correctly detecting the versions of Anaconda Python that have
# the bug. Anaconda PyPy does not have the bug.
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
            import ctypes.wintypes
            with open(os.path.join(libs_dir, {4!r})) as file:
                load_order = file.read().split()
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.LoadLibraryExW.restype = ctypes.wintypes.HMODULE
            kernel32.LoadLibraryExW.argtypes = ctypes.wintypes.LPCWSTR, ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD
            for lib in load_order:
                lib_path = os.path.join(os.path.join(libs_dir, lib))
                if os.path.isfile(lib_path) and not kernel32.LoadLibraryExW(lib_path, None, 8):
                    raise OSError('Error loading {{}}; {{}}'.format(lib, ctypes.FormatError(ctypes.get_last_error())))


_delvewheel_patch_{1}()
del _delvewheel_patch_{1}
# end delvewheel patch
"""

# Template for patching a .py file for Python 3.10 and above. For these Python
# versions, os.add_dll_directory() is used as the exclusive strategy.
#
# The template must produce Python code that is compatible with Python 3.10 and
# the oldest version of Python that can run delvewheel.
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
    if os.path.isdir(libs_dir := os.path.abspath(os.path.join(os.path.dirname(__file__), {2}{3!r}))):
        os.add_dll_directory(libs_dir)


_delvewheel_patch_{1}()
del _delvewheel_patch_{1}
# end delvewheel patch
"""

pp = pprint.PrettyPrinter(indent=4)


def walk(top: str, last: str) -> collections.abc.Iterator[tuple[str, list[str], list[str]]]:
    """Like os.walk(top) except every folder with the name given by last (case-
    sensitive) is traversed last."""
    final = []
    for root, dirnames, filenames in os.walk(top):
        for i, dirname in enumerate(dirnames):
            if dirname == last:
                del dirnames[i]
                final.append(os.path.join(root, dirname))
                break
        yield root, dirnames, filenames
    for root in final:
        yield from os.walk(root)


def get_line_ending(b: bytes) -> bytes:
    """Return the first line ending in b. Possible line endings are b'\n',
    b'\r', and b'\r\n'. If b does not contain any line endings, return
    b'\r\n'."""
    for i, byte in enumerate(b):
        if byte == 10:  # \n
            return b'\n'
        if byte == 13:  # \r
            return b'\r' if i + 1 == len(b) or b[i + 1] != 10 else b'\r\n'
    return b'\r\n'


class WheelRepair:
    """An instance represents a wheel that can be repaired."""

    _whl_path: str  # path to wheel
    _whl_name: str  # name of wheel
    _distribution_name: str
    _version: str  # wheel version
    _extract_dir_obj: typing.Optional[tempfile.TemporaryDirectory]  # wheel extraction directory object
    _extract_dir: str  # wheel extraction directory
    _data_dir: str  # extracted path to .data directory, is set even if directory does not exist
    _purelib_dir: str  # extracted path to .data/purelib directory, is set even if directory does not exist
    _platlib_dir: str  # extracted path to .data/platlib directory, is set even if directory does not exist
    _include: set[str]  # additional DLLs to include
    _exclude: set[str]  # DLLs to exclude
    _wheel_dirs: typing.Optional[list[str]]  # extracted directories from inside wheel
    _ignore_existing: bool  # whether to ignore DLLs that are already inside wheel
    _analyze_existing: bool  # whether to analyze and vendor in dependencies of DLLs that are already in the wheel
    _analyze_existing_exes: bool  # whether to analyze and vendor in dependencies of EXEs that are in the wheel
    _arch: _dll_list.MachineType  # CPU architecture of wheel
    _min_supported_python: typing.Optional[tuple[int, int]]
        # minimum supported Python version based on Python tags (ignoring the
        # Python-Requires metadatum), None if unknown

    def __init__(self,
                 whl_path: str,
                 extract_dir: typing.Optional[str],
                 include: typing.Optional[set[str]],
                 exclude: typing.Optional[set[str]],
                 ignore_existing: bool,
                 analyze_existing: bool,
                 analyze_existing_exes: bool) -> None:
        """Initialize a wheel repair object.
        whl_path: Path to the wheel to repair
        extract_dir: Directory where wheel is extracted. If None, a temporary
            directory is created.
        include: Set of lowercase DLL names to force inclusion into the wheel
        exclude: Set of lowercase DLL names to force exclusion from wheel
            (cannot overlap with include)
        ignore_existing: whether to ignore DLLs that are already in the wheel
        analyze_existing: whether to analyze and vendor in dependencies of DLLs
            that are already in the wheel
        analyze_existing_exes: whether to analyze and vendor in dependencies of
            EXEs that are in the wheel"""
        if not os.path.isfile(whl_path):
            raise FileNotFoundError(f'{whl_path} not found')

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
        if _Config.verbose >= 1:
            print(f'extracting {self._whl_name} to {self._extract_dir}')
        with zipfile.ZipFile(self._whl_path) as whl_file:
            whl_file.extractall(self._extract_dir)

        self._data_dir = os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.data')
        self._purelib_dir = os.path.join(self._data_dir, 'purelib')
        self._platlib_dir = os.path.join(self._data_dir, 'platlib')

        self._include = set() if include is None else include
        self._exclude = set() if exclude is None else exclude

        # Modify self._exclude to include those that are already part of every
        # Python distribution the wheel targets.
        abi_tags = whl_name_split[-2].split('.')
        platform_tag = whl_name_split[-1]
        if '.' in platform_tag:
            raise NotImplementedError('Wheels targeting multiple CPU architectures are not supported')
        ignore_by_abi_platform = set().union(*_dll_list.ignore_by_abi_platform.values())
        for abi_tag in abi_tags:
            abi_platform = f'{abi_tag}-{platform_tag}'
            for abi_platform_re in _dll_list.ignore_by_abi_platform:
                if re.fullmatch(abi_platform_re, abi_platform):
                    ignore_by_abi_platform &= _dll_list.ignore_by_abi_platform[abi_platform_re]
                    break
            else:
                ignore_by_abi_platform = set()
                break
        self._exclude |= ignore_by_abi_platform

        python_tags = whl_name_split[-3].split('.')
        if abi_tags == ['abi3']:
            ignore_abi3 = set().union(*_dll_list.ignore_abi3.values())
            for python_tag in python_tags:
                python_platform = f'{python_tag}-{platform_tag}'
                for python_platform_re in _dll_list.ignore_abi3:
                    if re.fullmatch(python_platform_re, python_platform):
                        ignore_abi3 &= _dll_list.ignore_abi3[python_platform_re]
                        break
                else:
                    ignore_abi3 = set()
                    break
            self._exclude |= ignore_abi3

        # If ignore_existing is True, save list of all directories in the
        # wheel. These directories will be used to search for DLLs that are
        # already in the wheel.
        if ignore_existing:
            self._wheel_dirs = [self._extract_dir]
            for root, dirnames, _ in os.walk(self._extract_dir):
                for dirname in dirnames:
                    self._wheel_dirs.append(os.path.join(root, dirname))
        else:
            self._wheel_dirs = None
        self._ignore_existing = ignore_existing

        self._analyze_existing = analyze_existing
        self._analyze_existing_exes = analyze_existing_exes

        # determine the CPU architecture of the wheel
        self._arch = _dll_list.MachineType.platform_tag_to_type(platform_tag)
        if not self._arch:
            for root, dirnames, filenames in os.walk(self._extract_dir):
                if root == self._data_dir:
                    dirnames[:] = set(dirnames) & {'platlib', 'purelib'}
                for filename in filenames:
                    if (filename_lower := filename.lower()).endswith('.pyd') or self._analyze_existing and filename_lower.endswith('.dll'):
                        if not (arch := _dll_utils.get_arch(os.path.join(root, filename))):
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
                if not (match := re.fullmatch(r'[A-Za-z]+([0-9])([0-9]*)', python_tag)):
                    unknown = True
                    break
                python_versions.append((int(match[1]), int(match[2]) if match[2] else 0))
            self._min_supported_python = None if unknown else min(python_versions)
        else:
            self._min_supported_python = None

    @staticmethod
    def _rehash(file_path: str) -> tuple[str, int]:
        """Return (hash, size) for a file with path file_path. The hash and
        size can be used to verify the integrity of the contents of a wheel."""
        with open(file_path, 'rb') as file:
            contents = file.read()
            hash = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode('latin1').rstrip('=')
            size = len(contents)
            return hash, size

    def _hashfile(self, afile: typing.BinaryIO, blocksize: int = 65536, length: int = 32, start: typing.Optional[typing.Iterable[str]] = None) -> str:
        """Hash the contents of start along with the contents of an open file
        handle with SHA256. Return the first length characters of the hash."""
        hasher = hashlib.sha256()
        if start:
            for start_item in start:
                hasher.update(start_item.encode())
                hasher.update(b'\x00')
        while buf := afile.read(blocksize):
            hasher.update(buf)
        return hasher.hexdigest()[:length]

    def _patch_py_contents_str(self, at_start: bool, libs_dir: str, load_order_filename: typing.Optional[str], depth: int) -> str:
        """Return the contents of the patch to place in a .py file as a str.

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

    def _patch_py_contents_bytes(self, at_start: bool, libs_dir: str, load_order_filename: typing.Optional[str], depth: int, newline: bytes) -> bytes:
        """Return the contents of the patch to place in a .py file as a bytes.

        at_start is whether the contents are placed at the beginning of the file
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used
        depth is the number of parent directories to traverse to reach the
            site-packages directory at runtime starting from the directory
            containing the .py file
        newline is the line ending to use"""
        patch = self._patch_py_contents_str(at_start, libs_dir, load_order_filename, depth).encode()
        if newline != b'\n':
            patch = patch.replace(b'\n', newline)
        return patch

    def _patch_py_file(self, py_path: str, libs_dir: str, load_order_filename: typing.Optional[str], depth: int) -> None:
        """Given the path to a .py file, create or patch the file so that
        vendored DLLs can be loaded at runtime. The patch is placed at the
        topmost location after the shebang (if any), docstring or header
        comments (if any), and any "from __future__ import" statements.

        py_path is the path to the .py file to create or patch
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used
        depth is the number of parent directories to traverse to reach the
            site-packages directory at runtime starting from the directory
            containing the .py file"""
        print(f'patching {os.path.relpath(py_path, self._extract_dir)}')

        py_name = os.path.basename(py_path)
        if py_name.lower() == '__init__.py':
            package_dir = os.path.dirname(os.path.relpath(py_path, self._extract_dir))
            if os.path.isfile(py_path):
                search = (
                    "__path__=__import__('pkgutil').extend_path(__path__,__name__)",
                    '__path__=__import__("pkgutil").extend_path(__path__,__name__)',
                    "__import__('pkg_resources').declare_namespace(__name__)",
                    '__import__("pkg_resources").declare_namespace(__name__)'
                )
                with open(py_path, encoding='utf-8', errors='surrogateescape') as file:
                    for line in file:
                        if line.rstrip().replace(' ', '') in search:
                            warnings.warn(
                                f'{package_dir} appears to be a namespace '
                                f'package. If so, use the --namespace-pkg '
                                f'option.')
                            break
            else:
                warnings.warn(
                    f'{package_dir} does not contain __init__.py. If it is a '
                    f'namespace package, use the --namespace-pkg option. '
                    f'Otherwise, create an empty __init__.py file to silence '
                    f'this warning.')

        open(py_path, 'ab+').close()  # create file if it doesn't exist
        with open(py_path, 'rb') as file:
            py_contents = file.read()
        newline = get_line_ending(py_contents)
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
            patch_py_contents = self._patch_py_contents_bytes(False, libs_dir, load_order_filename, depth, newline)
            py_contents_split = py_contents.splitlines(True)
            with open(py_path, 'wb') as file:
                file.write(b''.join(py_contents_split[:future_import_lineno]).rstrip())
                file.write(newline * 3)
                file.write(patch_py_contents)
                if remainder := b''.join(py_contents_split[future_import_lineno:]).lstrip():
                    file.write(newline)
                    file.write(remainder)
        elif docstring is not None:
            # place patch just after docstring
            patch_py_contents = self._patch_py_contents_bytes(False, libs_dir, load_order_filename, depth, newline)
            if len(children) == 0 or not isinstance(children[0], ast.Expr) or ast.literal_eval(children[0].value) != docstring:
                # verify that the first child node is the docstring
                raise ValueError(f'Error parsing {py_name}: docstring exists but is not the first element of the parse tree')
            if len(children) == 1:
                # append patch
                with open(py_path, 'wb') as file:
                    file.write(py_contents.rstrip())
                    file.write(newline * 3)
                    file.write(patch_py_contents)
            else:
                # insert patch after docstring
                py_contents = b'\n'.join(py_contents.splitlines())  # normalize line endings to facilitate search for docstring
                docstring_search_start_index = 0
                for line in py_contents.splitlines(True):
                    if line.lstrip().startswith(b'#'):
                        # ignore comments at start of file
                        docstring_search_start_index += len(line)
                    else:
                        break
                pattern = (rb'"""([^\\]|\\.)*?"""|'  # 3 double quotes
                           rb"'''([^\\]|\\.)*?'''|"  # 3 single quotes
                           rb'"([^\\\n]|\\.)*?"|'  # 1 double quote
                           rb"'([^\\\n]|\\.)*?'")  # 1 single quote
                if not (match := re.search(pattern, py_contents[docstring_search_start_index:], re.DOTALL)):
                    raise ValueError(f'Error parsing {py_name}: docstring exists but was not found')
                docstring_end_index = docstring_search_start_index + match.end()
                docstring_end_line = py_contents.find(b'\n', docstring_end_index)
                if docstring_end_line == -1:
                    docstring_end_line = len(py_contents)
                if (extra_text := py_contents[docstring_end_index: docstring_end_line]) and not extra_text.isspace():
                    raise ValueError(f'Error parsing {py_name}: extra text {extra_text!r} is on the line where the docstring ends. Move the extra text to a new line and try again.')
                with open(py_path, 'wb') as file:
                    contents = py_contents[:docstring_end_index].rstrip()
                    if newline != b'\n':
                        contents = contents.replace(b'\n', newline)
                    file.write(contents)
                    file.write(newline * 3)
                    file.write(patch_py_contents)
                    file.write(newline)
                    contents = py_contents[docstring_end_index:].lstrip()
                    if newline != b'\n':
                        contents = contents.replace(b'\n', newline)
                    file.write(contents)
                    if not contents.endswith(newline):
                        file.write(newline)
        else:
            py_contents_lines = py_contents.splitlines()
            start = 0
            if py_contents_lines and py_contents_lines[0].startswith(b'#!'):
                start = 1
            while start < len(py_contents_lines) and py_contents_lines[start].strip() in (b'', b'#'):
                start += 1
            if start < len(py_contents_lines) and py_contents_lines[start][:1] == b'#':
                # insert patch after header comments
                end = start + 1
                while end < len(py_contents_lines) and py_contents_lines[end][:1] == b'#':
                    end += 1
                patch_py_contents = self._patch_py_contents_bytes(False, libs_dir, load_order_filename, depth, newline)
                with open(py_path, 'wb') as file:
                    file.write(newline.join(py_contents_lines[:end]).rstrip())
                    file.write(newline * 3)
                    file.write(patch_py_contents)
                    if remainder := newline.join(py_contents_lines[end:]).lstrip():
                        file.write(newline)
                        file.write(remainder)
                        if not remainder.endswith(newline):
                            file.write(newline)
            elif py_contents_lines and py_contents_lines[0].startswith(b'#!'):
                # insert patch after shebang
                patch_py_contents = self._patch_py_contents_bytes(False, libs_dir, load_order_filename, depth, newline)
                with open(py_path, 'wb') as file:
                    file.write(py_contents_lines[0].rstrip())
                    file.write(newline * 3)
                    file.write(patch_py_contents)
                    if remainder := newline.join(py_contents_lines[1:]).lstrip():
                        file.write(newline)
                        file.write(remainder)
                        if not remainder.endswith(newline):
                            file.write(newline)
            else:
                # prepend patch
                patch_py_contents = self._patch_py_contents_bytes(True, libs_dir, load_order_filename, depth, newline)
                with open(py_path, 'wb') as file:
                    file.write(patch_py_contents)
                    if remainder := py_contents.lstrip():
                        file.write(newline)
                        file.write(remainder)
                        if not remainder.endswith(newline):
                            file.write(newline)

        # verify that the file can be parsed properly
        with open(py_path, 'rb') as file:
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
            if item.lower() == '__init__.py' and os.path.isfile(path := os.path.join(dir, item)):
                return path
        return None

    def _patch_package(self, package_dir: str, namespace_pkgs: set[tuple[str]], libs_dir: str, load_order_filename: str, depth: int) -> set[str]:
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
            site-packages directory at runtime starting from inside
            package_dir"""
        package_name = os.path.basename(package_dir)
        namespace_root_ext_modules = set()
        if any(x[0] == package_name for x in namespace_pkgs):
            for item in os.listdir(package_dir):
                if os.path.isfile(item_path := os.path.join(package_dir, item)):
                    if (item_lower := item.lower()).endswith('.py') and item_lower != '__init__.py':
                        self._patch_py_file(item_path, libs_dir, load_order_filename, depth)
                    elif item_lower.endswith('.pyd'):
                        namespace_root_ext_modules.add(item_path)
                elif os.path.isdir(item_path) and \
                        (item not in self._root_level_module_names(package_dir) or self._get_init(item_path)):
                    namespace_root_ext_modules.update(self._patch_package(item_path, set(x[1:] for x in namespace_pkgs if x[0] == package_name and len(x) > 1), libs_dir, load_order_filename, depth + 1))
        else:
            self._patch_py_file(self._get_init(package_dir) or os.path.join(package_dir, '__init__.py'), libs_dir, load_order_filename, depth)
        return namespace_root_ext_modules

    def _patch_custom(self, item_path: str, libs_dir: str, load_order_filename: str, depth: int) -> bool:
        """Patch a package or .py file so that vendored DLLs can be found at
        runtime. The patch is placed at every line consisting of the comment
        '# delvewheel: patch'. Return True iff the patch was applied at least
        once.

        item_path is the absolute path to the extracted package or .py file
        libs_dir is the name of the directory where DLLs are stored.
        load_order_filename is the name of the .load-order file, or None if the
            file is not used
        depth is the number of parent directories to traverse to reach the
            site-packages directory at runtime starting from item_path"""
        if os.path.isdir(item_path):
            result = False
            for item in os.listdir(item_path):
                if os.path.isdir(new_item_path := os.path.join(item_path, item)) or \
                        os.path.isfile(new_item_path) and item[-3:].lower() == '.py':
                    result |= self._patch_custom(new_item_path, libs_dir, load_order_filename, depth + 1)
            return result
        with open(item_path, encoding='utf-8', errors='surrogateescape') as file:
            contents = file.read()
        if not re.search(pattern := '^# *delvewheel *: *patch *$', contents, flags=re.MULTILINE):
            return False
        print(f'patching {os.path.relpath(item_path, self._extract_dir)}', end='')
        with open(item_path, encoding='utf-8', errors='surrogateescape', newline='') as file:
            line = file.readline()
        for newline in ('\r\n', '\r', '\n'):
            if line.endswith(newline):
                break
        else:
            newline = '\r\n'
        patch_py_contents = self._patch_py_contents_str(False, libs_dir, load_order_filename, depth).rstrip()
        contents, count = re.subn(pattern, patch_py_contents, contents, flags=re.MULTILINE)
        with open(item_path, 'w', encoding='utf-8', errors='surrogateescape', newline=newline) as file:
            file.write(contents)
        print(f' (count {count})' if count > 1 else '')
        return True

    def _get_repair_version(self) -> str:
        """If this wheel has already been repaired, return the delvewheel
        version that performed the repair or '(unknown version)' if the version
        could not be determined. Return the empty string if the wheel has not
        been repaired."""
        if os.path.isfile(filename := os.path.join(self._extract_dir, f'{self._distribution_name}-{self._version}.dist-info', 'DELVEWHEEL')):
            with open(filename) as file:
                if (line := file.readline()).startswith('Version: '):
                    return line[len('Version: '):].rstrip()
            return '(unknown version)'
        return ''

    def _split_dependency_paths(self, dependency_paths: collections.abc.Iterable) -> tuple[set, set]:
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

    def _root_level_module_names(self, path: str) -> set[str]:
        """Given the absolute path to the extracted wheel contents or to an
        extracted package, return a set of original-case names of the Python
        modules at the root of the wheel or package. A name does not include
        the file extension or compatibility tag.

        Precondition: path is to a folder that exists"""
        module_names = set()
        for top_level in (self._extract_dir, self._purelib_dir, self._platlib_dir):
            if os.path.isdir(search_dir := os.path.join(top_level, self._get_site_packages_relpath(path))):
                for filename in os.listdir(search_dir):
                    if os.path.isfile(os.path.join(search_dir, filename)) and \
                            ((filename_lower := filename.lower()).endswith('.py') or filename_lower.endswith('.pyd')):
                        module_names.add(filename[:filename.index('.')])
        return module_names

    @staticmethod
    def _isdir_case(root: str, remainder: tuple[str]) -> bool:
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
        if repair_version := self._get_repair_version():
            print(f'Delvewheel {repair_version} has already repaired this wheel.')
            return

        # find dependencies
        dependency_paths = set()
        ignored_dll_names = set()
        not_found_dll_names = set()
        for root, dirnames, filenames in os.walk(self._extract_dir):
            if root == self._data_dir:
                dirnames[:] = set(dirnames) & {'platlib', 'purelib'}
            for filename in filenames:
                if (filename_lower := filename.lower()).endswith('.pyd') or self._analyze_existing and filename_lower.endswith('.dll') or self._analyze_existing_exes and filename_lower.endswith('.exe'):
                    executable_path = os.path.join(root, filename)
                    discovered, _, ignored, not_found = _dll_utils.get_all_needed(executable_path, self._exclude, self._wheel_dirs, 'ignore', False, False)
                    dependency_paths |= discovered
                    ignored_dll_names |= ignored
                    not_found_dll_names |= not_found

        # find extra dependencies specified with --include
        extra_dependency_paths = set()
        for dll_name in self._include:
            if dll_info := _dll_utils.find_library(dll_name, None, self._arch, False, False):
                extra_dependency_paths.add(dll_info[0])
            else:
                not_found_dll_names.add(dll_name)

        if self._ignore_existing:
            dependency_paths_in_wheel, dependency_paths_outside_wheel = self._split_dependency_paths(dependency_paths)
            for path in dependency_paths_in_wheel.copy():
                if os.path.basename(path).lower() in self._include:
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

        if self._ignore_existing:
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

    def repair(
            self,
            target: str,
            no_mangles: set[str],
            no_mangle_all: bool,
            with_mangle: bool,
            strip: bool,
            lib_sdir: str,
            log_diagnostics: bool,
            namespace_pkgs: set[tuple[str]],
            include_symbols: bool,
            include_imports: bool,
            custom_patch: bool) -> None:
        """Repair the wheel in a manner similar to auditwheel.

        target is the target directory for storing the repaired wheel
        no_mangles is a set of lowercase DLL names that will not be mangled
        no_mangle_all is True if no DLL name mangling should happen at all
        with_mangle is True if the direct dependencies of the DLLs that are
            already in the wheel should be name-mangled. Requires
            --ignore-existing. Requires that no_mangle_all be False.
        strip is True if we should strip DLLs that contain trailing data when
            name-mangling
        lib_sdir is the suffix for the directory to store the DLLs
        log_diagnostics is True if diagnostic information is written to the
            DELVEWHEEL metadata file
        namespace_pkgs is a set of paths, relative to the wheel root,
            corresponding to the namespace packages. Each path is represented
            as a tuple of path components
        include_symbols is True if .pdb symbol files should be included with
            the vendored DLLs
        custom_patch is True to indicate that the DLL patch location is
            custom"""
        print(f'repairing {self._whl_path}')

        # check whether wheel has already been repaired
        if repair_version := self._get_repair_version():
            print(f'Delvewheel {repair_version} has already repaired this wheel.')
            return

        # find dependencies
        print('finding DLL dependencies')
        dependency_paths = set()
        associated_paths = set()
        ignored_dll_names = set()
        executable_paths = []
        has_top_level_ext_module = False
        for root, dirnames, filenames in os.walk(self._extract_dir):
            if root == self._data_dir:
                dirnames[:] = set(dirnames) & {'platlib', 'purelib'}
            for filename in filenames:
                is_extension_module = (filename_lower := filename.lower()).endswith('.pyd')
                is_existing_dll = self._analyze_existing and filename_lower.endswith('.dll')
                is_existing_exe = self._analyze_existing_exes and filename_lower.endswith('.exe')
                if is_extension_module or is_existing_dll or is_existing_exe:
                    executable_path = os.path.join(root, filename)
                    if _dll_utils.get_arch(executable_path) != self._arch:
                        raise RuntimeError(f'{os.path.relpath(executable_path, self._extract_dir)} has a CPU architecture that is not compatible with this wheel')
                    if is_extension_module and self._get_site_packages_relpath(root) == os.curdir:
                        if _Config.verbose >= 1:
                            print(f'analyzing top-level extension module {os.path.relpath(executable_path, self._extract_dir)}')
                        has_top_level_ext_module = True
                    elif is_extension_module:
                        if _Config.verbose >= 1:
                            print(f'analyzing package-level extension module {os.path.relpath(executable_path, self._extract_dir)}')
                    elif is_existing_dll:
                        if _Config.verbose >= 1:
                            print(f'analyzing existing DLL {os.path.relpath(executable_path, self._extract_dir)}')
                    elif _Config.verbose >= 1:
                        # is_existing_exe
                        print(f'analyzing existing EXE {os.path.relpath(executable_path, self._extract_dir)}')
                    executable_paths.append(executable_path)
                    discovered, associated, ignored = _dll_utils.get_all_needed(executable_path, self._exclude, self._wheel_dirs, 'raise', include_symbols, include_imports)[:3]
                    dependency_paths |= discovered
                    associated_paths |= associated
                    ignored_dll_names |= ignored

        # if --ignore-existing is specified, ignore DLLs that were found inside
        # the wheel unless they are specified with --include
        dependency_paths_in_wheel, dependency_paths_outside_wheel = self._split_dependency_paths(dependency_paths)
        if self._ignore_existing:
            for p in dependency_paths_in_wheel:
                name_lower = os.path.basename(p).lower()
                no_mangles.add(name_lower)
                if not with_mangle:
                    no_mangles.update(_dll_utils.get_direct_mangleable_needed(p, self._exclude, no_mangles))
                if name_lower not in self._include:
                    ignored_dll_names.add(name_lower)

        # find extra dependencies specified with --include that have not yet
        # been found
        dependency_names_outside_wheel = {os.path.basename(p) for p in dependency_paths_outside_wheel}  # this is NOT lowercased
        dependency_names_outside_wheel_lower = {name.lower() for name in dependency_names_outside_wheel}
        extra_dependency_paths = set()
        for dll_name in self._include:
            if dll_name in dependency_names_outside_wheel_lower:
                continue
            if dll_info := _dll_utils.find_library(dll_name, None, self._arch, include_symbols, include_imports):
                extra_dependency_paths.add(dll_info[0])
                associated_paths.update(dll_info[1])
            else:
                raise FileNotFoundError(f'{dll_name} not found')
        if not dependency_names_outside_wheel and not extra_dependency_paths:
            print('no external dependencies are needed')
            os.makedirs(target, exist_ok=True)
            shutil.copy2(self._whl_path, target)
            print(f'wheel copied to {os.path.abspath(os.path.join(target, self._whl_name))}')
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
                f'not found')

        if _Config.verbose >= 1:
            to_copy = set(os.path.basename(p) for p in dependency_paths_outside_wheel | extra_dependency_paths)
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
        for dependency_path in dependency_paths_outside_wheel | extra_dependency_paths:
            if _Config.verbose >= 1:
                print(f'copying {dependency_path} -> {os.path.join(libs_dir, os.path.basename(dependency_path))}')
            shutil.copy2(dependency_path, libs_dir)
        dependency_paths_outside_wheel_copied = {os.path.join(libs_dir, os.path.basename(dependency_path)) for dependency_path in dependency_paths_outside_wheel}
        for associated_path in associated_paths:
            if _Config.verbose >= 1:
                print(f'copying {associated_path} -> {os.path.join(libs_dir, os.path.basename(associated_path))}')
            shutil.copy2(associated_path, libs_dir)

        # mangle library names
        name_mangler = {}  # dict from lowercased old name to new name
        if no_mangle_all:
            print('skip mangling DLL names')
        else:
            print('mangling DLL names')
            name_mangle_graph = {}  # map from lowercase DLL name to list of lowercase DLL dependencies that will be name-mangled
            lib_name_casemap = {}  # map from lowercase DLL name to original case DLL name
            for dependency_path in dependency_paths:
                # dependency_path is NOT lowercased
                lib_name = os.path.basename(dependency_path)
                lib_name_lower = lib_name.lower()
                if not any(r.fullmatch(lib_name_lower) for r in _dll_list.no_mangle_regexes) and \
                        lib_name_lower not in no_mangles:
                    lib_name_casemap[lib_name_lower] = lib_name
                    name_mangle_graph[lib_name_lower] = _dll_utils.get_direct_mangleable_needed(dependency_path, self._exclude, no_mangles)
            lib_name_lower_hashmap = {}  # map from lowercase DLL name to the hash that will be appended to the name
            for lib_name_lower in graphlib.TopologicalSorter(name_mangle_graph).static_order():
                lib_name = lib_name_casemap[lib_name_lower]
                with open(os.path.join(libs_dir, lib_name), 'rb') as lib_file:
                    lib_name_lower_hashmap[lib_name_lower] = self._hashfile(lib_file, start=(lib_name_lower_hashmap[x] for x in name_mangle_graph[lib_name_lower]))
                root, ext = os.path.splitext(lib_name)
                name_mangler[lib_name_lower] = f'{root}-{lib_name_lower_hashmap[lib_name_lower]}{ext}'
        for executable_path in executable_paths:
            if no_mangle_all:
                needed = []
            else:
                executable_name = os.path.basename(executable_path)
                if _Config.verbose >= 1:
                    print(f'repairing {executable_name} -> {executable_name}')
                needed = _dll_utils.get_direct_mangleable_needed(executable_path, self._exclude, no_mangles)
            _dll_utils.replace_needed(executable_path, needed, name_mangler, strip)
        for dependency_path in dependency_paths_outside_wheel_copied | dependency_paths_in_wheel:
            lib_name = os.path.basename(dependency_path)
            lib_name_lower = lib_name.lower()
            if no_mangle_all:
                needed = []
            else:
                # lib_name is NOT lowercased
                if _Config.verbose >= 1:
                    if lib_name_lower in name_mangler:
                        print(f'repairing {lib_name} -> {name_mangler[lib_name_lower]}')
                    else:
                        print(f'repairing {lib_name} -> {lib_name}')
                needed = _dll_utils.get_direct_mangleable_needed(dependency_path, self._exclude, no_mangles)
            _dll_utils.replace_needed(dependency_path, needed, name_mangler, strip)
            if lib_name_lower in name_mangler:
                os.rename(dependency_path, os.path.join(libs_dir, name_mangler[lib_name_lower]))

        if self._min_supported_python is None or self._min_supported_python < (3, 10):
            load_order_filename = f'.load-order-{self._distribution_name}-{self._version}'
        else:
            load_order_filename = None

        dist_info_foldername = f'{self._distribution_name}-{self._version}.dist-info'
        if custom_patch:
            # replace all instances of '# delvewheel: patch' with the patch
            custom_patch_occurred = False
            for item in os.listdir(self._extract_dir):
                if os.path.isdir(item_path := os.path.join(self._extract_dir, item)) and item != dist_info_foldername and item != os.path.basename(self._data_dir) and item != libs_dir_name or \
                        os.path.isfile(item_path) and item_path[-3:].lower() == '.py':
                    custom_patch_occurred |= self._patch_custom(item_path, libs_dir_name, load_order_filename, 0)
            for extra_dir in (self._purelib_dir, self._platlib_dir):
                if os.path.isdir(extra_dir):
                    for item in os.listdir(extra_dir):
                        if os.path.isdir(item_path := os.path.join(extra_dir, item)) or \
                                os.path.isfile(item_path) and item_path[-3:].lower() == '.py':
                            custom_patch_occurred |= self._patch_custom(item_path, libs_dir_name, load_order_filename, 0)
            if not custom_patch_occurred:
                raise RuntimeError("'# delvewheel: patch' comment not found")
        else:
            # Patch each package to load dependent DLLs from correct location
            # at runtime.
            #
            # However, if a module and a folder are next to each other and have
            # the same name and case,
            # - If the folder does not contain __init__.py, do not patch
            #   the folder. Otherwise, the import resolution order of the
            #   module and the folder may be swapped.
            # - If the folder contains __init__.py, patch the module (if it is
            #   pure Python) and the folder.
            namespace_root_ext_modules = set()
            for item in os.listdir(self._extract_dir):
                if os.path.isdir(package_dir := os.path.join(self._extract_dir, item)) and \
                        item != dist_info_foldername and \
                        item != os.path.basename(self._data_dir) and \
                        item != libs_dir_name and \
                        (item not in self._root_level_module_names(self._extract_dir) or self._get_init(package_dir)):
                    namespace_root_ext_modules.update(self._patch_package(package_dir, namespace_pkgs, libs_dir_name, load_order_filename, 1))
            for extra_dir in (self._purelib_dir, self._platlib_dir):
                if os.path.isdir(extra_dir):
                    for item in os.listdir(extra_dir):
                        if os.path.isdir(package_dir := os.path.join(extra_dir, item)) and \
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
                    f'{"s" if len(dirnames) == 1 else ""} root-level '
                    f'extension module{"s" if len(filenames) > 1 else ""} '
                    f'{os.pathsep.join(filenames)} and need'
                    f'{"s" if len(dirnames) == 1 else ""} '
                    f'{"an " if len(dirnames) == 1 else ""}extra '
                    f'cop{"ies" if len(dirnames) > 1 else "y"} of the '
                    'vendored DLLs. To avoid duplicate DLLs, move extension '
                    'modules into regular (non-namespace) packages.')
                dirnames = list(set(map(os.path.dirname, namespace_root_ext_modules)))
                dirnames.sort(key=self._namespace_pkg_sortkey)
                seen_relative = set()
                for dirname in dirnames:
                    if (dirname_relative := self._get_site_packages_relpath(dirname)) not in seen_relative:
                        for filename in os.listdir(libs_dir):
                            filepath = os.path.join(libs_dir, filename)
                            if _Config.verbose >= 1:
                                print(f'copying {filepath} -> {os.path.join(dirname, filename)}')
                            shutil.copy2(filepath, dirname)
                        seen_relative.add(dirname_relative)

        if load_order_filename is not None:
            # Create .load-order file containing list of DLLs to load during
            # import. Contrary to what the filename suggests, the DLLs are not
            # listed in any particular order. In an older version of
            # delvewheel, the DLLs needed to be listed in a particular order,
            # and the old filename has been kept to maintain backward
            # compatibility with re-bundling tools such as PyInstaller.
            for dependency_name in dependency_names_outside_wheel.copy():
                # dependency_name is NOT lowercased
                if (dependency_name_lower := dependency_name.lower()) in name_mangler:
                    dependency_names_outside_wheel.remove(dependency_name)
                    dependency_names_outside_wheel.add(name_mangler[dependency_name_lower])
            # If the wheel contains a top-level extension module, then the
            # load-order file will be installed directly into site-packages. To
            # avoid conflicts with load-order files from other distributions,
            # include the distribution name and version in the load-order
            # filename. Do this regardless of whether the wheel actually
            # contains a top-level extension module.
            if os.path.exists(load_order_filepath := os.path.join(libs_dir, load_order_filename)):
                raise FileExistsError(f'{os.path.relpath(load_order_filepath, self._extract_dir)} already exists')
            with open(os.path.join(libs_dir, load_order_filename), 'w', newline='\n') as file:
                file.write('\n'.join(dependency_names_outside_wheel))
                file.write('\n')

        # Create .dist-info/DELVEWHEEL file to log repair information. The
        # first line of the file must be 'Version: ' followed by the delvewheel
        # version. Further lines are for information purposes only and are
        # subject to change without notice between delvewheel versions.
        filename = os.path.join(self._extract_dir, dist_info_foldername, 'DELVEWHEEL')
        with open(filename, 'w', newline='\n') as file:
            file.write(f'Version: {_version.__version__}\n')
            if log_diagnostics:
                file.write(f'Arguments: {sys.argv}\n')

        # update record file, which tracks wheel contents and their checksums
        try:
            # remove JSON web signature
            os.remove(os.path.join(self._extract_dir, dist_info_foldername, 'RECORD.jws'))
        except FileNotFoundError:
            pass
        try:
            # remove S/MIME signature
            os.remove(os.path.join(self._extract_dir, dist_info_foldername, 'RECORD.p7s'))
        except FileNotFoundError:
            pass
        record_filepath = os.path.join(self._extract_dir, dist_info_foldername, 'RECORD')
        if _Config.verbose >= 1:
            print(f'updating {os.path.join(dist_info_foldername, "RECORD")}')
        with open(record_filepath, 'w', newline='\n') as record_file:
            writer = csv.writer(record_file, lineterminator='\n')
            for root, _, files in os.walk(self._extract_dir):
                for file in files:
                    if (file_path := os.path.join(root, file)) == record_filepath:
                        writer.writerow((os.path.relpath(record_filepath, self._extract_dir).replace('\\', '/'), '', ''))
                    else:
                        hash, size = self._rehash(file_path)
                        writer.writerow((os.path.relpath(file_path, self._extract_dir).replace('\\', '/'), f'sha256={hash}', size))

        # repackage wheel
        print('repackaging wheel')
        if 'SOURCE_DATE_EPOCH' in os.environ:
            source_date_epoch = int(os.environ['SOURCE_DATE_EPOCH'])
            if source_date_epoch < 315532800:
                warnings.warn('SOURCE_DATE_EPOCH is too small, clipping to 315532800 (1980-01-01 00:00:00)')
                source_date_epoch = 315532800
            if source_date_epoch > 4354819199:
                # ZipInfo.date_time always rounds down to an even number, so
                # allow 4354819199 even though 4354819198 is the effective
                # maximum.
                warnings.warn('SOURCE_DATE_EPOCH is too large, clipping to 4354819198 (2107-12-31 23:59:58)')
                source_date_epoch = 4354819198
            date_time = datetime.datetime.fromtimestamp(source_date_epoch, tz=datetime.timezone.utc).timetuple()[:6]
        else:
            date_time = None
        os.makedirs(target, exist_ok=True)
        whl_dest_path = os.path.join(target, self._whl_name)
        with zipfile.ZipFile(whl_dest_path, 'w', zipfile.ZIP_DEFLATED) as whl_file:
            for root, dirs, files in walk(self._extract_dir, dist_info_foldername):
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    zip_dir_name = os.path.relpath(dir_path, self._extract_dir).replace('\\', '/') + '/'
                    zip_info = zipfile.ZipInfo.from_file(dir_path, zip_dir_name)
                    if date_time is not None:
                        zip_info.date_time = date_time
                    whl_file.writestr(zip_info, b'')
                for file in files:
                    file_path = os.path.join(root, file)
                    relpath = os.path.relpath(file_path, self._extract_dir)
                    zip_file_name = relpath.replace('\\', '/')
                    zip_info = zipfile.ZipInfo.from_file(file_path, zip_file_name)
                    zip_info.compress_type = zipfile.ZIP_DEFLATED
                    if date_time is not None:
                        zip_info.date_time = date_time
                    if _Config.verbose >= 1:
                        print(f'adding {relpath}')
                    with open(file_path, 'rb') as f:
                        whl_file.writestr(zip_info, f.read())
        print(f'fixed wheel written to {os.path.abspath(whl_dest_path)}')
