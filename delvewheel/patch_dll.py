"""DLL file patching functions."""

import itertools
import os
import platform
import typing
import setuptools.msvc
import distutils.util
import pefile
import machomachomangler.pe
from . import dll_list


class PEContext:
    """Context manager for PE file."""
    def __init__(self, name: str) -> None:
        self._pe = pefile.PE(name)

    def __enter__(self) -> pefile.PE:
        return self._pe

    def __exit__(self, exc_type, exc_value, traceback):
        self._pe.close()


def _get_bitness(path: str) -> int:
    """Return the bitness (32 or 64) of an x86 PE file. Return 0 if PE file is
    not for x86.

    Implementation is based on the PE file specification at
    https://docs.microsoft.com/en-us/windows/win32/debug/pe-format."""
    with open(path, 'rb') as file:
        file.seek(0x3c)
        pe_signature_offset = int.from_bytes(file.read(4), 'little')
        file.seek(pe_signature_offset + 4)
        machine = file.read(2)
    if machine == b'd\x86':
        return 64
    elif machine == b'L\x01':
        return 32
    else:
        return 0


def find_library(name: str, wheel_dirs: typing.Optional[typing.Iterable], bitness: int) -> typing.Optional[str]:
    """Given the name of a DLL, return the path to the DLL, or None if the DLL
    cannot be found. The search goes in the following order and considers only
    the DLLs with the given bitness.
    1. If not None, the directories in wheel_dirs.
    2. The PATH environment variable.
    3. The Visual C++ 14.x runtime redistributable directory, if it exists."""
    if wheel_dirs is not None:
        for wheel_dir in wheel_dirs:
            path = os.path.join(wheel_dir, name)
            if os.path.isfile(path) and _get_bitness(path) == bitness:
                return path
    for folder in os.environ['PATH'].split(';'):
        path = os.path.join(folder, name)
        if os.path.isfile(path) and _get_bitness(path) == bitness:
            return path
    try:
        vcvars = setuptools.msvc.msvc14_get_vc_env(distutils.util.get_platform())
        vcruntime = vcvars['py_vcruntime_redist']
        redist_dir = os.path.dirname(vcruntime)
        path = os.path.normpath(os.path.join(redist_dir, name))
        if os.path.isfile(path) and _get_bitness(path) == bitness:
            return path
        return None
    except:
        return None


def get_direct_needed(lib_path: str, include_delay_imports: bool = True) -> set:
    """Given the path to a shared library, return a set containing the lowercase
    DLL names of all its direct dependencies.
    If include_delay_imports is True, delay-loaded dependencies are included.
    Otherwise, they are not included"""
    with PEContext(lib_path) as pe:
        imports = []
        if include_delay_imports:
            attrs = ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT')
        else:
            attrs = ('DIRECTORY_ENTRY_IMPORT',)
        for attr in attrs:
            if hasattr(pe, attr):
                imports = itertools.chain(imports, getattr(pe, attr))
        needed = set()
        for entry in imports:
            needed.add(entry.dll.decode('utf-8').lower())
    return needed


def get_direct_mangleable_needed(lib_path: str, no_dlls: set, no_mangles: set) -> set:
    """Given the path to a shared library, return a set containing the lowercase
    DLL names of all direct dependencies that belong in the wheel and should be
    name-mangled.

    no_dlls is a set of lowercase additional DLL names that do not belong in the
    wheel.

    no_mangles is a set of lowercase additional DLL names not to mangle."""
    with PEContext(lib_path) as pe:
        imports = []
        for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            if hasattr(pe, attr):
                imports = itertools.chain(imports, getattr(pe, attr))
        needed = set()
        lib_bitness = 64 if pe.FILE_HEADER.Machine == 34404 else 32
        ignore_names = dll_list.ignore_names_32 if lib_bitness == 32 else dll_list.ignore_names_64
        for entry in imports:
            dll_name = entry.dll.decode('utf-8').lower()
            if dll_name not in ignore_names and \
                    dll_name not in no_dlls and \
                    not any(r.search(dll_name) for r in dll_list.ignore_regexes) and \
                    dll_name not in no_mangles and \
                    not any(dll_name.startswith(prefix) for prefix in dll_list.no_mangle_prefixes):
                needed.add(dll_name)
    return needed


def get_all_needed(lib_path: str,
                   add_dlls: set,
                   no_dlls: set,
                   wheel_dirs: typing.Optional[typing.Iterable],
                   on_error: str = 'raise') -> typing.Tuple[typing.Set[str], typing.Set[str], typing.Set[str]]:
    """Given the path to a shared library, return a 3-tuple of sets
    (discovered, ignored, not_found).

    discovered contains the DLL paths of all direct and indirect dependencies of
    that shared library that should be bundled into the wheel. ignored contains
    the DLL names of all direct and indirect dependencies of that shared library
    that will not be bundled into the wheel because they are assumed to be on
    the target system.

    If on_error is 'raise', FileNotFoundError is raised if a dependent library
    cannot be found, and not_found is the empty set. If on_error is 'ignore',
    not_found contains the DLL names of all dependent DLLs that cannot be
    found.

    All DLL names in the returned sets are lowercase.

    add_dlls is a set of DLL names to force inclusion into the wheel. We do not
    search for dependencies of these DLLs.

    no_dlls is a set of DLL names to force exclusion from the wheel. We do not
    search for dependencies of these DLLs. Cannot overlap with add_dlls.

    If wheel_dirs is not None, it is an iterable of directories in the wheel
    where dependencies are searched first."""
    interpreter_bitness = 64 if platform.architecture()[0] == '64bit' else 32
    first_lib_path = lib_path.lower()
    stack = [first_lib_path]
    discovered = set()
    ignored = set()
    not_found = set()
    while stack:
        lib_path = stack.pop()
        if lib_path not in discovered:
            discovered.add(lib_path)
            with PEContext(lib_path) as pe:
                lib_bitness = 64 if pe.FILE_HEADER.Machine == 34404 else 32
                if interpreter_bitness != lib_bitness:
                    # bitness of Python interpreter must match that of the DLL
                    # so that find_library() can find it
                    raise OSError(f'Dependent library {lib_path} is {lib_bitness}-bit but Python interpreter is {interpreter_bitness}-bit')

                imports = []
                for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                    if hasattr(pe, attr):
                        imports = itertools.chain(imports, getattr(pe, attr))
                ignore_names = dll_list.ignore_names_32 if lib_bitness == 32 else dll_list.ignore_names_64
                for entry in imports:
                    dll_name = entry.dll.decode('utf-8').lower()
                    if dll_name not in ignore_names and \
                            not any(r.search(dll_name) for r in dll_list.ignore_regexes) and \
                            dll_name not in no_dlls:
                        dll_path = find_library(dll_name, wheel_dirs, interpreter_bitness)
                        if dll_path:
                            stack.append(dll_path)
                        elif on_error == 'raise':
                            raise FileNotFoundError(f'Unable to find library: {dll_name}')
                        else:
                            not_found.add(dll_name)
                    elif dll_name not in add_dlls:
                        ignored.add(dll_name)
    discovered.remove(first_lib_path)
    for add_dll_name in add_dlls:
        add_dll_path = find_library(add_dll_name, wheel_dirs, interpreter_bitness)
        if add_dll_path:
            discovered.add(add_dll_path)
        elif on_error == 'raise':
            raise FileNotFoundError(f'Unable to find library: {add_dll_name}')
        else:
            not_found.add(add_dll_name)
    return discovered, ignored, not_found


def replace_needed(lib_path: str, old_deps: typing.Iterable, name_map: dict) -> None:
    """For the DLL at lib_path, replace its declared dependencies on old_deps
    with those in name_map.
    old_deps: a subset of the dependencies that lib_path has
    name_map: a dict that maps an old dependency name to a new name, must
        contain at least all the keys in old_deps"""
    used_name_map = {dep.encode('utf-8'): name_map[dep].encode('utf-8') for dep in old_deps}
    if not used_name_map:
        # no dependency names to change
        return
    with open(lib_path, 'rb') as f:
        buf = f.read()
    try:
        buf = machomachomangler.pe.redll(buf, used_name_map)
    except ValueError as ex:
        if "Can't add new section" in str(ex):
            raise RuntimeError(
                'Unable to rename the dependencies of '
                f'{os.path.basename(lib_path)} because this DLL has trailing '
                'data. If this DLL was created with MinGW, run the strip '
                f'utility. Otherwise, include {old_deps} in the --no-mangle '
                'flag. In addition, if you believe that delvewheel should '
                'avoid name-mangling a specific DLL by default, open an issue '
                'at https://github.com/adang1345/delvewheel/issues and include '
                'this error message.')
        raise ex
    with open(lib_path, 'wb') as f:
        f.write(buf)
    with PEContext(lib_path) as pe:
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(lib_path)
