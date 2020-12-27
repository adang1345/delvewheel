"""DLL file patching functions."""

import itertools
import platform
import ctypes.util
import typing
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
                   on_error: str = 'raise') -> tuple[set[str], set[str], set[str]]:
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
    """
    first_lib_path = lib_path.lower()
    stack = [first_lib_path]
    discovered = set()
    ignored = set()
    not_found = set()
    while stack:
        lib_path = stack.pop()
        if lib_path not in discovered:
            discovered.add(lib_path)
            interpreter_bitness = 64 if platform.architecture()[0] == '64bit' else 32
            with PEContext(lib_path) as pe:
                lib_bitness = 64 if pe.FILE_HEADER.Machine == 34404 else 32
                if interpreter_bitness != lib_bitness:
                    # bitness of Python interpreter must match that of the DLL so
                    # that ctypes.util.find_library() can find it
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
                        dll_path = ctypes.util.find_library(dll_name)
                        if dll_path:
                            stack.append(dll_path)
                        elif on_error == 'raise':
                            raise FileNotFoundError(f'Unable to find library: {dll_name}')
                        else:
                            not_found.add(dll_name)
                        # print(f'{lib_path} needs {dll_name}')
                    elif dll_name not in add_dlls:
                        ignored.add(dll_name)
    discovered.remove(first_lib_path)
    for add_dll_name in add_dlls:
        add_dll_path = ctypes.util.find_library(add_dll_name)
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
    buf = machomachomangler.pe.redll(buf, used_name_map)
    with open(lib_path, 'wb') as f:
        f.write(buf)
    with PEContext(lib_path) as pe:
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(lib_path)
