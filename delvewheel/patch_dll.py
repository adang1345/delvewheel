"""DLL file patching functions."""

import ctypes
import itertools
import os
import pathlib
import platform
import sys
import typing
import warnings
import setuptools.msvc
import pefile
import machomachomangler.pe
from . import dll_list


pefile.fast_load = True


class PEContext:
    """Context manager for PE file."""
    def __init__(self, path: str, parse_imports: bool, verbose: int) -> None:
        """
        path: path to PE file
        parse_imports: whether to parse the import table and delay import table
        verbose: verbosity level
        """
        self._pe = pefile.PE(path)
        if parse_imports:
            self._pe.parse_data_directories([
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
            ], import_dllnames_only=True)
        self._name = os.path.basename(path)
        self._verbose = verbose

    def __enter__(self) -> pefile.PE:
        return self._pe

    def __exit__(self, exc_type, exc_value, traceback):
        if self._verbose >= 2:
            for w in self._pe.get_warnings():
                print(f'{self._name}: {w}')
        self._pe.close()


def get_bitness(path: str) -> int:
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


def _translate_directory() -> typing.Callable[[str, int], str]:
    """Closure that computes certain values once only for determining how to
    translate a directory when searching for DLLs on Windows.

    Returns a function translate_directory(directory: str, bitness: int) -> str
    that performs directory translations. Given a directory to search for a DLL
    of the given bitness, translate the directory, taking the Windows file
    system redirector into account.

    See https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
    for more information about the Windows file system redirector."""
    if sys.platform != 'win32':
        # no file system redirection on non-Windows systems
        return lambda directory, bitness: directory

    # determine bitness of interpreter and OS
    interpreter_bitness = 64 if platform.architecture()[0] == '64bit' else 32
    if interpreter_bitness == 64:
        os_bitness = 64
    else:
        kernel32 = ctypes.windll.kernel32
        wow64_process = ctypes.c_int()
        if not kernel32.IsWow64Process(ctypes.c_void_p(kernel32.GetCurrentProcess()), ctypes.byref(wow64_process)):
            raise OSError(f'Unable to determine whether WOW64 is active, GetLastError()={kernel32.GetLastError()}')
        os_bitness = 64 if wow64_process.value else 32

    # file system redirection map
    windir = os.environ.get('windir', r'C:\Windows')
    redirect_map_64_32 = {
        fr'{windir}\System32': fr'{windir}\SysWOW64',
        fr'{windir}\lastgood\System32': fr'{windir}\lastgood\SysWOW64',
    }
    redirect_exceptions = [
        pathlib.Path(fr'{windir}\System32\catroot'),
        pathlib.Path(fr'{windir}\System32\catroot2'),
        pathlib.Path(fr'{windir}\System32\driverstore'),
        pathlib.Path(fr'{windir}\System32\drivers\etc'),
        pathlib.Path(fr'{windir}\System32\logfiles'),
        pathlib.Path(fr'{windir}\System32\spool'),
    ]
    redirect_map_32_64 = {
        fr'{windir}\System32': fr'{windir}\Sysnative',
    }

    lastgood_system32 = fr'{windir}\lastgood\System32'
    warned = False

    if interpreter_bitness == os_bitness == 64:
        def translate_directory(directory: str, bitness: int) -> str:
            if bitness == 64:
                return directory
            # perform file system redirection manually
            if any(redirect_exception == pathlib.Path(directory) or redirect_exception in pathlib.Path(directory).parents for redirect_exception in redirect_exceptions):
                return directory
            directory = os.path.normpath(directory)
            for start_dir in redirect_map_64_32:
                if directory.lower().startswith(start_dir.lower()):
                    end_dir = redirect_map_64_32[start_dir] + directory[len(start_dir):]
                    return end_dir
            return directory
        return translate_directory
    elif interpreter_bitness == 32 and os_bitness == 64:
        def translate_directory(directory: str, bitness: int) -> str:
            if bitness == 32:
                return directory
            # disable file system redirection
            directory = os.path.normpath(directory)
            for start_dir in redirect_map_32_64:
                if directory.lower().startswith(start_dir.lower()):
                    end_dir = redirect_map_32_64[start_dir] + directory[len(start_dir):]
                    return end_dir
            nonlocal warned
            if directory.lower().startswith(lastgood_system32.lower()) and not warned:
                warnings.warn(f'{lastgood_system32} is ignored in DLL search path due to technical limitations', RuntimeWarning)
                warned = True
            return directory
        return translate_directory
    return lambda directory, bitness: directory


_translate_directory = _translate_directory()


def find_library(name: str, wheel_dirs: typing.Optional[typing.Iterable], bitness: int) -> typing.Optional[str]:
    """Given the name of a DLL, return the path to the DLL, or None if the DLL
    cannot be found. DLL names are searched in a case-insensitive fashion. The
    search goes in the following order and considers only the DLLs with the
    given bitness.

    1. If not None, the directories in wheel_dirs.
    2. The PATH environment variable. (If we are on a case-sensitive file system
       and a directory contains more than one DLL with the correct bitness that
       differs by case only, then choose one arbitrarily.)
    3. On Windows, the Visual C++ 14.x runtime redistributable directory, if it
       exists."""
    name = name.lower()
    if wheel_dirs is not None:
        for wheel_dir in wheel_dirs:
            try:
                contents = os.listdir(wheel_dir)
            except FileNotFoundError:
                continue
            for item in contents:
                if name == item.lower():
                    path = os.path.join(wheel_dir, item)
                    if os.path.isfile(path) and get_bitness(path) == bitness:
                        return path
    for directory in os.environ['PATH'].split(os.pathsep):
        directory = _translate_directory(directory, bitness)
        try:
            contents = os.listdir(directory)
        except FileNotFoundError:
            continue
        for item in contents:
            if name == item.lower():
                path = os.path.join(directory, item)
                if os.path.isfile(path) and get_bitness(path) == bitness:
                    return path
    if sys.platform == 'win32':
        try:
            vcvars = setuptools.msvc.msvc14_get_vc_env('win_amd64' if bitness == 64 else 'win32')
            vcruntime = vcvars['py_vcruntime_redist']
            redist_dir = os.path.dirname(vcruntime)
            path = os.path.normpath(os.path.join(redist_dir, name))
            if os.path.isfile(path) and get_bitness(path) == bitness:
                return path
            return None
        except:
            return None
    return None


def get_direct_needed(lib_path: str, include_delay_imports: bool, lower: bool, verbose: int) -> set:
    """Given the path to a shared library, return a set containing the DLL
    names of all its direct dependencies.

    If include_delay_imports is True, delay-loaded dependencies are included.
    Otherwise, they are not included.

    If lower is True, the DLL names are all lowercase. Otherwise, they are in
    the original case."""
    with PEContext(lib_path, True, verbose) as pe:
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
            name = entry.dll.decode('utf-8')
            if lower:
                name = name.lower()
            needed.add(name)
    return needed


def get_direct_mangleable_needed(lib_path: str, no_dlls: set, no_mangles: set, verbose: int) -> set:
    """Given the path to a shared library, return a set containing the lowercase
    DLL names of all direct dependencies that belong in the wheel and should be
    name-mangled.

    no_dlls is a set of lowercase additional DLL names that do not belong in the
    wheel.

    no_mangles is a set of lowercase additional DLL names not to mangle."""
    with PEContext(lib_path, True, verbose) as pe:
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
                   no_dlls: set,
                   wheel_dirs: typing.Optional[typing.Iterable],
                   on_error: str,
                   verbose: int) -> typing.Tuple[typing.Set[str], typing.Set[str], typing.Set[str]]:
    """Given the path to a shared library, return a 3-tuple of sets
    (discovered, ignored, not_found).

    discovered contains the original-case DLL paths of all direct and indirect
    dependencies of that shared library that should be bundled into the wheel.
    ignored contains the lowercased DLL names of all direct and indirect
    dependencies of that shared library that will not be bundled into the wheel
    because they are assumed to be on the target system.

    If on_error is 'raise', FileNotFoundError is raised if a dependent library
    cannot be found. If on_error is 'ignore', not_found contains the lowercased
    DLL names of all dependent DLLs that cannot be found.

    no_dlls is a set of DLL names to force exclusion from the wheel. We do not
    search for dependencies of these DLLs. Cannot overlap with add_dlls.

    If wheel_dirs is not None, it is an iterable of directories in the wheel
    where dependencies are searched first."""
    first_lib_path = lib_path.lower()
    stack = [first_lib_path]
    discovered = set()
    ignored = set()
    not_found = set()
    while stack:
        lib_path = stack.pop()
        if lib_path not in discovered:
            discovered.add(lib_path)
            with PEContext(lib_path, True, verbose) as pe:
                imports = []
                for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                    if hasattr(pe, attr):
                        imports = itertools.chain(imports, getattr(pe, attr))
                lib_bitness = 64 if pe.FILE_HEADER.Machine == 34404 else 32
                ignore_names = dll_list.ignore_names_32 if lib_bitness == 32 else dll_list.ignore_names_64
                for entry in imports:
                    dll_name = entry.dll.decode('utf-8').lower()
                    if dll_name not in ignore_names and \
                            not any(r.search(dll_name) for r in dll_list.ignore_regexes) and \
                            dll_name not in no_dlls:
                        dll_path = find_library(dll_name, wheel_dirs, lib_bitness)
                        if dll_path:
                            stack.append(dll_path)
                        elif on_error == 'raise':
                            raise FileNotFoundError(f'Unable to find library: {dll_name}')
                        else:
                            not_found.add(dll_name)
                    else:
                        ignored.add(dll_name)
    discovered.remove(first_lib_path)
    return discovered, ignored, not_found


def replace_needed(lib_path: str, old_deps: typing.Iterable, name_map: dict, verbose: int) -> None:
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
                f'utility. Otherwise, include {os.pathsep.join(old_deps)} in '
                'the --no-mangle flag. In addition, if you believe that '
                'delvewheel should avoid name-mangling a specific DLL by '
                'default, open an issue at '
                'https://github.com/adang1345/delvewheel/issues and include '
                'this error message.') from None
        raise ex
    with open(lib_path, 'wb') as f:
        f.write(buf)
    with PEContext(lib_path, False, verbose) as pe:
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(lib_path)
