"""DLL file patching functions."""

import ctypes
import itertools
import os
import pathlib
import sys
import typing
import warnings
import setuptools.msvc
import pefile
import machomachomangler.pe
from . import _dll_list


pefile.fast_load = True


class PEContext:
    """Context manager for PE file."""
    def __init__(self, path: typing.Optional[str], data: typing.Optional[bytes], parse_imports: bool, verbose: int) -> None:
        """
        path: path to PE file
        data: byte string containing PE file data
        parse_imports: whether to parse the import table and delay import table
        verbose: verbosity level

        Exactly one of path and data must be non-None.
        """
        if path is data is None or path is not None and data is not None:
            raise ValueError('Exactly one of path and data must be provided')
        self._pe = pefile.PE(path, data)
        if parse_imports:
            self._pe.parse_data_directories([
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
            ], import_dllnames_only=True)
        self._name = 'None' if path is None else os.path.basename(path)
        self._verbose = verbose

    def __enter__(self) -> pefile.PE:
        return self._pe

    def __exit__(self, exc_type, exc_value, traceback):
        if self._verbose >= 2:
            for w in self._pe.get_warnings():
                print(f'{self._name}: {w}')
        self._pe.close()


def get_arch(path: str) -> str:
    """Return the architecture of a PE file. Possible architectures are 'x86',
    'x64', and 'arm64'. If the PE file is not one of these architectures,
    return ''.

    Implementation is based on the PE file specification at
    https://docs.microsoft.com/en-us/windows/win32/debug/pe-format."""
    with open(path, 'rb') as file:
        file.seek(0x3c)
        pe_signature_offset = int.from_bytes(file.read(4), 'little')
        file.seek(pe_signature_offset + 4)
        machine = file.read(2)
    if machine == b'L\x01':
        return 'x86'
    elif machine == b'd\x86':
        return 'x64'
    elif machine == b'd\xaa':
        return 'arm64'
    else:
        return ''


def _translate_directory() -> typing.Callable[[str, str], str]:
    """Closure that computes certain values once only for determining how to
    translate a directory when searching for DLLs on Windows.

    Returns a function translate_directory(directory: str, arch: str) -> str
    that performs directory translations. Given a directory to search for a DLL
    of the given architecture ('x86', 'x64', 'arm64'), translate the directory,
    taking the Windows file system redirector into account.

    See https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
    for more information about the Windows file system redirector.

    OS    | Python | Wheel | Action
    -------------------------------
    x86   | x86    | x86   | none
    x86   | x86    | x64   | none
    x86   | x86    | arm64 | none
    -------------------------------
    x64   | x86    | x86   | none
    x64   | x86    | x64   | redirect System32 to Sysnative
    x64   | x86    | arm64 | none
    -------------------------------
    x64   | x64    | x86   | redirect System32 to SysWOW64
    x64   | x64    | x64   | none
    x64   | x64    | arm64 | none
    -------------------------------
    arm64 | x86    | x86   | none
    arm64 | x86    | x64   | none
    arm64 | x86    | arm64 | redirect System32 to Sysnative
    -------------------------------
    arm64 | x64    | x86   | redirect System32 to SysWOW64
    arm64 | x64    | x64   | none
    arm64 | x64    | arm64 | none
    -------------------------------
    arm64 | arm64  | x86   | redirect System32 to SysWOW64
    arm64 | arm64  | x64   | none
    arm64 | arm64  | arm64 | none"""
    def null_translator(directory: str, arch: str) -> str:
        return directory
    if sys.platform != 'win32':
        # no file system redirection on non-Windows systems
        return null_translator

    # determine architecture of interpreter and OS
    kernel32 = ctypes.windll.kernel32
    interpreter_arch = get_arch(sys.executable)
    if not interpreter_arch:
        warnings.warn('Running delvewheel on this CPU architecture is not supported', RuntimeWarning)
        return null_translator
    if interpreter_arch == 'arm64':
        os_arch = 'arm64'
    elif hasattr(kernel32, 'IsWow64Process2'):
        process_machine = ctypes.c_ushort()
        native_machine = ctypes.c_ushort()
        if not kernel32.IsWow64Process2(ctypes.c_void_p(kernel32.GetCurrentProcess()), ctypes.byref(process_machine), ctypes.byref(native_machine)):
            raise OSError(f'Unable to determine whether WOW64 is active, Error={ctypes.FormatError()}')
        if not process_machine.value:
            os_arch = interpreter_arch
        elif native_machine.value == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            os_arch = 'x64'
        elif native_machine.value == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
            os_arch = 'arm64'
        else:
            raise OSError(f'Unexpected native machine type 0x{native_machine.value:04X}')
    elif hasattr(kernel32, 'IsWow64Process'):
        wow64_process = ctypes.c_int()
        if not kernel32.IsWow64Process(ctypes.c_void_p(kernel32.GetCurrentProcess()), ctypes.byref(wow64_process)):
            raise OSError(f'Unable to determine whether WOW64 is active, Error={ctypes.FormatError()}')
        os_arch = 'x64' if wow64_process.value else interpreter_arch
    else:
        os_arch = 'x86'

    # file system redirection map
    windir = os.environ.get('windir', r'C:\Windows')
    lastgood_system32 = fr'{windir}\lastgood\System32'
    redirect_map_system32_to_syswow64 = {
        fr'{windir}\System32': fr'{windir}\SysWOW64',
        lastgood_system32: fr'{windir}\lastgood\SysWOW64',
    }
    redirect_exceptions = [
        pathlib.Path(fr'{windir}\System32\catroot'),
        pathlib.Path(fr'{windir}\System32\catroot2'),
        pathlib.Path(fr'{windir}\System32\driverstore'),
        pathlib.Path(fr'{windir}\System32\drivers\etc'),
        pathlib.Path(fr'{windir}\System32\logfiles'),
        pathlib.Path(fr'{windir}\System32\spool'),
    ]
    redirect_map_system32_to_sysnative = {
        fr'{windir}\System32': fr'{windir}\Sysnative',
    }

    def translate_system32_to_syswow64(directory: str) -> str:
        """Perform file system redirection manually. Use when the Python
        interpreter running delvewheel is not subject to redirection but the
        interpreter that runs the wheel would be subject to redirection on this
        machine."""
        if any(redirect_exception == pathlib.Path(directory) or redirect_exception in pathlib.Path(directory).parents for redirect_exception in redirect_exceptions):
            return directory
        directory = os.path.normpath(directory)
        for start_dir in redirect_map_system32_to_syswow64:
            if directory.lower().startswith(start_dir.lower()):
                end_dir = redirect_map_system32_to_syswow64[start_dir] + directory[len(start_dir):]
                return end_dir
        return directory

    def translate_system32_to_sysnative(directory: str) -> str:
        """Bypass file system redirection. Use when the Python interpreter
        running delvewheel is subject to redirection but the interpreter that
        runs the wheel would not be subject to redirection on this machine."""
        directory = os.path.normpath(directory)
        for start_dir in redirect_map_system32_to_sysnative:
            if directory.lower().startswith(start_dir.lower()):
                end_dir = redirect_map_system32_to_sysnative[start_dir] + directory[len(start_dir):]
                return end_dir
        if directory.lower().startswith(lastgood_system32.lower()):
            warnings.warn(f'{lastgood_system32} is ignored in DLL search path due to technical limitations', RuntimeWarning)
        return directory

    if os_arch == 'x64' and interpreter_arch == 'x86':
        return lambda directory, arch: translate_system32_to_sysnative(directory) if arch == 'x64' else directory
    elif os_arch == 'arm64' and interpreter_arch == 'x86':
        return lambda directory, arch: translate_system32_to_sysnative(directory) if arch == 'arm64' else directory
    elif os_arch != 'x86' != interpreter_arch:
        return lambda directory, arch: translate_system32_to_syswow64(directory) if arch == 'x86' else directory
    return null_translator


_translate_directory = _translate_directory()


def find_library(name: str, wheel_dirs: typing.Optional[typing.Iterable], arch: str) -> typing.Optional[str]:
    """Given the name of a DLL, return the path to the DLL, or None if the DLL
    cannot be found. DLL names are searched in a case-insensitive fashion. The
    search goes in the following order and considers only the DLLs with the
    given architecture.

    1. If not None, the directories in wheel_dirs.
    2. The PATH environment variable. (If we are on a case-sensitive file
       system and a directory contains more than one DLL with the correct
       architecture that differs by case only, then choose one arbitrarily.)
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
                    if os.path.isfile(path) and get_arch(path) == arch:
                        return path
    for directory in os.environ['PATH'].split(os.pathsep):
        directory = _translate_directory(directory, arch)
        try:
            contents = os.listdir(directory)
        except FileNotFoundError:
            continue
        for item in contents:
            if name == item.lower():
                path = os.path.join(directory, item)
                if os.path.isfile(path) and get_arch(path) == arch:
                    return path
    if sys.platform == 'win32':
        if arch == 'x86':
            plat_spec = 'win32'
        elif arch == 'x64':
            plat_spec = 'x86_amd64'
        else:
            plat_spec = 'x86_arm64'
        try:
            vcvars = setuptools.msvc.msvc14_get_vc_env(plat_spec)
            vcruntime = vcvars['py_vcruntime_redist']
            redist_dir = os.path.dirname(vcruntime)
            path = os.path.normpath(os.path.join(redist_dir, name))
            if os.path.isfile(path) and get_arch(path) == arch:
                return path
            return None
        except Exception:
            return None
    return None


def get_direct_needed(lib_path: str, include_delay_imports: bool, lower: bool, verbose: int) -> set:
    """Given the path to a shared library, return a set containing the DLL
    names of all its direct dependencies.

    If include_delay_imports is True, delay-loaded dependencies are included.
    Otherwise, they are not included.

    If lower is True, the DLL names are all lowercase. Otherwise, they are in
    the original case."""
    with PEContext(lib_path, None, True, verbose) as pe:
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
    with PEContext(lib_path, None, True, verbose) as pe:
        imports = []
        for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            if hasattr(pe, attr):
                imports = itertools.chain(imports, getattr(pe, attr))
        needed = set()
        if pe.FILE_HEADER.Machine == 0x014c:
            ignore_names = _dll_list.ignore_names_x86
        elif pe.FILE_HEADER.Machine == 0x8664:
            ignore_names = _dll_list.ignore_names_x64
        else:
            ignore_names = _dll_list.ignore_names_arm64
        for entry in imports:
            dll_name = entry.dll.decode('utf-8').lower()
            if dll_name not in ignore_names and \
                    dll_name not in no_dlls and \
                    not any(r.search(dll_name) for r in _dll_list.ignore_regexes) and \
                    dll_name not in no_mangles and \
                    not any(dll_name.startswith(prefix) for prefix in _dll_list.no_mangle_prefixes):
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
            with PEContext(lib_path, None, True, verbose) as pe:
                imports = []
                for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                    if hasattr(pe, attr):
                        imports = itertools.chain(imports, getattr(pe, attr))
                if pe.FILE_HEADER.Machine == 0x014c:
                    lib_arch = 'x86'
                    ignore_names = _dll_list.ignore_names_x86
                elif pe.FILE_HEADER.Machine == 0x8664:
                    lib_arch = 'x64'
                    ignore_names = _dll_list.ignore_names_x64
                else:
                    lib_arch = 'arm64'
                    ignore_names = _dll_list.ignore_names_arm64
                for entry in imports:
                    dll_name = entry.dll.decode('utf-8').lower()
                    if dll_name not in ignore_names and \
                            not any(r.search(dll_name) for r in _dll_list.ignore_regexes) and \
                            dll_name not in no_dlls:
                        dll_path = find_library(dll_name, wheel_dirs, lib_arch)
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
        buf = bytes(machomachomangler.pe.redll(buf, used_name_map))
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
    with PEContext(None, buf, False, verbose) as pe:
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        buf = pe.write()
    with open(lib_path, 'wb') as f:
        f.write(buf)
