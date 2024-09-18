"""Utilities for analyzing and patching DLL files."""

import ctypes
import ctypes.wintypes
import errno
import io
import itertools
import os
import pathlib
import re
import struct
import subprocess
import sys
import textwrap
import typing
import warnings
import pefile
from . import _dll_list
from ._dll_list import MachineType


pefile.fast_load = True
_SECTION_HEADER_FORMAT = (
    '<'   # little-endian
    '8s'  # Name
    'I'   # VirtualSize
    'I'   # VirtualAddress
    'I'   # SizeOfRawData
    'I'   # PointerToRawData
    'I'   # PointerToRelocations
    'I'   # PointerToLinenumbers
    'H'   # NumberOfRelocations
    'H'   # NumberOfLinenumbers
    'I'   # Characteristics
)
_SECTION_HEADER_SIZE = struct.calcsize(_SECTION_HEADER_FORMAT)
_NEW_SECTION_CHARACTERISTICS = pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']
_ATTRIBUTE_CERTIFICATE_TABLE_ALIGNMENT = 8


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
        if (path is None) == (data is None):
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


def get_arch(path: str) -> typing.Optional[MachineType]:
    """Return the architecture of a PE file. If the PE file is not for a
    supported architecture, return None.

    Implementation is based on the PE file specification at
    https://docs.microsoft.com/en-us/windows/win32/debug/pe-format."""
    with open(path, 'rb') as file:
        file.seek(0x3c)
        pe_signature_offset = int.from_bytes(file.read(4), 'little')
        file.seek(pe_signature_offset + 4)
        machine = int.from_bytes(file.read(2), 'little')
    return MachineType.machine_field_to_type(machine)


def get_interpreter_arch() -> MachineType:
    """Return the architecture of the currently running interpreter.
    Precondition: We are running on Windows."""
    try:
        return get_arch(sys.executable)
    except OSError as e:
        if e.errno != errno.EINVAL:
            raise
        # For Windows Store version of Python, sys.executable is an
        # application execution alias that can't be read directly. Use
        # GetModuleFileNameW() to get executable path instead.
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.GetModuleFileNameW.restype = ctypes.wintypes.DWORD
        kernel32.GetModuleFileNameW.argtypes = ctypes.wintypes.HMODULE, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD

        size = 256
        while size <= 32768:
            filename = ctypes.create_unicode_buffer(size)
            if not kernel32.GetModuleFileNameW(None, filename, size):
                raise OSError(ctypes.FormatError(ctypes.get_last_error())) from None
            elif ctypes.get_last_error() != 122:  # ERROR_INSUFFICIENT_BUFFER
                return get_arch(filename.value)
            size *= 2
        raise OSError('Insufficient buffer size 32768 for GetModuleFileNameW()') from None


def _translate_directory() -> typing.Callable[[str, MachineType], str]:
    """Closure that computes certain values once only for determining how to
    translate a directory when searching for DLLs on Windows.

    Returns a function translate_directory(directory: str, arch: MachineType) -> str
    that performs directory translations. Given a directory to search for a DLL
    of the given architecture, translate the directory, taking the Windows file
    system redirector into account.

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
    def null_translator(directory: str, arch: MachineType) -> str:
        return directory
    if sys.platform != 'win32':
        # no file system redirection on non-Windows systems
        return null_translator

    # determine architecture of interpreter and OS
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    interpreter_arch = get_interpreter_arch()
    if not interpreter_arch:
        # file system redirection rules are unknown
        return null_translator
    if interpreter_arch is MachineType.ARM64:
        os_arch = MachineType.ARM64
    elif hasattr(kernel32, 'IsWow64Process2'):
        process_machine = ctypes.wintypes.USHORT()
        native_machine = ctypes.wintypes.USHORT()
        kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
        kernel32.IsWow64Process2.restype = ctypes.wintypes.BOOL
        kernel32.IsWow64Process2.argtypes = ctypes.wintypes.HANDLE, ctypes.wintypes.PUSHORT, ctypes.wintypes.PUSHORT
        if not kernel32.IsWow64Process2(kernel32.GetCurrentProcess(), process_machine, native_machine):
            raise OSError(f'Unable to determine whether WOW64 is active, Error={ctypes.FormatError(ctypes.get_last_error())}')
        if not process_machine.value:
            os_arch = interpreter_arch
        else:
            os_arch = MachineType.machine_field_to_type(native_machine.value)
        if not os_arch:
            raise OSError(f'Unexpected native machine type 0x{native_machine.value:04X}')
    elif hasattr(kernel32, 'IsWow64Process'):
        wow64_process = ctypes.wintypes.BOOL()
        kernel32.IsWow64Process.restype = ctypes.wintypes.BOOL
        kernel32.IsWow64Process.argtypes = ctypes.wintypes.HANDLE, ctypes.wintypes.PBOOL
        if not kernel32.IsWow64Process(kernel32.GetCurrentProcess(), wow64_process):
            raise OSError(f'Unable to determine whether WOW64 is active, Error={ctypes.FormatError(ctypes.get_last_error())}')
        os_arch = MachineType.AMD64 if wow64_process.value else interpreter_arch
    else:
        os_arch = MachineType.I386

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
            warnings.warn(f'{lastgood_system32} is ignored in DLL search path due to technical limitations')
        return directory

    if os_arch is MachineType.AMD64 and interpreter_arch is MachineType.I386:
        return lambda directory, arch: translate_system32_to_sysnative(directory) if arch is MachineType.AMD64 else directory
    elif os_arch is MachineType.ARM64 and interpreter_arch is MachineType.I386:
        return lambda directory, arch: translate_system32_to_sysnative(directory) if arch is MachineType.ARM64 else directory
    elif os_arch is not MachineType.I386 is not interpreter_arch:
        return lambda directory, arch: translate_system32_to_syswow64(directory) if arch is MachineType.I386 else directory
    return null_translator


_translate_directory = _translate_directory()


def find_library(
        name: str,
        wheel_dirs: typing.Optional[typing.Iterable],
        arch: MachineType,
        include_symbols: bool,
        include_imports: bool) -> typing.Optional[typing.Tuple[str, typing.List[str]]]:
    """Given the name of a DLL, return a tuple where
    - the 1st element is the path to the DLL
    - the 2nd element is a list that may contain paths to the .pdb symbol file
      and/or the .lib import library file associated with the DLL. If
      include_symbols is True, then search for the .pdb symbol file. If
      include_imports is True, then search for the .lib import library file.
      Excluding the file extension, the name of the associated file is assumed
      to be the same as the name of the DLL.

    If the DLL cannot be found, then return None. All file names are searched
    in a case-insensitive fashion. If we are on a case-sensitive file system
    and a directory contains more than one file whose name matches what we're
    searching for, and the file names differ by case only, then choose one
    arbitrarily. The search goes in the following order and considers only the
    DLLs with the architecture arch.

    1. If not None, the directories in wheel_dirs. We never search for symbol
       files or import library files in wheel_dirs.
    2. The PATH environment variable, with any applicable adjustments due to
       the Windows file system redirector."""
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
                        return path, []
    for directory in os.environ['PATH'].split(os.pathsep):
        directory = _translate_directory(directory, arch)
        try:
            contents = os.listdir(directory)
        except FileNotFoundError:
            continue
        dll_path = None
        for item in contents:
            if name == item.lower():
                path = os.path.join(directory, item)
                if os.path.isfile(path) and get_arch(path) == arch:
                    dll_path = path
                    break
        associated_paths = []
        if include_symbols:
            symbol_name = os.path.splitext(name)[0] + '.pdb'
            for item in contents:
                if symbol_name == item.lower():
                    path = os.path.join(directory, item)
                    if os.path.isfile(path):
                        associated_paths.append(path)
                        break
        if include_imports:
            imports_name = os.path.splitext(name)[0] + '.lib'
            for item in contents:
                if imports_name == item.lower():
                    path = os.path.join(directory, item)
                    if os.path.isfile(path):
                        associated_paths.append(path)
                        break
        if dll_path:
            return dll_path, associated_paths
    return None


def get_direct_needed(lib_path: str, verbose: int) -> set:
    """Given the path to a shared library, return a set containing the DLL
    names of all its direct dependencies. Regular and delay-load dependencies
    are included. The DLL names are in the original case."""
    with PEContext(lib_path, None, True, verbose) as pe:
        imports = []
        for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            if hasattr(pe, attr):
                imports = itertools.chain(imports, getattr(pe, attr))
        lib_name_lower = os.path.basename(lib_path).lower()
        needed = set()
        for entry in imports:
            name = entry.dll.decode()
            if lib_name_lower not in _dll_list.ignore_dependency or name.lower() not in _dll_list.ignore_dependency[lib_name_lower]:
                needed.add(name)
    return needed


def get_direct_mangleable_needed(lib_path: str, exclude: set, no_mangles: set, verbose: int) -> list:
    """Given the path to a shared library, return a deterministically-ordered
    list containing the lowercase DLL names of all direct dependencies that
    belong in the wheel and should be name-mangled.

    exclude is a set of lowercase additional DLL names that do not belong in
    the wheel.

    no_mangles is a set of lowercase additional DLL names not to mangle."""
    with PEContext(lib_path, None, True, verbose) as pe:
        imports = []
        for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            if hasattr(pe, attr):
                imports = itertools.chain(imports, getattr(pe, attr))
        needed = []
        lib_arch = MachineType.machine_field_to_type(pe.FILE_HEADER.Machine)
        if not lib_arch:
            raise ValueError(f'{lib_path} has an unsupported CPU architecture')
        ignore_names = _dll_list.ignore_names[lib_arch]
        lib_name_lower = os.path.basename(lib_path).lower()
        for entry in imports:
            dll_name = entry.dll.decode().lower()
            if dll_name not in ignore_names and \
                    dll_name not in exclude and \
                    not any(r.fullmatch(dll_name) for r in _dll_list.ignore_regexes) and \
                    dll_name not in no_mangles and \
                    (lib_name_lower not in _dll_list.ignore_dependency or dll_name not in _dll_list.ignore_dependency[lib_name_lower]) and \
                    not any(r.fullmatch(dll_name) for r in _dll_list.no_mangle_regexes):
                needed.append(dll_name)
    return needed


def _toolset_too_old(linker_version: typing.Tuple[int, int], vc_redist_linker_version: typing.Tuple[int, int]) -> bool:
    """Given the linker version of a DLL and the linker version of a Visual C++
    runtime redistributable DLL, return True iff the Visual C++ runtime
    redistributable DLL comes from an older platform toolset than that which
    was used to build the DLL.

    There are certain linker versions where there is ambiguity. The DLL and the
    Visual C++ runtime redistributable DLL might be associated with the same
    platform toolset version. Or the DLL was built against the earliest release
    of a platform toolset and the Visual C++ runtime redistributable DLL comes
    from the latest release of the previous version of the platform toolset. In
    this situation, assume that the toolset is not too old."""
    # cutoffs obtained from https://github.com/abbodi1406/vcredist/blob/master/source_links/README.md
    cutoffs = [
        (14, 30),  # earliest for Visual Studio 2022
        (14, 20),  # earliest for Visual Studio 2019, latest for 2017
        (14, 10),  # earliest for Visual Studio 2017, latest for 2015
    ]
    return any(vc_redist_linker_version < cutoff <= linker_version for cutoff in cutoffs)


def get_all_needed(lib_path: str,
                   exclude: set,
                   wheel_dirs: typing.Optional[typing.Iterable],
                   on_error: str,
                   include_symbols: bool,
                   include_imports: bool,
                   verbose: int) -> typing.Tuple[typing.Set[str], typing.Set[str], typing.Set[str], typing.Set[str]]:
    """Given the path to a shared library, return a 4-tuple of sets
    (discovered, symbols, ignored, not_found).
    - discovered contains the original-case DLL paths of all direct and
      indirect dependencies of that shared library that should be bundled into
      the wheel.
    - associated contains the original-case paths of any .pdb or .lib files
      corresponding to the DLLs in discovered.
    - ignored contains the lowercased DLL names of all direct and indirect
      dependencies of that shared library that will not be bundled into the
      wheel because they are assumed to be on the target system.
    - If on_error is 'raise', FileNotFoundError is raised if a dependent
      library cannot be found. If on_error is 'ignore', not_found contains the
      lowercased DLL names of all dependent DLLs that cannot be found.

    exclude is a set of DLL names to force exclusion from the wheel. We do not
    search for dependencies of these DLLs.

    If wheel_dirs is not None, it is an iterable of directories in the wheel
    where dependencies are searched first.

    include_symbols specifies whether to search for .pdb symbol files

    include_imports specifies whether to search for .lib import library
    files"""
    first_lib_path = lib_path.lower()
    stack = [first_lib_path]
    discovered = set()
    associated = set()
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
                lib_arch = MachineType.machine_field_to_type(pe.FILE_HEADER.Machine)
                if not lib_arch:
                    raise ValueError(f'{lib_path} has an unsupported CPU architecture')
                ignore_names = _dll_list.ignore_names[lib_arch]
                lib_name_lower = os.path.basename(lib_path).lower()
                for entry in imports:
                    dll_name = entry.dll.decode().lower()
                    if dll_name not in ignore_names and \
                            not any(r.fullmatch(dll_name) for r in _dll_list.ignore_regexes) and \
                            dll_name not in exclude and \
                            (lib_name_lower not in _dll_list.ignore_dependency or dll_name not in _dll_list.ignore_dependency[lib_name_lower]):
                        dll_info = find_library(dll_name, wheel_dirs, lib_arch, include_symbols, include_imports)
                        if dll_info:
                            stack.append(dll_info[0])
                            associated.update(dll_info[1])
                            if re.fullmatch(_dll_list.vc_redist, dll_name):
                                # warn if potentially incompatible MSVC++
                                # library is found
                                linker_version = pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion
                                with PEContext(dll_info[0], None, False, verbose) as pe2:
                                    vc_redist_linker_version = pe2.OPTIONAL_HEADER.MajorLinkerVersion, pe2.OPTIONAL_HEADER.MinorLinkerVersion
                                if _toolset_too_old(linker_version, vc_redist_linker_version):
                                    linker_version = f'{linker_version[0]}.{linker_version[1]}'
                                    vc_redist_linker_version = f'{vc_redist_linker_version[0]}.{vc_redist_linker_version[1]}'
                                    warnings.warn(f'{os.path.basename(lib_path)} was built with a newer platform toolset ({linker_version}) than the discovered {os.path.basename(dll_info[0])} ({vc_redist_linker_version}). This may cause compatibility issues.')
                        elif on_error == 'raise':
                            raise FileNotFoundError(f'Unable to find library: {dll_name}')
                        else:
                            not_found.add(dll_name)
                    else:
                        ignored.add(dll_name)
    discovered.remove(first_lib_path)
    return discovered, associated, ignored, not_found


def clear_dependent_load_flags(lib_path: str, verbose: int):
    """If the DLL given by lib_path has a non-0 value for DependentLoadFlags,
    then set the value to 0, fix the PE checksum, and clear any signatures.

    lib_path: path to the DLL
    verbose: verbosity level, 0 to 2"""
    with PEContext(lib_path, None, False, verbose) as pe:
        pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']])
        if not hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') or not pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags:
            return
        if verbose >= 1:
            print(f'clearing DependentLoadFlags={pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags:#x} for {os.path.basename(lib_path)}')
        pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags = 0

        # determine whether to remove signatures from overlay
        pe_size = max(section.PointerToRawData + section.SizeOfRawData for section in pe.sections)
        cert_table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        truncate = cert_table.VirtualAddress == _round_to_next(pe_size, _ATTRIBUTE_CERTIFICATE_TABLE_ALIGNMENT) and cert_table.VirtualAddress + cert_table.Size == os.path.getsize(lib_path)

        # clear reference to attribute certificate table if it exists
        cert_table.VirtualAddress = 0
        cert_table.Size = 0

        fix_checksum = bool(pe.OPTIONAL_HEADER.CheckSum)
        lib_data = pe.write()

    if truncate:
        lib_data = lib_data[:pe_size]
    if fix_checksum:
        with PEContext(None, lib_data, False, verbose) as pe:
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            pe.write(lib_path)
    else:
        with open(lib_path, 'wb') as f:
            f.write(lib_data)


def _round_to_next(size: int, alignment: int) -> int:
    """Return smallest n such that n % alignment == 0 and n >= size."""
    if size % alignment == 0:
        return size
    else:
        return alignment * (size // alignment + 1)


def _are_characteristics_suitable(section: pefile.SectionStructure) -> bool:
    """Determine whether a PE section is suitable for writing new DLL names."""
    return (not section.IMAGE_SCN_CNT_CODE and
            section.IMAGE_SCN_CNT_INITIALIZED_DATA and
            not section.IMAGE_SCN_CNT_UNINITIALIZED_DATA and
            not section.IMAGE_SCN_GPREL and
            not section.IMAGE_SCN_LNK_NRELOC_OVFL and
            not section.IMAGE_SCN_MEM_DISCARDABLE and
            not section.IMAGE_SCN_MEM_EXECUTE and
            section.IMAGE_SCN_MEM_READ)


def _get_pe_size_and_enough_padding(pe: pefile.PE, new_dlls: typing.Iterable[bytes]) -> typing.Tuple[int, bool]:
    """Determine the size of a PE file (excluding any overlay) and whether the
    file has enough padding for writing the elements of new_dlls.

    Determining whether the file has enough padding is an instance of the NP-
    complete bin packing problem, so we use the Next Fit approximation
    algorithm. new_dlls must be in a deterministic order in order for the Next
    Fit algorithm to return a deterministic result.

    Side effect: pe.sections is sorted by VirtualAddress. In most cases this
    should make no difference because the PE specification requires that the
    sections be ordered by VirtualAddress.

    Precondition: pe must have at least 1 DLL dependency"""
    pe_size = 0
    new_dlls = list(new_dlls)
    dlls_i = 0
    pe.sections.sort(key=lambda section: section.VirtualAddress)
    for section_i, section in enumerate(pe.sections):
        pe_size = max(pe_size, section.PointerToRawData + section.SizeOfRawData)
        if dlls_i < len(new_dlls) and section.Misc_VirtualSize < section.SizeOfRawData and _are_characteristics_suitable(section):
            padding_size = section.SizeOfRawData - section.Misc_VirtualSize
            if section_i + 1 < len(pe.sections):
                padding_size = min(padding_size, pe.sections[section_i + 1].VirtualAddress - section.VirtualAddress - section.Misc_VirtualSize)
            while dlls_i < len(new_dlls) and len(new_dlls[dlls_i]) < padding_size:
                padding_size -= len(new_dlls[dlls_i]) + 1
                dlls_i += 1
    return pe_size, dlls_i == len(new_dlls)


def replace_needed(lib_path: str, old_deps: typing.List[str], name_map: typing.Dict[str, str], strip: bool, verbose: int, test: typing.List[str]) -> None:
    """For the DLL at lib_path, replace its declared dependencies on old_deps
    with those in name_map. Also, if the DLL has a non-0 value for
    DependentLoadFlags, then set the value to 0

    old_deps: a subset of the dependencies that lib_path has, in list form. Can
        be empty, in which case the only thing we do is clear the
        DependentLoadFlags value if it's non-0.
    name_map: a dict that maps an old dependency name to a new name, must
        contain at least all the keys in old_deps
    strip: whether to try to strip DLLs that contain overlays if not enough
        internal padding exists
    verbose: verbosity level, 0 to 2
    test: testing options for internal use"""
    if not old_deps:
        # no dependency names to change
        clear_dependent_load_flags(lib_path, verbose)
        return
    name_map = {dep.lower().encode('utf-8'): name_map[dep].encode('utf-8') for dep in old_deps}
        # keep only the DLLs that will be mangled

    # If an attribute certificate table exists and is the only thing in the
    # overlay, remove the table. In this case, we end up removing the entire
    # overlay without needing to run strip.
    with PEContext(lib_path, None, False, verbose) as pe:
        pe_size = max(section.PointerToRawData + section.SizeOfRawData for section in pe.sections)
        cert_table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        truncate = cert_table.VirtualAddress == _round_to_next(pe_size, _ATTRIBUTE_CERTIFICATE_TABLE_ALIGNMENT) and cert_table.VirtualAddress + cert_table.Size == os.path.getsize(lib_path)
    if truncate:
        with open(lib_path, 'rb+') as f:
            f.truncate(pe_size)

    # New dependency names are longer than the old ones, so we cannot simply
    # overwrite the bytes of the old dependency names. Determine whether the PE
    # file has enough usable internal padding to use to write the new
    # dependency names. If so, overwrite the padding. Otherwise, as long as the
    # PE file contains no overlay or the overlay can be stripped, append a new
    # PE section to store the new names. Determining whether enough internal
    # padding exists is an instance of the bin packing problem in which the new
    # dependency names are items and the contiguous padding runs are bins. The
    # bin packing problem is NP-hard, so for simplicity, we use the Next Fit
    # algorithm.
    with PEContext(lib_path, None, False, verbose) as pe:
        pe_size, enough_padding = _get_pe_size_and_enough_padding(pe, name_map.values())
    if 'not_enough_padding' in test:
        enough_padding = False
    if not enough_padding and pe_size < os.path.getsize(lib_path) and strip:
        # try to strip the overlay
        try:
            subprocess.check_call(['strip', '-s', lib_path])
        except FileNotFoundError:
            raise FileNotFoundError('GNU strip not found in PATH') from None
        with PEContext(lib_path, None, False, verbose) as pe:
            pe_size, enough_padding = _get_pe_size_and_enough_padding(pe, name_map.values())

    lib_name = os.path.basename(lib_path)
    if not enough_padding and pe_size < os.path.getsize(lib_path):
        # cannot rename dependencies due to overlay
        if strip:
            raise RuntimeError(textwrap.fill(
                f'Unable to rename the dependencies of {lib_name} because '
                'this DLL does not contain enough internal padding to fit the '
                'new dependency names, and it contains an overlay. The GNU '
                'strip utility was run automatically in attempt to remove the '
                'overlay but failed to remove all of it. Unless you have '
                'knowledge to the contrary, you should assume that the '
                'overlay exists for an important reason and is not safe to '
                f'remove. Include {os.pathsep.join(old_deps)} in the '
                '--no-mangle flag to fix this error.',
                initial_indent=' ' * len('RuntimeError: ')).lstrip())
        else:
            error_text = [
                textwrap.fill(
                    f'Unable to rename the dependencies of {lib_name} because '
                    'this DLL does not contain enough internal padding to fit '
                    'the new dependency names, and it contains an overlay. '
                    'Commonly, the overlay consists of symbols that can be '
                    'safely removed, although there exist situations where '
                    'the data must be present for the DLL to function '
                    'properly. Here are your options.',
                    initial_indent=' ' * len('RuntimeError: ')).lstrip(),
                '\n',
                textwrap.fill(
                    '- Try to remove the overlay using the GNU strip '
                    f"utility with the command `strip -s {lib_name}'.",
                    subsequent_indent='  '
                ),
                '\n',
                textwrap.fill(
                    '- Use the --strip flag to ask delvewheel to execute '
                    'strip automatically when an overlay is detected.',
                    subsequent_indent='  '
                ),
                '\n',
                textwrap.fill(
                    f'- Include {os.pathsep.join(old_deps)} in the '
                    '--no-mangle flag.',
                    subsequent_indent='  '
                )
            ]
            raise RuntimeError(''.join(error_text))

    with PEContext(lib_path, None, True, verbose) as pe:
        if enough_padding:
            # overwrite padding with new DLL names
            pe.sections.sort(key=lambda section: section.VirtualAddress)
            new_dlls_rva_mapping = {}  # map lowercase old DLL name to rva of new DLL name
            old_new_dlls = list(name_map.items())
            dlls_i = 0
            for section_i, section in enumerate(pe.sections):
                rva = section.VirtualAddress + section.Misc_VirtualSize
                if (section.Misc_VirtualSize < section.SizeOfRawData and
                        (section_i + 1 == len(pe.sections) or rva < pe.sections[section_i + 1].VirtualAddress)
                        and _are_characteristics_suitable(section)):
                    file_offset = section.PointerToRawData + section.Misc_VirtualSize
                    while (dlls_i < len(old_new_dlls) and
                           file_offset + len(old_new_dlls[dlls_i][1]) < section.PointerToRawData + section.SizeOfRawData and
                           (section_i + 1 == len(pe.sections) or rva + len(old_new_dlls[dlls_i][1]) < pe.sections[section_i + 1].VirtualAddress)):
                        old_dll, new_dll = old_new_dlls[dlls_i]
                        pe.set_bytes_at_offset(file_offset, new_dll + b'\x00')
                        new_dlls_rva_mapping[old_dll] = rva
                        new_dll_size = len(new_dll) + 1
                        section.Misc_VirtualSize += new_dll_size
                        rva += new_dll_size
                        file_offset += new_dll_size
                        dlls_i += 1
                    if dlls_i == len(old_new_dlls):
                        break
            else:
                raise RuntimeError('Expected enough internal padding to write new DLL names but ran out of space when writing them')

            # update headers and import tables
            pe.OPTIONAL_HEADER.SizeOfInitializedData = sum(max(section.SizeOfRawData, _round_to_next(section.Misc_VirtualSize, pe.OPTIONAL_HEADER.FileAlignment)) for section in pe.sections if section.IMAGE_SCN_CNT_INITIALIZED_DATA)
            pe.OPTIONAL_HEADER.SizeOfImage = _round_to_next(pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    old_dll = entry.dll.lower()
                    if old_dll in new_dlls_rva_mapping:
                        entry.struct.Name = new_dlls_rva_mapping[old_dll]
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    old_dll = entry.dll.lower()
                    if old_dll in new_dlls_rva_mapping:
                        entry.struct.szName = new_dlls_rva_mapping[old_dll]
        else:  # not enough_padding
            # generate data containing strings for new DLL names
            new_section_offset_mapping = {}  # map lowercase old DLL name to offset of new DLL name within new section
            with io.BytesIO() as new_section_data:
                for old_dll, new_dll in name_map.items():
                    new_section_offset_mapping[old_dll] = new_section_data.tell()
                    new_section_data.write(new_dll)
                    new_section_data.write(b'\x00')
                new_section_data = new_section_data.getvalue()

            # update PE headers to what they will need to be once the
            # new section header and new section are added
            section_table_end = pe.sections[-1].get_file_offset() + _SECTION_HEADER_SIZE
            if 'header_space' not in test and pe.OPTIONAL_HEADER.SizeOfHeaders - section_table_end >= _SECTION_HEADER_SIZE:
                # there's enough unused space to add new section header
                new_section_header_space_needed = 0
            else:
                # There's not enough unused space to add new section header;
                # calculate how much extra space to add. In nearly all cases,
                # FileAlignment extra bytes will be added.
                new_section_header_space_needed = _round_to_next(_SECTION_HEADER_SIZE, pe.OPTIONAL_HEADER.FileAlignment)
            new_section_data_size = len(new_section_data)
            new_section_data_padded_size = _round_to_next(new_section_data_size, pe.OPTIONAL_HEADER.FileAlignment)
            new_section_rva = _round_to_next(max(section.VirtualAddress + section.Misc_VirtualSize for section in pe.sections), pe.OPTIONAL_HEADER.SectionAlignment)

            pe.FILE_HEADER.NumberOfSections += 1
            pe.OPTIONAL_HEADER.SizeOfInitializedData += new_section_data_padded_size
            pe.OPTIONAL_HEADER.SizeOfImage = _round_to_next(new_section_rva + new_section_data_size, pe.OPTIONAL_HEADER.SectionAlignment)
            pe.OPTIONAL_HEADER.SizeOfHeaders += new_section_header_space_needed
            for section in pe.sections:
                section.PointerToRawData += new_section_header_space_needed

            # update import tables
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    old_dll = entry.dll.lower()
                    if old_dll in new_section_offset_mapping:
                        entry.struct.Name = new_section_rva + new_section_offset_mapping[old_dll]
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    old_dll = entry.dll.lower()
                    if old_dll in new_section_offset_mapping:
                        entry.struct.szName = new_section_rva + new_section_offset_mapping[old_dll]

        # clear reference to attribute certificate table if it exists
        cert_table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        cert_table.VirtualAddress = 0
        cert_table.Size = 0

        # clear DependentLoadFlags value
        pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']])
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags:
            if verbose >= 1:
                print(f'clearing DependentLoadFlags={pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags:#x} for {os.path.basename(lib_path)}')
            pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags = 0

        # all changes to headers are done; serialize the PE file
        fix_checksum = bool(pe.OPTIONAL_HEADER.CheckSum)
        lib_data = pe.write()

        if not enough_padding:
            # add new section header and new section
            with io.BytesIO() as new_lib_data:
                new_lib_data.write(lib_data[:section_table_end])
                new_section_header = struct.pack(
                    _SECTION_HEADER_FORMAT,
                    b'dlvwhl',  # Name
                    new_section_data_size,  # VirtualSize
                    new_section_rva,  # VirtualAddress
                    new_section_data_padded_size,  # SizeOfRawData
                    len(lib_data) + new_section_header_space_needed,  # PointerToRawData
                    0,  # PointerToRelocations
                    0,  # PointerToLinenumbers
                    0,  # NumberOfRelocations
                    0,  # NumberOfLinenumbers
                    _NEW_SECTION_CHARACTERISTICS  # Characteristics
                )
                new_lib_data.write(new_section_header)
                if new_section_header_space_needed:
                    new_lib_data.write(b'\x00' * (new_section_header_space_needed - _SECTION_HEADER_SIZE))
                    new_lib_data.write(lib_data[section_table_end:])
                else:
                    new_lib_data.write(lib_data[section_table_end + _SECTION_HEADER_SIZE:])
                new_lib_data.write(new_section_data)
                new_lib_data.write(b'\x00' * (new_section_data_padded_size - new_section_data_size))
                lib_data = new_lib_data.getvalue()

    if fix_checksum:
        with PEContext(None, lib_data, False, verbose) as pe:
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            pe.write(lib_path)
    else:
        with open(lib_path, 'wb') as f:
            f.write(lib_data)
