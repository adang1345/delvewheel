"""Utilities for analyzing and patching DLL files."""

import ctypes
import io
import itertools
import os
import pathlib
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
    kernel32 = ctypes.windll.kernel32
    interpreter_arch = get_arch(sys.executable)
    if not interpreter_arch:
        # file system redirection rules are unknown
        return null_translator
    if interpreter_arch is MachineType.ARM64:
        os_arch = MachineType.ARM64
    elif hasattr(kernel32, 'IsWow64Process2'):
        process_machine = ctypes.c_ushort()
        native_machine = ctypes.c_ushort()
        if not kernel32.IsWow64Process2(ctypes.c_void_p(kernel32.GetCurrentProcess()), ctypes.byref(process_machine), ctypes.byref(native_machine)):
            raise OSError(f'Unable to determine whether WOW64 is active, Error={ctypes.FormatError()}')
        if not process_machine.value:
            os_arch = interpreter_arch
        else:
            os_arch = MachineType.machine_field_to_type(native_machine.value)
        if not os_arch:
            raise OSError(f'Unexpected native machine type 0x{native_machine.value:04X}')
    elif hasattr(kernel32, 'IsWow64Process'):
        wow64_process = ctypes.c_int()
        if not kernel32.IsWow64Process(ctypes.c_void_p(kernel32.GetCurrentProcess()), ctypes.byref(wow64_process)):
            raise OSError(f'Unable to determine whether WOW64 is active, Error={ctypes.FormatError()}')
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
            warnings.warn(f'{lastgood_system32} is ignored in DLL search path due to technical limitations', RuntimeWarning)
        return directory

    if os_arch is MachineType.AMD64 and interpreter_arch is MachineType.I386:
        return lambda directory, arch: translate_system32_to_sysnative(directory) if arch is MachineType.AMD64 else directory
    elif os_arch is MachineType.ARM64 and interpreter_arch is MachineType.I386:
        return lambda directory, arch: translate_system32_to_sysnative(directory) if arch is MachineType.ARM64 else directory
    elif os_arch is not MachineType.I386 is not interpreter_arch:
        return lambda directory, arch: translate_system32_to_syswow64(directory) if arch is MachineType.I386 else directory
    return null_translator


_translate_directory = _translate_directory()


def find_library(name: str, wheel_dirs: typing.Optional[typing.Iterable], arch: MachineType) -> typing.Optional[str]:
    """Given the name of a DLL, return the path to the DLL, or None if the DLL
    cannot be found. DLL names are searched in a case-insensitive fashion. The
    search goes in the following order and considers only the DLLs with the
    given architecture.

    1. If not None, the directories in wheel_dirs.
    2. The PATH environment variable, with any applicable adjustments due to
       the Windows file system redirector. (If we are on a case-sensitive file
       system and a directory contains more than one DLL with the correct
       architecture that differs by case only, then choose one arbitrarily.)"""
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


def get_direct_mangleable_needed(lib_path: str, no_dlls: set, no_mangles: set, verbose: int) -> list:
    """Given the path to a shared library, return a deterministically-ordered
    list containing the lowercase DLL names of all direct dependencies that
    belong in the wheel and should be name-mangled.

    no_dlls is a set of lowercase additional DLL names that do not belong in
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
        for entry in imports:
            dll_name = entry.dll.decode('utf-8').lower()
            if dll_name not in ignore_names and \
                    dll_name not in no_dlls and \
                    not any(r.fullmatch(dll_name) for r in _dll_list.ignore_regexes) and \
                    dll_name not in no_mangles and \
                    not any(r.fullmatch(dll_name) for r in _dll_list.no_mangle_regexes):
                needed.append(dll_name)
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
    search for dependencies of these DLLs.

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
                lib_arch = MachineType.machine_field_to_type(pe.FILE_HEADER.Machine)
                if not lib_arch:
                    raise ValueError(f'{lib_path} has an unsupported CPU architecture')
                ignore_names = _dll_list.ignore_names[lib_arch]
                for entry in imports:
                    dll_name = entry.dll.decode('utf-8').lower()
                    if dll_name not in ignore_names and \
                            not any(r.fullmatch(dll_name) for r in _dll_list.ignore_regexes) and \
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
    """Determine the size of a PE file (excluding any trailing data) and
    whether the file has enough padding for writing the elements of new_dlls.

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
    with those in name_map.
    old_deps: a subset of the dependencies that lib_path has, in list form
    name_map: a dict that maps an old dependency name to a new name, must
        contain at least all the keys in old_deps
    strip: whether to try to strip DLLs that contain trailing data if not
        enough internal padding exists
    verbose: verbosity level, 0 to 2
    test: testing options for internal use"""
    if not old_deps:
        # no dependency names to change
        return
    name_map = {dep.lower().encode('utf-8'): name_map[dep].encode('utf-8') for dep in old_deps}
        # keep only the DLLs that will be mangled

    # New dependency names are longer than the old ones, so we cannot simply
    # overwrite the bytes of the old dependency names. Determine whether the PE
    # file has enough usable internal padding to use to write the new
    # dependency names. If so, overwrite the padding. Otherwise, as long as the
    # PE file contains no trailing data or the trailing data can be stripped,
    # append a new PE section to store the new names. Determining whether
    # enough internal padding exists is an instance of the bin packing problem
    # in which the new dependency names are items and the contiguous padding
    # runs are bins. The bin packing problem is NP-hard, so for simplicity, we
    # use the Next Fit algorithm.
    with PEContext(lib_path, None, False, verbose) as pe:
        pe_size, enough_padding = _get_pe_size_and_enough_padding(pe, name_map.values())
    if 'not_enough_padding' in test:
        enough_padding = False
    if not enough_padding and pe_size < os.path.getsize(lib_path) and strip:
        # try to strip the trailing data
        try:
            subprocess.check_call(['strip', '-s', lib_path])
        except FileNotFoundError:
            raise FileNotFoundError('GNU strip not found in PATH') from None
        with PEContext(lib_path, None, False, verbose) as pe:
            pe_size, enough_padding = _get_pe_size_and_enough_padding(pe, name_map.values())

    lib_name = os.path.basename(lib_path)
    with open(lib_path, 'rb') as f:
        # workaround for https://github.com/erocarrera/pefile/issues/356
        lib_data = f.read()
    if not enough_padding and pe_size < len(lib_data):
        # cannot rename dependencies due to trailing data
        if strip:
            raise RuntimeError(textwrap.fill(
                f'Unable to rename the dependencies of {lib_name} because '
                'this DLL does not contain enough internal padding to fit the '
                'new dependency names, and it contains trailing data after '
                'the point where the DLL file specification ends. The GNU '
                'strip utility was run automatically in attempt to remove the '
                'trailing data but failed to remove all of it. Unless you '
                'have knowledge to the contrary, you should assume that the '
                'trailing data exist for an important reason and are not safe '
                f'to remove. Include {os.pathsep.join(old_deps)} in the '
                '--no-mangle flag to fix this error.',
                initial_indent=' ' * len('RuntimeError: ')).lstrip())
        else:
            error_text = [
                textwrap.fill(
                    f'Unable to rename the dependencies of {lib_name} because '
                    'this DLL does not contain enough internal padding to fit '
                    'the new dependency names, and it contains trailing data '
                    'after the point where the DLL file specification ends. '
                    'Commonly, the trailing data consist of symbols that can '
                    'be safely removed, although there exist situations where '
                    'the data must be present for the DLL to function '
                    'properly. Here are your options.',
                    initial_indent=' ' * len('RuntimeError: ')).lstrip(),
                '\n',
                textwrap.fill(
                    '- Try to remove the trailing data using the GNU strip '
                    f"utility with the command `strip -s {lib_name}'.",
                    subsequent_indent='  '
                ),
                '\n',
                textwrap.fill(
                    '- Use the --strip flag to ask delvewheel to execute '
                    'strip automatically when trailing data are detected.',
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

    with PEContext(None, lib_data, True, verbose) as pe:
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
            section_table_end = (pe.DOS_HEADER.e_lfanew + 4 +
                                 pe.FILE_HEADER.sizeof() +
                                 pe.FILE_HEADER.SizeOfOptionalHeader +
                                 pe.FILE_HEADER.NumberOfSections * _SECTION_HEADER_SIZE)
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

        # clear any signatures
        cert_table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if cert_table.Size:
            warnings.warn(f'Authenticode signature has been removed from {lib_name}', UserWarning)
            cert_table.VirtualAddress = 0
            cert_table.Size = 0

        # all changes to headers are done; serialize the PE file
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

    # fix the checksum
    with PEContext(None, lib_data, False, verbose) as pe:
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(lib_path)
