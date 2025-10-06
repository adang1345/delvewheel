import argparse
import glob
import os
import re
import warnings
from ._wheel_repair import WheelRepair
from ._version import __version__
from . import _Config
from . import _dll_utils


def _dir_suffix(s: str) -> str:
    """Helper for argument parser for validating a directory suffix."""
    if not s or any(c in r'<>:"/\|?*' or ord(c) < 32 for c in s) or \
            any(s.endswith(x) for x in ('.dist-info', '.data', ' ', '.')):
        raise argparse.ArgumentTypeError(f'Invalid directory suffix {s!r}')
    return s


def _dll_names(s: str) -> str:
    """Helper for argument parser for validating a list of DLL names"""
    for dll_name in filter(None, map(str.strip, s.split(os.pathsep))):
        if any(c in r'<>:"/\|?*' or ord(c) < 32 for c in dll_name):
            raise argparse.ArgumentTypeError(f'Invalid DLL name {dll_name!r}')
    return s


def _namespace_pkgs(s: str) -> str:
    for namespace_pkg in filter(None, s.split(os.pathsep)):
        if any(c in r'<>:"/\|?*' or ord(c) < 32 for c in namespace_pkg) or not re.fullmatch(r'[^.]+(\.[^.]+)*', namespace_pkg):
            raise argparse.ArgumentTypeError(f'Invalid namespace package {namespace_pkg!r}')
    return s


def main():
    """Main function"""
    # parse arguments
    parser = argparse.ArgumentParser(description=f'delvewheel {__version__}: Create self-contained wheels for Windows')
    subparsers = parser.add_subparsers(dest='command', required=True)
    parser_show_description = 'Search a wheel for external DLL dependencies'
    parser_show = subparsers.add_parser('show', help=parser_show_description, description=parser_show_description)
    parser_repair_description = 'Vendor in external DLL dependencies of a wheel'
    parser_repair = subparsers.add_parser('repair', help=parser_repair_description, description=parser_repair_description)
    parser_needed_description = 'List the direct DLL dependencies of a single executable'
    parser_needed = subparsers.add_parser('needed', help=parser_needed_description, description=parser_needed_description)
    for subparser in (parser_show, parser_repair):
        subparser.add_argument('wheel', nargs='+', help='wheel(s) to show or repair')
        subparser.add_argument('--add-path', action='append', default=[], metavar='PATHS', help=f'additional path(s) to search for DLLs, {os.pathsep!r}-delimited')
        subparser.add_argument('--include', '--add-dll', action='append', default=[], metavar='DLLS', type=_dll_names, help=f'force inclusion of DLL name(s), {os.pathsep!r}-delimited')
        subparser.add_argument('--exclude', '--no-dll', action='append', default=[], metavar='DLLS', type=_dll_names, help=f'force exclusion of DLL name(s), {os.pathsep!r}-delimited')
        subparser.add_argument('--ignore-existing', '--ignore-in-wheel', action='store_true', help="don't search for or vendor in DLLs that are already in the wheel")
        subparser.add_argument('--analyze-existing', action='store_true', help='analyze and vendor in dependencies of DLLs that are already in the wheel')
        subparser.add_argument('--analyze-existing-exes', action='store_true', help='analyze and vendor in dependencies of EXEs that are in the wheel')
        subparser.add_argument('-v', action='count', default=0, help='verbosity')
        subparser.add_argument('--extract-dir', help=argparse.SUPPRESS)
        subparser.add_argument('--test', default='', help=argparse.SUPPRESS)  # comma-separated testing options, internal use only
    parser_repair.add_argument('-w', '--wheel-dir', dest='target', default='wheelhouse', help='directory to write repaired wheel')
    parser_repair.add_argument('--no-mangle', action='append', default=[], metavar='DLLS', type=_dll_names, help=f'DLL names(s) not to mangle, {os.pathsep!r}-delimited')
    group = parser_repair.add_mutually_exclusive_group()
    group.add_argument('--no-mangle-all', action='store_true', help="don't mangle any DLL names")
    group.add_argument('--with-mangle', action='store_true', help='mangle the direct dependencies of DLLs that are already in the wheel (with --ignore-existing)')
    parser_repair.add_argument('--strip', action='store_true', help='strip DLLs that contain trailing data when name-mangling')
    parser_repair.add_argument('-L', '--lib-sdir', default='.libs', type=_dir_suffix, help='directory suffix to store vendored DLLs (default .libs)')
    group = parser_repair.add_mutually_exclusive_group()
    group.add_argument('--namespace-pkg', default='', metavar='PKGS', type=_namespace_pkgs, help=f'namespace package(s), {os.pathsep!r}-delimited')
    group.add_argument('--custom-patch', action='store_true', help='customize the location of the DLL search path patch')
    parser_repair.add_argument('--no-diagnostic', action='store_true', help=argparse.SUPPRESS)  # don't write diagnostic information to DELVEWHEEL metadata file
    parser_repair.add_argument('--include-symbols', action='store_true', help='include .pdb symbol files with vendored DLLs')
    parser_repair.add_argument('--include-imports', action='store_true', help='include .lib import library files with the vendored DLLs')
    parser_needed.add_argument('file', help='path to a DLL or PYD file')
    parser_needed.add_argument('-v', action='count', default=0, help='verbosity')
    args = parser.parse_args()

    # handle arguments
    if args.v > 2:
        warnings.warn(f'Requested verbosity level {args.v} exceeds maximum of 2; using level 2')
    _Config.verbose = args.v
    if args.command in ('show', 'repair'):
        _Config.test = args.test.split(',')
        add_paths = dict.fromkeys(os.path.abspath(path) for path in os.pathsep.join(args.add_path).split(os.pathsep) if path)
        include = set(dll_name.lower() for dll_name in os.pathsep.join(args.include).split(os.pathsep) if dll_name)
        exclude = set(dll_name.lower() for dll_name in os.pathsep.join(args.exclude).split(os.pathsep) if dll_name)

        if intersection := include & exclude:
            raise ValueError(f'Cannot force both inclusion and exclusion of {intersection}')

        if add_paths:
            os.environ['PATH'] = f'{os.pathsep.join(add_paths)}{os.pathsep}{os.environ["PATH"]}'

        wheels = []
        for wheel in args.wheel:
            if '*' in wheel:
                if not (expanded := glob.glob(wheel)):
                    raise FileNotFoundError(f'No wheels match the pattern {wheel}')
                wheels.extend(expanded)
            else:
                wheels.append(wheel)
        for wheel in wheels:
            wr = WheelRepair(wheel, args.extract_dir, include, exclude, args.ignore_existing, args.analyze_existing, args.analyze_existing_exes)
            if args.command == 'show':
                wr.show()
            else:  # args.command == 'repair'
                if args.with_mangle and not args.ignore_existing:
                    parser_repair.error('--with-mangle requires --ignore-existing')
                no_mangles = set(dll_name.lower() for dll_name in os.pathsep.join(args.no_mangle).split(os.pathsep) if dll_name)
                namespace_pkgs = set(tuple(namespace_pkg.split('.')) for namespace_pkg in args.namespace_pkg.split(os.pathsep) if namespace_pkg)
                wr.repair(args.target, no_mangles, args.no_mangle_all, args.with_mangle, args.strip, args.lib_sdir, not args.no_diagnostic and 'SOURCE_DATE_EPOCH' not in os.environ, namespace_pkgs, args.include_symbols, args.include_imports, args.custom_patch)
    else:  # args.command == 'needed'
        for dll_name in sorted(_dll_utils.get_direct_needed(args.file), key=str.lower):
            print(dll_name)


if __name__ == '__main__':
    main()
