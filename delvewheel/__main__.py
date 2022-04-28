import argparse
import os
import sys
from .wheel_repair import WheelRepair
from . import patch_dll


def subdir_suffix(s: str) -> str:
    """Helper for argument parser for validating a subdirectory suffix."""
    if not s or any(c in r'<>:"/\|?*' or ord(c) < 32 for c in s) or \
            any(s.endswith(x) for x in ('.dist-info', '.data', ' ', '.')):
        raise argparse.ArgumentTypeError(f'Invalid subdirectory suffix {s!r}')
    return s


def main():
    """Main function"""
    # parse arguments
    parser = argparse.ArgumentParser(description='Self-contained wheels for Windows')
    kwargs = {'dest': 'command'}
    if sys.version_info[:2] >= (3, 7):
        kwargs['required'] = True
    subparsers = parser.add_subparsers(**kwargs)
    parser_show_description = 'Search a wheel for external DLL dependencies'
    parser_show = subparsers.add_parser('show', help=parser_show_description, description=parser_show_description)
    parser_repair_description = 'Vendor in external DLL dependencies of a wheel'
    parser_repair = subparsers.add_parser('repair', help=parser_repair_description, description=parser_repair_description)
    parser_needed_description = 'List the direct DLL dependencies of a single executable'
    parser_needed = subparsers.add_parser('needed', help=parser_needed_description, description=parser_needed_description)
    for subparser in (parser_show, parser_repair):
        subparser.add_argument('wheel', nargs='+', help='wheel(s) to show or repair')
        subparser.add_argument('--add-path', default='', metavar='PATHS', help=f'additional path(s) to search for DLLs, {os.pathsep!r}-delimited')
        subparser.add_argument('--add-dll', default='', metavar='DLLS', help=f'force inclusion of DLL name(s), {os.pathsep!r}-delimited')
        subparser.add_argument('--no-dll', default='', metavar='DLLS', help=f'force exclusion of DLL name(s), {os.pathsep!r}-delimited')
        subparser.add_argument('--ignore-in-wheel', action='store_true', help="don't search for or vendor in DLLs that are already in the wheel")
        subparser.add_argument('-v', action='count', default=0, help='verbosity')
        subparser.add_argument('--extract-dir', help=argparse.SUPPRESS)
    parser_repair.add_argument('-w', '--wheel-dir', dest='target', default='wheelhouse', help='directory to write repaired wheel')
    parser_repair.add_argument('--no-mangle', default='', metavar='DLLS', help=f'DLL names(s) not to mangle, {os.pathsep!r}-delimited')
    parser_repair.add_argument('--no-mangle-all', action='store_true', help="don't mangle any DLL names")
    parser_repair.add_argument('-L', '--lib-sdir', default='.libs', type=subdir_suffix, help='directory suffix in package to store vendored DLLs (default .libs)')
    parser_needed.add_argument('file', help='path to a DLL or PYD file')
    parser_needed.add_argument('-v', action='count', default=0, help='verbosity')
    args = parser.parse_args()
    if args.command is None:
        raise ValueError('No command provided. Use -h for help.')

    # handle command
    if args.command in ('show', 'repair'):
        add_paths = set(os.path.abspath(path) for path in args.add_path.split(os.pathsep) if path)
        add_dlls = set(dll_name.lower() for dll_name in args.add_dll.split(os.pathsep) if dll_name)
        no_dlls = set(dll_name.lower() for dll_name in args.no_dll.split(os.pathsep) if dll_name)

        intersection = add_dlls & no_dlls
        if intersection:
            raise ValueError(f'Cannot force both inclusion and exclusion of {intersection}')

        if add_paths:
            os.environ['PATH'] = f'{os.pathsep.join(add_paths)}{os.pathsep}{os.environ["PATH"]}'

        for wheel in args.wheel:
            wr = WheelRepair(wheel, args.extract_dir, add_dlls, no_dlls, args.ignore_in_wheel, args.v)
            if args.command == 'show':
                wr.show()
            else:  # args.command == 'repair'
                no_mangles = set(dll_name.lower() for dll_name in args.no_mangle.split(os.pathsep) if dll_name)
                wr.repair(args.target, no_mangles, args.no_mangle_all, args.lib_sdir)
    else:  # args.command == 'needed'
        for dll_name in patch_dll.get_direct_needed(args.file, True, args.v):
            print(dll_name)


if __name__ == '__main__':
    main()
