[![CI](https://github.com/adang1345/delvewheel/workflows/CI/badge.svg)](https://github.com/adang1345/delvewheel/actions?query=workflow%3ACI)  [![PyPI version](https://img.shields.io/pypi/v/delvewheel?logo=pypi)](https://pypi.org/project/delvewheel) [![Python versions](https://img.shields.io/pypi/pyversions/delvewheel?logo=python)](https://pypi.org/project/delvewheel)
# delvewheel

`delvewheel` is a command-line tool for creating Python wheel packages for Windows that have DLL dependencies that may not be present on the target system. It is functionally similar to [`auditwheel`](https://github.com/pypa/auditwheel) (for Linux) and [`delocate`](https://github.com/matthew-brett/delocate) (for Mac OS).

Suppose that you have built a Python wheel for Windows containing an extension module, but the wheel depends on DLLs that are present in the build environment but may not be present on the end user's machine. This tool determines which DLLs a wheel depends on (aside from system libraries) and copies those DLLs into the wheel.

## Installation

`delvewheel` can be installed using pip.
```Shell
pip install delvewheel
```
You can also install from the source code by opening a command-line shell at the repository root and running
```Shell
pip install .
```
Python 3.6+ on Windows is required.

## Usage

`delvewheel show`: show external DLLs that the wheel depends on

`delvewheel repair`: copy external DLL dependencies into the wheel and patch the wheel so that these libraries are loaded at runtime

`delvewheel needed`: list the direct DLL dependencies of a single executable

`delvewheel` searches for the location of DLL dependencies using the default Python search order for shared libraries. To specify an additional directory to search for DLLs, add the location of the DLL to the `PATH` environment variable or use the `--add-path` option.

For a summary of additional command-line options, use the `-h` option (`delvewheel -h`, `delvewheel show -h`, `delvewheel repair -h`, `delvewheel needed -h`).

## Additional Options
`delvewheel show`
- `--add-path`: additional path(s) to search for DLLs, semicolon delimited. These paths are searched before those in the `PATH` environment variable.
- `--add-dll`: name(s) of additional DLL(s) to vendor into the wheel, semicolon delimited. We do not automatically search for dependencies of these DLLs.
- `--no-dll`: name(s) of DLL(s) to specifically exclude from the wheel, semicolon delimited. Dependencies of these DLLs are also automatically excluded if no other included DLL depends on them.
- `-v`: verbose mode
- `--extract-dir`: directory to store extracted contents of wheel for debug use (default is a temp directory)

`delvewheel repair`
- `--add-path`: additional path(s) to search for DLLs, semicolon delimited. These paths are searched before those in the `PATH` environment variable.
- `--add-dll`: name(s) of additional DLL(s) to vendor into the wheel, semicolon delimited. We do not automatically search for or vendor in dependencies of these DLLs, nor do we mangle the names of these DLLs.
- `--no-dll`: name(s) of DLL(s) to specifically exclude from the wheel, semicolon delimited. Dependencies of these DLLs are also automatically excluded if no other included DLL depends on them.
- `-v`: verbose mode
- `--extract-dir`: directory to store extracted contents of wheel for debug use (default is a temp directory)
- `-w`,`--wheel-dir`: directory to write the repaired wheel (default is `wheelhouse` relative to current working directory)
- `--no-mangle`: name(s) of DLL(s) not to mangle, semicolon-delimited
- `--no-mangle-all`: don't mangle any DLL names
- `-L`,`--lib-sdir`: subdirectory suffix in package to store vendored DLLs (default `.libs`)

## Limitations

- `delvewheel` reads DLL file headers to determine which libraries a wheel depends on. DLLs that are loaded at runtime using `ctypes`/`cffi` (from Python) or `LoadLibrary` (from C/C++) will be missed. You can, however, specify additional DLLs to vendor into the wheel using the `--add-dll` option.
- Wheels created using `delvewheel` are not guaranteed to work on systems older than Windows 7. If you intend to create a wheel for an old Windows system, you should test the resultant wheel thoroughly. If it turns out that getting the wheel to work on an older system simply requires an extra DLL, you can use the `--add-dll` flag to vendor additional DLLs into the wheel.
- To avoid DLL hell, we mangle the file names of most DLLs that are vendored into the wheel. This way, a Python process that tries loading a vendored DLL does not end up using a different DLL with the same name. Due to a limitation in the [`machomachomangler`](https://github.com/njsmith/machomachomangler) dependency, `delvewheel` is unable to name-mangle DLLs containing extra data at the end of the binary. If your DLL was created with MinGW, you can use the `strip` utility to remove the extra data. Otherwise, use the `--no-mangle` flag.
- The bitness of the Python interpreter that runs `delvewheel` must match the bitness of the wheel that is repaired. For example, you cannot run `delvewheel` from a 32-bit Python interpreter to repair a wheel that is meant for 64-bit Python.
