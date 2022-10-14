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

## Supported Platforms
Python 3.6+ is required to run `delvewheel`.

The environment used to run `delvewheel` does _not_ need to match the target environment of the wheel being repaired. For example, you can run `delvewheel` using 32-bit Python 3.6 to repair a wheel for 64-bit Python 3.10. You can even run `delvewheel` with PyPy3.6 on 32-bit x86 Linux to repair a wheel whose target environment is CPython 3.11 on Windows arm64.

## Usage

`delvewheel show`: show external DLLs that the wheel depends on

`delvewheel repair`: copy external DLL dependencies into the wheel and patch the wheel so that these libraries are loaded at runtime

`delvewheel needed`: list the direct DLL dependencies of a single executable

`delvewheel` searches for the location of DLL dependencies in the following order.
1. The `PATH` environment variable.
2. The Visual C++ 14.x runtime redistributable directory, if it exists.

To specify an additional directory to search for DLLs, add the location of the DLL to the `PATH` environment variable or use the `--add-path` option.

For a summary of additional command-line options, use the `-h` option (`delvewheel -h`, `delvewheel show -h`, `delvewheel repair -h`, `delvewheel needed -h`).

## Additional Options

The path separator to use in the following options is `';'` on Windows and `':'` on Unix-like platforms.

`delvewheel show`
- `--add-path`: additional path(s) to search for DLLs, path-separator-delimited. These paths are searched before those in the `PATH` environment variable.
- `--add-dll`: name(s) of additional DLL(s) to vendor into the wheel, path-separator-delimited. We do not automatically search for dependencies of these DLLs unless another included DLL depends on them. If you use this option, it is your responsibility to ensure that the additional DLL is found at load time.
- `--no-dll`: name(s) of DLL(s) to specifically exclude from the wheel, path-separator-delimited. Dependencies of these DLLs are also automatically excluded if no other included DLL depends on them.
- `--ignore-in-wheel`: don't search for or vendor in DLLs that are already in the wheel. We still search for and vendor in dependencies of these DLLs if they are not in the wheel. This flag is meant for simpler integration with other DLL bundling tools/techniques but is not a catch-all. If you use this flag, it is your responsibility to ensure that the DLLs that are already in the wheel are loaded correctly.
- `-v`: verbosity
  - `-v`: level 1, some diagnostic information
  - `-vv`: level 2, include warnings from `pefile`
- `--extract-dir`: directory to store extracted contents of wheel for debug use (default is a temp directory)

`delvewheel repair`
- `--add-path`: additional path(s) to search for DLLs, path-separator-delimited. These paths are searched before those in the `PATH` environment variable.
- `--add-dll`: name(s) of additional DLL(s) to vendor into the wheel, path-separator-delimited. We do not automatically search for or vendor in dependencies of these DLLs unless another included DLL depends on them. We do not mangle the names of these DLLs or their direct dependencies. If you use this option, it is your responsibility to ensure that the additional DLL is found at load time.
- `--no-dll`: name(s) of DLL(s) to specifically exclude from the wheel, path-separator-delimited. Dependencies of these DLLs are also automatically excluded if no other included DLL depends on them.
- `--ignore-in-wheel`: don't search for or vendor in DLLs that are already in the wheel. Don't mangle the names of these DLLs or their direct dependencies. We still search for and vendor in dependencies of these DLLs if they are not in the wheel. This flag is meant for simpler integration with other DLL bundling tools/techniques but is not a catch-all. If you use this flag, it is your responsibility to ensure that the DLLs that are already in the wheel are loaded correctly.
- `-v`: verbosity
  - `-v`: level 1, some diagnostic information
  - `-vv`: level 2, include warnings from `pefile`
- `--extract-dir`: directory to store extracted contents of wheel for debug use (default is a temp directory)
- `-w`,`--wheel-dir`: directory to write the repaired wheel (default is `wheelhouse` relative to current working directory)
- `--no-mangle`: name(s) of DLL(s) not to mangle, path-separator-delimited
- `--no-mangle-all`: don't mangle any DLL names
- `-L`,`--lib-sdir`: subdirectory suffix to store vendored DLLs (default `.libs`). For example, if your wheel is named `mywheel-0.0.1-cp310-cp310-win_amd64.whl`, then the vendored DLLs are stored in `mywheel.libs` by default. If your wheel contains a top-level extension module that is not in any package, then this setting is ignored, and vendored DLLs are instead placed directly into `site-packages` when the wheel is installed.

## Limitations

- `delvewheel` reads DLL file headers to determine which libraries a wheel depends on. DLLs that are loaded at runtime using `ctypes`/`cffi` (from Python) or `LoadLibrary` (from C/C++) will be missed. You can, however, specify additional DLLs to vendor into the wheel using the `--add-dll` option. If you elect to do this, it is your responsibility to ensure that the additional DLL is found at load time.
- Wheels created using `delvewheel` are not guaranteed to work on systems older than Windows 7 SP1. If you intend to create a wheel for an old Windows system, you should test the resultant wheel thoroughly. If it turns out that getting the wheel to work on an older system simply requires an extra DLL, you can use the `--add-dll` flag to vendor additional DLLs into the wheel.
- To avoid DLL hell, we mangle the file names of most DLLs that are vendored into the wheel. This way, a Python process that tries loading a vendored DLL does not end up using a different DLL with the same name. Due to a limitation in the [`machomachomangler`](https://github.com/njsmith/machomachomangler) dependency, `delvewheel` is unable to name-mangle DLLs whose dependents contain extra data at the end of the binary. If your DLL was created with MinGW, you can use the `strip` utility to remove the extra data. Otherwise, use the `--no-mangle` flag.
- `delvewheel` cannot repair a wheel that contains extension modules targeting more than one CPU architecture (e.g. both `win32` and `win_amd64`). You should create a separate wheel for each CPU architecture and repair each individually.
- `delvewheel` creates or patches `__init__.py` in each top-level package so that the DLLs are loaded properly during import. This will cause issues if you have a top-level namespace package that requires `__init__.py` to be absent to function properly.
