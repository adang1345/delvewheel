[![CI](https://github.com/adang1345/delvewheel/workflows/CI/badge.svg)](https://github.com/adang1345/delvewheel/actions?query=workflow%3ACI)  [![PyPI version](https://img.shields.io/pypi/v/delvewheel?logo=pypi)](https://pypi.org/project/delvewheel) [![Python versions](https://img.shields.io/pypi/pyversions/delvewheel?logo=python)](https://pypi.org/project/delvewheel)
# delvewheel

`delvewheel` is a command-line tool for creating self-contained Python wheel packages for Windows that have DLL dependencies that may not be present on the target system. It is functionally similar to [`auditwheel`](https://github.com/pypa/auditwheel) (for Linux) and [`delocate`](https://github.com/matthew-brett/delocate) (for macOS).

Suppose that you have built a Python wheel for Windows containing an extension module, and the wheel depends on DLLs that are present in the build environment but may not be present on the end user's machine. This tool determines which DLLs a wheel depends on (aside from system libraries) and copies those DLLs into the wheel. This tool also takes extra steps to avoid [DLL hell](https://en.wikipedia.org/wiki/DLL_Hell) and to ensure that the DLLs are properly loaded at runtime.

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
`delvewheel` can be run using Python 3.7+ on any platform.

`delvewheel` can repair wheels targeting Python 2.6+ for `win32`, `win_amd64`, or `win_arm64`.

The environment used to run `delvewheel` does _not_ need to match the target environment of the wheel being repaired. For example, you can run `delvewheel` using 32-bit Python 3.7 to repair a wheel for 64-bit Python 2.6. You can even run `delvewheel` with PyPy3.6 on 32-bit x86 Linux to repair a wheel whose target environment is CPython 3.11 on Windows arm64.

## Usage

`delvewheel show`: show external DLLs that the wheel depends on

`delvewheel repair`: copy external DLL dependencies into the wheel and patch the wheel so that these libraries are loaded at runtime

`delvewheel needed`: list the direct DLL dependencies of a single executable

`delvewheel` uses the `PATH` environment variable to search for DLL dependencies. To specify an additional directory to search for DLLs, add the location of the DLL to the `PATH` environment variable or use the `--add-path` option.

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
- `--strip`: strip DLLs that contain trailing data when name-mangling. The GNU `strip` utility must be present in `PATH`.
- `-L`,`--lib-sdir`: subdirectory suffix to store vendored DLLs (default `.libs`). For example, if your wheel is named `mywheel-0.0.1-cp310-cp310-win_amd64.whl`, then the vendored DLLs are stored in `mywheel.libs` by default. If your wheel contains a top-level extension module that is not in any package, then this setting is ignored, and vendored DLLs are instead placed directly into `site-packages` when the wheel is installed.
- `--namespace-pkg`: namespace packages, specified in case-sensitive dot notation and delimited by the path separator. Normally, we patch or create `__init__.py` in each top-level package to add the vendored DLL location to the DLL search path at runtime. If you have a top-level namespace package that requires `__init__.py` to be absent or unmodified, then this technique can cause problems. This option tells `delvewheel` to use an alternate strategy that does not create or modify `__init__.py` at the root of the given namespace package(s). For example,
  - `--namespace-pkg package1` declares `package1` as a namespace package.
  - On Windows, `--namespace-pkg package1.package2;package3` declares `package1`, `package1\package2`, and `package3` as namespace packages.

## Limitations

- `delvewheel` reads DLL file headers to determine which libraries a wheel depends on. DLLs that are loaded at runtime using `ctypes`/`cffi` (from Python) or `LoadLibrary` (from C/C++) will be missed. You can, however, specify additional DLLs to vendor into the wheel using the `--add-dll` option. If you elect to do this, it is your responsibility to ensure that the additional DLL is found at load time.
- Wheels created using `delvewheel` are not guaranteed to work on systems older than Windows 7 SP1. If you intend to create a wheel for an old Windows system, you should test the resultant wheel thoroughly. If it turns out that getting the wheel to work on an older system simply requires an extra DLL, you can use the `--add-dll` flag to vendor additional DLLs into the wheel.
- To avoid DLL hell, we mangle the file names of most DLLs that are vendored into the wheel. This way, a Python process that tries loading a vendored DLL does not end up using a different DLL with the same name. Due to a limitation in how name-mangling is performed, `delvewheel` is unable to name-mangle DLLs whose dependents contain insufficient internal padding to fit the mangled names and contain trailing data at the end of the binary. An exception will be raised if such a DLL is encountered. Commonly, trailing data consist of symbols that can be safely removed using the GNU `strip` utility, although there exist situations where the data must be present for the DLL to function properly. To remove the trailing data, execute `strip -s EXAMPLE.dll` or use the `--strip` flag. To keep the trailing data and skip name mangling, use the `--no-mangle` or `--no-mangle-all` flag.
- Any DLL containing an Authenticode signature will have its signature cleared if its dependencies are name-mangled.
- `delvewheel` cannot repair a wheel that contains extension modules targeting more than one CPU architecture (e.g. both `win32` and `win_amd64`). You should create a separate wheel for each CPU architecture and repair each individually.
- If your project has a [delay-load DLL dependency](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls), you must use a custom delay-load import hook when building the DLL that has the delay-load dependency. This ensures that the directory containing the vendored DLLs is included in the DLL search path when delay-loading. For convenience, we provide a suitable hook for Microsoft Visual C/C++ at [delayload/delayhook.c](delayload/delayhook.c). Add the file to your C/C++ project when building your DLL.
