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
- `--ignore-existing`: don't search for or vendor in DLLs that are already in the wheel. We still search for and vendor in dependencies of these DLLs if they are not in the wheel. This flag is meant for simpler integration with other DLL bundling tools/techniques but is not a catch-all. If you use this flag, it is your responsibility to ensure that the DLLs that are already in the wheel are loaded correctly.
- `--analyze-existing`: analyze and vendor in dependencies of DLLs that are already in the wheel. If you use this option, it is your responsibility to ensure that these dependencies are found at load time.
- `-v`: verbosity
  - `-v`: level 1, some diagnostic information
  - `-vv`: level 2, include warnings from `pefile`
- `--extract-dir`: directory to store extracted contents of wheel for debug use (default is a temp directory)

`delvewheel repair`
- `--add-path`: additional path(s) to search for DLLs, path-separator-delimited. These paths are searched before those in the `PATH` environment variable.
- `--add-dll`: name(s) of additional DLL(s) to vendor into the wheel, path-separator-delimited. We do not automatically search for or vendor in dependencies of these DLLs unless another included DLL depends on them. We do not mangle the names of these DLLs or their direct dependencies. If you use this option, it is your responsibility to ensure that the additional DLL is found at load time.
- `--no-dll`: name(s) of DLL(s) to specifically exclude from the wheel, path-separator-delimited. Dependencies of these DLLs are also automatically excluded if no other included DLL depends on them.
- `--ignore-existing`: don't search for or vendor in DLLs that are already in the wheel. Don't mangle the names of these DLLs or their direct dependencies. We still search for and vendor in dependencies of these DLLs if they are not in the wheel. This flag is meant for simpler integration with other DLL bundling tools/techniques but is not a catch-all. If you use this flag, it is your responsibility to ensure that the DLLs that are already in the wheel are loaded correctly.
- `--analyze-existing`: analyze and vendor in dependencies of DLLs that are already in the wheel. These dependencies are name-mangled by default. If you use this option, it is your responsibility to ensure that these dependencies are found at load time.
- `-v`: verbosity
  - `-v`: level 1, some diagnostic information
  - `-vv`: level 2, include warnings from `pefile`
- `--extract-dir`: directory to store extracted contents of wheel for debug use (default is a temp directory)
- `-w`,`--wheel-dir`: directory to write the repaired wheel (default is `wheelhouse` relative to current working directory)
- `--no-mangle`: name(s) of DLL(s) not to mangle, path-separator-delimited
- `--no-mangle-all`: don't mangle any DLL names
- `--strip`: strip DLLs that contain an overlay when name-mangling. The GNU `strip` utility must be present in `PATH`.
- `-L`,`--lib-sdir`: subdirectory suffix to store vendored DLLs (default `.libs`). For example, if your wheel is named `mywheel-0.0.1-cp310-cp310-win_amd64.whl`, then the vendored DLLs are stored in `mywheel.libs` by default. If your wheel contains a top-level extension module that is not in any package, then this setting is ignored, and vendored DLLs are instead placed directly into `site-packages` when the wheel is installed.
- `--namespace-pkg`: namespace packages, specified in case-sensitive dot notation and delimited by the path separator. Normally, we patch or create `__init__.py` in each top-level package to add the vendored DLL location to the DLL search path at runtime. If you have a top-level namespace package that requires `__init__.py` to be absent or unmodified, then this technique can cause problems. This option tells `delvewheel` to use an alternate strategy that does not create or modify `__init__.py` at the root of the given namespace package(s). For example,
  - `--namespace-pkg package1` declares `package1` as a namespace package.
  - On Windows, `--namespace-pkg package1.package2;package3` declares `package1`, `package1\package2`, and `package3` as namespace packages.
- `--include-symbols`: include `.pdb` symbol files with the vendored DLLs. To be included, a symbol file must be in the same directory as the DLL and have the same filename before the extension, e.g. `example.dll` and `example.pdb`.
- `--include-imports`: include `.lib` import library files with the vendored DLLs. To be included, an import library file must be in the same directory as the DLL and have the same filename before the extension, e.g. `example.dll` and `example.lib`.

## Version Scheme

[Semantic versioning](https://semver.org/) is used.

## Name Mangling

This section describes in detail how and why `delvewheel` mangles the vendored DLL filenames by default. It is fairly technical, so feel free to skip it if it's not relevant to you.

Suppose you install two Python extension modules `A.pyd` and `B.pyd` into a single Python environment, where the modules come from separate projects. Each module depends on a DLL named `C.dll`, so each project ships its own `C.dll`. Because of how the Windows DLL loader works, if `A.pyd` is loaded before `B.pyd`, then both modules end up using `A.pyd`'s version of `C.dll`. Windows does not allow two DLLs with the same name to be loaded in a single process (unless you have a private SxS assembly, but that's a complicated topic that's best avoided in my opinion). This is a problem if `B.pyd` is not compatible with `A.pyd`'s version of `C.dll`. Maybe `B.pyd` requires a newer version of `C.dll` than `A.pyd`. Or maybe the two `C.dll`s are completely unrelated, and the two project authors by chance chose the same DLL name. This situation is known as DLL hell.

To avoid this issue, `delvewheel` renames the vendored DLLs. For each DLL, `delvewheel` computes a hash based on the DLL contents and the wheel distribution name and appends the hash to the DLL name. For example, if the authors of `A.pyd` and `B.pyd` both decided to use `delvewheel` as part of their projects, then `A.pyd`'s version of `C.dll` could be renamed to `C-a55e90393a19a36b45c623ef23fe3f4a.dll`, while `B.pyd`'s version of `C.dll` could be renamed to `C-b7f2aeead421653280728b792642e14f.dll`. Now that the two DLLs have different names, they can both be loaded into a single Python process. Even if only one of the two projects decided to use `delvewheel`, then the two DLLs would have different names, and DLL hell would be avoided.

Simply renaming the DLLs is not enough, though because `A.pyd` is still looking for `C.dll`. To fix this, `delvewheel` goes into `A.pyd` and finds its [import directory table](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table), which tells the Windows loader the names of the DLL dependencies. This table contains an entry with a pointer to the string `"C.dll"`, which is embedded somewhere in `A.pyd`. `delvewheel` then finds a suitable location in `A.pyd` to write the string `"C-a55e90393a19a36b45c623ef23fe3f4a.dll"` and edits the import directory table entry to point to this string. Now, when `A.pyd` is loaded, it knows to look for `C-a55e90393a19a36b45c623ef23fe3f4a.dll`.

So far, we have described the simplest possible example where there exists one Python extension module with one DLL dependency. In the real world, DLL dependency relationships are often more complicated, and `delvewheel` can handle them as well. For example, suppose a project has the following properties.

- There are two extension modules `D.pyd` and `E.pyd`.
- `D.pyd` depends on `F.dll` and `G.dll`.
- `F.dll` depends on `G.dll` and `H.dll`.
- `E.pyd` depends on `I.dll`.
- `I.dll` depends on `H.dll` and `J.dll`.

`delvewheel` would execute the following when name-mangling.

- Edit the import directory table of `D.pyd` to point to `F-c070a14b5ebd1ef22dc434b34bcbb0ae.dll` and `G-38752d7e43f7175f4f5e7e906bbeaac7.dll`.
- Edit the import directory table of `E.pyd` to point to `I-348818deee8c8bfbc462c6ba9c8e1898.dll`.
- Edit the import directory table of `F.dll` to point to `G-38752d7e43f7175f4f5e7e906bbeaac7.dll` and `H-43c80d2389f603a00e22dd9862246dba.dll`.
- Edit the import directory table of `I.dll` to point to `H-43c80d2389f603a00e22dd9862246dba.dll` and `J-9f50744ed67c3a6e5b24b39c08b2b207.dll`.
- Rename `F.dll` to `F-c070a14b5ebd1ef22dc434b34bcbb0ae.dll`.
- Rename `G.dll` to `G-38752d7e43f7175f4f5e7e906bbeaac7.dll`.
- Rename `H.dll` to `H-43c80d2389f603a00e22dd9862246dba.dll`.
- Rename `I.dll` to `I-348818deee8c8bfbc462c6ba9c8e1898.dll`.
- Rename `J.dll` to `J-9f50744ed67c3a6e5b24b39c08b2b207.dll`.

## Limitations

- `delvewheel` reads DLL file headers to determine which libraries a wheel depends on. DLLs that are loaded at runtime using `ctypes`/`cffi` (from Python) or `LoadLibrary` (from C/C++) will be missed. Support for runtime-loaded DLLs is limited; however, the following options are available.
  - Specify additional DLLs to vendor into the wheel using the `--add-dll` option.
  - Include the runtime-loaded DLL into the wheel yourself, and use the `--analyze-existing` option.

  If you use any of these options, it is your responsibility to ensure that the runtime-loaded DLLs are found at load time.
- Wheels created using `delvewheel` are not guaranteed to work on systems older than Windows 7 SP1. We avoid vendoring system libraries that are provided by Windows 7 SP1 or later. If you intend to create a wheel for an older Windows system that requires an extra DLL, use the `--add-dll` flag to vendor additional DLLs into the wheel.
- Due to a limitation in how name-mangling is performed, `delvewheel` is unable to name-mangle DLLs whose dependents contain insufficient internal padding to fit the mangled names and contain an overlay at the end of the binary. An exception will be raised if such a DLL is encountered. Commonly, the overlay consists of symbols that can be safely removed using the GNU `strip` utility, although there exist situations where the data must be present for the DLL to function properly. To remove the overlay, execute `strip -s EXAMPLE.dll` or use the `--strip` flag. To keep the overlay and skip name mangling, use the `--no-mangle` or `--no-mangle-all` flag.
- Any DLL containing an Authenticode signature will have its signature cleared if its dependencies are name-mangled or if it was built with a non-`0` value for the [`/DEPENDENTLOADFLAG`](https://learn.microsoft.com/en-us/cpp/build/reference/dependentloadflag?view=msvc-170) linker flag.
- `delvewheel` cannot repair a wheel that contains extension modules targeting more than one CPU architecture (e.g. both `win32` and `win_amd64`). You should create a separate wheel for each CPU architecture and repair each individually.
- If your project has a [delay-load DLL dependency](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls), you must use a custom delay-load import hook when building the DLL that has the delay-load dependency. This ensures that the directory containing the vendored DLLs is included in the DLL search path when delay-loading. For convenience, we provide a suitable hook for Microsoft Visual C/C++ at [delayload/delayhook.c](delayload/delayhook.c). Add the file to your C/C++ project when building your DLL.
- An `__init__.py` file in a top-level package or a `.py` file at the root of a namespace package must be parsable by the version of Python that runs `delvewheel`. For instance, you cannot run `delvewheel` using Python 3.9 to repair a wheel containing a top-level package with an `__init__.py` file that uses syntax features introduced in Python 3.10. Aside from this rule, there are no other requirements regarding the relationship between the version of Python that runs `delvewheel` and the version(s) of Python that the wheel supports.
