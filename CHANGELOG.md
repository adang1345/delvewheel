## 1.3.1 <sub><sup>(_16 February 2023_)</sup></sub>
- Improve error message if `--strip` fails to remove all trailing data.
- Correct the calculation that determines whether a DLL contains trailing data if the last entry in the PE section header does not correspond to the last section of the PE file.
- Remove the `machomachomangler` dependency. `delvewheel` now takes full responsibility for DLL name-mangling.

## 1.3.0 <sub><sup>(_10 February 2023_)</sup></sub>
- Use Unix line endings for the `RECORD` and `DELVEWHEEL` metadata files.
- Improve error message in name-mangling step when a DLL has trailing data.
- Preserve the order of paths specified with `--add-path`.
- Introduce the `--strip` flag to automatically strip DLLs with trailing data during the name-mangling step.

## 1.2.0 <sub><sup>(_7 January 2023_)</sup></sub>
- Drop support for Python 3.6. Python 3.7+ will be required to run `delvewheel` itself. Wheels with a target Python version of 3.6 can still be repaired.
- Don't vendor DLLs included with CPython 3.9 or 3.10 arm64 for wheels targeting those versions.
- Make the `DELVEWHEEL` metadata file more structured.
- Add tests for wheels that have no external DLL dependencies.
- Include `delvewheel` version in help menu.

## 1.1.4 <sub><sup>(_4 December 2022_)</sup></sub>
- Add Python 3.12 to trove classifiers.
- Don't vendor DLLs required by CPython 2.6, 3.2, and 3.3 for wheels targeting those versions.
- Validate DLL names provided as arguments.
- Improve Anaconda Python detection.
- Use wheel distribution name in hash for name-mangling.

## 1.1.3 <sub><sup>(_4 December 2022_)</sup></sub>
- Withdrawn due to a mistake in the release process.

## 1.1.2 <sub><sup>(_15 November 2022_)</sup></sub>
- For `abi3` wheels, don't include DLLs included with Python.
- Don't assume `vcruntime140_1.dll` is present for Python 3.8 x64.
- Don't vendor DLLs included with CPython 3.12.

## 1.1.1 <sub><sup>(_4 November 2022_)</sup></sub>
- Improve compatibility with PyInstaller. Repaired wheels no longer raise an error immediately if they can't find the vendored DLLs when in a PyInstaller environment.
- Remove the Visual C++ runtime redistributable directory from the default search path.

## 1.1.0 <sub><sup>(_14 October 2022_)</sup></sub>
- Revise lists of system DLLs.
- Introduce experimental support for repair of `win_arm64` wheels.
- Improve documentation and code style.
- Optimize the `__init__.py` patch for Python >= 3.10.
- Ensure that `delvewheel show` always shows the dependent DLLs that are not found.

## 1.0.1 <sub><sup>(_29 September 2022_)</sup></sub>
- Add unit tests for more Python versions and platforms.
- Avoid including `libpypy3.9-c.dll` when repairing a PyPy3.9 wheel.
- Avoid `OSError: [Errno 22] Invalid argument` during name-mangling step when running `delvewheel` in PyPy.

## 1.0.0 <sub><sup>(_26 September 2022_)</sup></sub>
- Label project as production/stable.
- Fix "relative import outside package" warning.
- Add unit tests.
- Make `delvewheel needed` output prettier.

## 0.0.25 <sub><sup>(_8 September 2022_)</sup></sub>
- Undo deprecation of `--no-mangle-all`. It will stay.

## 0.0.24 <sub><sup>(_2 September 2022_)</sup></sub>
- Don't mangle `ucrtbased.dll`.
- Fix DLL load error for Anaconda Python 3.8 and 3.9.

## 0.0.23 <sub><sup>(_17 August 2022_)</sup></sub>
- Increase hash length when name-mangling DLLs.
- Remove extra newline from output end.
- Document CPU architecture limitations.
- Document warning regarding `--add-dll`.
- Deprecate `--no-mangle-all`.

## 0.0.22 <sub><sup>(_28 April 2022_)</sup></sub>
- Improve performance of reading PE files.
- Print warnings from `pefile` at verbosity level 2.
- Disable the Anaconda workaround for Python 3.8.13.

## 0.0.21 <sub><sup>(_1 April 2022_)</sup></sub>
- Record command-line arguments in `DELVEWHEEL` file to aid in diagnosing issues.
- Don't vendor DLLs that are included with PyPy3.7 64-bit or PyPy2.7.

## 0.0.20 <sub><sup>(_20 February 2022_)</sup></sub>
- Remove the limitation where the bitness of Python interpreter must match the bitness of the wheel.
- Ensure that the search for `.pyd` files is case-insensitive. Previously, extension modules would be missed if the `.pyd` extension was not all lowercase.

## 0.0.19 <sub><sup>(_18 February 2022_)</sup></sub>
- Fix a bug where using `--add-dll` can cause failures during the name-mangling step.
- Fix a bug where `--ignore-in-wheel` does not take effect during a wheel repair.
- Allow `delvewheel` to run on non-Windows systems.
- Disable the Anaconda workaround on versions where Anaconda has fixed its bug.
- Do not start the `__init__.py` patch with `"""""""` if unnecessary.
- Document the limitations of `--ignore-in-wheel`.
- Don't vendor DLLs included with CPython 3.11 or PyPy3.8 for wheels targeting those versions.

## 0.0.18 <sub><sup>(_22 January 2022_)</sup></sub>
- Fix a parse error if `__init__.py` contains a docstring that uses triple single-quotes.
- Fix a parse error if `__init__.py` contains a docstring whose contents start with a double-quote.

## 0.0.17 <sub><sup>(_9 December 2021_)</sup></sub>
- Don't mangle `libwinpthread*.dll`.

## 0.0.16 <sub><sup>(_9 December 2021_)</sup></sub>
- Avoid adding `__init__.py` to a folder with the same name as a top-level module. This ensures that the module search order is unaffected by the wheel repair process.

## 0.0.15 <sub><sup>(_30 September 2021_)</sup></sub>
- Fix an issue with the Anaconda workaround where `CONDA_DLL_SEARCH_MODIFICATION_ENABLE` was not restored.

## 0.0.14 <sub><sup>(_5 August 2021_)</sup></sub>
- Work around a bug in Anaconda distribution of Python where `os.add_dll_directory()` has no effect.
- Don't vendor DLLs included with Python 3.10 for wheels targeting this version.

## 0.0.13 <sub><sup>(_12 July 2021_)</sup></sub>
- Continue searching when a DLL dependency of the wrong bitness is found.

## 0.0.12 <sub><sup>(_23 March 2021_)</sup></sub>
- Parse `__init__.py` correctly when comments precede the docstring.
- Fix `__init__.py` for Python < 3.8.

## 0.0.11 <sub><sup>(_15 February 2021_)</sup></sub>
- Introduce the `--ignore-in-wheel` flag.
- Avoid repairing wheels that were already repaired.
- Don't vendor DLLs that are already included with a Python installation.
- Add the Microsoft Visual C++ runtime redistributable directory to the DLL search path.

## 0.0.10 <sub><sup>(_6 February 2021_)</sup></sub>
- Ensure that vendored DLLs can be loaded when the wheel has a top-level module.
- Patch `__init__.py` correctly in a platlib wheel.
- Clarify the documentation for the `--no-dll` flag.

## 0.0.9 <sub><sup>(_26 January 2021_)</sup></sub>
- Use the `delvewheel` version number instead of random string when patching `__init__.py`.
- Correct the patching of `__init__.py` when it contains a `__future__` import.

## 0.0.8 <sub><sup>(_18 January 2021_)</sup></sub>
- Correct the parsing of `__init__.py` with docstring that starts or ends with whitespace.

## 0.0.7 <sub><sup>(_18 January 2021_)</sup></sub>
- Patch `__init__.py` correctly in a purelib wheel.
- Enforce incompatibility with non-Windows platforms.

## 0.0.6 <sub><sup>(_5 January 2021_)</sup></sub>
- Fix error running on Python 3.8 or earlier.

## 0.0.5 <sub><sup>(_4 January 2021_)</sup></sub>
- Improve error message if a DLL cannot be name-mangled.
- Don't mangle `msvcr*.dll`.
- Change `--add-path` to prepend to `PATH` instead of appending.

## 0.0.4 <sub><sup>(_27 December 2020_)</sup></sub>
- Correct case where `PATH` does not end with `;`.

## 0.0.3 <sub><sup>(_26 December 2020_)</sup></sub>
- Introduce `--no-mangle-all` option.
- Improve error message if DLL name mangling fails.
- Place vendored DLLs in a folder at the top level of the wheel.

## 0.0.2 <sub><sup>(_26 December 2020_)</sup></sub>
- Patch `__init__.py` correctly when it is nonempty initially and has no docstring.
- Clarify documentation for `--add-dll`.

## 0.0.1 <sub><sup>(_23 December 2020_)</sup></sub>
- First release.
