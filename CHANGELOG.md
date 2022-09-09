# 0.0.25
- Undo deprecation of `--no-mangle-all`. It will stay.

# 0.0.24
- Don't mangle `ucrtbased.dll`.
- Fix DLL load error for Anaconda Python 3.8 and 3.9.

# 0.0.23
- Increase hash length when name-mangling DLLs.
- Remove extra newline from output end.
- Document CPU architecture limitations.
- Document warning regarding `--add-dll`.
- Deprecate `--no-mangle-all`.

# 0.0.22
- Improve performance of reading PE files.
- Print warnings from `pefile` at verbosity level 2.
- Disable the Anaconda workaround for Python 3.8.13.

# 0.0.21
- Record command-line arguments in `DELVEWHEEL` file to aid in diagnosing issues.
- Don't vendor DLLs that are included with PyPy3.7 64-bit or PyPy2.7.

# 0.0.20
- Remove the limitation where the bitness of Python interpreter must match the bitness of the wheel.
- Ensure that the search for `.pyd` files is case-insensitive. Previously, extension modules would be missed if the `.pyd` extension was not all lowercase.

# 0.0.19
- Fix a bug where using `--add-dll` can cause failures during the name-mangling step.
- Fix a bug where `--ignore-in-wheel` does not take effect during a wheel repair.
- Allow `delvewheel` to run on non-Windows systems.
- Disable the Anaconda workaround on versions where Anaconda has fixed its bug.
- Do not start the `__init__.py` patch with `"""""""` if unnecessary.
- Document the limitations of `--ignore-in-wheel`.
- Don't vendor DLLs included with CPython 3.11 or PyPy3.8 for wheels targeting those versions.

# 0.0.18
- Fix a parse error if `__init__.py` contains a docstring that uses triple single-quotes.
- Fix a parse error if `__init__.py` contains a docstring whose contents start with a double-quote.

# 0.0.17
- Don't mangle `libwinpthread*.dll`.

# 0.0.16
- Avoid adding `__init__.py` to a folder with the same name as a top-level module. This ensures that the module search order is unaffected by the wheel repair process.

# 0.0.15
- Fix an issue with the Anaconda workaround where `CONDA_DLL_SEARCH_MODIFICATION_ENABLE` was not restored.

# 0.0.14
- Work around a bug in Anaconda distribution of Python where `os.add_dll_directory()` has no effect.
- Don't vendor DLLs included with Python 3.10 for wheels targeting this version.

# 0.0.13
- Continue searching when a DLL dependency of the wrong bitness is found.

# 0.0.12
- Parse `__init__.py` correctly when comments precede the docstring.
- Fix `__init__.py` for Python < 3.8.

# 0.0.11
- Introduce the `--ignore-in-wheel` flag.
- Avoid repairing wheels that were already repaired.
- Don't vendor DLLs that are already included with a Python installation.
- Add the Microsoft Visual C++ runtime redistributable directory to the DLL search path.

# 0.0.10
- Ensure that vendored DLLs can be loaded when the wheel has a top-level module.
- Patch `__init__.py` correctly in a platlib wheel.
- Clarify the documentation for the `--no-dll` flag.

# 0.0.9
- Use the `delvewheel` version number instead of random string when patching `__init__.py`.
- Correct the patching of `__init__.py` when it contains a `__future__` import.

# 0.0.8
- Correct the parsing of `__init__.py` with docstring that starts or ends with whitespace.

# 0.0.7
- Patch `__init__.py` correctly in a purelib wheel.
- Enforce incompatibility with non-Windows platforms.

# 0.0.6
- Fix error running on Python 3.8 or earlier.

# 0.0.5
- Improve error message if a DLL cannot be name-mangled.
- Don't mangle `msvcr*.dll`.
- Change `--add-path` to prepend to `PATH` instead of appending.

## 0.0.4
- Correct case where `PATH` does not end with `;`.

## 0.0.3
- Introduce `--no-mangle-all` option.
- Improve error message if DLL name mangling fails.
- Place vendored DLLs in a folder at the top level of the wheel.

## 0.0.2
- Patch `__init__.py` correctly when it is nonempty initially and has no docstring.
- Clarify documentation for `--add-dll`.

## 0.0.1
- First release.
