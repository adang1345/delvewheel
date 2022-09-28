import os
import re
import shutil
import subprocess
import sys
import typing
import unittest
import zipfile

DEBUG = False


def check_call(args: list):
    if DEBUG:
        return subprocess.check_call(args)
    return subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def is_mangled(filename: str) -> bool:
    """Return True if filename is a name-mangled DLL name, False otherwise."""
    return re.match(r'^[^-]+-[0-9a-f]{32}\.dll$', filename.lower()) is not None


def import_iknowpy_successful(build_tag: str = '', modules: typing.Optional[list] = None) -> bool:
    """Return True iff wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl
    can be installed successfully, imported, uninstalled, and deleted.

    If build_tag is specified, use the wheel containing the build tag
    instead.

    If modules is specified, verify that the modules in that list are imported
    successfully."""
    if build_tag:
        whl_path = f'wheelhouse/iknowpy-1.5.0-{build_tag}-cp310-cp310-win_amd64.whl'
    else:
        whl_path = f'wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'
    if modules is None:
        modules = ['iknowpy']
    try:
        check_call(['pip', 'install', '--force-reinstall', whl_path])
        for module in modules:
            check_call(['python', '-c', f'import {module}'])
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        try:
            check_call(['pip', 'uninstall', '-y', 'iknowpy'])
        except subprocess.CalledProcessError:
            pass
        try:
            os.remove(whl_path)
        except FileNotFoundError:
            pass


def import_simpleext_successful(build_tag: str = '', modules: typing.Optional[list] = None) -> bool:
    """Return True iff wheelhouse/simpleext-0.0.1-cp310-cp310-win_amd64.whl
    can be installed successfully, imported, uninstalled, and deleted.

    If build_tag is specified, use the wheel containing the build tag
    instead.

    If modules is specified, verify that the modules in that list are imported
    successfully."""
    if build_tag:
        whl_path = f'wheelhouse/simpleext-0.0.1-{build_tag}-cp310-cp310-win_amd64.whl'
    else:
        whl_path = f'wheelhouse/simpleext-0.0.1-cp310-cp310-win_amd64.whl'
    if modules is None:
        modules = ['simpleext']
    try:
        check_call(['pip', 'install', '--force-reinstall', whl_path])
        for module in modules:
            check_call(['python', '-c', f'import {module}'])
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        try:
            check_call(['pip', 'uninstall', '-y', 'simpleext'])
        except subprocess.CalledProcessError:
            pass
        try:
            os.remove(whl_path)
        except FileNotFoundError:
            pass


class RepairTestCase(unittest.TestCase):
    """Tests for delvewheel repair"""
    def test_basic(self):
        """Basic repair for the iknowpy package"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_not_found(self):
        """DLL not found"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])

    def test_no_mangle_1(self):
        """--no-mangle for a single DLL, case-insensitive"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnOwEnGiNe.dLl', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if path.name.startswith('iKnowEngine'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_no_mangle_2(self):
        """--no-mangle for 2 DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnowEngine.dll;iKnowBase.dll', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if path.name.startswith('iKnowEngine') or path.name.startswith('iKnowBase'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_no_mangle_all(self):
        """--no-mangle for all DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_add_dll_1(self):
        """--add-dll for 1 DLL"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--add-dll', 'kernel32.dll', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            kernel32_found = False
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if path.name.startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')
        self.assertTrue(import_iknowpy_successful())

    def test_add_dll_1_exist(self):
        """-add-dll for 1 DLL that's being added anyway"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--add-dll', 'iKnowEngine.dll', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_add_dll_2_repeat(self):
        """--add-dll for 2 DLLs that are the same"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--add-dll', 'kernel32.dll;kernel32.dll', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            kernel32_found = False
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if path.name.startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')
        self.assertTrue(import_iknowpy_successful())

    def test_add_dll_2(self):
        """--add-dll for 2 DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--add-dll', 'kernel32.dll;kernelbase.dll', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        kernel32_found = False
        kernelbase_found = False
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if path.name.lower().startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                elif path.name.lower().startswith('kernelbase'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernelbase_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')
        self.assertTrue(kernelbase_found, 'kernelbase.dll found')
        self.assertTrue(import_iknowpy_successful())

    def test_add_dll_no_dll_overlap(self):
        """overlap between --add-dll and --no-dll generates an error"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--add-dll', 'kernel32.dll', '--no-dll', 'Kernel32.dll', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])

    def test_no_dll_irrelevant(self):
        """--no-dll for DLL that's not included anyway"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'nonexistent.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_no_dll_irrelevant_2(self):
        """--no-dll for 2 DLLs that are not included anyway"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'nonexistent.dll;nonexistent2.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_no_dll_iknowengine(self):
        """--no-dll for iKnowEngine.dll, which should eliminate all iKnow*.dll
        and icu*.dll dependencies"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'iKnowEngine.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                self.assertTrue(path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'))
        try:
            check_call(['pip', 'install', '--force-reinstall', 'wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
            with self.assertRaises(subprocess.CalledProcessError):
                check_call(['python', '-c', 'import iknowpy'])
            check_call(['python', '-c', 'import os; os.add_dll_directory(os.path.abspath("iknowpy")); import iknowpy'])
        finally:
            try:
                check_call(['pip', 'uninstall', '-y', 'iknowpy'])
            except subprocess.CalledProcessError:
                pass
            try:
                os.remove('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl')
            except FileNotFoundError:
                pass

    def test_no_dll_all(self):
        """--no-dll that removes all DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'iKnowEngine.dll;msvcp140.dll;concrt140.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        self.assertFalse(os.path.exists('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'))

    def test_ignore_in_wheel_irrelevant(self):
        """--ignore-in-wheel when no DLLs are in the wheel"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-in-wheel', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_ignore_in_wheel(self):
        """--ignore-in-wheel ignores iKnowEngine.dll and does not mangle it or
        its direct dependencies"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-in-wheel', 'iknowpy/iknowpy-1.5.0-0ignore-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-0ignore-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if any(path.name.startswith(x) for x in ('iKnowBase', 'iKnowShell', 'iKnowCore', 'iKnowALI')):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                elif path.name.startswith('iKnowEngine'):
                    self.fail('iKnowEngine.dll is ignored')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful('0ignore'))

    def test_ignore_in_wheel_override(self):
        """--ignore-in-wheel would ignore iKnowEngine.dll, but --add-dll
        overrides this and prevents it and its direct dependencies from name-
        mangling."""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-in-wheel', '--add-dll', 'iKnowEngine.dll', 'iknowpy/iknowpy-1.5.0-0ignore-cp310-cp310-win_amd64.whl'])
        iknowengine_found = False
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-0ignore-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.0', 'concrt140.dll', 'msvcp140.dll'):
                    continue
                if any(path.name.startswith(x) for x in ('iKnowEngine', 'iKnowBase', 'iKnowShell', 'iKnowCore', 'iKnowALI')):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    if path.name == 'iKnowEngine.dll':
                        iknowengine_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(iknowengine_found, 'iKnowEngine.dll found')
        self.assertTrue(import_iknowpy_successful('0ignore'))

    def test_extract_dir(self):
        """--extract-dir"""
        try:
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'iKnowEngine.dll;msvcp140.dll;concrt140.dll', '--no-mangle-all', '--extract-dir', 'temp', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
            self.assertFalse(os.path.exists('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'))
            self.assertTrue(os.path.exists('temp/iknowpy'))
        finally:
            if os.path.exists('temp'):
                shutil.rmtree('temp')

    def test_wheel_dir_short(self):
        """-w"""
        try:
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'iKnowEngine.dll', '-w', 'wheelhouse2', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
            self.assertTrue(os.path.exists('wheelhouse2/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'))
        finally:
            if os.path.exists('wheelhouse2'):
                shutil.rmtree('wheelhouse2')

    def test_wheel_dir_long(self):
        """--wheel-dir"""
        try:
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'iKnowEngine.dll', '-w', 'wheelhouse2', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
            self.assertTrue(os.path.exists('wheelhouse2/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'))
        finally:
            if os.path.exists('wheelhouse2'):
                shutil.rmtree('wheelhouse2')

    def test_lib_sdir_short(self):
        """-L"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', '-L', '.libs2', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel).iterdir():
                if path.name == 'iknowpy.libs2':
                    break
            else:
                self.fail('iknowpy.libs2 not found')
        self.assertTrue(import_iknowpy_successful())

    def test_lib_sdir_long(self):
        """--lib-sdir"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', '--lib-sdir', '.libs2', 'iknowpy/iknowpy-1.5.0-cp310-cp310-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.0-cp310-cp310-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel).iterdir():
                if path.name == 'iknowpy.libs2':
                    break
            else:
                self.fail('iknowpy.libs2 not found')
        self.assertTrue(import_iknowpy_successful())

    def test_purelib(self):
        """Extension module resides in purelib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-0purelib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0purelib'))

    def test_platlib(self):
        """Extension module resides in platlib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-0platlib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0platlib'))

    def test_purelib_platlib(self):
        """Extension modules are in purelib and platlib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-0purelibplatlib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0purelibplatlib', ['iknowpy', 'iknowpy2']))

    def test_normal_purelib(self):
        """Extension modules are in normal and purelib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-0normalpurelib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0normalpurelib', ['iknowpy', 'iknowpy2']))

    def test_normal_platlib(self):
        """Extension modules are in normal and platlib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-0normalplatlib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0normalplatlib', ['iknowpy', 'iknowpy2']))

    def test_normal_purelib_platlib(self):
        """Extension modules are in normal, purelib, and platlib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.0-0normalpurelibplatlib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0normalpurelibplatlib', ['iknowpy', 'iknowpy2', 'iknowpy3']))

    def test_top_level(self):
        """Top-level extension module in root directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful())

    def test_top_level_purelib(self):
        """Top-level extension module in purelib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0toplevelpurelib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0toplevelpurelib'))

    def test_top_level_platlib(self):
        """Top-level extension module in platlib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0toplevelplatlib-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0toplevelplatlib'))

    def test_top_package_levels(self):
        """Both top-level and package-level extension modules are present"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0toppackagelevels-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0toppackagelevels', ['simpleext', 'simpleext2.simpleext']))

    def test_init_patch(self):
        """Various __init__.py cases that must be patched correctly
        0. no __init__.py
        1. blank file
        2. docstring with whitespace preceding the quotes
        3. docstring with surrounding whitespace within quotes
        4. 3 single-quotes
        5. 1 future import
        6. multiple future imports
        7. docstring and multiple future imports
        8. escaped quotes at docstring end"""
        cases = 9
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0init-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0init', [f'simpleext{x}.simpleext' for x in range(cases)]))

    def test_wrong_bitness(self):
        """Error happens if dependency of wrong bitness is found"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x86', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp310-cp310-win_amd64.whl'])

    def test_skip_wrong_bitness(self):
        """Continue searching if dependency of wrong bitness is found"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x86;simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp310-cp310-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful())

    def test_cross_bitness(self):
        """Repair a 32-bit wheel using 64-bit Python"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x86', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp310-cp310-win32.whl'])

    def test_cross_version(self):
        """Repair a Python 3.6 wheel using Python 3.10"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp36-cp36m-win_amd64.whl'])

    def test_cross_implementation(self):
        """Repair a PyPy wheel using CPython"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-pp39-pypy39_pp73-win_amd64.whl'])

    def test_multiple_versions(self):
        """Repair a wheel targeting multiple Python versions"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp36.cp310-cp36m.cp310-win_amd64.whl'])
        try:
            check_call(['pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp36.cp310-cp36m.cp310-win_amd64.whl'])
            check_call(['python', '-c', 'import simpleext'])
        finally:
            try:
                check_call(['pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass
            try:
                os.remove('wheelhouse/simpleext-0.0.1-cp36.cp310-cp36m.cp310-win_amd64.whl')
            except FileNotFoundError:
                pass

    @unittest.skipUnless(sys.version_info[:2] == (3, 6), 'Python version is not 3.6')
    def test_python36(self):
        """delvewheel can be run on Python 3.6"""
        check_call(['delvewheel', 'show', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp36-cp36m-win_amd64.whl'])
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp36-cp36m-win_amd64.whl'])
        try:
            check_call(['pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp36-cp36m-win_amd64.whl'])
            check_call(['python', '-c', 'import simpleext'])
        finally:
            try:
                check_call(['pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass
            try:
                os.remove('wheelhouse/simpleext-0.0.1-cp36-cp36m-win_amd64.whl')
            except FileNotFoundError:
                pass

    @unittest.skipUnless(sys.implementation.name == 'pypy', 'Python implementation is not PyPy')
    def test_pypy(self):
        """delvewheel can be run on PyPy and can repair a PyPy wheel"""
        check_call(['delvewheel', 'show', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-pp39-pypy39_pp73-win_amd64.whl'])
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-pp39-pypy39_pp73-win_amd64.whl'])
        try:
            check_call(['pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-pp39-pypy39_pp73-win_amd64.whl'])
            check_call(['python', '-c', 'import simpleext'])
        finally:
            try:
                check_call(['pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass
            try:
                os.remove('wheelhouse/simpleext-0.0.1-pp39-pypy39_pp73-win_amd64.whl')
            except FileNotFoundError:
                pass


class NeededTestCase(unittest.TestCase):
    """Tests for delvewheel needed"""
    def test_iknowengine(self):
        p = subprocess.run(['delvewheel', 'needed', 'iknowpy/iKnowEngine.dll'], capture_output=True, text=True, check=True)
        self.assertEquals(
            'api-ms-win-crt-convert-l1-1-0.dll\napi-ms-win-crt-heap-l1-1-0.dll\napi-ms-win-crt-locale-l1-1-0.dll\n'
            'api-ms-win-crt-math-l1-1-0.dll\napi-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\n'
            'iKnowALI.dll\niKnowBase.dll\niKnowCore.dll\niKnowShell.dll\nKERNEL32.dll\nMSVCP140.dll\n'
            'VCRUNTIME140.dll\nVCRUNTIME140_1.dll\n', p.stdout)
        self.assertFalse(p.stderr)

    def test_simpleext(self):
        p = subprocess.run(['delvewheel', 'needed', 'simpleext/x64/simpledll.dll'], capture_output=True, text=True, check=True)
        self.assertEquals('api-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\nKERNEL32.dll\n'
                          'VCRUNTIME140.dll\n', p.stdout)
        self.assertFalse(p.stderr)

    def test_simpleext_32bit(self):
        p = subprocess.run(['delvewheel', 'needed', 'simpleext/x86/simpledll.dll'], capture_output=True, text=True, check=True)
        self.assertEquals('api-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\nKERNEL32.dll\n'
                          'VCRUNTIME140.dll\n', p.stdout)
        self.assertFalse(p.stderr)


if __name__ == '__main__':
    unittest.main()
