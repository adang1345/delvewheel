import collections.abc
import io
import os
import re
import shutil
import subprocess
import sys
import typing
import unittest
import zipfile

DEBUG = False


def check_call(args: list, env: typing.Optional[collections.abc.Mapping] = None):
    base_env = os.environ.copy()
    if env is not None:
        for var in env:
            if env[var] is None:
                base_env.pop(var, None)
            else:
                base_env[var] = env[var]
    if DEBUG:
        return subprocess.check_call(args, env=base_env)
    return subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=base_env)


def is_mangled(filename: str) -> bool:
    """Return True if filename is a name-mangled DLL name, False otherwise."""
    return re.fullmatch(r'[^-]+-[0-9a-f]{32}\.dll', filename.lower()) is not None


def import_iknowpy_successful(build_tag: str = '', modules: typing.Optional[list] = None) -> bool:
    """Return True iff wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl
    can be installed successfully, imported, uninstalled, and deleted.

    If build_tag is specified, use the wheel containing the build tag
    instead.

    If modules is specified, verify that the modules in that list are imported
    successfully."""
    if build_tag:
        whl_path = f'wheelhouse/iknowpy-1.5.3-{build_tag}-cp312-cp312-win_amd64.whl'
    else:
        whl_path = f'wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'
    if modules is None:
        modules = ['iknowpy']
    try:
        check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', whl_path])
        for module in modules:
            check_call([sys.executable, '-c', f'import {module}'])
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        try:
            check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'iknowpy'])
        except subprocess.CalledProcessError:
            pass


def import_simpleext_successful(build_tag: str = '', modules: typing.Optional[list] = None) -> bool:
    """Return True iff wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl
    can be installed successfully, imported, uninstalled, and deleted.

    If build_tag is specified, use the wheel containing the build tag
    instead.

    If modules is specified, verify that the modules in that list are imported
    successfully."""
    if build_tag:
        whl_path = f'wheelhouse/simpleext-0.0.1-{build_tag}-cp312-cp312-win_amd64.whl'
    else:
        whl_path = f'wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl'
    if modules is None:
        modules = ['simpleext']
    try:
        check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', whl_path])
        for module in modules:
            check_call([sys.executable, '-c', f'import {module}'])
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        try:
            check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
        except subprocess.CalledProcessError:
            pass


class TestCase(unittest.TestCase):
    def namespace_helper(self, whl: str, namespace_pkg: str, *,
                         mangle: bool = True,
                         patched: typing.Optional[typing.List[str]] = None,
                         not_patched: typing.Optional[typing.List[str]] = None,
                         exist: typing.Optional[typing.List[str]] = None,
                         not_exist: typing.Optional[typing.List[str]] = None,
                         importable: typing.Optional[typing.List[str]] = None):
        """Run a test of namespace package support. All paths must be specified
        using forward slashes.

        whl: path to the wheel to repair
        namespace_pkg: the value to pass to the --namespace-pkg option during
            repair
        mangle: (optional) whether to mangle the DLL names, default True
        patched: (optional) list of paths to files that should be patched,
            relative to wheel root
        not_patched: (optional) list of paths to files that should not be
            created or patched, relative to wheel root
        exist: (optional) list of paths that should exist after repair,
            relative to wheel root
        not_exist: (optional) list of paths that should not exist after repair,
            relative to wheel root
        importable: (optional) list of names that should be importable after
            the repaired wheel is installed, must be None if testing on non-
            Windows platform"""
        try:
            check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', *(() if mangle else ('--no-mangle-all',)), '--namespace-pkg', namespace_pkg, whl])
            repaired_whl = os.path.join('wheelhouse', os.path.basename(whl))
            with zipfile.ZipFile(repaired_whl) as whl_file:
                if patched:
                    for item in patched:
                        with io.TextIOWrapper(whl_file.open(item)) as file:
                            self.assertIn('_delvewheel_patch_', file.read(), f'{item} is patched')
                if not_patched:
                    for item in not_patched:
                        try:
                            with io.TextIOWrapper(whl_file.open(item)) as file:
                                self.assertNotIn('_delvewheel_patch_', file.read(), f'{item} is not patched')
                        except KeyError:
                            pass
                if exist:
                    for item in exist:
                        whl_file.getinfo(item)
                if not_exist:
                    for item in not_exist:
                        with self.assertRaises(KeyError, msg=f'{item} does not exist'):
                            whl_file.getinfo(item)
            if sys.platform == 'win32':
                check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', repaired_whl])
            if importable:
                if sys.platform != 'win32':
                    raise RuntimeError('Cannot test imports on non-Windows system')
                for item in importable:
                    check_call([sys.executable, '-c', f'import {item}'])
        finally:
            if sys.platform == 'win32':
                try:
                    check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
                except subprocess.CalledProcessError:
                    pass

    @classmethod
    def tearDownClass(cls):
        if DEBUG:
            return
        for item in os.listdir('.'):
            if os.path.isdir(item) and item.startswith('wheelhouse'):
                shutil.rmtree(item)


class ShowTestCase(TestCase):
    """Tests for delvewheel show"""
    def test_v(self):
        """-v"""
        check_call(['delvewheel', 'show', '--add-path', 'simpleext/x64', '-v', 'simpleext/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])

    def test_vv(self):
        """-vv"""
        check_call(['delvewheel', 'show', '--add-path', 'simpleext/x64', '-vv', 'simpleext/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])

    def test_already_repaired(self):
        """Show is canceled if wheel is already repaired."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        output = subprocess.check_output(['delvewheel', 'show', 'wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('has already repaired', output)

    def test_pure_python(self):
        """No dependencies needed if wheel is pure Python."""
        output = subprocess.check_output(['delvewheel', 'show', 'no_dependencies/more_itertools-9.0.0-py3-none-any.whl'], text=True)
        self.assertIn('will be copied into the wheel.\n    None', output)

    def test_no_external(self):
        """No dependencies needed if wheel has an extension module that has no
        external dependencies."""
        output = subprocess.check_output(['delvewheel', 'show', 'no_dependencies/h3ronpy-0.16.0-cp38-abi3-win_amd64.whl'], text=True)
        self.assertIn('will be copied into the wheel.\n    None', output)

    def test_wrong_platform(self):
        """No dependencies needed if wheel has an extension module that is not
        for Windows."""
        output = subprocess.check_output(['delvewheel', 'show', 'no_dependencies/h3ronpy-0.16.0-cp38-abi3-macosx_10_7_x86_64.whl'], text=True)
        self.assertIn('will be copied into the wheel.\n    None', output)

    def test_ignore_data(self):
        """Ignore .pyd file in .data/data directory."""
        output = subprocess.check_output(['delvewheel', 'show', 'simpleext/simpleext-0.0.1-0ignore-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('will be copied into the wheel.\n    None', output)

    def test_analyze_existing(self):
        """--analyze-existing shows dependencies of existing DLLs"""
        output = subprocess.check_output(['delvewheel', 'show', '--add-path', 'simpleext/x64;iknowpy', '--analyze-existing', 'simpleext/simpleext-0.0.1-0analyze-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('icudt74.dll', output)
        self.assertIn('msvcp140.dll', output)


class RepairTestCase(TestCase):
    """Tests for delvewheel repair"""
    def test_basic(self):
        """Basic repair for the iknowpy package"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_not_found(self):
        """DLL not found"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])

    def test_no_mangle_1(self):
        """--no-mangle for a single DLL, case-insensitive"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnOwEnGiNe.dLl', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('iKnowEngine'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_no_mangle_2(self):
        """--no-mangle for 2 DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnowEngine.dll;iKnowBase.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('iKnowEngine') or path.name.startswith('iKnowBase'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_no_mangle_3(self):
        """--no-mangle for 2 DLLs, flag specified twice"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnowEngine.dll', '--no-mangle', 'iKnowBase.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('iKnowEngine') or path.name.startswith('iKnowBase'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_no_mangle_all(self):
        """--no-mangle for all DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_strip_0(self):
        """--strip has no effect when it's not needed"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--strip', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_strip_1(self):
        """--strip needed for 1 DLL"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy/trailing_data_1;iknowpy', '--test', 'not_enough_padding', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy/trailing_data_1;iknowpy', '--strip', '--test', 'not_enough_padding', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_add_path_2(self):
        """--add-path specified twice"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy/trailing_data_1', '--add-path', 'iknowpy', '--test', 'not_enough_padding', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy/trailing_data_1', '--add-path', 'iknowpy', '--strip', '--test', 'not_enough_padding', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_strip_2(self):
        """--strip needed for 2 DLLs"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy/trailing_data_1;iknowpy/trailing_data_2;iknowpy', '--test', 'not_enough_padding', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy/trailing_data_1;iknowpy/trailing_data_2;iknowpy', '--strip', '--test', 'not_enough_padding', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_add_dll(self):
        """--add-dll is alias for --include"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--add-dll', 'kernEl32.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            kernel32_found = False
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')
        self.assertTrue(import_iknowpy_successful())

    def test_include_1(self):
        """--include for 1 DLL, case-insensitive"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'kernEl32.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            kernel32_found = False
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')
        self.assertTrue(import_iknowpy_successful())

    def test_include_1_exist(self):
        """-include for 1 DLL that's being added anyway"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'iKnowEngine.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful())

    def test_include_2_repeat(self):
        """--include for 2 DLLs that are the same"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'kernel32.dll;kernel32.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            kernel32_found = False
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')
        self.assertTrue(import_iknowpy_successful())

    def test_include_2(self):
        """--include for 2 DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'kernel32.dll;kernelbase.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        kernel32_found = False
        kernelbase_found = False
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
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

    def test_include_3(self):
        """--include for 2 DLLs, flag specified twice"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'kernel32.dll', '--include', 'kernelbase.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        kernel32_found = False
        kernelbase_found = False
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
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

    def test_include_exclude_overlap(self):
        """overlap between --include and --exclude generates an error"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'kernel32.dll', '--exclude', 'Kernel32.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])

    def test_exclude_irrelevant(self):
        """--exclude for DLL that's not included anyway"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'nonexistent.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_exclude_irrelevant_2(self):
        """--exclude for 2 DLLs that are not included anyway"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'nonexistent.dll;nonexistent2.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_no_dll_iknowengine(self):
        """--no-dll is alias for --exclude"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-dll', 'iKnowEngine.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                self.assertTrue(path.name in ('.load-order-iknowpy-1.5.3', 'msvcp140.dll'))
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
            with self.assertRaises(subprocess.CalledProcessError):
                check_call([sys.executable, '-c', 'import iknowpy'])
            check_call([sys.executable, '-c', 'import os; os.add_dll_directory(os.path.abspath("iknowpy")); import iknowpy'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'iknowpy'])
            except subprocess.CalledProcessError:
                pass

    def test_exclude_iknowengine(self):
        """--exclude for iKnowEngine.dll, which should eliminate all iKnow*.dll
        and icu*.dll dependencies"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'iKnowEngine.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                self.assertTrue(path.name in ('.load-order-iknowpy-1.5.3', 'msvcp140.dll'))
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
            with self.assertRaises(subprocess.CalledProcessError):
                check_call([sys.executable, '-c', 'import iknowpy'])
            check_call([sys.executable, '-c', 'import os; os.add_dll_directory(os.path.abspath("iknowpy")); import iknowpy'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'iknowpy'])
            except subprocess.CalledProcessError:
                pass

    def test_exclude_all(self):
        """--exclude that removes all DLLs"""
        output = subprocess.check_output(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'iKnowEngine.dll;msvcp140.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('no external dependencies are needed', output)

    def test_exclude_all_2(self):
        """--exclude that removes all DLLs, flag specified twice"""
        output = subprocess.check_output(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'iKnowEngine.dll', '--exclude', 'msvcp140.dll', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('no external dependencies are needed', output)

    def test_ignore_existing_irrelevant(self):
        """--ignore-existing when no DLLs are in the wheel"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-existing', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_ignore_existing(self):
        """--ignore-existing ignores iKnowEngine.dll and does not mangle it or
        its direct dependencies"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-existing', 'iknowpy/iknowpy-1.5.3-0ignore-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-0ignore-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if any(path.name.startswith(x) for x in ('iKnowBase', 'iKnowShell', 'iKnowCore', 'iKnowALI', 'msvcp140')):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                elif path.name.startswith('iKnowEngine'):
                    self.fail('iKnowEngine.dll is ignored')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful('0ignore'))

    def test_analyze_existing(self):
        """--analyze-existing vendors in dependencies of existing icuuc74.dll"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64;iknowpy', '--analyze-existing', 'simpleext/simpleext-0.0.1-0analyze-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-0analyze-cp312-cp312-win_amd64.whl') as wheel:
            i = 0
            for path in zipfile.Path(wheel, 'simpleext-0.0.1.data/platlib/').iterdir():
                self.assertTrue(any(path.name.startswith(x) for x in ('icudt74', 'msvcp140', 'simpledll')))
                self.assertTrue(is_mangled(path.name))
                i += 1
            self.assertEqual(3, i)

    def test_analyze_existing2(self):
        """--analyze-existing with --no-mangle-all"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64;iknowpy', '--analyze-existing', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0analyze-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-0analyze-cp312-cp312-win_amd64.whl') as wheel:
            self.assertEqual({'icudt74.dll', 'msvcp140.dll', 'simpledll.dll'}, set(path.name for path in zipfile.Path(wheel, 'simpleext-0.0.1.data/platlib/').iterdir()))

    def test_ignore_in_wheel(self):
        """--ignore-in-wheel is an alias for --ignore-existing"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-in-wheel', 'iknowpy/iknowpy-1.5.3-0ignore-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-0ignore-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if any(path.name.startswith(x) for x in ('iKnowBase', 'iKnowShell', 'iKnowCore', 'iKnowALI', 'msvcp140')):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                elif path.name.startswith('iKnowEngine'):
                    self.fail('iKnowEngine.dll is ignored')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(import_iknowpy_successful('0ignore'))

    def test_ignore_existing_override(self):
        """--ignore-existing would ignore iKnowEngine.dll, but --include
        overrides this and prevents it and its direct dependencies from name-
        mangling."""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--ignore-existing', '--include', 'iKnowEngine.dll', 'iknowpy/iknowpy-1.5.3-0ignore-cp312-cp312-win_amd64.whl'])
        iknowengine_found = False
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-0ignore-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if any(path.name.startswith(x) for x in ('iKnowEngine', 'iKnowBase', 'iKnowShell', 'iKnowCore', 'iKnowALI', 'msvcp140')):
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
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'iKnowEngine.dll;msvcp140.dll', '--no-mangle-all', '--extract-dir', 'temp', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
            self.assertTrue(os.path.exists('temp/iknowpy'))
        finally:
            shutil.rmtree('temp', True)

    def test_wheel_dir_short(self):
        """-w"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'iKnowEngine.dll', '-w', 'wheelhouse2', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(os.path.exists('wheelhouse2/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'))

    def test_wheel_dir_long(self):
        """--wheel-dir"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--exclude', 'iKnowEngine.dll', '-w', 'wheelhouse2', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(os.path.exists('wheelhouse2/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'))

    def test_lib_sdir_short(self):
        """-L"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', '-L', '.libs2', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel).iterdir():
                if path.name == 'iknowpy.libs2':
                    break
            else:
                self.fail('iknowpy.libs2 not found')
        self.assertTrue(import_iknowpy_successful())

    def test_lib_sdir_long(self):
        """--lib-sdir"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', '--lib-sdir', '.libs2', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel).iterdir():
                if path.name == 'iknowpy.libs2':
                    break
            else:
                self.fail('iknowpy.libs2 not found')
        self.assertTrue(import_iknowpy_successful())

    def test_purelib(self):
        """Extension module resides in purelib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-0purelib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0purelib'))

    def test_platlib(self):
        """Extension module resides in platlib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-0platlib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0platlib'))

    def test_purelib_platlib(self):
        """Extension modules are in purelib and platlib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-0purelibplatlib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0purelibplatlib', ['iknowpy', 'iknowpy2']))

    def test_normal_purelib(self):
        """Extension modules are in normal and purelib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-0normalpurelib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0normalpurelib', ['iknowpy', 'iknowpy2']))

    def test_normal_platlib(self):
        """Extension modules are in normal and platlib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-0normalplatlib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0normalplatlib', ['iknowpy', 'iknowpy2']))

    def test_normal_purelib_platlib(self):
        """Extension modules are in normal, purelib, and platlib directories"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-0normalpurelibplatlib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful('0normalpurelibplatlib', ['iknowpy', 'iknowpy2', 'iknowpy3']))

    def test_top_level(self):
        """Top-level extension module in root directory

        Also check that the contents are compressed"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl') as whl:
            zip_info = whl.getinfo('simpleext.cp312-win_amd64.pyd')
            self.assertGreater(zip_info.file_size, zip_info.compress_size)
        self.assertTrue(import_simpleext_successful())

    def test_top_level_purelib(self):
        """Top-level extension module in purelib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0toplevelpurelib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0toplevelpurelib'))

    def test_top_level_platlib(self):
        """Top-level extension module in platlib directory"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0toplevelplatlib-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0toplevelplatlib'))

    def test_top_package_levels(self):
        """Both top-level and package-level extension modules are present"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0toppackagelevels-cp312-cp312-win_amd64.whl'])
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
        8. escaped quotes at docstring end
        9. comment before docstring
        10. comment without docstring
        11. blank line, multiline comment, no docstring
        12. comment, no docstring, code
        13. shebang
        14. shebang, comment, code
        15. shebang, split comments, code
        16. 1 double-quote
        17. 1 single-quote
        18. 1 double-quote with line continuation
        19: 1 double-quote with function docstring
        20: r-string
        21: commented out docstring, real docstring"""
        with zipfile.ZipFile('simpleext/simpleext-0.0.1-0init-cp312-cp312-win_amd64.whl') as wheel:
            cases = 1 + max(int(re.fullmatch(r'simpleext(\d+)', x.name)[1]) for x in zipfile.Path(wheel).iterdir() if re.fullmatch(r'simpleext(\d+)', x.name))
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0init-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0init', [f'simpleext{x}.simpleext' for x in range(cases)]))

    def test_wrong_bitness(self):
        """Error happens if dependency of wrong bitness is found"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x86', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])

    def test_skip_wrong_bitness(self):
        """Continue searching if dependency of wrong bitness is found"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x86;simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful())

    def test_cross_bitness(self):
        """Repair a 32-bit wheel using 64-bit Python"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x86', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-cp312-win32.whl'])

    def test_cross_version(self):
        """Repair a Python 3.6 wheel using Python 3.12"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp36-cp36m-win_amd64.whl'])

    def test_cross_implementation(self):
        """Repair a PyPy wheel using CPython"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-pp310-pypy310_pp73-win_amd64.whl'])

    def test_multiple_versions(self):
        """Repair a wheel targeting multiple Python versions"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])
            check_call([sys.executable, '-c', 'import simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass

    def test_multiple_wheels(self):
        """Repair multiple wheels in a single command"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl', 'simpleext/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
            check_call([sys.executable, '-c', 'import simpleext'])
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])
            check_call([sys.executable, '-c', 'import simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass

    def test_v(self):
        """-v"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', '-v', 'simpleext/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])

    def test_vv(self):
        """-vv"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', '-vv', 'simpleext/simpleext-0.0.1-cp36.cp312-cp36m.cp312-win_amd64.whl'])

    def test_abi3_cp36(self):
        """Repair an abi3 wheel for CPython 3.6+."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp36-abi3-win_amd64.whl'])
        try:
            with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-cp36-abi3-win_amd64.whl') as wheel:
                simpledll_found = False
                vcruntime_found = False
                for path in zipfile.Path(wheel, 'simpleext-0.0.1.data/platlib/').iterdir():
                    if path.name == 'simpledll.dll':
                        simpledll_found = True
                    elif path.name == 'vcruntime140.dll':
                        vcruntime_found = True
                self.assertTrue(simpledll_found)
                self.assertFalse(vcruntime_found)
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp36-abi3-win_amd64.whl'])
            check_call([sys.executable, '-c', 'import simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass

    def test_abi3_cp312(self):
        """Repair an abi3 wheel for CPython 3.12+."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-abi3-win_amd64.whl'])
        try:
            with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-cp312-abi3-win_amd64.whl') as wheel:
                simpledll_found = False
                vcruntime_found = False
                for path in zipfile.Path(wheel, 'simpleext-0.0.1.data/platlib/').iterdir():
                    if path.name == 'simpledll.dll':
                        simpledll_found = True
                    elif path.name == 'vcruntime140.dll':
                        vcruntime_found = True
                self.assertTrue(simpledll_found)
                self.assertFalse(vcruntime_found)
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp312-abi3-win_amd64.whl'])
            check_call([sys.executable, '-c', 'import simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass

    def test_already_repaired(self):
        """Repair is canceled if wheel is already repaired."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        output = subprocess.check_output(['delvewheel', 'repair', 'wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('has already repaired', output)

    def test_pure_python(self):
        """If wheel is pure Python, no repair happens, and the wheel is copied
        as-is."""
        output = subprocess.check_output(['delvewheel', 'repair', 'no_dependencies/more_itertools-9.0.0-py3-none-any.whl'], text=True)
        self.assertIn('no external dependencies are needed', output)
        self.assertTrue(os.path.isfile('wheelhouse/more_itertools-9.0.0-py3-none-any.whl'))

    def test_no_external(self):
        """If wheel has an extension module that has no external dependencies,
        no repair happens, and the wheel is copied as-is."""
        output = subprocess.check_output(['delvewheel', 'repair', 'no_dependencies/h3ronpy-0.16.0-cp38-abi3-win_amd64.whl'], text=True)
        self.assertIn('no external dependencies are needed', output)
        self.assertTrue(os.path.isfile('wheelhouse/h3ronpy-0.16.0-cp38-abi3-win_amd64.whl'))

    def test_wrong_platform(self):
        """If wheel has an extension module that is not for Windows, no repair
        happens, and the wheel is copied as-is."""
        output = subprocess.check_output(['delvewheel', 'repair', 'no_dependencies/h3ronpy-0.16.0-cp38-abi3-macosx_10_7_x86_64.whl'], text=True)
        self.assertIn('no external dependencies are needed', output)
        self.assertTrue(os.path.isfile('wheelhouse/h3ronpy-0.16.0-cp38-abi3-macosx_10_7_x86_64.whl'))

    def test_header_space(self):
        """PE header space is added correctly in name-mangling step."""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--test', 'not_enough_padding,header_space', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_iknowpy_successful())

    def test_namespace0(self):
        """basic test for namespace packages"""
        for namespace_pkgs in ('ns0;ns1;ns2',
                               'ns0;ns0;ns1;ns2',  # package specified twice
                               'ns0;ns1;ns2;ns3'):  # nonexistent package
            self.namespace_helper(
                'simpleext/simpleext-0.0.1-0namespace-cp312-cp312-win_amd64.whl', namespace_pkgs,
                patched=[
                    'ns0/reg/__init__.py',
                    'simpleext-0.0.1.data/platlib/ns1/reg/__init__.py',
                    'simpleext-0.0.1.data/purelib/ns2/reg/__init__.py',
                ],
                not_patched=[
                    'ns0/__init__.py',
                    'simpleext-0.0.1.data/purelib/ns1/__init__.py',
                    'simpleext-0.0.1.data/platlib/ns2/__init__.py',
                ],
                importable=[
                    'ns0.reg.simpleext',
                    'ns1.reg.simpleext',
                    'ns2.reg.simpleext',
                ],
            )

    def test_namespace1(self):
        """.py file in a namespace package"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-1namespace-cp312-cp312-win_amd64.whl', 'ns',
            patched=[
                'ns/a.py',
            ],
            not_patched=[
                'ns/__init__.py',
            ],
            importable=[
                'simpleext',
                'ns.a',
            ],
        )

    def test_namespace2(self):
        """.pyd file in a namespace package"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-2namespace-cp312-cp312-win_amd64.whl', 'ns',
            mangle=False,
            not_patched=[
                'ns/__init__.py',
            ],
            exist=[
                'simpleext.libs/simpledll.dll',
                'ns/simpledll.dll',
            ],
            importable=[
                'ns.simpleext',
            ],
        )

    def test_namespace3(self):
        """deeply nested namespace package"""
        not_patched = ['ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/reg/a.py']
        not_patched.extend('ns/' * x + '__init__.py' for x in range(1, not_patched[0].count('ns/') + 1))
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-3namespace-cp312-cp312-win_amd64.whl', 'ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns',
            not_patched=not_patched,
            patched=[
                'ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/ns/reg/__init__.py',
            ],
            importable=[
                'simpleext',
                'ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.ns.reg.a'
            ],
        )

    def test_namespace4(self):
        """mixed namespace and regular packages"""
        for namespace_pkgs in ('ns.ns',
                               'ns;ns.ns',  # redundant, one package is subpackage of another
                               'ns.ns;Reg'):  # case-sensitive, Reg should not match reg
            self.namespace_helper(
                'simpleext/simpleext-0.0.1-4namespace-cp312-cp312-win_amd64.whl', namespace_pkgs,
                not_patched=[
                    'ns/__init__.py',
                    'ns/ns/__init__.py',
                    'ns/ns/reg/a.py',
                ],
                patched=[
                    'reg/__init__.py',
                    'ns/reg/__init__.py',
                    'ns/ns/reg/__init__.py',
                    'ns/ns/a.py',
                ],
                importable=[
                    'simpleext',
                    'reg',
                    'ns.reg',
                    'ns.ns.reg.a',
                    'ns.ns.a',
                ],
            )

    def test_namespace5(self):
        """.py file with same name as folder that doesn't have __init__.py"""
        importable = list('abcdefghijkl')
        importable.extend('ns.' + x for x in importable[3:])
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-5namespace-cp312-cp312-win_amd64.whl', 'ns',
            not_patched=[
                'a.py',
                'd.py',
                'h.py',
                'j.py',
                'a/__init__.py',
                'd/__init__.py',
                'g/__init__.py',
                'i/__init__.py',
                'ns/__init__.py',
                'ns/d/__init__.py',
                'ns/g/__init__.py',
                'ns/i/__init__.py',
                'simpleext-0.0.1.data/platlib/b.py',
                'simpleext-0.0.1.data/platlib/e.py',
                'simpleext-0.0.1.data/platlib/g.py',
                'simpleext-0.0.1.data/platlib/l.py',
                'simpleext-0.0.1.data/platlib/b/__init__.py',
                'simpleext-0.0.1.data/platlib/e/__init__.py',
                'simpleext-0.0.1.data/platlib/h/__init__.py',
                'simpleext-0.0.1.data/platlib/k/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/e/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/h/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/k/__init__.py',
                'simpleext-0.0.1.data/purelib/c.py',
                'simpleext-0.0.1.data/purelib/f.py',
                'simpleext-0.0.1.data/purelib/i.py',
                'simpleext-0.0.1.data/purelib/k.py',
                'simpleext-0.0.1.data/purelib/c/__init__.py',
                'simpleext-0.0.1.data/purelib/f/__init__.py',
                'simpleext-0.0.1.data/purelib/j/__init__.py',
                'simpleext-0.0.1.data/purelib/l/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/f/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/j/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/l/__init__.py',
            ],
            patched=[
                'ns/d.py',
                'ns/h.py',
                'ns/j.py',
                'simpleext-0.0.1.data/platlib/ns/e.py',
                'simpleext-0.0.1.data/platlib/ns/g.py',
                'simpleext-0.0.1.data/platlib/ns/l.py',
                'simpleext-0.0.1.data/purelib/ns/f.py',
                'simpleext-0.0.1.data/purelib/ns/i.py',
                'simpleext-0.0.1.data/purelib/ns/k.py',
            ],
            importable=importable,
        )

    def test_namespace6(self):
        """.py file with same name as folder that has __init__.py, which has
        mixed case"""
        importable = list('abcdefghijkl')
        importable.extend('ns.' + x for x in importable[3:])
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-6namespace-cp312-cp312-win_amd64.whl', 'ns',
            not_patched=[
                'ns/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/__init__.py',
                'a.py',
                'd.py',
                'h.py',
                'j.py',
                'simpleext-0.0.1.data/platlib/b.py',
                'simpleext-0.0.1.data/platlib/e.py',
                'simpleext-0.0.1.data/platlib/g.py',
                'simpleext-0.0.1.data/platlib/l.py',
                'simpleext-0.0.1.data/purelib/c.py',
                'simpleext-0.0.1.data/purelib/f.py',
                'simpleext-0.0.1.data/purelib/i.py',
                'simpleext-0.0.1.data/purelib/k.py',
            ],
            patched=[
                'a/__init__.pY',
                'd/__iniT__.py',
                'g/__init__.py',
                'i/__init__.py',
                'ns/d/__init__.py',
                'ns/g/__init__.py',
                'ns/i/__init__.py',
                'ns/d.py',
                'ns/h.py',
                'ns/j.py',
                'simpleext-0.0.1.data/platlib/b/__init__.py',
                'simpleext-0.0.1.data/platlib/e/__init__.py',
                'simpleext-0.0.1.data/platlib/h/__init__.py',
                'simpleext-0.0.1.data/platlib/k/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/e/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/h/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/k/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/e.py',
                'simpleext-0.0.1.data/platlib/ns/g.py',
                'simpleext-0.0.1.data/platlib/ns/l.py',
                'simpleext-0.0.1.data/purelib/c/__init__.py',
                'simpleext-0.0.1.data/purelib/f/__init__.py',
                'simpleext-0.0.1.data/purelib/j/__init__.py',
                'simpleext-0.0.1.data/purelib/l/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/f/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/j/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/l/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/f.py',
                'simpleext-0.0.1.data/purelib/ns/i.py',
                'simpleext-0.0.1.data/purelib/ns/k.py',
            ],
            importable=importable,
        )

    def test_namespace7(self):
        """.pyd file with same name as folder that doesn't have __init__.py"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-7namespace-cp312-cp312-win_amd64.whl', 'ns',
            mangle=False,
            not_patched=[
                'ns/__init__.py',
                'ns/simpleext/__init__.py',
                'simpleext/__init__.py',
            ],
            exist=[
                'simpleext-0.0.1.data/platlib/simpledll.dll',
                'ns/simpledll.dll',
            ],
            importable=[
                'simpleext',
                'ns.simpleext',
            ],
        )

    def test_namespace8(self):
        """.py and .pyd files with same name but different case as folder that
        doesn't have __init__.py"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-8namespace-cp312-cp312-win_amd64.whl', 'ns',
            mangle=False,
            not_patched=[
                'ns/__init__.py',
                'a.py',
            ],
            patched=[
                'A/__init__.py',
                'ns/A/__init__.py',
                'ns/Simpleext/__init__.py',
                'ns/a.py',
                'Simpleext/__init__.py',
            ],
            exist=[
                'simpleext-0.0.1.data/platlib/simpledll.dll',
                'ns/simpledll.dll',
            ],
            importable=[
                'A',
                'ns.A',
                'ns.Simpleext',
                'ns.a',
                'ns.simpleext',
                'Simpleext',
                'a',
                'simpleext',
            ],
        )

    def test_namespace9(self):
        """pkgutil-style namespace package and pkg_resources-style namespace
        package"""
        try:
            import setuptools
        except ModuleNotFoundError:
            raise ModuleNotFoundError('setuptools needs to be installed to run this test') from None
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-9namespace-cp312-cp312-win_amd64.whl', 'pkgutil_style;pkg_resources_style',
            mangle=False,
            not_patched=[
                'pkgutil_style/__init__.py',
                'pkg_resources_style/__init__.py',
            ],
            patched=[
                'pkgutil_style/reg/__init__.py',
                'pkg_resources_style/reg/__init__.py',
            ],
            exist=[
                'simpleext.libs/simpledll.dll',
                'pkgutil_style/simpledll.dll',
                'pkg_resources_style/simpledll.dll',
            ],
            importable=[
                'pkgutil_style.simpleext',
                'pkgutil_style.reg.simpleext',
                'pkg_resources_style.simpleext',
                'pkg_resources_style.reg.simpleext',
            ],
        )

    def test_namespace10(self):
        """extension modules are split across root, platlib, and purelib"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-10namespace-cp312-cp312-win_amd64.whl', 'ns;ns0',
            mangle=False,
            not_patched=[
                'ns/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/__init__.py',
                'simpleext-0.0.1.data/platlib/ns0/__init__.py',
                'simpleext-0.0.1.data/purelib/ns0/__init__.py',
            ],
            exist=[
                'simpleext.libs/simpledll.dll',
                'ns/simpledll.dll',
                'simpleext-0.0.1.data/platlib/ns0/simpledll.dll',
            ],
            not_exist=[
                'simpleext-0.0.1.data/platlib/ns/simpledll.dll',
                'simpleext-0.0.1.data/purelib/ns/simpledll.dll',
                'simpleext-0.0.1.data/purelib/ns0/simpledll.dll',
            ],
            importable=[
                'ns.simpleext',
                'ns.simpleext0',
                'ns.simpleext1',
                'ns0.simpleext',
                'ns0.simpleext0',
            ],
        )

    def test_ignore_data(self):
        """Ignore .pyd file in .data/data directory."""
        output = subprocess.check_output(['delvewheel', 'repair', 'simpleext/simpleext-0.0.1-0ignore-cp312-cp312-win_amd64.whl'], text=True)
        self.assertIn('no external dependencies are needed', output)

    def test_include_symbols0(self):
        """Simple test of the --include-symbols flag."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--include-symbols', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl') as whl_file:
            whl_file.getinfo('simpleext-0.0.1.data/platlib/simpledll.pdb')
            self.assertRaises(KeyError, whl_file.getinfo, 'simpleext-0.0.1.data/platlib/simpledll.lib')

    def test_include_symbols1(self):
        """Two copies of symbol file exist if 2 copies of DLL exist"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--namespace-pkg', 'ns', '--include-symbols', 'simpleext/simpleext-0.0.1-2namespace-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-2namespace-cp312-cp312-win_amd64.whl') as whl_file:
            whl_file.getinfo('simpleext.libs/simpledll.pdb')
            self.assertRaises(KeyError, whl_file.getinfo, 'simpleext.libs/simpledll.lib')
            whl_file.getinfo('ns/simpledll.pdb')
            self.assertRaises(KeyError, whl_file.getinfo, 'ns/simpledll.lib')

    def test_include_imports0(self):
        """Simple test of the --include-imports flag."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--include-imports', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl') as whl_file:
            self.assertRaises(KeyError, whl_file.getinfo, 'simpleext-0.0.1.data/platlib/simpledll.pdb')
            whl_file.getinfo('simpleext-0.0.1.data/platlib/simpledll.lib')

    def test_include_imports1(self):
        """Two copies of import library file exist if 2 copies of DLL exist"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--namespace-pkg', 'ns', '--include-imports', 'simpleext/simpleext-0.0.1-2namespace-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-2namespace-cp312-cp312-win_amd64.whl') as whl_file:
            self.assertRaises(KeyError, whl_file.getinfo, 'simpleext.libs/simpledll.pdb')
            whl_file.getinfo('simpleext.libs/simpledll.lib')
            self.assertRaises(KeyError, whl_file.getinfo, 'ns/simpledll.pdb')
            whl_file.getinfo('ns/simpledll.lib')

    def test_include_symbols_imports(self):
        """--include-symbols and --include-imports flags in combination."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--include-symbols', '--include-imports', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-cp312-cp312-win_amd64.whl') as whl_file:
            whl_file.getinfo('simpleext-0.0.1.data/platlib/simpledll.pdb')
            whl_file.getinfo('simpleext-0.0.1.data/platlib/simpledll.lib')

    def test_filename_special_character(self):
        """RECORD is fixed correctly when filename contains the ',' special
        character."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-0record-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-0record-cp312-cp312-win_amd64.whl') as whl_file:
            with io.TextIOWrapper(whl_file.open('simpleext-0.0.1.dist-info/RECORD')) as file:
                self.assertTrue(any(line.startswith('"simpleext-0.0.1.data/data/a,b.txt"') for line in file))

    def test_source_date_epoch(self):
        """The SOURCE_DATE_EPOCH environment variable can be used to have
        reproducible builds."""
        source_date_epochs = [None, '650203200', '650203200', '650203202']
        contents = []
        for i, source_date_epoch in enumerate(source_date_epochs):
            check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '-w', f'wheelhouse{i}', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'], {'SOURCE_DATE_EPOCH': source_date_epoch})
            with open(f'wheelhouse{i}/simpleext-0.0.1-cp312-cp312-win_amd64.whl', 'rb') as whl_file:
                contents.append(whl_file.read())
        self.assertNotEqual(contents[0], contents[1])
        self.assertNotEqual(contents[0], contents[3])
        self.assertEqual(contents[1], contents[2])
        self.assertNotEqual(contents[1], contents[3])

    def test_dependent_load_flags(self):
        """/DEPENDENTLOADFLAG:0x800 is cleared in vendored DLL when name-
        mangling is disabled"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64/DependentLoadFlags', '--no-mangle-all', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful())

    def test_dependent_load_flags2(self):
        """/DEPENDENTLOADFLAG:0x800 is cleared in vendored DLL when name-
        mangling is enabled"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64/DependentLoadFlags', 'simpleext/simpleext-0.0.1-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful())

    def test_dependent_load_flags3(self):
        """/DEPENDENTLOADFLAG:0x800 is cleared in .pyd file"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-0dlf-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0dlf'))

    def test_checksum(self):
        """PE checksum is handled when name-mangling is enabled"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-0checksum-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0checksum'))

    def test_checksum2(self):
        """PE checksum is handled when name-mangling is disabled"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0checksum-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0checksum'))

    def test_dependent_load_flags_and_checksum(self):
        """PE checksum is handled when name-mangling is enabled and
        /DEPENDENTLOADFLAG:0x800 is specified"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-0dlf_cs-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0dlf_cs'))

    def test_dependent_load_flags_and_checksum2(self):
        """PE checksum is handled when name-mangling is disabled and
        /DEPENDENTLOADFLAG:0x800 is specified"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--no-mangle-all', 'simpleext/simpleext-0.0.1-0dlf_cs-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0dlf_cs'))

    def test_signed(self):
        """Authenticode signature is removed"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-0sign-cp312-cp312-win_amd64.whl'])
        self.assertTrue(import_simpleext_successful('0sign'))

    def test_free_threaded(self):
        """Free-threaded wheel can be repaired"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp313-cp313t-win_amd64.whl'])

    def test_mutually_exclusive(self):
        """--namespace-pkg and --custom-patch can't both be used"""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--namespace-pkg', 'ns0', '--custom-patch', 'simpleext/simpleext-0.0.1-0namespace-cp312-cp312-win_amd64.whl'])

    def test_custom_none(self):
        """Exception is raised when --custom-patch is specified and no location
        was found."""
        with self.assertRaises(subprocess.CalledProcessError):
            check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--custom-patch', 'simpleext/simpleext-0.0.1-0custom-cp312-cp312-win_amd64.whl'])

    def test_custom(self):
        """--custom-patch with multiple locations"""
        p = subprocess.run(['delvewheel', 'repair', '--add-path', 'simpleext/x64', '--custom-patch', 'simpleext/simpleext-0.0.1-1custom-cp312-cp312-win_amd64.whl'], capture_output=True, text=True, check=True)
        self.assertEqual(8, p.stdout.count('patching '))
        self.assertEqual(1, p.stdout.count(' (count 2)'))

    def test_remove_signature_jws(self):
        """Remove RECORD.jws signature file"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-1sign-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-1sign-cp312-cp312-win_amd64.whl') as whl_file:
            self.assertRaises(KeyError, whl_file.getinfo, 'simpleext-0.0.1.dist-info/RECORD.jws')

    def test_remove_signature_p7s(self):
        """Remove RECORD.p7s signature file"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-2sign-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/simpleext-0.0.1-2sign-cp312-cp312-win_amd64.whl') as whl_file:
            self.assertRaises(KeyError, whl_file.getinfo, 'simpleext-0.0.1.dist-info/RECORD.p7s')


class NeededTestCase(TestCase):
    """Tests for delvewheel needed"""
    def test_iknowengine(self):
        p = subprocess.run(['delvewheel', 'needed', 'iknowpy/iKnowEngine.dll'], capture_output=True, text=True, check=True)
        self.assertEqual(
            'api-ms-win-crt-convert-l1-1-0.dll\napi-ms-win-crt-heap-l1-1-0.dll\napi-ms-win-crt-locale-l1-1-0.dll\n'
            'api-ms-win-crt-math-l1-1-0.dll\napi-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\n'
            'iKnowALI.dll\niKnowBase.dll\niKnowCore.dll\niKnowShell.dll\nKERNEL32.dll\nMSVCP140.dll\n'
            'VCRUNTIME140.dll\nVCRUNTIME140_1.dll\n', p.stdout)
        self.assertFalse(p.stderr)

    def test_simpleext(self):
        p = subprocess.run(['delvewheel', 'needed', 'simpleext/x64/simpledll.dll'], capture_output=True, text=True, check=True)
        self.assertEqual('api-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\nKERNEL32.dll\n'
                          'VCRUNTIME140.dll\n', p.stdout)
        self.assertFalse(p.stderr)

    def test_simpleext_32bit(self):
        p = subprocess.run(['delvewheel', 'needed', 'simpleext/x86/simpledll.dll'], capture_output=True, text=True, check=True)
        self.assertEqual('api-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\nKERNEL32.dll\n'
                          'VCRUNTIME140.dll\n', p.stdout)
        self.assertFalse(p.stderr)

    def test_msvcp140(self):
        """msvcp140.dll's delay-load dependency on concrt140.dll is ignored."""
        p = subprocess.run(['delvewheel', 'needed', 'iknowpy/msvcp140.dll'], capture_output=True, text=True, check=True)
        self.assertEqual(
            'api-ms-win-crt-convert-l1-1-0.dll\napi-ms-win-crt-environment-l1-1-0.dll\n'
            'api-ms-win-crt-filesystem-l1-1-0.dll\napi-ms-win-crt-heap-l1-1-0.dll\napi-ms-win-crt-locale-l1-1-0.dll\n'
            'api-ms-win-crt-math-l1-1-0.dll\napi-ms-win-crt-runtime-l1-1-0.dll\napi-ms-win-crt-stdio-l1-1-0.dll\n'
            'api-ms-win-crt-string-l1-1-0.dll\napi-ms-win-crt-time-l1-1-0.dll\napi-ms-win-crt-utility-l1-1-0.dll\n'
            'KERNEL32.dll\nVCRUNTIME140.dll\nVCRUNTIME140_1.dll\n', p.stdout)
        self.assertFalse(p.stderr)


@unittest.skipUnless(sys.version_info[:2] == (3, 8), 'Python version is not 3.8')
class Python38TestCase(TestCase):
    """delvewheel can be run on Python 3.8, the oldest supported version"""

    # mock the Conda-Forge distribution of Python 3.8 to test loading with
    # LoadLibraryExW()
    _patch = "import platform, sys; sys.version = '3.8.20 | packaged by conda-forge | (default, Sep 30 2024, 17:44:03) [MSC v.1929 64 bit (AMD64)]'; platform.python_implementation = lambda: 'CPython'; "

    def test_show(self):
        """Wheel target is older"""
        check_call(['delvewheel', 'show', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp36-cp36m-win_amd64.whl'])

    def test_repair_simpleext(self):
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-cp38-cp38-win_amd64.whl'])
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-cp38-cp38-win_amd64.whl'])
            check_call([sys.executable, '-c', self._patch + 'import simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass

    def test_repair_iknowpy(self):
        try:
            check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle-all', 'iknowpy/iknowpy-1.5.3-cp38-cp38-win_amd64.whl'])
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/iknowpy-1.5.3-cp38-cp38-win_amd64.whl'])
            check_call([sys.executable, '-c', self._patch + 'import iknowpy'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'iknowpy'])
            except subprocess.CalledProcessError:
                pass

    def test_needed(self):
        check_call(['delvewheel', 'needed', 'simpleext/x64/simpledll.dll'])

    def test_fixed_address(self):
        """Vendored DLL loads properly when base address is a multiple of
        2**32. For this test, the address is 0x300000000."""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64/FixedAddress', 'simpleext/simpleext-0.0.1-0fixed-cp38-cp38-win_amd64.whl'])
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-0fixed-cp38-cp38-win_amd64.whl'])
            check_call([sys.executable, '-c', self._patch + 'import simpleext.simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass


@unittest.skipUnless(sys.implementation.name == 'pypy', 'Python implementation is not PyPy')
class PyPyTestCase(TestCase):
    """delvewheel can be run on PyPy"""
    def test_show(self):
        check_call(['delvewheel', 'show', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-pp310-pypy310_pp73-win_amd64.whl'])

    def test_repair(self):
        """delvewheel can be run on PyPy and can repair a PyPy wheel"""
        check_call(['delvewheel', 'repair', '--add-path', 'simpleext/x64', 'simpleext/simpleext-0.0.1-pp310-pypy310_pp73-win_amd64.whl'])
        try:
            check_call([sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'wheelhouse/simpleext-0.0.1-pp310-pypy310_pp73-win_amd64.whl'])
            check_call([sys.executable, '-c', 'import simpleext'])
        finally:
            try:
                check_call([sys.executable, '-m', 'pip', 'uninstall', '-y', 'simpleext'])
            except subprocess.CalledProcessError:
                pass

    def test_needed(self):
        check_call(['delvewheel', 'needed', 'simpleext/x64/simpledll.dll'])


@unittest.skipUnless(sys.platform == 'linux', 'platform is not Linux')
class LinuxTestCase(TestCase):
    """delvewheel can be run on Linux"""
    def test_show(self):
        check_call(['delvewheel', 'show', '--add-path', 'iknowpy', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])

    def test_repair_basic(self):
        """Basic repair for the iknowpy package"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')

    def test_repair_no_mangle_1(self):
        """--no-mangle for a single DLL, case-insensitive"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnOwEnGiNe.dLl', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('iKnowEngine'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')

    def test_repair_no_mangle_2(self):
        """--no-mangle for 2 DLLs"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--no-mangle', 'iKnowEngine.dll:iKnowBase.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('iKnowEngine') or path.name.startswith('iKnowBase'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')

    def test_include_1(self):
        """--include for 1 DLL, case-insensitive"""
        check_call(['delvewheel', 'repair', '--add-path', 'iknowpy', '--include', 'kernEl32.dll', 'iknowpy/iknowpy-1.5.3-cp312-cp312-win_amd64.whl'])
        with zipfile.ZipFile('wheelhouse/iknowpy-1.5.3-cp312-cp312-win_amd64.whl') as wheel:
            kernel32_found = False
            for path in zipfile.Path(wheel, 'iknowpy.libs/').iterdir():
                if path.name in ('.load-order-iknowpy-1.5.3',):
                    continue
                if path.name.startswith('kernel32'):
                    self.assertFalse(is_mangled(path.name), f'{path.name} is not mangled')
                    kernel32_found = True
                else:
                    self.assertTrue(is_mangled(path.name), f'{path.name} is mangled')
        self.assertTrue(kernel32_found, 'kernel32.dll found')

    def test_needed(self):
        check_call(['delvewheel', 'needed', 'simpleext/x64/simpledll.dll'])

    def test_namespace6(self):
        """namespace support where filename of __init__.py is case-
        insensitive"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-6namespace-cp312-cp312-win_amd64.whl', 'ns',
            not_patched=[
                'ns/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/__init__.py',
                'a.py',
                'd.py',
                'h.py',
                'j.py',
                'simpleext-0.0.1.data/platlib/b.py',
                'simpleext-0.0.1.data/platlib/e.py',
                'simpleext-0.0.1.data/platlib/g.py',
                'simpleext-0.0.1.data/platlib/l.py',
                'simpleext-0.0.1.data/purelib/c.py',
                'simpleext-0.0.1.data/purelib/f.py',
                'simpleext-0.0.1.data/purelib/i.py',
                'simpleext-0.0.1.data/purelib/k.py',
            ],
            patched=[
                'a/__init__.pY',
                'd/__iniT__.py',
                'g/__init__.py',
                'i/__init__.py',
                'ns/d/__init__.py',
                'ns/g/__init__.py',
                'ns/i/__init__.py',
                'ns/d.py',
                'ns/h.py',
                'ns/j.py',
                'simpleext-0.0.1.data/platlib/b/__init__.py',
                'simpleext-0.0.1.data/platlib/e/__init__.py',
                'simpleext-0.0.1.data/platlib/h/__init__.py',
                'simpleext-0.0.1.data/platlib/k/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/e/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/h/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/k/__init__.py',
                'simpleext-0.0.1.data/platlib/ns/e.py',
                'simpleext-0.0.1.data/platlib/ns/g.py',
                'simpleext-0.0.1.data/platlib/ns/l.py',
                'simpleext-0.0.1.data/purelib/c/__init__.py',
                'simpleext-0.0.1.data/purelib/f/__init__.py',
                'simpleext-0.0.1.data/purelib/j/__init__.py',
                'simpleext-0.0.1.data/purelib/l/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/f/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/j/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/l/__init__.py',
                'simpleext-0.0.1.data/purelib/ns/f.py',
                'simpleext-0.0.1.data/purelib/ns/i.py',
                'simpleext-0.0.1.data/purelib/ns/k.py',
            ],
        )

    def test_namespace9(self):
        """namespace support where ':' is the path separator"""
        self.namespace_helper(
            'simpleext/simpleext-0.0.1-9namespace-cp312-cp312-win_amd64.whl', 'pkgutil_style:pkg_resources_style',
            mangle=False,
            not_patched=[
                'pkgutil_style/__init__.py',
                'pkg_resources_style/__init__.py',
            ],
            patched=[
                'pkgutil_style/reg/__init__.py',
                'pkg_resources_style/reg/__init__.py',
            ],
            exist=[
                'simpleext.libs/simpledll.dll',
                'pkgutil_style/simpledll.dll',
                'pkg_resources_style/simpledll.dll',
            ],
        )


if __name__ == '__main__':
    unittest.main()
