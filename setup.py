import setuptools
import shutil


def rmtree(path):
    """Like shutil.rmtree() but is silent if path does not exist."""
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


class CleanCommand(setuptools.Command):
    """Clean all build and distribution files"""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        rmtree('build')
        rmtree('dist')
        rmtree('delvewheel.egg-info')
        rmtree('delvewheel/__pycache__')


setuptools.setup(cmdclass={'clean': CleanCommand})
