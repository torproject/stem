"""
Helper functions for our test framework.

::

  get_unit_tests - provides our unit tests
  get_integ_tests - provides our integration tests

  clean_orphaned_pyc - removes any *.pyc without a corresponding *.py
"""

import os

import stem.util.conf

import test.static_checks

CONFIG = stem.util.conf.config_dict("test", {
  "test.unit_tests": "",
  "test.integ_tests": "",
})


def get_unit_tests(prefix = None):
  """
  Provides the classes for our unit tests.

  :param str prefix: only provide the test if the module starts with this prefix

  :returns: an **iterator** for our unit tests
  """

  return _get_tests(CONFIG["test.unit_tests"].splitlines(), prefix)


def get_integ_tests(prefix = None):
  """
  Provides the classes for our integration tests.

  :param str prefix: only provide the test if the module starts with this prefix

  :returns: an **iterator** for our integration tests
  """

  return _get_tests(CONFIG["test.integ_tests"].splitlines(), prefix)


def _get_tests(modules, prefix):
  for import_name in modules:
    if import_name:
      if prefix and not import_name.startswith(prefix):
        continue

      # Dynamically imports test modules. The __import__() call has a couple
      # quirks that make this a little clunky...
      #
      #   * it only accepts modules, not the actual class we want to import
      #
      #   * it returns the top level module, so we need to transverse into it
      #     for the test class

      module_name = '.'.join(import_name.split('.')[:-1])
      module = __import__(module_name)

      for subcomponent in import_name.split(".")[1:]:
        module = getattr(module, subcomponent)

      yield module


def clean_orphaned_pyc(paths):
  """
  Deletes any file with a *.pyc extention without a corresponding *.py. This
  helps to address a common gotcha when deleting python files...

  * You delete module 'foo.py' and run the tests to ensure that you haven't
    broken anything. They pass, however there *are* still some 'import foo'
    statements that still work because the bytecode (foo.pyc) is still around.

  * You push your change.

  * Another developer clones our repository and is confused because we have a
    bunch of ImportErrors.

  :param list paths: paths to search for orphaned pyc files

  :returns: list of files that we deleted
  """

  orphaned_pyc = []

  for base_dir in paths:
    for pyc_path in test.static_checks._get_files_with_suffix(base_dir, ".pyc"):
      # If we're running python 3 then the *.pyc files are no longer bundled
      # with the *.py. Rather, they're in a __pycache__ directory.
      #
      # At the moment there's no point in checking for orphaned bytecode with
      # python 3 because it's an exported copy of the python 2 codebase, so
      # skipping.

      if "__pycache__" in pyc_path:
        continue

      if not os.path.exists(pyc_path[:-1]):
        orphaned_pyc.append(pyc_path)
        os.remove(pyc_path)

  return orphaned_pyc
