# Copyright 2012-2013, Damian Johnson
# See LICENSE for licensing information

"""
Helper functions for our test framework.

::

  get_unit_tests - provides our unit tests
  get_integ_tests - provides our integration tests

  clean_orphaned_pyc - removes any *.pyc without a corresponding *.py
  get_stylistic_issues - checks for PEP8 and other stylistic issues
  get_pyflakes_issues - static checks for problems via pyflakes
"""

import re
import os

import stem.util.conf
import stem.util.system

CONFIG = stem.util.conf.config_dict("test", {
  "pep8.ignore": [],
  "pyflakes.ignore": [],
  "integ.test_directory": "./test/data",
  "test.unit_tests": "",
  "test.integ_tests": "",
})

# mapping of files to the issues that should be ignored
PYFLAKES_IGNORE = None


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

  for path in paths:
    for pyc_path in _get_files_with_suffix(path, ".pyc"):
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


def get_stylistic_issues(paths):
  """
  Checks for stylistic issues that are an issue according to the parts of PEP8
  we conform to. This alsochecks a few other stylistic issues:

  * two space indentations
  * tabs are the root of all evil and should be shot on sight
  * standard newlines (\\n), not windows (\\r\\n) nor classic mac (\\r)

  :param list paths: paths to search for stylistic issues

  :returns: dict of the form ``path => [(line_number, message)...]``
  """

  # The pep8 command give output of the form...
  #
  #   FILE:LINE:CHARACTER ISSUE
  #
  # ... for instance...
  #
  #   ./test/mocking.py:868:31: E225 missing whitespace around operator

  ignored_issues = ','.join(CONFIG["pep8.ignore"])
  issues = {}

  for path in paths:
    pep8_output = stem.util.system.call("pep8 --ignore %s %s" % (ignored_issues, path))

    for line in pep8_output:
      line_match = re.match("^(.*):(\d+):(\d+): (.*)$", line)

      if line_match:
        path, line, _, issue = line_match.groups()

        if not _is_test_data(path):
          issues.setdefault(path, []).append((int(line), issue))

    for file_path in _get_files_with_suffix(path):
      if _is_test_data(file_path):
        continue

      with open(file_path) as f:
        file_contents = f.read()

      lines, file_issues, prev_indent = file_contents.split("\n"), [], 0
      is_block_comment = False

      for index, line in enumerate(lines):
        whitespace, content = re.match("^(\s*)(.*)$", line).groups()

        # TODO: This does not check that block indentations are two spaces
        # because differentiating source from string blocks ("""foo""") is more
        # of a pita than I want to deal with right now.

        if '"""' in content:
          is_block_comment = not is_block_comment

        if "\t" in whitespace:
          file_issues.append((index + 1, "indentation has a tab"))
        elif "\r" in content:
          file_issues.append((index + 1, "contains a windows newline"))
        elif content != content.rstrip():
          file_issues.append((index + 1, "line has trailing whitespace"))

      if file_issues:
        issues[file_path] = file_issues

  return issues


def get_pyflakes_issues(paths):
  """
  Performs static checks via pyflakes.

  :param list paths: paths to search for problems

  :returns: dict of the form ``path => [(line_number, message)...]``
  """

  global PYFLAKES_IGNORE

  if PYFLAKES_IGNORE is None:
    pyflakes_ignore = {}

    for line in CONFIG["pyflakes.ignore"]:
      path, issue = line.split("=>")
      pyflakes_ignore.setdefault(path.strip(), []).append(issue.strip())

    PYFLAKES_IGNORE = pyflakes_ignore

  # Pyflakes issues are of the form...
  #
  #   FILE:LINE: ISSUE
  #
  # ... for instance...
  #
  #   stem/prereq.py:73: 'long_to_bytes' imported but unused
  #   stem/control.py:957: undefined name 'entry'

  issues = {}

  for path in paths:
    pyflakes_output = stem.util.system.call("pyflakes %s" % path)

    for line in pyflakes_output:
      line_match = re.match("^(.*):(\d+): (.*)$", line)

      if line_match:
        path, line, issue = line_match.groups()

        if not _is_test_data(path) and not issue in PYFLAKES_IGNORE.get(path, []):
          issues.setdefault(path, []).append((int(line), issue))

  return issues


def _is_test_data(path):
  return os.path.normpath(path).startswith(os.path.normpath(CONFIG["integ.test_directory"]))


def _get_files_with_suffix(base_path, suffix = ".py"):
  """
  Iterates over files in a given directory, providing filenames with a certain
  suffix.

  :param str base_path: directory to be iterated over
  :param str suffix: filename suffix to look for

  :returns: iterator that yields the absolute path for files with the given suffix
  """

  if os.path.isfile(base_path):
    if base_path.endswith(suffix):
      yield base_path
  else:
    for root, _, files in os.walk(base_path):
      for filename in files:
        if filename.endswith(suffix):
          yield os.path.join(root, filename)
