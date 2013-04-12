"""
Helper functions for our test framework.

::

  get_unit_tests - provides our unit tests
  get_integ_tests - provides our integration tests
"""

import stem.util.conf

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
