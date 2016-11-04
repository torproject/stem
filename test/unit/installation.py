import json
import os
import re
import unittest

import test.runner
import test.util


class TestInstallation(unittest.TestCase):
  # TODO: remove when dropping support for python 2.6
  skip_reason = 'setUpClass() unsupported in python 2.6'

  @classmethod
  def setUpClass(self):
    setup_path = os.path.join(test.util.STEM_BASE, 'setup.py')
    self.skip_reason = None
    self.setup_contents = False

    if os.path.exists(setup_path):
      with open(setup_path) as setup_file:
        self.setup_contents = setup_file.read()
    else:
      self.skip_reason = '(only for git checkout)'

  def test_installs_all_modules(self):
    if self.skip_reason:
      test.runner.skip(self, self.skip_reason)
      return True

    # Modules cited my our setup.py looks like...
    #
    #   packages = ['stem', 'stem.descriptor', 'stem.util'],

    modules = json.loads(re.search('packages = (\[.*\])', self.setup_contents).group(1).replace("'", '"'))
    module_paths = dict([(m, os.path.join(test.util.STEM_BASE, m.replace('.', os.path.sep))) for m in modules])

    for module, path in module_paths.items():
      if not os.path.exists(path):
        self.fail("setup.py's module %s doesn't exist at %s" % (module, path))

    for entry in os.walk(os.path.join(test.util.STEM_BASE, 'stem')):
      directory = entry[0]

      if directory.endswith('__pycache__'):
        continue
      elif directory not in module_paths.values():
        self.fail("setup.py doesn't install %s" % directory)

  def test_installs_all_data_files(self):
    if self.skip_reason:
      test.runner.skip(self, self.skip_reason)
      return True

    # Checking that we have all non-source files. Data looks like...
    #
    #   package_data = {'stem': ['cached_tor_manual.cfg', 'settings.cfg']},

    package_data = json.loads(re.search('package_data = (\{.*\})', self.setup_contents).group(1).replace("'", '"'))
    data_files = []

    for module, files in package_data.items():
      for module_file in files:
        data_files.append(os.path.join(test.util.STEM_BASE, module.replace('.', os.path.sep), module_file))

    for path in data_files:
      if not os.path.exists(path):
        self.fail("setup.py installs a data file that doesn't exist: %s" % path)

    for entry in os.walk(os.path.join(test.util.STEM_BASE, 'stem')):
      directory = entry[0]

      if directory.endswith('__pycache__'):
        continue

      for filename in entry[2]:
        path = os.path.join(directory, filename)

        if path.endswith('.py') or path.endswith('.pyc') or path.endswith('.swp') or path.endswith('orig'):
          continue
        elif path not in data_files:
          self.fail("setup.py doesn't install %s" % path)
