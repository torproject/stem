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

  def test_installation_has_all_modules(self):
    if self.skip_reason:
      test.runner.skip(self, self.skip_reason)
      return True

    # Modules cited my our setup.py looks like...
    #
    #   packages = ['stem', 'stem.descriptor', 'stem.util'],

    modules = re.search('packages = \[(.*)\]', self.setup_contents).group(1).replace("'", '').replace(',', '').split()
    module_paths = dict([(m, os.path.join(test.util.STEM_BASE, m.replace('.', os.path.sep))) for m in modules])

    for module, path in module_paths.items():
      if not os.path.exists(path):
        self.fail("module %s from our setup.py doesn't exit at %s" % (module, path))

    for entry in os.walk(os.path.join(test.util.STEM_BASE, 'stem')):
      path = entry[0]

      if path.endswith('__pycache__'):
        continue
      elif path not in module_paths.values():
        self.fail("%s isn't installed by our setup.py" % path)
