import glob
import os
import shutil
import sys
import unittest

import stem
import stem.util.system

import test.runner


class TestInstallation(unittest.TestCase):
  @test.runner.only_run_once
  def test_installing_stem(self):
    base_directory = os.path.sep.join(__file__.split(os.path.sep)[:-3])

    if not os.path.exists(os.path.sep.join([base_directory, 'setup.py'])):
      test.runner.skip(self, '(only for git checkout)')

    original_cwd = os.getcwd()

    try:
      os.chdir(base_directory)
      stem.util.system.call(sys.executable + ' setup.py install --prefix /tmp/stem_test')
      stem.util.system.call(sys.executable + ' setup.py clean --all')  # tidy up the build directory
      site_packages_paths = glob.glob('/tmp/stem_test/lib*/*/site-packages')

      if len(site_packages_paths) != 1:
        self.fail('We should only have a single site-packages directory, but instead had: %s' % site_packages_paths)

      self.assertEqual(stem.__version__, stem.util.system.call([sys.executable, '-c', "import sys;sys.path.insert(0, '%s');import stem;print(stem.__version__)" % site_packages_paths[0]])[0])
    finally:
      shutil.rmtree('/tmp/stem_test')
      os.chdir(original_cwd)
