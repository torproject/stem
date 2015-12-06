import glob
import os
import shutil
import sys
import unittest

import stem
import stem.util.system

import test.runner

BASE_DIRECTORY = os.path.sep.join(__file__.split(os.path.sep)[:-3])


class TestInstallation(unittest.TestCase):
  @classmethod
  def setUpClass(self):
    self.site_packages_path = None
    self.skip_reason = None
    self.installation_error = None

    if not os.path.exists(os.path.join(BASE_DIRECTORY, 'setup.py')):
      self.skip_reason = '(only for git checkout)'

    original_cwd = os.getcwd()

    try:
      os.chdir(BASE_DIRECTORY)
      stem.util.system.call(sys.executable + ' setup.py install --prefix /tmp/stem_test')
      stem.util.system.call(sys.executable + ' setup.py clean --all')  # tidy up the build directory
      site_packages_paths = glob.glob('/tmp/stem_test/lib*/*/site-packages')

      if len(site_packages_paths) != 1:
        self.installation_error = 'We should only have a single site-packages directory, but instead had: %s' % site_packages_paths

      self.site_packages_path = site_packages_paths[0]
    except Exception as exc:
      self.installation_error = 'Unable to download the man page: %s' % exc
    finally:
      os.chdir(original_cwd)

  @classmethod
  def tearDownClass(self):
    if os.path.exists('/tmp/stem_test'):
      shutil.rmtree('/tmp/stem_test')

  def requires_installation(self):
    if self.skip_reason:
      test.runner.skip(self, self.skip_reason)
      return True
    elif self.installation_error:
      self.fail(self.installation_error)

    return False

  @test.runner.only_run_once
  def test_installing_stem(self):
    """
    Attempt to use the package we install.
    """

    if self.requires_installation():
      return

    self.assertEqual(stem.__version__, stem.util.system.call([sys.executable, '-c', "import sys;sys.path.insert(0, '%s');import stem;print(stem.__version__)" % self.site_packages_path])[0])

  def test_installs_all_files(self):
    """
    Check that all the files in the stem directory are present in the
    installatnion. This is a very common gotcha since our setup.py
    requires us to remember to add new modules and non-source files.
    """

    if self.requires_installation():
      return

    expected, installed = set(), set()

    for root, dirnames, filenames in os.walk(os.path.join(BASE_DIRECTORY, 'stem')):
      for filename in filenames:
        if not filename.endswith('.pyc') and not filename.endswith('.swp'):
          expected.add(os.path.join(root, filename)[len(BASE_DIRECTORY) + 1:])

    for root, dirnames, filenames in os.walk(self.site_packages_path):
      for filename in filenames:
        if not filename.endswith('.pyc') and not filename.endswith('egg-info'):
          installed.add(os.path.join(root, filename)[len(self.site_packages_path) + 1:])

    missing = expected.difference(installed)
    extra = installed.difference(expected)

    if missing:
      self.fail("The following files were expected to be in our installation but weren't. Maybe our setup.py needs to be updated?\n\n%s" % '\n'.join(missing))
    elif extra:
      self.fail("The following files weren't expected to be in our installation.\n\n%s" % '\n'.join(extra))
