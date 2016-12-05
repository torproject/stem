import glob
import os
import shutil
import sys
import tarfile
import unittest

import stem
import stem.util.system

import test.runner
import test.util

INSTALL_MISMATCH_MSG = "Running 'python setup.py sdist' doesn't match our git contents in the following way. The manifest in our setup.py may need to be updated...\n\n"


class TestInstallation(unittest.TestCase):
  # TODO: remove when dropping support for python 2.6
  skip_reason = 'setUpClass() unsupported in python 2.6'

  @classmethod
  def setUpClass(self):
    self.site_packages_path = None
    self.skip_reason = None
    self.installation_error = None

    if not os.path.exists(os.path.join(test.util.STEM_BASE, 'setup.py')):
      self.skip_reason = '(only for git checkout)'

    original_cwd = os.getcwd()

    try:
      os.chdir(test.util.STEM_BASE)
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
  def test_sdist_matches_git(self):
    """
    Check the source distribution tarball we make for releases matches the
    contents of 'git archive'. This primarily is meant to test that our
    MANIFEST.in is up to date.
    """

    if self.requires_installation():
      return
    elif not stem.util.system.is_available('git'):
      test.runner.skip(self, '(git unavailable)')
      return

    original_cwd = os.getcwd()
    dist_path = os.path.join(test.util.STEM_BASE, 'dist')
    git_contents = [line.split()[-1] for line in stem.util.system.call('git ls-tree --full-tree -r HEAD')]

    try:
      os.chdir(test.util.STEM_BASE)
      stem.util.system.call(sys.executable + ' setup.py sdist')

      # tarball has a prefix 'stem-[verion]' directory so stipping that out

      dist_tar = tarfile.open(os.path.join(dist_path, 'stem-dry-run-%s.tar.gz' % stem.__version__))
      tar_contents = ['/'.join(info.name.split('/')[1:]) for info in dist_tar.getmembers() if info.isfile()]
    finally:
      if os.path.exists(dist_path):
        shutil.rmtree(dist_path)

      os.chdir(original_cwd)

    issues = []

    for path in git_contents:
      if path not in tar_contents and path not in ['.gitignore']:
        issues.append('  * %s is missing from our release tarball' % path)

    for path in tar_contents:
      if path not in git_contents and path not in ['MANIFEST.in', 'PKG-INFO']:
        issues.append("  * %s isn't expected in our release tarball" % path)

    if issues:
      self.fail(INSTALL_MISMATCH_MSG + '\n'.join(issues))

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
    installation. This is a very common gotcha since our setup.py
    requires us to remember to add new modules and non-source files.
    """

    if self.requires_installation():
      return

    expected, installed = set(), set()

    for root, dirnames, filenames in os.walk(os.path.join(test.util.STEM_BASE, 'stem')):
      for filename in filenames:
        file_format = filename.split('.')[-1]

        if file_format not in ('pyc', 'swp', 'swo'):
          expected.add(os.path.join(root, filename)[len(test.util.STEM_BASE) + 1:])

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
