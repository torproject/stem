import glob
import os
import shutil
import sys
import tarfile
import threading
import unittest

import stem
import stem.util.system

import test.util

from test.util import (
  skip,
  only_run_once,
)

INSTALL_MISMATCH_MSG = "Running 'python setup.py sdist' doesn't match our git contents in the following way. The manifest in our setup.py may need to be updated...\n\n"

BASE_INSTALL_PATH = '/tmp/stem_test'
DIST_PATH = os.path.join(test.util.STEM_BASE, 'dist')
SETUP_THREAD, INSTALL_FAILURE, INSTALL_PATH, SDIST_FAILURE = None, None, None, None


def setup():
  """
  Performs setup our tests will need. This mostly just needs disk iops so it
  can happen asynchronously with other tests.
  """

  global SETUP_THREAD

  def _setup():
    global INSTALL_FAILURE, INSTALL_PATH, SDIST_FAILURE
    original_cwd = os.getcwd()

    try:
      os.chdir(test.util.STEM_BASE)

      try:
        os.chdir(test.util.STEM_BASE)
        stem.util.system.call('%s setup.py install --prefix %s' % (sys.executable, BASE_INSTALL_PATH), timeout = 60)
        stem.util.system.call('%s setup.py clean --all' % sys.executable, timeout = 60)  # tidy up the build directory
        site_packages_paths = glob.glob('%s/lib*/*/site-packages' % BASE_INSTALL_PATH)

        if len(site_packages_paths) != 1:
          raise AssertionError('We should only have a single site-packages directory, but instead had: %s' % site_packages_paths)

        INSTALL_PATH = site_packages_paths[0]
      except Exception as exc:
        INSTALL_FAILURE = AssertionError("Unable to install with 'python setup.py install': %s" % exc)

      if not os.path.exists(DIST_PATH):
        try:
          stem.util.system.call('%s setup.py sdist' % sys.executable, timeout = 60)
        except Exception as exc:
          SDIST_FAILURE = exc
      else:
        SDIST_FAILURE = AssertionError("%s already exists, maybe you manually ran 'python setup.py sdist'?" % DIST_PATH)
    finally:
      os.chdir(original_cwd)

  if SETUP_THREAD is None:
    SETUP_THREAD = threading.Thread(target = _setup)
    SETUP_THREAD.start()

  return SETUP_THREAD


def clean():
  if os.path.exists(BASE_INSTALL_PATH):
    shutil.rmtree(BASE_INSTALL_PATH)

  if os.path.exists(DIST_PATH):
    shutil.rmtree(DIST_PATH)


def _assert_has_all_files(path):
  """
  Check that all the files in the stem directory are present in the
  installation. This is a very common gotcha since our setup.py
  requires us to remember to add new modules and non-source files.

  :raises: **AssertionError** files don't match our content
  """

  expected, installed = set(), set()

  for root, dirnames, filenames in os.walk(os.path.join(test.util.STEM_BASE, 'stem')):
    for filename in filenames:
      file_format = filename.split('.')[-1]

      if file_format not in test.util.IGNORED_FILE_TYPES:
        expected.add(os.path.join(root, filename)[len(test.util.STEM_BASE) + 1:])

  for root, dirnames, filenames in os.walk(path):
    for filename in filenames:
      if not filename.endswith('.pyc') and not filename.endswith('egg-info'):
        installed.add(os.path.join(root, filename)[len(path) + 1:])

  missing = expected.difference(installed)
  extra = installed.difference(expected)

  if missing:
    raise AssertionError("The following files were expected to be in our installation but weren't. Maybe our setup.py needs to be updated?\n\n%s" % '\n'.join(missing))
  elif extra:
    raise AssertionError("The following files weren't expected to be in our installation.\n\n%s" % '\n'.join(extra))


class TestInstallation(unittest.TestCase):
  @only_run_once
  def test_install(self):
    """
    Installs with 'python setup.py install' and checks we can use what we
    install.
    """

    if not INSTALL_PATH:
      setup().join()

    if INSTALL_FAILURE:
      raise INSTALL_FAILURE

    self.assertEqual(stem.__version__, stem.util.system.call([sys.executable, '-c', "import sys;sys.path.insert(0, '%s');import stem;print(stem.__version__)" % INSTALL_PATH])[0])
    _assert_has_all_files(INSTALL_PATH)

  @only_run_once
  def test_sdist(self):
    """
    Creates a source distribution tarball with 'python setup.py sdist' and
    checks that it matches the content of our git repository. This primarily is
    meant to test that our MANIFEST.in is up to date.
    """

    if not stem.util.system.is_available('git'):
      skip(self, '(git unavailable)')
      return

    setup().join()

    if SDIST_FAILURE:
      raise SDIST_FAILURE

    git_contents = [line.split()[-1] for line in stem.util.system.call('git ls-tree --full-tree -r HEAD')]

    # tarball has a prefix 'stem-[verion]' directory so stipping that out

    dist_tar = tarfile.open(os.path.join(DIST_PATH, 'stem-dry-run-%s.tar.gz' % stem.__version__))
    tar_contents = ['/'.join(info.name.split('/')[1:]) for info in dist_tar.getmembers() if info.isfile()]

    issues = []

    for path in git_contents:
      if path not in tar_contents and path not in ['.gitignore']:
        issues.append('  * %s is missing from our release tarball' % path)

    for path in tar_contents:
      if path not in git_contents and path not in ['MANIFEST.in', 'PKG-INFO']:
        issues.append("  * %s isn't expected in our release tarball" % path)

    if issues:
      self.fail(INSTALL_MISMATCH_MSG + '\n'.join(issues))
