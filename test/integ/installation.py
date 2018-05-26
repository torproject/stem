"""
Tests installation of our library.
"""

import glob
import os
import shutil
import sys
import tarfile
import time
import unittest

import stem
import stem.prereq
import stem.util.system
import stem.util.test_tools
import test

from stem.util.test_tools import asynchronous

BASE_INSTALL_PATH = '/tmp/stem_test'
DIST_PATH = os.path.join(test.STEM_BASE, 'dist')
PYTHON_EXE = sys.executable if sys.executable else 'python'
INSTALL_MISMATCH_MSG = "Running 'python setup.py sdist' doesn't match our git contents in the following way. The manifest in our setup.py may need to be updated...\n\n"


def _assert_has_all_files(path):
  """
  Check that all the files in the stem directory are present in the
  installation. This is a very common gotcha since our setup.py
  requires us to remember to add new modules and non-source files.

  :raises: **AssertionError** files don't match our content
  """

  expected, installed = set(), set()

  for root, dirnames, filenames in os.walk(os.path.join(test.STEM_BASE, 'stem')):
    for filename in filenames:
      file_format = filename.split('.')[-1]

      if file_format not in test.IGNORED_FILE_TYPES:
        expected.add(os.path.join(root, filename)[len(test.STEM_BASE) + 1:])

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
  @staticmethod
  def run_tests(args):
    test_install = stem.util.test_tools.ASYNC_TESTS['test.integ.installation.test_install']
    test_install.run()
    stem.util.test_tools.ASYNC_TESTS['test.integ.installation.test_sdist'].run(test_install.pid())

  @asynchronous
  def test_install():
    """
    Installs with 'python setup.py install' and checks we can use what we
    install.
    """

    try:
      try:
        stem.util.system.call('%s setup.py install --prefix %s' % (PYTHON_EXE, BASE_INSTALL_PATH), timeout = 60, cwd = test.STEM_BASE)
        stem.util.system.call('%s setup.py clean --all' % PYTHON_EXE, timeout = 60, cwd = test.STEM_BASE)  # tidy up the build directory

        if stem.prereq.is_pypy():
          site_packages_paths = glob.glob('%s/site-packages' % BASE_INSTALL_PATH)
        else:
          site_packages_paths = glob.glob('%s/lib*/*/site-packages' % BASE_INSTALL_PATH)
      except Exception as exc:
        raise AssertionError("Unable to install with 'python setup.py install': %s" % exc)

      if len(site_packages_paths) != 1:
        raise AssertionError('We should only have a single site-packages directory, but instead had: %s' % site_packages_paths)

      install_path = site_packages_paths[0]
      version_output = stem.util.system.call([PYTHON_EXE, '-c', "import sys;sys.path.insert(0, '%s');import stem;print(stem.__version__)" % install_path])[0]

      if stem.__version__ != version_output:
        raise AssertionError('We expected the installed version to be %s but was %s' % (stem.__version__, version_output))

      _assert_has_all_files(install_path)
    finally:
      if os.path.exists(BASE_INSTALL_PATH):
        shutil.rmtree(BASE_INSTALL_PATH)

  @asynchronous
  def test_sdist(dependency_pid):
    """
    Creates a source distribution tarball with 'python setup.py sdist' and
    checks that it matches the content of our git repository. This primarily is
    meant to test that our MANIFEST.in is up to date.
    """

    while stem.util.system.is_running(dependency_pid):
      time.sleep(0.1)  # we need to run these tests serially

    git_dir = os.path.join(test.STEM_BASE, '.git')

    if not stem.util.system.is_available('git'):
      raise stem.util.test_tools.SkipTest('(git unavailable)')
    elif not os.path.exists(git_dir):
      raise stem.util.test_tools.SkipTest('(not a git checkout)')

    if os.path.exists(DIST_PATH):
      raise AssertionError("%s already exists, maybe you manually ran 'python setup.py sdist'?" % DIST_PATH)

    try:
      try:
        stem.util.system.call('%s setup.py sdist --dryrun' % PYTHON_EXE, timeout = 60, cwd = test.STEM_BASE)
      except Exception as exc:
        raise AssertionError("Unable to run 'python setup.py sdist': %s" % exc)

      git_contents = [line.split()[-1] for line in stem.util.system.call('git --git-dir=%s ls-tree --full-tree -r HEAD' % git_dir)]

      # tarball has a prefix 'stem-[verion]' directory so stipping that out

      dist_tar = tarfile.open(os.path.join(DIST_PATH, 'stem-dry-run-%s.tar.gz' % stem.__version__))
      tar_contents = ['/'.join(info.name.split('/')[1:]) for info in dist_tar.getmembers() if info.isfile()]

      issues = []

      for path in git_contents:
        if path not in tar_contents and path not in ['.gitignore', '.travis.yml']:
          issues.append('  * %s is missing from our release tarball' % path)

      for path in tar_contents:
        if path not in git_contents and path not in ['MANIFEST.in', 'PKG-INFO']:
          issues.append("  * %s isn't expected in our release tarball" % path)

      if issues:
        raise AssertionError(INSTALL_MISMATCH_MSG + '\n'.join(issues))
    finally:
      if os.path.exists(DIST_PATH):
        shutil.rmtree(DIST_PATH)
