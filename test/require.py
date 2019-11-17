# Copyright 2012-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Testing requirements. This provides annotations to skip tests that shouldn't be
run.

::

  Test Requirements
  |- only_run_once - skip test if it has been ran before
  |- needs - skips the test unless a requirement is met
  |
  |- cryptography - skips test unless the cryptography module is present
  |- ed25519_support - skips test unless cryptography has ed25519 support
  |- command - requires a command to be on the path
  |- proc - requires the platform to have recognized /proc contents
  |
  |- controller - skips test unless tor provides a controller endpoint
  |- version - skips test unless we meet a tor version requirement
  |- ptrace - requires 'DisableDebuggerAttachment' to be set
  +- online - skips unless targets allow for online tests
"""

import stem.util.system
import stem.version
import test
import test.runner

RAN_TESTS = []


def only_run_once(func):
  """
  Skips the test if it has ran before. If it hasn't then flags it as being ran.
  This is useful to prevent lengthy tests that are independent of integ targets
  from being run repeatedly with ``RUN_ALL``.
  """

  def wrapped(self, *args, **kwargs):
    if self.id() not in RAN_TESTS:
      RAN_TESTS.append(self.id())
      return func(self, *args, **kwargs)
    else:
      self.skipTest('(already ran)')

  return wrapped


def needs(condition, message):
  """
  Skips the test unless the conditional evaluates to 'true'.
  """

  def decorator(func):
    def wrapped(self, *args, **kwargs):
      if condition():
        return func(self, *args, **kwargs)
      else:
        self.skipTest('(%s)' % message)

    return wrapped

  return decorator


def _can_access_controller():
  return test.runner.get_runner().is_accessible()


def _can_ptrace():
  # If we're running a tor version where ptrace is disabled and we didn't
  # set 'DisableDebuggerAttachment=1' then we can infer that it's disabled.

  has_option = test.tor_version() >= stem.version.Requirement.TORRC_DISABLE_DEBUGGER_ATTACHMENT
  return not has_option or test.runner.Torrc.PTRACE in test.runner.get_runner().get_options()


def _is_online():
  return test.Target.ONLINE in test.runner.get_runner().attribute_targets


def command(cmd):
  """
  Skips the test unless a command is available on the path.
  """

  return needs(lambda: stem.util.system.is_available(cmd), '%s unavailable' % cmd)


def version(req_version):
  """
  Skips the test unless we meet the required version.

  :param stem.version.Version req_version: required tor version for the test
  """

  return needs(lambda: test.tor_version() >= req_version, 'requires %s' % req_version)


cryptography = needs(stem.prereq.is_crypto_available, 'requires cryptography')
ed25519_support = needs(lambda: stem.prereq.is_crypto_available(ed25519 = True), 'requires ed25519 support')
proc = needs(stem.util.proc.is_available, 'proc unavailable')
controller = needs(_can_access_controller, 'no connection')
ptrace = needs(_can_ptrace, 'DisableDebuggerAttachment is set')
online = needs(_is_online, 'requires online target')
