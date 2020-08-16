import re

from docutils.utils import unescape
from docutils.nodes import reference
from docutils.parsers.rst.roles import set_classes

TRAC_URL = 'https://trac.torproject.org/{ticket}'
SPEC_URL = 'https://gitweb.torproject.org/torspec.git/commit/?id={commit}'


def role_trac(name, rawtext, argument, lineno, inliner, options = {}, content = []):
  """
  Aliases :trac:`1234` to 'https://trac.torproject.org/1234'.
  """

  if not argument.isdigit() or int(argument) <= 0:
    return (
      [inliner.problematic(rawtext, rawtext, msg)],
      [inliner.reporter.error('Invalid trac ticket: %s' % argument, line = lineno)],
    )

  return (
    [reference(rawtext, 'ticket %s' % argument, refuri = TRAC_URL.format(ticket = argument), **options)],
    [],
  )


def role_spec(name, rawtext, argument, lineno, inliner, options = {}, content = []):
  """
  Aliases :spec:`25b0d43` to 'https://gitweb.torproject.org/torspec.git/commit/?id=25b0d43'.
  """

  if not re.match('^[0-9a-f]{7}$', argument):
    return (
      [inliner.problematic(rawtext, rawtext, msg)],
      [inliner.reporter.error('Spec tag expects a short commit id (seven hex characters): %s' % argument, line = lineno)],
    )

  return (
    [reference(rawtext, 'spec', refuri = SPEC_URL.format(commit = argument), **options)],
    [],
  )


def setup(app):
  """
  Installs the plugin.

  :param app: sphinx application context
  """

  app.add_role('trac', role_trac)
  app.add_role('spec', role_spec)
