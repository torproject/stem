import re

from docutils.utils import unescape
from docutils.nodes import reference
from docutils.parsers.rst.roles import set_classes

STEM_TICKET_URL = 'https://github.com/torproject/stem/issues/{ticket}'
TOR_TICKET_URL = 'https://gitlab.torproject.org/tpo/core/tor/-/issues/{ticket}'
TRAC_URL = 'https://trac.torproject.org/{ticket}'
SPEC_URL = 'https://gitweb.torproject.org/torspec.git/commit/?id={commit}'


def role_ticket(name, rawtext, argument, lineno, inliner, options = {}, content = []):
  """
  Alias :ticket:`1234` or :ticket:`tor-1234` to a link for that ticket. Tickets
  default to be for Stem if no project is indicated.
  """

  if '-' in argument:
    project, ticket = argument.split('-', 1)
  else:
    project, ticket = 'stem', argument

  if not ticket.isdigit() or int(ticket) <= 0:
    return error('Invalid ticket number: %s' % ticket, rawtext, lineno, inliner)

  if project == 'stem':
    label = 'ticket %s' % ticket
    url = STEM_TICKET_URL.format(ticket = ticket)
  elif project == 'tor':
    label = 'tor ticket %s' % ticket
    url = TOR_TICKET_URL.format(ticket = ticket)
  else:
    return error('Project %s is unrecognized: %s' % (project, argument), rawtext, lineno, inliner)

  return (
    [reference(rawtext, label, refuri = url, **options)],
    [],
  )


def role_trac(name, rawtext, argument, lineno, inliner, options = {}, content = []):
  """
  Aliases :trac:`1234` to 'https://trac.torproject.org/1234'.
  """

  if not argument.isdigit() or int(argument) <= 0:
    return error('Invalid ticket number: %s' % argument, rawtext, lineno, inliner)

  return (
    [reference(rawtext, 'ticket %s' % argument, refuri = TRAC_URL.format(ticket = argument), **options)],
    [],
  )


def role_spec(name, rawtext, argument, lineno, inliner, options = {}, content = []):
  """
  Aliases :spec:`25b0d43` to 'https://gitweb.torproject.org/torspec.git/commit/?id=25b0d43'.
  """

  if not re.match('^[0-9a-f]{7}$', argument):
    return error('Spec tag expects a short commit id (seven hex characters): %s' % argument, rawtext, lineno, inliner)

  return (
    [reference(rawtext, 'spec', refuri = SPEC_URL.format(commit = argument), **options)],
    [],
  )


def error(message, rawtext, lineno, inliner):
  msg = inliner.reporter.error(message, line = lineno)
  prb = inliner.problematic(rawtext, rawtext, msg)

  return ([prb], [msg])


def setup(app):
  """
  Installs the plugin.

  :param app: sphinx application context
  """

  app.add_role('ticket', role_ticket)
  app.add_role('trac', role_trac)
  app.add_role('spec', role_spec)
