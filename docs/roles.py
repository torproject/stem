import re

from docutils.utils import unescape
from docutils.nodes import reference
from docutils.parsers.rst.roles import set_classes


def role_trac(name, rawtext, text, lineno, inliner, options={}, content=[]):
  """
  Aliases :trac:`1234` to 'https://trac.torproject.org/1234'.

  :param name: the role name used in the document
  :param rawtext: the entire markup snippet, with role
  :param text: the text marked with the role
  :param lineno: the line number where rawtext appears in the input
  :param inliner: the inliner instance that called us
  :param options: directive options for customization
  :param content: the directive content for customization
  """

  # checking if the number is valid
  try:
    ticket_num = int(text)

    if ticket_num <= 0:
      raise ValueError
  except ValueError:
    msg = inliner.reporter.error('Invalid trac ticket: %s' % text, line=lineno)
    prb = inliner.problematic(rawtext, rawtext, msg)

    return ([prb], [msg])

  app = inliner.document.settings.env.app
  link_text = 'ticket %s' % unescape(str(ticket_num))

  return (
    [make_link_node(rawtext, app, 'trac_url', link_text, str(ticket_num), options)],
    [],
  )


def role_spec(name, rawtext, text, lineno, inliner, options={}, content=[]):
  """
  Aliases :spec:`25b0d43` to 'https://gitweb.torproject.org/torspec.git/commit/?id=25b0d43'.
  """

  # checking if the input is a valid short commit id

  if not re.match('^[0-9a-f]{7}$', text):
    msg = inliner.reporter.error('Spec tag expects a short commit id (seven hex characters): %s' % text, line=lineno)
    prb = inliner.problematic(rawtext, rawtext, msg)

    return ([prb], [msg])

  app = inliner.document.settings.env.app

  return (
    [make_link_node(rawtext, app, 'spec_url', 'spec', text, options)],
    [],
  )


def make_link_node(rawtext, app, url_type, link_text, slug, options):
  """
  Creates a link to a trac ticket.

  :param rawtext: text being replaced with link node
  :param app: sphinx application context
  :param url_type: base for our url
  :param link_text: text for the link
  :param slug: ID of the thing to link to
  :param options: options dictionary passed to role func
  """

  base_url = getattr(app.config, url_type, None)

  if not base_url:
    raise ValueError("'%s' isn't set in our config" % url_type)

  ref = base_url.format(slug = slug)
  set_classes(options)

  return reference(rawtext, link_text, refuri = ref, **options)


def setup(app):
  """
  Installs the plugin.

  :param app: sphinx application context
  """

  app.add_role('trac', role_trac)
  app.add_config_value('trac_url', None, 'env')

  app.add_role('spec', role_spec)
  app.add_config_value('spec_url', None, 'env')
