from docutils.utils import unescape
from docutils.nodes import reference
from docutils.parsers.rst.roles import set_classes


def role_trac(name, rawtext, text, lineno, inliner, options={}, content=[]):
  """
  Returns two part tuple consisting of node and system messages. Both allowed
  to be empty.

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
    msg = inliner.reporter.error(
         'Invalid trac ticket: %s' % (text), line=lineno)
    prb = inliner.problematic(rawtext, rawtext, msg)

    return ([prb], [msg])

  app = inliner.document.settings.env.app

  return (
    [make_link_node(rawtext, app, 'ticket', str(ticket_num), options)],
    [],
  )


def make_link_node(rawtext, app, link_type, slug, options):
  """
  Creates a link to a trac ticket.

  :param rawtext: text being replaced with link node
  :param app: sphinx application context
  :param link_type: link type (issue, changeset, etc.)
  :param slug: ID of the thing to link to
  :param options: options dictionary passed to role func
  """

  trac_base_url = getattr(app.config, 'trac_url', None)

  if not trac_base_url:
    raise ValueError('trac_url is not set')

  ref = trac_base_url.rstrip('/') + '/' + slug
  set_classes(options)
  name = link_type + ' ' + unescape(slug)  # sets the text to 'ticket 345'

  return reference(rawtext, name, refuri = ref, **options)


def setup(app):
  """
  Installs the plugin.

  :param app: sphinx application context
  """

  app.add_role('trac', role_trac)
  app.add_config_value('trac_url', None, 'env')
