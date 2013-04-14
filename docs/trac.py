from docutils.utils import unescape
from docutils.nodes import reference
from docutils.parsers.rst.roles import set_classes


def role_trac(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """Returns two part tuple consisting of node and system messages.
    Both allowed to be empty.

    :param name: The role name used in the document.
    :param rawtext: The entire markup snippet, with role.
    :param text: The text marked with the role.
    :param lineno: The line number where rawtext appears in the input.
    :param inliner: The inliner instance that called us.
    :param options: Directive options for customization.
    :param content: The directive content for customization.
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
    node = make_link_node(rawtext, app, 'ticket', str(ticket_num), options)
    return ([node], [])


def make_link_node(rawtext, app, type, slug, options):
    """Creates a link to a trac ticket.

    :param rawtext: Text being replaced with link node.
    :param app: Sphinx application context
    :param type: Link type (issue, changeset, etc.)
    :param slug: ID of the thing to link to
    :param options: Options dictionary passed to role func.
    """

    # checking if trac_url is set in conf.py
    try:
        base = app.config.trac_url
        if not base:
            raise AttributeError

    except AttributeError, e:
        raise ValueError('trac_url is not set (%s)' % str(e))

    slash = '/' if base[-1] != '/' else ''
    ref = base + slash + slug
    set_classes(options)
    name = type + ' ' + unescape(slug)
    node = reference(rawtext, name, refuri=ref, **options)
    return node


def setup(app):
    """Installs the plugin.

    :param app: Sphinx application context.
    """

    app.add_role('trac', role_trac)
    app.add_config_value('trac_url', None, 'env')
    return
