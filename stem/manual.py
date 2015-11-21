# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Provides information available about Tor from `its manual
<https://www.torproject.org/docs/tor-manual.html.en>`_.

**Module Overview:**

::

  is_important - Indicates if a configuration option is of particularly common importance.

  Manual - Information about Tor available from its manual.
   +- from_man - Retrieves manual information from its man page.

.. versionadded:: 1.5.0
"""

import collections
import os

import stem.prereq
import stem.util.conf
import stem.util.enum
import stem.util.log
import stem.util.system

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

Category = stem.util.enum.Enum('GENERAL', 'CLIENT', 'RELAY', 'DIRECTORY', 'AUTHORITY', 'HIDDEN_SERVICE', 'TESTING', 'UNKNOWN')
ConfigOption = collections.namedtuple('ConfigOption', ['category', 'name', 'usage', 'summary', 'description'])

CATEGORY_SECTIONS = {
  'GENERAL OPTIONS': Category.GENERAL,
  'CLIENT OPTIONS': Category.CLIENT,
  'SERVER OPTIONS': Category.RELAY,
  'DIRECTORY SERVER OPTIONS': Category.DIRECTORY,
  'DIRECTORY AUTHORITY SERVER OPTIONS': Category.AUTHORITY,
  'HIDDEN SERVICE OPTIONS': Category.HIDDEN_SERVICE,
  'TESTING NETWORK OPTIONS': Category.TESTING,
}


@lru_cache()
def _config():
  """
  Provides a dictionary for our manual.cfg. This has a couple categories...

    * manual.important (list) - list of lowercase configuration options
      considered to be important

    * manual.summary.* (str) - summary descriptions of config options, key uses
      the lowercase configuration option
  """

  config = stem.util.conf.Config()
  config_path = os.path.join(os.path.dirname(__file__), 'manual.cfg')

  try:
    config.load(config_path)
    config_dict = dict([(key.lower(), config.get_value(key)) for key in config.keys()])
    config_dict['manual.important'] = [name.lower() for name in config.get_value('manual.important', [], multiple = True)]
    return config_dict
  except Exception as exc:
    stem.util.log.warn("BUG: stem failed to load its internal manual information from '%s': %s" % (config_path, exc))
    return {}


def is_important(option):
  """
  Indicates if a configuration option of particularly common importance or not.

  :param str option: tor configuration option to check

  :returns: **bool** that's **True** if this is an important option and
    **False** otherwise
  """

  return option.lower() in _config()['manual.important']


class Manual(object):
  """
  Parsed tor man page. Tor makes no guarantees about its man page format so
  this may not always be compatible. If not you can use the cached manual
  information stored with Stem.

  This does not include every bit of information from the tor manual. For
  instance, I've excluded the 'THE CONFIGURATION FILE FORMAT' section. If
  there's a part you'd find useful then `file an issue
  <https://trac.torproject.org/projects/tor/wiki/doc/stem/bugs>`_ and we can
  add it.

  :var str name: brief description of the tor command
  :var str synopsis: brief tor command usage
  :var str description: general description of what tor does

  :var dict commandline_options: mapping of commandline arguments to their descripton
  :var dict signals: mapping of signals tor accepts to their description
  :var dict files: mapping of file paths to their description

  :var dict config_option: **ConfigOption** tuples for tor configuration options
  """

  def __init__(self, name, synopsis, description, commandline_options, signals, files, config_options):
    self.name = name
    self.synopsis = synopsis
    self.description = description
    self.commandline_options = commandline_options
    self.signals = signals
    self.files = files
    self.config_options = config_options

  @staticmethod
  def from_man(man_path = 'tor'):
    """
    Reads and parses a given man page.

    :param str man_path: path argument for 'man', for example you might want
      '/path/to/tor/doc/tor.1' to read from tor's git repository
    """

    try:
      man_output = stem.util.system.call('man -P cat %s' % man_path)
    except OSError as exc:
      raise IOError("Unable to run 'man -P cat %s': %s" % (man_path, exc))

    categories, config_options = _get_categories(man_output), OrderedDict()

    for category_header, category_enum in CATEGORY_SECTIONS.items():
      _add_config_options(config_options, category_enum, categories.get(category_header, []))

    for category in categories:
      if category.endswith(' OPTIONS') and category not in CATEGORY_SECTIONS and category != 'COMMAND-LINE OPTIONS':
        _add_config_options(config_options, Category.UNKNOWN, categories.get(category, []))

    return Manual(
      _join_lines(categories.get('NAME', [])),
      _join_lines(categories.get('SYNOPSIS', [])),
      _join_lines(categories.get('DESCRIPTION', [])),
      _get_indented_descriptions(categories.get('COMMAND-LINE OPTIONS', [])),
      _get_indented_descriptions(categories.get('SIGNALS', [])),
      _get_indented_descriptions(categories.get('FILES', [])),
      config_options,
    )


def _get_categories(content):
  """
  The man page is headers followed by an indented section. First pass gets
  the mapping of category titles to their lines.
  """

  # skip header and footer lines

  if content and 'TOR(1)' in content[0]:
    content = content[1:]

  if content and 'TOR(1)' in content[-1]:
    content = content[:-1]

  categories = {}
  category, lines = None, []

  for line in content:
    # replace non-ascii characters
    #
    #   \u2019 - smart single quote
    #   \u2014 - extra long dash
    #   \xb7 - centered dot

    char_for = chr if stem.prereq.is_python_3() else unichr
    line = line.replace(char_for(0x2019), "'").replace(char_for(0x2014), '-').replace(char_for(0xb7), '*')

    if line and not line.startswith(' '):
      if category:
        if lines[-1] == '':
          lines = lines[:-1]  # sections end with an extra empty line

        categories[category] = lines

      category, lines = line.strip(), []
    else:
      if line.startswith('       '):
        line = line[7:]  # contents of a section have a seven space indentation

      lines.append(line)

  if category:
    categories[category] = lines

  return categories


def _get_indented_descriptions(lines):
  """
  Parses the commandline argument and signal sections. These are options
  followed by an indented description. For example...

  ::

    -f FILE
        Specify a new configuration file to contain further Tor configuration
        options OR pass - to make Tor read its configuration from standard
        input. (Default: /usr/local/etc/tor/torrc, or $HOME/.torrc if that file
        is not found)

  There can be additional paragraphs not related to any particular argument but
  ignoring those.
  """

  options, last_arg = OrderedDict(), None

  for line in lines:
    if line and not line.startswith(' '):
      options[line], last_arg = [], line
    elif last_arg and line.startswith('    '):
      options[last_arg].append(line[4:])

  return dict([(arg, ' '.join(desc_lines)) for arg, desc_lines in options.items() if desc_lines])


def _add_config_options(config_options, category, lines):
  """
  Parses a section of tor configuration options. These have usage information,
  followed by an indented description. For instance...

  ::

    ConnLimit NUM
        The minimum number of file descriptors that must be available to the
        Tor process before it will start. Tor will ask the OS for as many file
        descriptors as the OS will allow (you can find this by "ulimit -H -n").
        If this number is less than ConnLimit, then Tor will refuse to start.


        You probably don't need to adjust this. It has no effect on Windows
        since that platform lacks getrlimit(). (Default: 1000)
  """

  last_option, usage, description = None, None, []

  if lines and lines[0].startswith('The following options'):
    lines = lines[lines.index(''):]  # drop the initial description

  for line in lines:
    if line and not line.startswith(' '):
      if last_option:
        summary = _config().get('manual.summary.%s' % last_option.lower(), '')
        config_options[last_option] = ConfigOption(category, last_option, usage, summary, _join_lines(description).strip())

      if ' ' in line:
        last_option, usage = line.split(' ', 1)
      else:
        last_option, usage = line, ''

      description = []
    else:
      if line.startswith('    '):
        line = line[4:]

      description.append(line)

  if last_option:
    summary = _config().get('manual.summary.%s' % last_option.lower(), '')
    config_options[last_option] = ConfigOption(category, last_option, usage, summary, _join_lines(description).strip())


def _join_lines(lines):
  """
  The man page provides line-wrapped content. Attempting to undo that. This is
  close to a simple join, but we still want empty lines to provide newlines.
  """

  content = []

  for line in lines:
    if line:
      if content and content[-1][-1] != '\n':
        line = ' ' + line

      content.append(line)
    else:
      if content and content[-1][-1] != '\n':
        content.append('\n\n')

  return ''.join(content)
