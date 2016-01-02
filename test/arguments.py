# Copyright 2015-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Commandline argument parsing for our test runner.
"""

import collections
import getopt

import stem.util.conf
import stem.util.log

from test.util import Target

LOG_TYPE_ERROR = """\
'%s' isn't a logging runlevel, use one of the following instead:
  TRACE, DEBUG, INFO, NOTICE, WARN, ERROR
"""

CONFIG = stem.util.conf.config_dict('test', {
  'msg.help': '',
  'target.description': {},
  'target.torrc': {},
})

DEFAULT_ARGS = {
  'run_unit': False,
  'run_integ': False,
  'specific_test': None,
  'logging_runlevel': None,
  'tor_path': 'tor',
  'run_targets': [Target.RUN_OPEN],
  'attribute_targets': [],
  'quiet': False,
  'verbose': False,
  'print_help': False,
}

OPT = 'auit:l:qvh'
OPT_EXPANDED = ['all', 'unit', 'integ', 'targets=', 'test=', 'log=', 'tor=', 'quiet', 'verbose', 'help']


def parse(argv):
  """
  Parses our arguments, providing a named tuple with their values.

  :param list argv: input arguments to be parsed

  :returns: a **named tuple** with our parsed arguments

  :raises: **ValueError** if we got an invalid argument
  """

  args = dict(DEFAULT_ARGS)

  try:
    recognized_args, unrecognized_args = getopt.getopt(argv, OPT, OPT_EXPANDED)

    if unrecognized_args:
      error_msg = "aren't recognized arguments" if len(unrecognized_args) > 1 else "isn't a recognized argument"
      raise getopt.GetoptError("'%s' %s" % ("', '".join(unrecognized_args), error_msg))
  except Exception as exc:
    raise ValueError('%s (for usage provide --help)' % exc)

  for opt, arg in recognized_args:
    if opt in ('-a', '--all'):
      args['run_unit'] = True
      args['run_integ'] = True
    elif opt in ('-u', '--unit'):
      args['run_unit'] = True
    elif opt in ('-i', '--integ'):
      args['run_integ'] = True
    elif opt in ('-t', '--targets'):
      run_targets, attribute_targets = [], []

      integ_targets = arg.split(',')
      all_run_targets = [t for t in Target if CONFIG['target.torrc'].get(t) is not None]

      # validates the targets and split them into run and attribute targets

      if not integ_targets:
        raise ValueError('No targets provided')

      for target in integ_targets:
        if target not in Target:
          raise ValueError('Invalid integration target: %s' % target)
        elif target in all_run_targets:
          run_targets.append(target)
        else:
          attribute_targets.append(target)

      # check if we were told to use all run targets

      if Target.RUN_ALL in attribute_targets:
        attribute_targets.remove(Target.RUN_ALL)
        run_targets = all_run_targets

      # if no RUN_* targets are provided then keep the default (otherwise we
      # won't have any tests to run)

      if run_targets:
        args['run_targets'] = run_targets

      args['attribute_targets'] = attribute_targets
    elif opt == '--test':
      args['specific_test'] = arg
    elif opt in ('-l', '--log'):
      arg = arg.upper()

      if arg not in stem.util.log.LOG_VALUES:
        raise ValueError(LOG_TYPE_ERROR % arg)

      args['logging_runlevel'] = arg
    elif opt in ('--tor'):
      args['tor_path'] = arg
    elif opt in ('-q', '--quiet'):
      args['quiet'] = True
    elif opt in ('-v', '--verbose'):
      args['verbose'] = True
    elif opt in ('-h', '--help'):
      args['print_help'] = True

  # translates our args dict into a named tuple

  Args = collections.namedtuple('Args', args.keys())
  return Args(**args)


def get_help():
  """
  Provides usage information, as provided by the '--help' argument. This
  includes a listing of the valid integration targets.

  :returns: **str** with our usage information
  """

  help_msg = CONFIG['msg.help']

  # gets the longest target length so we can show the entries in columns
  target_name_length = max(map(len, Target))
  description_format = '\n    %%-%is - %%s' % target_name_length

  for target in Target:
    help_msg += description_format % (target, CONFIG['target.description'].get(target, ''))

  help_msg += '\n'

  return help_msg
