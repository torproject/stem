# Copyright 2015-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Commandline argument parsing for our interpreter prompt.
"""

import getopt
import os

import stem.interpreter
import stem.util.connection

from typing import Any, Dict, NamedTuple, Optional, Sequence

OPT = 'i:s:h'
OPT_EXPANDED = ['interface=', 'socket=', 'tor=', 'run=', 'no-color', 'help']


class Arguments(NamedTuple):
  control_address: str = '127.0.0.1'
  control_port: Optional[int] = None
  user_provided_port: bool = False
  control_socket: str = '/var/run/tor/control'
  user_provided_socket: bool = False
  tor_path: str = 'tor'
  run_cmd: Optional[str] = None
  run_path: Optional[str] = None
  disable_color: bool = False
  print_help: bool = False

  @staticmethod
  def parse(argv: Sequence[str]) -> 'stem.interpreter.arguments.Arguments':
    """
    Parses our commandline arguments into this class.

    :param argv: input arguments to be parsed

    :returns: :class:`stem.interpreter.arguments.Arguments` for this
      commandline input

    :raises: **ValueError** if we got an invalid argument
    """

    args = {}  # type: Dict[str, Any]

    try:
      recognized_args, unrecognized_args = getopt.getopt(argv, OPT, OPT_EXPANDED)  # type: ignore

      if unrecognized_args:
        error_msg = "aren't recognized arguments" if len(unrecognized_args) > 1 else "isn't a recognized argument"
        raise getopt.GetoptError("'%s' %s" % ("', '".join(unrecognized_args), error_msg))
    except Exception as exc:
      raise ValueError('%s (for usage provide --help)' % exc)

    for opt, arg in recognized_args:
      if opt in ('-i', '--interface'):
        if ':' in arg:
          address, port = arg.rsplit(':', 1)
        else:
          address, port = None, arg

        if address is not None:
          if not stem.util.connection.is_valid_ipv4_address(address):
            raise ValueError("'%s' isn't a valid IPv4 address" % address)

          args['control_address'] = address

        if not stem.util.connection.is_valid_port(port):
          raise ValueError("'%s' isn't a valid port number" % port)

        args['control_port'] = int(port)
        args['user_provided_port'] = True
      elif opt in ('-s', '--socket'):
        args['control_socket'] = arg
        args['user_provided_socket'] = True
      elif opt in ('--tor'):
        args['tor_path'] = arg
      elif opt in ('--run'):
        if os.path.exists(arg):
          args['run_path'] = arg
        else:
          args['run_cmd'] = arg
      elif opt == '--no-color':
        args['disable_color'] = True
      elif opt in ('-h', '--help'):
        args['print_help'] = True

    return Arguments(**args)

  @staticmethod
  def get_help() -> str:
    """
    Provides our --help usage information.

    :returns: **str** with our usage information
    """

    defaults = Arguments()

    return stem.interpreter.msg(
      'msg.help',
      address = defaults.control_address,
      port = defaults.control_port if defaults.control_port else 'default',
      socket = defaults.control_socket,
    )
