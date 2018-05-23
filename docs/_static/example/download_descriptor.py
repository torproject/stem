"""
Simple script to dowload a descriptor from Tor's ORPort or DirPort.
"""

import collections
import getopt
import sys

import stem
import stem.descriptor.remote
import stem.util.connection
import stem.util.tor_tools

# By default downloading moria1's server descriptor from itself.

DEFAULT_ARGS = {
  'descriptor_type': 'server',
  'fingerprint': '9695DFC35FFEB861329B9F1AB04C46397020CE31',
  'download_from': stem.DirPort('128.31.0.34', 9131),
  'print_help': False,
}

VALID_TYPES = ('server', 'extrainfo', 'consensus')

HELP_TEXT = """\
Downloads a descriptor through Tor's ORPort or DirPort.

  -t, --type TYPE                 descriptor type to download, options are:
                                    %s
  -f, --fingerprint FP            relay to download the descriptor of
      --orport ADDRESS:PORT       ORPort to download from
      --dirport ADDRESS:PORT      DirPort to download from
  -h, --help                      presents this help
""" % ', '.join(VALID_TYPES)


def parse(argv):
  """
  Parses our arguments, providing a named tuple with their values.

  :param list argv: input arguments to be parsed

  :returns: a **named tuple** with our parsed arguments

  :raises: **ValueError** if we got an invalid argument
  """

  args = dict(DEFAULT_ARGS)

  try:
    recognized_args, unrecognized_args = getopt.getopt(argv, 't:f:h', ['type=', 'fingerprint=', 'orport=', 'dirport=', 'help'])

    if unrecognized_args:
      raise getopt.GetoptError("'%s' aren't recognized arguments" % "', '".join(unrecognized_args))
  except Exception as exc:
    raise ValueError('%s (for usage provide --help)' % exc)

  for opt, arg in recognized_args:
    if opt in ('-t', '--type'):
      if arg not in VALID_TYPES:
        raise ValueError("'%s' isn't a recognized decriptor type, options are: %s" % (arg, ', '.join(VALID_TYPES)))

      args['descriptor_type'] = arg
    elif opt in ('-f', '--fingerprint'):
      if not stem.util.tor_tools.is_valid_fingerprint(arg):
        raise ValueError("'%s' isn't a relay fingerprint" % arg)

      args['fingerprint'] = arg
    elif opt in ('--orport', '--dirport'):
      if ':' not in arg:
        raise ValueError("'%s' should be of the form 'address:port'" % arg)

      address, port = arg.rsplit(':', 1)

      if not stem.util.connection.is_valid_ipv4_address(address):
        raise ValueError("'%s' isn't a valid IPv4 address" % address)
      elif not stem.util.connection.is_valid_port(port):
        raise ValueError("'%s' isn't a valid port number" % port)

      endpoint_class = stem.ORPort if opt == '--orport' else stem.DirPort
      args['download_from'] = endpoint_class(address, port)
    elif opt in ('-h', '--help'):
      args['print_help'] = True

  # translates our args dict into a named tuple

  Args = collections.namedtuple('Args', args.keys())
  return Args(**args)


def main():
  try:
    args = parse(sys.argv[1:])
  except ValueError as exc:
    print(exc)
    sys.exit(1)

  if args.print_help:
    print(HELP_TEXT)
    sys.exit()

  print('Downloading %s descriptor from %s:%s...\n' % (args.descriptor_type, args.download_from.address, args.download_from.port))
  desc = None

  if args.descriptor_type in ('server', 'extrainfo'):
    if args.descriptor_type == 'server':
      download_func = stem.descriptor.remote.get_server_descriptors
    else:
      download_func = stem.descriptor.remote.get_extrainfo_descriptors

    desc = download_func(
      fingerprints = [args.fingerprint],
      endpoints = [args.download_from],
    ).run()[0]
  elif args.descriptor_type == 'consensus':
    for consensus_desc in stem.descriptor.remote.get_consensus(endpoints = [args.download_from]):
      if consensus_desc.fingerprint == args.fingerprint:
        desc = consensus_desc
        break

    if not desc:
      print('Unable to find a descriptor for %s in the consensus' % args.fingerprint)
      sys.exit(1)
  else:
    print("'%s' is not a recognized descriptor type, options are: %s" % (args.descriptor_type, ', '.join(VALID_TYPES)))
    sys.exit(1)

  print(desc)

if __name__ == '__main__':
  main()
