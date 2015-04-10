import getopt
import logging
import subprocess
import sys
import time

LOGGER = logging.getLogger('republish')
LOGGER.setLevel(logging.INFO)

handler = logging.FileHandler('/home/stem/republish.log')
handler.setFormatter(logging.Formatter(
  fmt = '%(asctime)s [%(levelname)s] %(message)s',
  datefmt = '%m/%d/%Y %H:%M:%S',
))
LOGGER.addHandler(handler)

OPT = 'r:h'
OPT_EXPANDED = ['repeat=', 'help']

HELP_MSG = """\
Republishes stem's website. This can either be done or on a reoccurring basis.
If stem's repository is unchanged then this is a no-op.

  -r, --repeat RATE     tries to republish the site at a set rate, in minutes
"""


def run(command, cwd = None):
  # Runs the given command. This returns the stdout if successful, and raises
  # an OSError if it fails.

  cmd = subprocess.Popen(command.split(' '), stdout = subprocess.PIPE, stderr = subprocess.PIPE, cwd = cwd)

  if cmd.wait() == 0:
    return cmd.communicate()[0]
  else:
    stdout, stderr = cmd.communicate()
    raise OSError("'%s' failed\n  stdout: %s\n  stderr: %s" % (command, stdout.strip(), stderr.strip()))


def republish_site():
  # Checks if stem's repository has changed, rebuilding the site if so. Ideally
  # we'd use plumbing commands to check this but... meh. Patches welcome.

  if 'Already up-to-date.' not in run('git pull', cwd = '/home/stem/stem'):
    start_time = time.time()
    LOGGER.log(logging.INFO, "Stem's repository has changed. Republishing...")
    run('make html', cwd = '/home/stem/stem/docs')
    run('sudo -u mirroradm static-master-update-component stem.torproject.org')

    runtime = int(time.time() - start_time)
    LOGGER.log(logging.INFO, '  site republished (took %s seconds)' % runtime)


if __name__ == '__main__':
  try:
    opts = getopt.getopt(sys.argv[1:], OPT, OPT_EXPANDED)[0]
  except getopt.GetoptError as exc:
    print('%s (for usage provide --help)' % exc)
    sys.exit(1)

  repeat_rate = None

  for opt, arg in opts:
    if opt in ('-r', '--repeat'):
      if arg.isdigit():
        repeat_rate = int(arg)
      else:
        print("The --repeat argument must be an integer, got '%s'" % arg)
        sys.exit(1)
    elif opt in ('-h', '--help'):
      print(HELP_MSG)
      sys.exit()

  if repeat_rate:
    LOGGER.log(logging.INFO, 'Starting stem site republisher')
    latest_run = 0  # unix timestamp for when we last ran

    while True:
      while time.time() < (latest_run + repeat_rate * 60):
        time.sleep(15)

      try:
        latest_run = time.time()
        republish_site()
      except OSError as exc:
        LOGGER.log(logging.WARN, str(exc))
  else:
    republish_site()
