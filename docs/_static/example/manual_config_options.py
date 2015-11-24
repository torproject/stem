from stem.manual import Manual
from stem.util import term

try:
  print("Downloading tor's manual information, please wait...")
  manual = Manual.from_remote()
  print("  done\n")
except IOError as exc:
  print("  unsuccessful (%s), using information provided with stem\n" % exc)
  manual = Manual.from_cache()  # fall back to our bundled manual information

print('Which tor configuration would you like to learn about?  (press ctrl+c to quit)\n')

try:
  while True:
    requested_option = raw_input('> ').strip()

    if requested_option:
      if requested_option in manual.config_options:
        option = manual.config_options[requested_option]
        print(term.format('%s %s' % (option.name, option.usage), term.Color.GREEN, term.Attr.BOLD))
        print(term.format(option.summary, term.Color.GREEN))  # brief description provided by stem

        print(term.format('\nFull Description:\n', term.Color.GREEN, term.Attr.BOLD))
        print(term.format(option.description + '\n', term.Color.GREEN))
      else:
        print(term.format("Sorry, we don't have any information about %s. Are you sure it's an option?" % requested_option, term.Color.RED))
except KeyboardInterrupt:
  pass  # user pressed ctrl+c

