To Russia With Love
===================

Say it's 1982, the height of the Cold War, and you're a journalist doing a piece on how the Internet looks from behind the Iron Curtain. Ignoring the minor detail that the Internet doesn't yet exist, we'll walk you through how you could do it - no passport required!

The Internet isn't uniform. Localization, censorship, and selective service based on your IP's geographic location can make the Internet a very different place depending on where you're coming from.

Tor relays are scattered all over the world and, as such, you can pretend to be from any place running an exit. This can be especially useful to evade pesky geolocational restrictions, such as news sites that refuse to work while you're traveling abroad.

Tor makes `configuring your exit locale <https://www.torproject.org/docs/faq.html.en#ChooseEntryExit>`_ easy through the **ExitNodes** torrc option. Note that you don't need a control port (or even stem) to do this, though they can be useful if you later want to do something more elaborate.

In the following example we're using stem to `start Tor <../api/process.html>`_, then reading a site through it with `PycURL <http://pycurl.sourceforge.net/>`_. This is not always reliable (some relays are lemons) so you may need to run this more than once.

**Do not rely on the following not to leak.** Though it seems to work, DNS resolution and other edge cases might expose your real IP. If you have a suggestion for how to improve this example then please `let me know <http://www.atagar.com/contact/>`_!

::

  import StringIO

  import pycurl
  import stem.process

  from stem.util import term

  SOCKS_PORT = 7000

  def curl(url):
    """ 
    Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
    """

    output = StringIO.StringIO()

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
    query.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
      query.perform()
      return output.getvalue()
    except pycurl.error, exc:
      return "Unable to reach %s (%s)" % (url, exc)

  # Start an instance of tor configured to only exit through Russia. This prints
  # tor's bootstrap information as it starts.

  def print_bootstrap_lines(line):
    if "Bootstrapped " in line:
      print term.format(line, term.Color.BLUE)

  print term.format("Starting Tor:\n", term.Attr.BOLD)

  tor_process = stem.process.launch_tor_with_config(
    config = {
      'SocksPort': str(SOCKS_PORT),
      'ExitNodes': '{ru}',
    },
    init_msg_handler = print_bootstrap_lines,
  )

  print term.format("\nChecking our endpoint:\n", term.Attr.BOLD)
  print term.format(curl("http://www.atagar.com/echo.php"), term.Color.BLUE)

  tor_process.kill()  # stops tor

.. image:: /_static/locale_selection_output.png

