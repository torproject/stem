To Russia With Love
===================

* :ref:`using-socksipy`
* :ref:`using-pycurl`
* :ref:`reading-twitter`

.. _using-socksipy:

Using SocksiPy
--------------

Say it's 1982, the height of the Cold War, and you're a journalist doing a piece on how the Internet looks from behind the Iron Curtain. Ignoring the minor detail that the Internet doesn't yet exist, we'll walk you through how you could do it - no passport required!

The Internet isn't uniform. Localization, censorship, and selective service based on your IP's geographic location can make the Internet a very different place depending on where you're coming from.

Tor relays are scattered all over the world and, as such, you can pretend to be from any place running an exit. This can be especially useful to evade pesky geolocational restrictions, such as news sites that refuse to work while you're traveling abroad.

Tor makes `configuring your exit locale <https://www.torproject.org/docs/faq.html.en#ChooseEntryExit>`_ easy through the **ExitNodes** torrc option. Note that you don't need a control port (or even Stem) to do this, though they can be useful if you later want to do something more elaborate.

In the following example we're using Stem to `start Tor <../api/process.html>`_, then read a site through it with `SocksiPy <http://socksipy.sourceforge.net/>`_. This is not always reliable (some relays are lemons) so you may need to run this more than once.

**Do not rely on the following not to leak.** Though it seems to work there may be edge cases that expose your real IP. If you have a suggestion for how to improve this example then please `let me know <https://www.atagar.com/contact/>`_!

::

  import StringIO
  import socket
  import urllib

  import socks  # SocksiPy module
  import stem.process

  from stem.util import term

  SOCKS_PORT = 7000

  # Set socks proxy and wrap the urllib module

  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
  socket.socket = socks.socksocket

  # Perform DNS resolution through the socket

  def getaddrinfo(*args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

  socket.getaddrinfo = getaddrinfo


  def query(url):
    """
    Uses urllib to fetch a site using SocksiPy for Tor over the SOCKS_PORT.
    """

    try:
      return urllib.urlopen(url).read()
    except:
      return "Unable to reach %s" % url


  # Start an instance of Tor configured to only exit through Russia. This prints
  # Tor's bootstrap information as it starts. Note that this likely will not
  # work if you have another Tor instance running.

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
  print term.format(query("https://www.atagar.com/echo.php"), term.Color.BLUE)

  tor_process.kill()  # stops tor

.. image:: /_static/locale_selection_output.png

.. _using-pycurl:

Using PycURL
------------

Besides SocksiPy, you can also use `PycURL <http://pycurl.sourceforge.net/>`_ to do the same. To do so replace the query() function above with...

::

  import pycurl

  def query(url):
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
    except pycurl.error as exc:
      return "Unable to reach %s (%s)" % (url, exc)

.. _reading-twitter:

Reading Twitter
---------------

Now lets do somthing a little more interesting, and read a Twitter feed over Tor. This can be easily done `using thier API <https://dev.twitter.com/docs/api/1/get/statuses/user_timeline>`_ (**warning: Twitter has deprecated the API that this example uses,** :trac:`9003`)...

::

  import json
  import socket
  import urllib

  import socks  # SockiPy module
  import stem.process

  SOCKS_PORT = 7000
  TWITTER_API_URL = "http://api.twitter.com/1/statuses/user_timeline.json?screen_name=%s&count=%i&include_rts=1"

  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
  socket.socket = socks.socksocket


  def poll_twitter_feed(user_id, tweet_count):
    """
    Polls Twitter for the tweets from a given user.
    """

    api_url = TWITTER_API_URL % (user_id, tweet_count)

    try:
      api_response = urllib.urlopen(api_url).read()
    except:
      raise IOError("Unable to reach %s" % api_url)

    return json.loads(api_response)

  tor_process = stem.process.launch_tor_with_config(
    config = {
      'SocksPort': str(SOCKS_PORT),
      'ExitNodes': '{ru}',
    },
  )

  try:
    for index, tweet in enumerate(poll_twitter_feed('ioerror', 3)):
      print "%i. %s" % (index + 1, tweet["created_at"])
      print tweet["text"]
      print
  except IOError, exc:
    print exc
  finally:
    tor_process.kill()  # stops tor

.. image:: /_static/twitter_output.png

