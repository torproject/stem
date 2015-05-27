To Russia With Love
===================

* :ref:`using-pycurl`
* :ref:`using-socksipy`
* :ref:`reading-twitter`
* :ref:`custom-path-selection`

.. _using-pycurl:

Using PycURL
------------

Say it's 1982, the height of the Cold War, and you're a journalist doing a
piece on how the Internet looks from behind the Iron Curtain. Ignoring the
minor detail that the Internet doesn't yet exist, we'll walk you through how
you could do it - no passport required!

The Internet isn't uniform. Localization, censorship, and selective service
based on your IP's geographic location can make the Internet a very different
place depending on where you're coming from.

Tor relays are scattered all over the world and, as such, you can pretend to be
from any place running an exit. This can be especially useful to evade pesky
geolocational restrictions, such as news sites that refuse to work while you're
traveling abroad.

Tor makes `configuring your exit locale
<https://www.torproject.org/docs/faq.html.en#ChooseEntryExit>`_ easy through
the **ExitNodes** torrc option. Note that you don't need a control port (or
even Stem) to do this, though they can be useful if you later want to do
something more elaborate.

In the following example we're using Stem to `start Tor
<../api/process.html>`_, then read a site through it with `PycURL
<http://pycurl.sourceforge.net/>`_. This is not always reliable (some relays
are lemons) so you may need to run this more than once.

Having an issue? The following are some common gotchas...

* PycURL's **PROXYTYPE_SOCKS5_HOSTNAME** was added in v7.19.5.1. Try `upgrading
  <http://tech.michaelaltfield.net/2015/02/22/pycurl-through-tor-without-leaking-dns-lookups/>`_
  if you get an AttributeError about it.

* The following example for exiting through Russia will only work if... well,
  the Tor network *has* a Russian exit. Often this isn't the case. If Tor fails
  to bootstrap try dropping the line with **'ExitNodes': '{ru}'**.

**Do not rely on the following not to leak.** Though it seems to work there may
be edge cases that expose your real IP. If you have a suggestion for how to
improve this example then please `let me know
<https://www.atagar.com/contact/>`_!

.. literalinclude:: /_static/example/client_usage_using_pycurl.py
   :language: python

.. image:: /_static/locale_selection_output.png

.. _using-socksipy:

Using SocksiPy
--------------

Besides PycURL, you can also use `SocksiPy <http://socksipy.sourceforge.net/>`_
to do the same. Be aware that the following example routes **all** socket
connections through Tor, so this'll break our ability to connect to Tor's
control port. To use this approach simply replace the query() function above
with...

.. literalinclude::  /_static/example/client_usage_using_socksipy.py
   :language: python

.. _reading-twitter:

Reading Twitter
---------------

Now lets do something a little more interesting, and read a Twitter feed over
Tor. This can be done `using their API
<https://dev.twitter.com/rest/reference/get/statuses/user_timeline>`_, for
authentication `see their instructions
<https://dev.twitter.com/oauth/overview/application-owner-access-tokens>`_...

.. literalinclude:: /_static/example/reading_twitter.py
   :language: python

.. image:: /_static/twitter_output.png

.. _custom-path-selection:

Custom Path Selection
---------------------

Routing requests over Tor is all well and good, but what if you want to do
something more sophisticated? Through Tor's controller interface you can manage
your own **circuits** and **streams**.

A **circuit** is your path through the Tor network. Circuits must consist of at
least two relays, and must end with a relay that allows connections to the
destination you want to reach.

**Streams** by contrast are TCP connections carried over a circuit. Tor handles
attaching streams to a circuit that can service it. To instead manage this
yourself call...

::

  controller.set_conf('__LeaveStreamsUnattached', '1')

For an example of this lets fetch a site over each relay to determine it's
reachability and speed. **Naturally doing this causes quite a bit of load so
please be careful not to leave this running!**

.. literalinclude:: /_static/example/custom_path_selection.py
   :language: python

::

  % python scan_network.py 
  000050888CF58A50E824E534063FF71A762CB227 => 2.62 seconds
  000149E6EF7102AACA9690D6E8DD2932124B94AB => 2.50 seconds
  000A10D43011EA4928A35F610405F92B4433B4DC => 2.18 seconds
  000F18AC2CDAE4C710BA0898DC9E21E72E0117D8 => 2.40 seconds
  0011BD2485AD45D984EC4159C88FC066E5E3300E => 2.03 seconds
  003000C32D9E16FCCAEFD89336467C01E16FB00D => 11.41 seconds
  008E9B9D7FF523CE1C5026B480E0127E64FA7A19 => 2.24 seconds
  009851DF933754B00DDE876FCE4088CE1B4940C1 => 2.39 seconds
  0098C475875ABC4AA864738B1D1079F711C38287 => Unable to reach https://check.torproject.org/ ((28, 'SSL connection timeout'))
  00B70D1F261EBF4576D06CE0DA69E1F700598239 => 2.41 seconds
  00DFA1137D178EE012B96F64D12F03B4D69CA0B2 => 4.53 seconds
  00EF4569C8E4E165286DE6D293DCCE1BB1F280F7 => Circuit failed to be created: CHANNEL_CLOSED
  00F12AB035D62C919A1F37C2A67144F17ACC9E75 => 3.58 seconds
  00F2D93EBAF2F51D6EE4DCB0F37D91D72F824B16 => 2.12 seconds
  00FCFBC5770DC6B716D917C73A0DE722CCF2DFE5 => 2.16 seconds
  ...

