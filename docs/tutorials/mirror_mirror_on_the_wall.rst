Mirror Mirror on the Wall
=========================

The following is an overview of **Tor descriptors**. If you're already familiar
with what they are and where to get them then you may want to skip to the end.

* :ref:`what-is-a-descriptor`
* :ref:`where-can-i-get-the-current-descriptors`
* :ref:`where-can-i-get-past-descriptors`
* :ref:`putting-it-together`

.. _what-is-a-descriptor:

What is a descriptor?
---------------------

Tor is made up of two parts: the application and a distributed network of a few
thousand volunteer relays. Information about these relays is public, and made
up of documents called **descriptors**.

There are several different kinds of descriptors, the most common ones being...

====================================================================== ===========
Descriptor Type                                                        Description
====================================================================== ===========
`Server Descriptor <../api/descriptor/server_descriptor.html>`_        Information that relays publish about themselves. Tor clients once downloaded this information, but now they use microdescriptors instead.
`ExtraInfo Descriptor <../api/descriptor/extrainfo_descriptor.html>`_  Relay information that tor clients do not need in order to function. This is self-published, like server descriptors, but not downloaded by default.
`Microdescriptor <../api/descriptor/microdescriptor.html>`_            Minimalistic document that just includes the information necessary for tor clients to work.
`Network Status Document <../api/descriptor/networkstatus.html>`_      Though tor relays are decentralized, the directories that track the overall network are not. These central points are called **directory authorities**, and every hour they publish a document called a **consensus** (aka, network status document). The consensus in turn is made up of **router status entries**.
`Router Status Entry <../api/descriptor/router_status_entry.html>`_    Relay information provided by the directory authorities including flags, heuristics used for relay selection, etc.
====================================================================== ===========

.. _where-can-i-get-the-current-descriptors:

Where can I get the current descriptors?
----------------------------------------

To work tor needs to have up-to-date information about relays within the
network. As such getting current descriptors is easy: *just run tor*.

Tor only gets the descriptors that it needs by default, so if you're scripting
against tor you may want to set some of the following in your `torrc
<https://www.torproject.org/docs/faq.html.en#torrc>`_. Keep in mind that these
add a small burden to the network, so don't set them in a widely distributed
application. And, of course, please consider `running tor as a relay
<https://www.torproject.org/docs/tor-doc-relay.html.en>`_ so you give back to
the network!

::

  # Descriptors have a range of time during which they're valid. To get the
  # most recent descriptor information, regardless of if tor needs it or not,
  # set the following.

  FetchDirInfoExtraEarly 1

  # If you aren't actively using tor as a client then tor will eventually stop
  # downloading descriptor information that it doesn't need. To prevent this
  # from happening set...

  FetchUselessDescriptors 1

  # Tor no longer downloads server descriptors by default, opting for
  # microdescriptors instead. If you want tor to download server descriptors
  # then set...

  UseMicrodescriptors 0

  # Tor doesn't need extrainfo descriptors to work. If you want tor to download
  # them anyway then set...

  DownloadExtraInfo 1

Now that tor is happy chugging along up-to-date descriptors are available
through tor's control socket...

::

  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    for desc in controller.get_network_statuses():
      print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

... or by reading directly from tor's data directory...

::

  from stem.descriptor import parse_file

  for desc in parse_file(open("/home/atagar/.tor/cached-consensus")):
    print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

.. _where-can-i-get-past-descriptors:

Where can I get past descriptors?
---------------------------------

Descriptor archives are available on `Tor's metrics site
<https://metrics.torproject.org/data.html>`_. These archives can be read with
the `DescriptorReader <api/descriptor/reader.html>`_...

::

  from stem.descriptor.reader import DescriptorReader

  with DescriptorReader(["/home/atagar/server-descriptors-2013-03.tar"]) as reader:
    for desc in reader:
      print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

.. _putting-it-together:

Putting it together...
----------------------

As discussed above there are three methods for reading descriptors...

* With the :class:`~stem.control.Controller` via methods like :func:`~stem.control.Controller.get_server_descriptors` and :func:`~stem.control.Controller.get_network_statuses`.
* By reading the file directly with :func:`~stem.descriptor.__init__.parse_file`.
* Reading with the `DescriptorReader <api/descriptor/reader.html>`_. This is best if you have you want to read everything from a directory or archive.

Now lets say you want to figure out who the *biggest* exit relays are. You
could use any of the methods above, but for this example we'll use the
:class:`~stem.control.Controller`. This uses server descriptors, so keep in
mind that you'll likely need to set "UseMicrodescriptors 0" in your torrc for
this to work.

::

  import sys

  from stem.control import Controller
  from stem.util import str_tools

  # provides a mapping of observed bandwidth to the relay nicknames
  def get_bw_to_relay():
    bw_to_relay = {}

    with Controller.from_port(port = 9051) as controller:
      controller.authenticate()

      for desc in controller.get_server_descriptors():
        if desc.exit_policy.is_exiting_allowed():
          bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)

    return bw_to_relay

  # prints the top fifteen relays

  bw_to_relay = get_bw_to_relay()
  count = 1

  for bw_value in sorted(bw_to_relay.keys(), reverse = True):
    for nickname in bw_to_relay[bw_value]:
      print "%i. %s (%s/s)" % (count, nickname, str_tools.get_size_label(bw_value, 2))
      count += 1

      if count > 15:
        sys.exit()

::

  % python example.py
  1. herngaard (40.95 MB/s)
  2. chaoscomputerclub19 (40.43 MB/s)
  3. chaoscomputerclub18 (40.02 MB/s)
  4. chaoscomputerclub20 (38.98 MB/s)
  5. wannabe (38.63 MB/s)
  6. dorrisdeebrown (38.48 MB/s)
  7. manning2 (38.20 MB/s)
  8. chaoscomputerclub21 (36.90 MB/s)
  9. TorLand1 (36.22 MB/s)
  10. bolobolo1 (35.93 MB/s)
  11. manning1 (35.39 MB/s)
  12. gorz (34.10 MB/s)
  13. ndnr1 (25.36 MB/s)
  14. politkovskaja2 (24.93 MB/s)
  15. wau (24.72 MB/s)

