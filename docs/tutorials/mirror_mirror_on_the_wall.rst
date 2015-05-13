Mirror Mirror on the Wall
=========================

The following is an overview of **Tor descriptors**. If you're already familiar
with what they are and where to get them then you may want to skip to the end.

* :ref:`what-is-a-descriptor`
* :ref:`where-can-i-get-the-current-descriptors`
* :ref:`where-can-i-get-past-descriptors`
* :ref:`can-i-get-descriptors-from-the-tor-process`
* :ref:`validating-the-descriptors-content`
* :ref:`saving-and-loading-descriptors`
* :ref:`putting-it-together`

.. _what-is-a-descriptor:

What is a descriptor?
---------------------

Tor is made up of two parts: the application and a distributed network of a few
thousand volunteer relays. Information about these relays is public, and made
up of documents called **descriptors**.

There are several different kinds of descriptors, the most common ones being...

================================================================================ ===========
Descriptor Type                                                                  Description
================================================================================ ===========
`Server Descriptor <../api/descriptor/server_descriptor.html>`_                  Information that relays publish about themselves. Tor clients once downloaded this information, but now they use microdescriptors instead.
`ExtraInfo Descriptor <../api/descriptor/extrainfo_descriptor.html>`_            Relay information that Tor clients do not need in order to function. This is self-published, like server descriptors, but not downloaded by default.
`Microdescriptor <../api/descriptor/microdescriptor.html>`_                      Minimalistic document that just includes the information necessary for Tor clients to work.
`Network Status Document <../api/descriptor/networkstatus.html>`_                Though Tor relays are decentralized, the directories that track the overall network are not. These central points are called **directory authorities**, and every hour they publish a document called a **consensus** (aka, network status document). The consensus in turn is made up of **router status entries**.
`Router Status Entry <../api/descriptor/router_status_entry.html>`_              Relay information provided by the directory authorities including flags, heuristics used for relay selection, etc.
`Hidden Service Descriptor <../api/descriptor/hidden_service_descriptor.html>`_  Information pertaining to a `Hidden Service <https://www.torproject.org/docs/hidden-services.html.en>`_. These can only be `queried through the tor process <over_the_river.html#hidden-service-descriptors>`_.
================================================================================ ===========

.. _where-can-i-get-the-current-descriptors:

Where can I get the current descriptors?
----------------------------------------

To work Tor needs to have up-to-date information about relays within the
network. As such getting current descriptors is easy: *just download it like
Tor does*.

The `stem.descriptor.remote <../api/descriptor/remote.html>`_ module downloads
descriptors from the tor directory authorities and mirrors. **Please show
some restraint when doing this**! This adds load to the network, and hence an
irresponsible script can make Tor worse for everyone.

Listing the current relays in the Tor network is as easy as...

::

  from stem.descriptor.remote import DescriptorDownloader

  downloader = DescriptorDownloader()

  try:
    for desc in downloader.get_consensus().run():
      print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)
  except Exception as exc:
    print "Unable to retrieve the consensus: %s" % exc 

.. _where-can-i-get-past-descriptors:

Where can I get past descriptors?
---------------------------------

Descriptor archives are available from `CollecTor
<https://collector.torproject.org/>`_. These archives can be read with
the `DescriptorReader <../api/descriptor/reader.html>`_...

::

  from stem.descriptor.reader import DescriptorReader

  with DescriptorReader(["/home/atagar/server-descriptors-2013-03.tar"]) as reader:
    for desc in reader:
      print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

.. _can-i-get-descriptors-from-the-tor-process:

Can I get descriptors from the Tor process?
-------------------------------------------

If you already have Tor running on your system then it is already downloading
descriptors on your behalf. Reusing these is a great way to keep from burdening
the rest of the Tor network.

Tor only gets the descriptors that it needs by default, so if you're scripting
against Tor you may want to set some of the following in your `torrc
<https://www.torproject.org/docs/faq.html.en#torrc>`_. Keep in mind that these
add a small burden to the network, so don't set them in a widely distributed
application. And, of course, please consider `running Tor as a relay
<https://www.torproject.org/docs/tor-doc-relay.html.en>`_ so you give back to
the network!

.. code-block:: lighttpd

  # Descriptors have a range of time during which they're valid. To get the
  # most recent descriptor information, regardless of if Tor needs it or not,
  # set the following.

  FetchDirInfoEarly 1
  FetchDirInfoExtraEarly 1

  # If you aren't actively using Tor as a client then Tor will eventually stop
  # downloading descriptor information that it doesn't need. To prevent this
  # from happening set...

  FetchUselessDescriptors 1

  # Tor no longer downloads server descriptors by default, opting for
  # microdescriptors instead. If you want Tor to download server descriptors
  # then set...

  UseMicrodescriptors 0

  # Tor doesn't need extrainfo descriptors to work. If you want Tor to download
  # them anyway then set...

  DownloadExtraInfo 1

Now that Tor is happy chugging along, up-to-date descriptors are available
through Tor's control socket...

::

  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    for desc in controller.get_network_statuses():
      print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

... or by reading directly from Tor's data directory...

::

  from stem.descriptor import parse_file

  for desc in parse_file('/home/atagar/.tor/cached-consensus'):
    print 'found relay %s (%s)' % (desc.nickname, desc.fingerprint)

.. _validating-the-descriptors-content:

Validating the descriptor's content
-----------------------------------

Stem can optionally validate descriptors, checking their integrity and
compliance with Tor's specs. This does the following...

* Checks that we have mandatory fields, and that their content conforms with
  what Tor's spec says they should have. This can be useful when data
  integrity is important to you since it provides an upfront assurance that
  the descriptor's correct (no need for 'None' checks).

* If you have **pycrypto** we'll validate signatures for descriptor types
  where that has been implemented (such as server and hidden service
  descriptors).

Prior to Stem 1.4.0 descriptors were validated by default, but this has become
opt-in since then.

General rule of thumb: if *speed* is your chief concern then leave it off, but
if *correctness* or *signature validation* is important then turn it on.
Validating is as simple as including **validate = True** in any method that
provides descriptors...

::

  from stem.descriptor import parse_file

  for desc in parse_file('/home/atagar/.tor/cached-consensus', validate = True):
    print 'found relay %s (%s)' % (desc.nickname, desc.fingerprint)

.. _saving-and-loading-descriptors:

Saving and loading descriptors
------------------------------

Tor descriptors are just plaintext documents. As such, if you'd rather not use
`Pickle <https://wiki.python.org/moin/UsingPickle>`_ you can persist a
descriptor by simply writing it to disk, then reading it back later.

::

  from stem.descriptor.remote import DescriptorDownloader

  downloader = DescriptorDownloader()
  server_descriptors = downloader.get_server_descriptors().run()

  with open('/tmp/descriptor_dump', 'wb') as descriptor_file:
    descriptor_file.write(''.join(map(str, server_descriptors)))

Our *server_descriptors* here is a list of
:class:`~stem.descriptor.server_descriptor.RelayDescriptor` instances. When we
write it to a file this looks like...

::

  router default 68.229.17.182 443 0 9030 
  platform Tor 0.2.4.23 on Windows XP
  protocols Link 1 2 Circuit 1
  published 2014-11-17 23:42:38
  fingerprint EE04 42C3 6DB6 6903 0816 247F 2607 382A 0783 2D5A
  uptime 63
  bandwidth 5242880 10485760 77824
  extra-info-digest 1ABA9FC6B912E755483D0F4F6E9BC1B23A2B7206
  ... etc...

We can then read it back with :func:`~stem.descriptor.__init__.parse_file`
by telling it the type of descriptors we're reading...

::

  from stem.descriptor import parse_file

  server_descriptors = parse_file('/tmp/descriptor_dump', descriptor_type = 'server-descriptor 1.0')

  for relay in server_descriptors:
    print relay.fingerprint

For an example of doing this with a consensus document `see here
<examples/persisting_a_consensus.html>`_.

.. _putting-it-together:

Putting it together...
----------------------

As discussed above there are four methods for reading descriptors...

* Download descriptors directly with `stem.descriptor.remote <../api/descriptor/remote.html>`_.
* Read a single file with :func:`~stem.descriptor.__init__.parse_file`.
* Read multiple files or an archive with the `DescriptorReader <../api/descriptor/reader.html>`_.
* Requesting them from Tor with :class:`~stem.control.Controller` methods like :func:`~stem.control.Controller.get_server_descriptors` and :func:`~stem.control.Controller.get_network_statuses`.

Now lets say you want to figure out who the *biggest* exit relays are. You
could use any of the methods above, but for this example we'll use
`stem.descriptor.remote <../api/descriptor/remote.html>`_...

::

  import sys 

  from stem.descriptor.remote import DescriptorDownloader
  from stem.util import str_tools

  # provides a mapping of observed bandwidth to the relay nicknames
  def get_bw_to_relay():
    bw_to_relay = {}

    downloader = DescriptorDownloader()

    try:
      for desc in downloader.get_server_descriptors().run():
        if desc.exit_policy.is_exiting_allowed():
          bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
    except Exception as exc:
      print "Unable to retrieve the server descriptors: %s" % exc 

    return bw_to_relay

  # prints the top fifteen relays

  bw_to_relay = get_bw_to_relay()
  count = 1

  for bw_value in sorted(bw_to_relay.keys(), reverse = True):
    for nickname in bw_to_relay[bw_value]:
      print "%i. %s (%s/s)" % (count, nickname, str_tools.size_label(bw_value, 2))
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

