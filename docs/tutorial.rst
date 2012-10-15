Tutorial
========

Getting started with any new library can be rather daunting, so lets get our feet wet by jumping straight in with a tutorial...

* :ref:`the-little-relay-that-could` - Hello world with the control port.
* :ref:`mirror-mirror-on-the-wall` - Querying information about the Tor network.

.. _the-little-relay-that-could:

The Little Relay that Could
---------------------------

Lets say you just set up your very first `Tor relay <https://www.torproject.org/docs/tor-doc-relay.html.en>`_. Thank you! Now you want to write a script that tells you how much it is being used.

First, for any script we write to be able to talk with our relay it'll need to have a control port available. This is a port that's usually only available on localhost and protected by either a password or authentication cookie.

Look at your `torrc <https://www.torproject.org/docs/faq.html.en#torrc>`_ for the following configuration options...

::

  # This provides a port for the script we write to talk to. If you set this
  # then be sure to also have either set the CookieAuthentication flag *or*
  # provide a HashedControlPassword!
  
  ControlPort 9051
  
  # This will make Tor write an authentication cookie file. Anything that can
  # read that file can connect to Tor. If you're going to run this script with
  # the same user as Tor then this is the easiest method of authentication to
  # use.
  
  CookieAuthentication 1
  
  # Alternatively we can authenticate with a password. To set a password first
  # get its hash...
  #
  # % tor --hash-password "my_password"
  # 16:E600ADC1B52C80BB6022A0E999A7734571A451EB6AE50FED489B72E3DF
  #
  # ... and use that for the HashedControlPassword in our torrc.
  
  HashedControlPassword 16:E600ADC1B52C80BB6022A0E999A7734571A451EB6AE50FED489B72E3DF

You'll need to restart Tor or issue a SIGHUP for these new settings to take effect. Now lets write a script that tells us how many bytes Tor has sent and received...

::

  from stem.control import Controller
  
  controller = Controller.from_port(control_port = 9051)
  controller.authenticate() # provide the password here if you set one
  
  bytes_read = controller.get_info("traffic/read")
  bytes_written = controller.get_info("traffic/written")
  
  print "My Tor relay has read %s bytes and written %s." % (bytes_read, bytes_written)
  controller.close()

::

  % python example.py 
  My Tor relay has read 33406 bytes and written 29649.

Congratulations! You've just written your first controller script.

.. _mirror-mirror-on-the-wall:

Mirror Mirror on the Wall
-------------------------

A script that tells us our contributed bandwidth is neat and all, but now lets figure out who the *biggest* exit relays are.

Information about the Tor relay network come from documents called **descriptors**. Descriptors can come from a few things...

1. The Tor control port with GETINFO options like **desc/all-recent** and **ns/all**.
2. Files in Tor's data directory, like **cached-descriptors** and **cached-consensus**.
3. The descriptor archive on `Tor's metrics site <https://metrics.torproject.org/data.html>`_.

We've already used the control port, so for this example we'll use the cached files directly. First locate Tor's data directory. If your torrc has a DataDirectory line then that's the spot. If not then check Tor's man page for the default location.

Tor has several descriptor types. For bandwidth information we'll go to the server descriptors, which are located in the **cached-descriptors** file. These have somewhat infrequently changing information published by the relays themselves.

To read this file we'll use the :class:`~stem.descriptor.reader.DescriptorReader`, a class designed to read descriptor files. The **cached-descriptors** is full of server descriptors, so the reader will provide us with :class:`~stem.descriptor.server_descriptor.RelayDescriptor` instances (a :class:`~stem.descriptor.server_descriptor.ServerDescriptor` subclass for relays).

::

  import sys
  from stem.descriptor.reader import DescriptorReader
  
  bw_to_relay = {} # mapping of observed bandwidth to the relay nicknames
  
  with DescriptorReader(["/home/atagar/.tor/cached-descriptors"]) as reader:
    for desc in reader:
      if desc.exit_policy.is_exiting_allowed():
        bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
  
  sorted_bw = sorted(bw_to_relay.keys(), reverse = True)
  
  # prints the top fifteen relays
  
  count = 1
  for bw_value in sorted_bw:
    for nickname in bw_to_relay[bw_value]:
      print "%i. %s (%i bytes/s)" % (count, nickname, bw_value)
      count += 1
      
      if count > 15:
        sys.exit()

::

  % python example.py 
  1. herngaard (42939655 bytes/s)
  2. chaoscomputerclub19 (42402911 bytes/s)
  3. chaoscomputerclub18 (41967097 bytes/s)
  4. chaoscomputerclub20 (40882989 bytes/s)
  5. wannabe (40514411 bytes/s)
  6. dorrisdeebrown (40349829 bytes/s)
  7. manning2 (40057719 bytes/s)
  8. chaoscomputerclub21 (38701399 bytes/s)
  9. TorLand1 (37983627 bytes/s)
  10. bolobolo1 (37676580 bytes/s)
  11. manning1 (37117034 bytes/s)
  12. gorz (35760527 bytes/s)
  13. ndnr1 (26595129 bytes/s)
  14. politkovskaja2 (26149682 bytes/s)
  15. wau (25929953 bytes/s)

