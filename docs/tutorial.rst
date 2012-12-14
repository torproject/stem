Tutorial
========

Getting started with any new library can be rather daunting, so let's get our feet wet by jumping straight in with a tutorial...

* :ref:`the-little-relay-that-could` - Hello world with the control port.
* :ref:`mirror-mirror-on-the-wall` - Querying information about the Tor network.

.. _the-little-relay-that-could:

The Little Relay that Could
---------------------------

Let's say you just set up your very first `Tor relay <https://www.torproject.org/docs/tor-doc-relay.html.en>`_. Thank you! Now you want to write a script that tells you how much it is being used.

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

You'll need to restart Tor or issue a SIGHUP for these new settings to take effect. Now let's write a script that tells us how many bytes Tor has sent and received...

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

A script that tells us our contributed bandwidth is neat and all, but now let's figure out who the *biggest* exit relays are.

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
  from stem.util import str_tools
  
  # provides a mapping of observed bandwidth to the relay nicknames
  def get_bw_to_relay():
    bw_to_relay = {}
    
    with DescriptorReader(["/home/atagar/.tor/cached-descriptors"]) as reader:
      for desc in reader:
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

This can be easily done through the controller too...

::

  def get_bw_to_relay():
    bw_to_relay = {}
    
    with Controller.from_port(control_port = 9051) as controller:
      controller.authenticate()
      
      for desc in controller.get_server_descriptors():
        if desc.exit_policy.is_exiting_allowed():
          bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
    
    return bw_to_relay

