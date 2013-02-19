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


