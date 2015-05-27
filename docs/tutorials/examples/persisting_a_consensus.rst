Saving and Loading a Tor Consensus
==================================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Reading and writing a Tor consensus to disk is similar to `other descriptor
types <../mirror_mirror_on_the_wall.html#saving-and-loading-descriptors>`_
with one small difference.

Most descriptors are just about a single relay. Server descriptors and
microdescriptors, for instance, can be concatenated together and dumped to a
file because they're each independent of each other.

The Tor consensus, however, is a larger document containing information about
the Tor network in addition to a little data on each of the relays.

In Stem the overall document is a
:class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`, and the
information on individual relays are
:class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` instances.

Why does this matter? By default when you read a consensus Stem provides you
**just** the :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`.
This is for performance reasons, and because usually that's what developers
want. But for writing the conssensus to disk we'll want the whole document
instead.

So how do we get it? Just tell Stem that's what you want. The
:class:`~stem.descriptor.__init__.DocumentHandler` tells Stem how to read the
consensus. For example, to write the consensus simply do the following...

.. literalinclude:: /_static/example/persisting_a_consensus.py
   :language: python

Our *consensus* here is the current
:class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`. The
**descriptor_dump** file now looks like...

::

  network-status-version 3
  vote-status consensus
  consensus-method 18
  valid-after 2014-11-17 23:00:00
  fresh-until 2014-11-18 00:00:00
  valid-until 2014-11-18 02:00:00
  voting-delay 300 300
  ... etc...

You can then read it back with :func:`~stem.descriptor.__init__.parse_file`...

.. literalinclude:: /_static/example/persisting_a_consensus_with_parse_file.py
   :language: python
