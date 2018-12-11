Checking Descriptor Digests
===========================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Tor relay information is provided by `multiple documents
<../mirror_mirror_on_the_wall.html#what-is-a-descriptor>`_. Signed descriptors
transitively validate others by inclusion of their digest. For example, our
consensus references server descriptor digest, and server descriptors in turn
cite extrainfo digests.

To illustrate, here’s a diagram from Iain...

.. image:: /_static/digest_chart.png

Stem can calculate digests from `server
<../../api/descriptor/server_descriptor.html#stem.descriptor.server_descriptor.ServerDescriptor.digest>`_,
`extrainfo
<../../api/descriptor/extrainfo_descriptor.html#stem.descriptor.extrainfo_descriptor.ExtraInfoDescriptor.digest>`_,
`microdescriptor
<../../api/descriptor/microdescriptor.html#stem.descriptor.microdescriptor.Microdescriptor.digest>`_,
and `consensus documents
<../../api/descriptor/networkstatus.html#stem.descriptor.networkstatus.NetworkStatusDocument.digest>`_.
For instance, to validate an extrainfo descriptor...

.. literalinclude:: /_static/example/check_digests.py
   :language: python

::

  % python check_digests.py
  What relay fingerprint would you like to validate?
  3BB34C63072D9D10E836EE42968713F7B9325F66

  Server descriptor digest is correct
  Extrainfo descriptor digest is correct

