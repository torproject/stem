East of the Sun & West of the Moon
==================================

The following is an overview of some of the utilities Stem provides.

* :ref:`connection-resolution`

.. _connection-resolution:

Connection Resolution
---------------------

Connection information is a useful tool for learning more about network
applications like Tor. Our :func:`stem.util.connection.get_connections`
function provides an easy method for accessing this information, with a few
caveats...

* Connection resolvers are platform specific. We `support several
  <../api/util/connection.html#stem.util.connection.Resolver>`_ but not not
  all, most notably Windows (:trac:`9850`).

* By default Tor runs with a feature called **DisableDebuggerAttachment**. This
  prevents debugging applications like gdb from analyzing Tor unless it is run
  as root. Unfortunately this also alters the permissions of the Tor process
  /proc contents breaking numerous system tools (including our resolvers). To
  use this function you need to either run as root (discouraged) or add
  **DisableDebuggerAttachment 0** to your torrc.

Please note that if you operate an exit relay it is **highly** discouraged for
you to look at or record this information. Not only is doing so eavesdropping,
but likely also a violation of wiretap laws. 

With that out of the way, how do you look up this information? Below is a
simple script that dumps Tor's present connections.

.. literalinclude:: /_static/example/utilities.py
   :language: python

::

  % python example.py
  Our platform supports connection resolution via: proc, netstat, sockstat, lsof, ss (picked proc)
  Tor is running with pid 17303

  Connections:

    192.168.0.1:59014 => 38.229.79.2:443
    192.168.0.1:58822 => 68.169.35.102:443

