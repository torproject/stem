East of the Sun & West of the Moon
==================================

The following is an overview of some of the utilities Stem provides.

* :ref:`terminal-styling`
* :ref:`multiprocessing`
* :ref:`connection-resolution`

.. _terminal-styling:

Terminal Styling
----------------

Know what's better than text? Pretty text!

OSX, Linux, BSD... really, everything except Windows supports terminal
formatting through `ANSI escape sequences
<https://en.wikipedia.org/wiki/ANSI_escape_code#CSI_codes>`_. Doing this
yourself is easy, but we also provide a module to make it `even easier
<../api/util/term.html>`_.

|

.. image:: /_static/words_with.png

|

.. literalinclude:: /_static/example/words_with.py
   :language: python

.. _multiprocessing:

Multiprocessing
---------------

Python's `multiprocessing module
<https://docs.python.org/2/library/multiprocessing.html>`_ gives building
blocks to parallelize around the `Global Interpreter Lock
<https://en.wikipedia.org/wiki/Global_interpreter_lock>`_. However, honestly
it's clunky to use.

Ever just wanted to simply turn your threads into subprocesses? `We can do
that <../api/util/system.html#stem.util.system.DaemonTask>`_.

**Threaded**

.. literalinclude:: /_static/example/fibonacci_threaded.py
   :language: python

::

  % python fibonacci_threaded.py
  took 21.1 seconds

**Multi-process**

.. literalinclude:: /_static/example/fibonacci_multiprocessing.py
   :language: python

::

  % python fibonacci_multiprocessing.py
  took 6.2 seconds
.. _connection-resolution:

Connection Resolution
---------------------

Connection information is a useful tool for learning more about network
applications like Tor. Our :func:`stem.util.connection.get_connections`
function provides an easy method for accessing this information, with a few
caveats...

* Connection resolvers are platform specific. We `support several
  <../api/util/connection.html#stem.util.connection.Resolver>`_ platforms but not all.

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

