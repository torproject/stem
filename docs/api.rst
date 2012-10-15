API
===

:mod:`stem.connection`
----------------------

Connecting and authenticating to a Tor process.

:mod:`stem.control`
-------------------

Provides the :class:`~stem.control.Controller` class which, as the name implies, is used for talking with and controlling a Tor instance. As a user this is the primary class that you'll need.

:mod:`stem.socket`
------------------

Base classes for communicating with a Tor control socket.

:mod:`stem.process`
-------------------

Used for launching Tor and managing the process.

:mod:`stem.version`
-------------------

Parsed versions that can be compared to the requirement for various features.

`stem.descriptor <stem.descriptor.html>`_
-----------------------------------------

Utilities for working with the Tor consensus and descriptors.

`stem.response <stem.response.html>`_
-------------------------------------

Parsed replies that we receive from the Tor control socket.

`stem.util <stem.util.html>`_
-----------------------------

Utility functions available to stem and its users.

.. toctree::
   :maxdepth: 2

