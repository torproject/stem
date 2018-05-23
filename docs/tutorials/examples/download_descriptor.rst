Download Tor Descriptors
========================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Tor relays provide a mirror for the tor relay descriptors it has cached.
These are available from its ORPort using `Tor's wire protocol
<https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_, and optionally
with http as well from a `DirPort
<https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_.

.. literalinclude:: /_static/example/download_descriptor.py
   :language: python

::

  % python download_descriptor.py --type consensus --dirport 128.31.0.34:9131
  Downloading consensus descriptor from 128.31.0.34:9131...

  r moria1 lpXfw1/+uGEym58asExGOXAgzjE IpcU7dolas8+Q+oAzwgvZIWx7PA 2018-05-23 02:41:25 128.31.0.34 9101 9131
  s Authority Fast Running Stable V2Dir Valid
  v Tor 0.3.3.5-rc-dev
  pr Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2
  w Bandwidth=20 Unmeasured=1
  p reject 1-65535

