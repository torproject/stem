Determine The Exit You're Using
===============================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Lets say you're using Tor and one day you run into something odd. Maybe a
misconfigured relay, or maybe one that's being malicious. How can you figure
out what exit you're using?

Here's a simple script that prints information about the exits used to service
the requests going through Tor...

.. literalinclude:: /_static/example/exit_used.py
   :language: python

Now if you make a request over Tor...

::

  % curl --socks4a 127.0.0.1:9050 google.com
  <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
  <TITLE>301 Moved</TITLE></HEAD><BODY>
  <H1>301 Moved</H1>
  The document has moved
  <A HREF="http://www.google.com/">here</A>.
  </BODY></HTML>

... this script will tell you about the exit...

::

  % python exit_used.py
  Tracking requests for tor exits. Press 'enter' to end.

  Exit relay for our connection to 64.15.112.44:80
    address: 31.172.30.2:443
    fingerprint: A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7
    nickname: chaoscomputerclub19
    locale: unknown

