The Little Relay that Could
===========================

Let's say you just set up your very first `Tor relay
<https://www.torproject.org/docs/tor-doc-relay.html.en>`_ (thank you!), and now
you want to write a script that tells you how much it is being used.

First, for any script to talk with your relay it will need to have a control
port available. This is a port that's usually only available on localhost and
protected by either a **password** or **authentication cookie**.

Look at your `torrc <https://www.torproject.org/docs/faq.html.en#torrc>`_ for
the following configuration options...

.. code-block:: bash

  # This provides a port for our script to talk with. If you set this then be
  # sure to also set either CookieAuthentication *or* HashedControlPassword!
  #
  # You could also use ControlSocket instead of ControlPort, which provides a
  # file based socket. You don't need to have authentication if you use
  # ControlSocket. For this example however we'll use a port.
  
  ControlPort 9051
  
  # Setting this will make Tor write an authentication cookie. Anything with
  # permission to read this file can connect to Tor. If you're going to run
  # your script with the same user or permission group as Tor then this is the
  # easiest method of authentication to use.
  
  CookieAuthentication 1
  
  # Alternatively we can authenticate with a password. To set a password first
  # get its hash...
  #
  # % tor --hash-password "my_password"
  # 16:E600ADC1B52C80BB6022A0E999A7734571A451EB6AE50FED489B72E3DF
  #
  # ... and use that for the HashedControlPassword in your torrc.
  
  HashedControlPassword 16:E600ADC1B52C80BB6022A0E999A7734571A451EB6AE50FED489B72E3DF

When you change your torrc you'll need to either restart Tor or issue a SIGHUP
for the new settings to take effect. Now let's write a script that tells us how
many bytes Tor has sent and received since it started. Note that there are a
`few ways to connect to Tor <../faq.html#how-do-i-connect-to-tor>`_. If you're
unfamiliar with the '**with**' keyword then see `here
<../faq.html#what-is-that-with-keyword-i-keep-seeing-in-the-tutorials>`_...

.. literalinclude:: /_static/example/hello_world.py
   :language: python

::

  % python example.py 
  My Tor relay has read 33406 bytes and written 29649.

Congratulations! You've just written your first controller script.

