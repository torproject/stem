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

