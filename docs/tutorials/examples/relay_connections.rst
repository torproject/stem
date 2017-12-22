Connection Summary
==================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

The following provides a summary of your relay's inbound and outbound
connections. Couple important notes...

  * To use this you must set **DisableDebuggerAttachment 0** in your torrc.
    Otherwise connection information will be unavailable.

  * **Be careful about the data you look at.** Inspection of client and exit
    traffic especially is wiretapping and not only unethical but likely
    illegal.

    That said, a general overview like this should be fine.

.. literalinclude:: /_static/example/relay_connections.py
   :language: python

::

  % relay_connections.py --ctrlport 29051

   0.3.2.0-alpha-dev   uptime: 01:20:44   flags: none

  +------------------------------+------+------+
  | Type                         | IPv4 | IPv6 |
  +------------------------------+------+------+
  | Inbound to our ORPort        | 2400 |    3 |
  | Inbound to our DirPort       |   12 |    0 |
  | Inbound to our ControlPort   |    2 |    0 |
  | Outbound to a relay          |  324 |    0 |
  | Outbound exit traffic        |    3 |    0 |
  +------------------------------+------+------+
  | Total                        | 2741 |    3 |
  +------------------------------+------+------+

  +------------------------------+------+------+
  | Exit Port                    | IPv4 | IPv6 |
  +------------------------------+------+------+
  | 443 (HTTPS)                  |    1 |    0 |
  | 8443 (PCsync HTTPS)          |    1 |    0 |
  | 54682                        |    1 |    0 |
  +------------------------------+------+------+
  | Total                        |    3 |    0 |
  +------------------------------+------+------+
