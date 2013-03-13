Double Double Toil and Trouble
==============================

Below is a listing of scripts and applications that use stem. If you have
something you would like to have included on this page then `let me know
<http://www.atagar.com/contact/>`_!

.. list-table::
   :widths: 1 10
   :header-rows: 0

   * - .. image:: /_static/arm.png
          :target: http://www.atagar.com/arm/

     - .. image:: /_static/label/arm.png
          :target: http://www.atagar.com/arm/

       Terminal status monitor for Tor. This provides a top like interface
       including system resource usage, connection information, and much more.

=========================================================================================================== ==========
`Consensus Tracker <https://gitweb.torproject.org/atagar/tor-utils.git/blob/HEAD:/consensusTracker.py>`_    Script that performs an hourly check for the number of relays within the Tor network, looking for large jumps that may indicate a sybil attack.
`Metrics Tasks <https://gitweb.torproject.org/metrics-tasks.git/tree>`_                                     One-off tasks related to Tor metrics. These mostly involve using descriptor information to answer a particular question. Tasks that involve stem are: `1854 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-1854/pylinf.py>`_, `6232 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-6232/pyentropy.py>`_, and `7241 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-7241/first_pass.py>`_.
`check_tor <http://anonscm.debian.org/gitweb/?p=users/lunar/check_tor.git;a=blob;f=check_tor.py;hb=HEAD>`_  Nagios check to verify that a relay is participating in the Tor network.
=========================================================================================================== ==========

