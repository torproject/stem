Double Double Toil and Trouble
==============================

Below is a listing of scripts and applications that use Stem. If you have
something you would like to have included on this page then `let me know
<https://www.atagar.com/contact/>`_!

Applications
============

.. Image Sources:
   
   * Arm
     Source: Oxygen (http://www.oxygen-icons.org/)
     License: CC v3 (A, SA)
     File: apps/utilities-system-monitor.png
   
   * Doctor
     Source: https://openclipart.org/detail/29839/stethoscope-by-metalmarious

.. list-table::
   :widths: 1 10
   :header-rows: 0

   * - .. image:: /_static/arm.png
          :target: https://www.atagar.com/arm/

     - .. image:: /_static/label/arm.png
          :target: https://www.atagar.com/arm/

       Terminal status monitor for Tor. This provides a top like interface
       including system resource usage, connection information, and much more.

   * - .. image:: /_static/doctor.png
          :target: https://gitweb.torproject.org/doctor.git/tree

     - .. image:: /_static/label/doctor.png
          :target: https://gitweb.torproject.org/doctor.git/tree

       Monitors the Tor consensus for a variety of issues including malformed
       descriptors, directory authority issues, sybil attacks, and much more.

=========================================================================================================== ==========
`RTT Prober <https://bitbucket.org/ra_/tor-rtt/>`_                                                          Measures round-trip times for Tor circuits.
`TorPS <https://www.torproject.org/getinvolved/volunteer.html.en#project-torps>`_                           Tor path simulator.
`Metrics Tasks <https://gitweb.torproject.org/metrics-tasks.git/tree>`_                                     One-off tasks related to Tor metrics. These mostly involve using descriptor information to answer a particular question. Tasks that involve Stem are: `1854 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-1854/pylinf.py>`_, `6232 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-6232/pyentropy.py>`_, and `7241 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-7241/first_pass.py>`_.
`check_tor <http://anonscm.debian.org/gitweb/?p=users/lunar/check_tor.git;a=blob;f=check_tor.py;hb=HEAD>`_  Nagios check to verify that a relay is participating in the Tor network.
`tbbscraper <https://github.com/zackw/tbbscraper/blob/master/controller/controller.py>`_                    Automated website scraper over Tor.
`torirc <https://github.com/alfred-gw/torirc>`_                                                             IRC-like chat client using Tor hidden services.
`ExitMap <https://github.com/NullHypothesis/exitmap>`_                                                      Scanner for malicious or misconfigured Tor exits.
=========================================================================================================== ==========

Scripts
=======

Client Usage
------------

* `Determine The Exit You're Using <examples/exit_used.html>`_

  Tells you the exit used for each Tor connection.

Descriptors
-----------

* `Comparing Directory Authority Flags <examples/compare_flags.html>`_

  Compares the votes of two directory authorities, in this case moria1 and
  maatuska with a special interest in the 'Running' flag.

