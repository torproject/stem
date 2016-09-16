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
     License: Public Domain
   
   * Exit Map
     Source: https://openclipart.org/detail/120607/treasure-map-by-tzunghaor
     License: Public Domain

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

   * - .. image:: /_static/exit_map.png
          :target: http://www.cs.kau.se/philwint/spoiled_onions/

     - .. image:: /_static/label/exit_map.png
          :target: http://www.cs.kau.se/philwint/spoiled_onions/

       Scanner by Philipp Winter to detect malicious and misconfigured Tor
       exits. For more information about how it works see his `Spoiled
       Onions <http://www.cs.kau.se/philwint/spoiled_onions/techreport.pdf>`_
       research paper.

=========================================================================================================== ==========
`OnionLauncher <https://github.com/neelchauhan/OnionLauncher>`_                                             Qt interface for launching tor.
`TorNova <https://github.com/neelchauhan/TorNova>`_                                                         GTK interface for launching tor.
`BeagleBone for Secret Agents <https://github.com/jbdatko/beagle-bone-for-secret-agents>`_                  Bridge with a `bandwidth monitor <https://github.com/jbdatko/beagle-bone-for-secret-agents/blob/master/ch2/beaglebridge.py>`_ on a BeagleBoard.
`NavigaTor <https://naviga-tor.github.io>`_                                                                 Measures round-trip times for Tor circuits.
`TorPS <https://www.torproject.org/getinvolved/volunteer.html.en#project-torps>`_                           Tor path simulator.
`Metrics Tasks <https://gitweb.torproject.org/metrics-tasks.git/tree>`_                                     One-off tasks related to Tor metrics. These mostly involve using descriptor information to answer a particular question. Tasks that involve Stem are: `1854 <https://gitweb.torproject.org/metrics-tasks.git/blob/HEAD:/task-1854/pylinf.py>`_, `6232 <https://gitweb.torproject.org/metrics-tasks.git/tree/task-6232/pyentropy.py>`_, and `7241 <https://gitweb.torproject.org/metrics-tasks.git/tree/task-7241/first_pass.py>`_.
`Onion Box <https://github.com/ralphwetzel/theonionbox>`_                                                   Web dashboard for relay operation.
`check_tor <http://anonscm.debian.org/gitweb/?p=users/lunar/check_tor.git;a=blob;f=check_tor.py;hb=HEAD>`_  Nagios check to verify that a relay is participating in the Tor network.
`munin-tor <https://github.com/mweinelt/munin-tor>`_                                                        Plugin to provide Munin graphs.
`tbbscraper <https://github.com/zackw/tbbscraper/blob/master/collector/lib/controller/controller.py>`_      Automated website scraper over Tor.
`torIRC <https://gist.github.com/torifier/f1a7c1ac7b6b003cd9e1c187df2c5347>`_                               IRC-like chat client using Tor hidden services.
`exit-funding <https://github.com/torservers/exit-funding>`_                                                Script to estimate how much exit relays have been used.
`torsearch <https://github.com/wfn/torsearch>`_                                                             Search engine prototype for descriptor data.
`or-applet <https://github.com/Yawning/or-applet>`_                                                         GUI widget to provide circuit information and an interactive interpreter.
`OnionBalance <https://github.com/DonnchaC/onionbalance>`_                                                  Tool for making distributed hidden service requests.
`OnionPerf <https://github.com/robgjansen/onionperf>`_                                                      Measures onion service performance over time using customizable client behavior models.
`OnioNS <https://github.com/Jesse-V/OnioNS-client>`_                                                        Distributed DNS for hidden services.
`OnionShare <https://github.com/micahflee/onionshare>`_                                                     Hidden service based file sharing application.
`OnionView <https://github.com/skyguy/onionview>`_                                                          GTK interface for viewing circuit information.
`OnionCircuits <https://git-tails.immerda.ch/onioncircuits/>`_                                              GTK interface for viewing circuit information.
`Syboa <https://gitorious.org/syboa/syboa>`_                                                                GTK interface similar to `TorK <http://sourceforge.net/projects/tork/>`_.
`hs-health <https://gitlab.com/hs-health/hs-health>`_                                                       Experiment to measure churn and reachability of hidden services.
`trnnr <https://github.com/NullHypothesis/trnnr>`_                                                          Python implementation of tor's nearest neighbour ranking.
`TorTP <https://github.com/vinc3nt/stem-tortp>`_                                                            Configures iptables to torify all traffic.
=========================================================================================================== ==========

Scripts
=======

Client Usage
------------

* `List Circuits <examples/list_circuits.html>`_

  List the path Tor uses for its present circuits.

* `Determine The Exit You're Using <examples/exit_used.html>`_

  Tells you the exit used for each Tor connection.

Descriptors
-----------

* `List Outdated Relays <examples/outdated_relays.html>`_

  Prints contact information for relays prior to a given version.

* `Comparing Directory Authority Flags <examples/compare_flags.html>`_

  Compares the votes of two directory authorities, in this case moria1 and
  maatuska with a special interest in the 'Running' flag.

* `Votes by Bandwidth Authorities <examples/votes_by_bandwidth_authorities.html>`_

  Provides information about the current votes from Tor's Bandwidth
  Authorities.

* `Saving and Loading a Tor Consensus <examples/persisting_a_consensus.html>`_

  Example for writing a Tor consensus to disk, and reading it back.

