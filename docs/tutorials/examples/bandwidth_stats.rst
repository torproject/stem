Bandwidth Heuristics
====================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

To select the relays it will use Tor consults several factors. Exit policies,
flags, as well as bandwidth heuristics so our circuits are zippy without
overtaxing individual relays.

These statistics are collected by a special subset of our directory authorites
called **bandwidth authorities**. See our `bandwidth file specification
<https://gitweb.torproject.org/torspec.git/tree/bandwidth-file-spec.txt>`_ for
details. Statistics are publicly available and generated each hour...

.. literalinclude:: /_static/example/bandwidth_stats.py
   :language: python

::

  % python bandwidth_stats.py

  Relay 6AD3EA55B87C80971F353EBA710F6550202A9355
    scanner = /scanner.5/scan-data/bws-59.4:60.1-done-2019-05-29-05:44:10
    measured_at = 1559123050
    pid_delta = -0.360692869958
    updated_at = 1559123050
    pid_error_sum = -0.178566523071
    nick = OrphanOrOften
    node_id = $6AD3EA55B87C80971F353EBA710F6550202A9355
    pid_bw = 538334
    bw = 538
    pid_error = -0.178566523071
    circ_fail = 0.0

  Relay 11B6727E38D249C83E20EEB0647BAD4FACECBEB6
    scanner = /scanner.8/scan-data/bws-92.4:93.1-done-2019-05-23-16:06:26
    measured_at = 1558641986
    pid_delta = 0.0352270644197
    updated_at = 1558641986
    pid_error_sum = -0.822158700788
    nick = snap269
    node_id = $11B6727E38D249C83E20EEB0647BAD4FACECBEB6
    pid_bw = 21124
    bw = 21
    pid_error = -0.822158700788
    circ_fail = 0.0

