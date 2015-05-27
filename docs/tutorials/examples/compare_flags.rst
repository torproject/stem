Comparing Directory Authority Flags
===================================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Compares the votes of two directory authorities, in this case moria1 and
maatuska, with a special interest in the 'Running' flag.

.. literalinclude:: /_static/example/compare_flags.py
   :language: python

::

  % python compare_flags.py 
  maatuska has the Running flag but moria1 doesn't: 92FCB6748A40E6088E22FBAB943AB2DD743EA818
  maatuska has the Running flag but moria1 doesn't: 6871F682350BA931838C0EC1E4A23044DAE06A73
  maatuska has the Running flag but moria1 doesn't: E2BB13AA2F6960CD93ABE5257A825687F3973C62
  moria1 has the Running flag but maatuska doesn't: 546C54E2A89D88E0794D04AECBF1AC8AC9DA81DE
  moria1 has the Running flag but maatuska doesn't: DCAEC3D069DC39AAE43D13C8AF31B5645E05ED61
  ...

