List Outdated Relays
====================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Time marches on. Tor makes new releases, and at some point needs to drop
support for old ones. Below is the script we used on :trac:`9476` to reach out
to relay operators that needed to upgrade.

.. literalinclude:: /_static/example/outdated_relays.py
   :language: python

::

  % python outdated_relays.py
  Checking for outdated relays...

    0.2.2.39        Random Person admin@gtr-10.de
    0.2.2.36        dobrovich_psckaal at vietrievus dot ok
    0.2.2.39        anonymous6 anonymous@mailinator.com
    0.2.2.39        anonymous12 anonymous@mailinator.com
    ...

  316 outdated relays found, 120 had contact information

