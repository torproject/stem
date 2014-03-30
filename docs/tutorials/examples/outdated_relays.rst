List Outdated Relays
====================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Time marches on. Tor makes new releases, and at some point needs to drop
support for old ones. Below is the script we used on :trac:`9476` to reach out
to relay operators that needed to upgrade.

::

  from stem.descriptor.remote import DescriptorDownloader
  from stem.version import Version

  downloader = DescriptorDownloader()
  count, with_contact = 0, 0

  print "Checking for outdated relays..."
  print

  for desc in downloader.get_server_descriptors():
    if desc.tor_version < Version('0.2.3.0'):
      count += 1

      if desc.contact:
        print '  %-15s %s' % (desc.tor_version, desc.contact.decode("utf-8", "replace"))
        with_contact += 1

  print
  print "%i outdated relays found, %i had contact information" % (count, with_contact)

::

  % python outdated_relays.py
  Checking for outdated relays...

    0.2.2.39        Random Person admin@gtr-10.de
    0.2.2.36        dobrovich_psckaal at vietrievus dot ok
    0.2.2.39        anonymous6 anonymous@mailinator.com
    0.2.2.39        anonymous12 anonymous@mailinator.com
    ...

  316 outdated relays found, 120 had contact information

