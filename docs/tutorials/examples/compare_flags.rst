Comparing Directory Authority Flags
===================================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Compares the votes of two directory authorities, in this case moria1 and
maatuska, with a special interest in the 'Running' flag.

::

  from stem.descriptor import DocumentHandler, remote

  # Query all authority votes asynchronously.

  downloader = remote.DescriptorDownloader(document_handler = DocumentHandler.DOCUMENT)
  queries = {}

  for name, authority in remote.get_authorities().items():
    if authority.v3ident is None:
      continue  # authority doens't vote if it lacks a v3ident

    queries[name] = downloader.get_vote(authority)

  # Wait for the votes to finish being downloaded, this produces a dictionary of
  # authority nicknames to their vote.

  votes = dict((name, query.run()[0]) for (name, query) in queries.items())

  # Get a superset of all the fingerprints in all the votes.

  all_fingerprints = set()

  for vote in votes.values():
    all_fingerprints.update(vote.routers.keys())

  # Finally, compare moria1's votes to maatuska.

  for fingerprint in all_fingerprints:
    moria1_vote = votes['moria1'].routers.get(fingerprint)
    maatuska_vote = votes['maatuska'].routers.get(fingerprint)

    if not moria1_vote and not maatuska_vote:
      print "both moria1 and maatuska haven't voted about %s" % fingerprint
    elif not moria1_vote:
      print "moria1 hasn't voted about %s" % fingerprint
    elif not maatuska_vote:
      print "maatuska hasn't voted about %s" % fingerprint
    elif 'Running' in moria1_vote.flags and 'Running' not in maatuska_vote.flags:
      print "moria1 has the Running flag but maatuska doesn't: %s" % fingerprint
    elif 'Running' in maatuska_vote.flags and 'Running' not in moria1_vote.flags:
      print "maatuska has the Running flag but moria1 doesn't: %s" % fingerprint

::

  % python compare_flags.py 
  maatuska has the Running flag but moria1 doesn't: 92FCB6748A40E6088E22FBAB943AB2DD743EA818
  maatuska has the Running flag but moria1 doesn't: 6871F682350BA931838C0EC1E4A23044DAE06A73
  maatuska has the Running flag but moria1 doesn't: E2BB13AA2F6960CD93ABE5257A825687F3973C62
  moria1 has the Running flag but maatuska doesn't: 546C54E2A89D88E0794D04AECBF1AC8AC9DA81DE
  moria1 has the Running flag but maatuska doesn't: DCAEC3D069DC39AAE43D13C8AF31B5645E05ED61
  ...

