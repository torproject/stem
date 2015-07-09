from collections import OrderedDict
from stem.descriptor import DocumentHandler, remote

# Query all authority votes asynchronously.

downloader = remote.DescriptorDownloader(document_handler=DocumentHandler.DOCUMENT)

# An ordered dictionary ensures queries are finished in the order they were
# added.

queries = OrderedDict()

for name, authority in remote.get_authorities().items():
  if authority.v3ident is None:
    continue  # authority doesn't vote if it lacks a v3ident

  queries[name] = downloader.get_vote(authority)

# Wait for the votes to finish being downloaded, this produces a dictionary of
# authority nicknames to their vote.

votes = dict((name, query.run()[0]) for (name, query) in queries.items())

# Get a superset of all the fingerprints in all the votes.

all_fingerprints = set()

for vote in votes.values():
  all_fingerprints.update(vote.routers.keys())

# Finally, compare moria1's votes to maatuska's votes.

for fingerprint in all_fingerprints:
  moria1_vote = votes['moria1'].routers.get(fingerprint)
  maatuska_vote = votes['maatuska'].routers.get(fingerprint)

  if not moria1_vote and not maatuska_vote:
    print("both moria1 and maatuska haven't voted about %s" % fingerprint)
  elif not moria1_vote:
    print("moria1 hasn't voted about %s" % fingerprint)
  elif not maatuska_vote:
    print("maatuska hasn't voted about %s" % fingerprint)
  elif 'Running' in moria1_vote.flags and 'Running' not in maatuska_vote.flags:
    print("moria1 has the Running flag but maatuska doesn't: %s" % fingerprint)
  elif 'Running' in maatuska_vote.flags and 'Running' not in moria1_vote.flags:
    print("maatuska has the Running flag but moria1 doesn't: %s" % fingerprint)
