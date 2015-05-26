from stem.descriptor import remote

# request votes from all the bandwidth authorities

queries = {}
downloader = remote.DescriptorDownloader()

for authority in remote.get_authorities().values():
  if authority.is_bandwidth_authority:
    queries[authority.nickname] = downloader.query(
      '/tor/status-vote/current/authority',
      endpoints = [(authority.address, authority.dir_port)],
    )

for authority_name, query in queries.items():
  try:
    print("Getting %s's vote from %s:" % (authority_name, query.download_url))

    measured, unmeasured = 0, 0

    for desc in query.run():
      if desc.measured:
        measured += 1
      else:
        unmeasured += 1

    print('  %i measured entries and %i unmeasured' % (measured, unmeasured))
  except Exception as exc:
    print("  failed to get the vote (%s)" % exc)
