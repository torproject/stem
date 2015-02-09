Votes by Bandwidth Authorities
==============================

.. image:: /_static/buttons/back.png
   :target: ../double_double_toil_and_trouble.html

Tor takes into account a relay's throughput when picking a route through the
Tor network for its circuits. That is to say large, fast relays receive more
traffic than small ones since they can better service the load.

To determine a relay's throughput special authorities, called **bandwidth
authorities**, take periodic measurements using them. The `lifecycle of new Tor
relays <https://blog.torproject.org/blog/lifecycle-of-a-new-relay>`_ is a bit
more complicated than that, but that's the general idea.

Bandwidth authorities include their measurements in their votes. The following
gets their current votes then prints how many relays it had a measurement for.

::

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
      print "Getting %s's vote from %s:" % (authority_name, query.download_url)

      measured, unmeasured = 0, 0

      for desc in query.run():
        if desc.measured:
          measured += 1
        else:
          unmeasured += 1

      print '  %i measured entries and %i unmeasured' % (measured, unmeasured)
    except Exception as exc:
      print "  failed to get the vote (%s)" % exc 

::

  % python bandwidth_auth_measured_counts.py
  Getting gabelmoo's vote from http://131.188.40.189:80/tor/status-vote/current/authority:
    5935 measured entries and 1332 unmeasured
  Getting tor26's vote from http://86.59.21.38:80/tor/status-vote/current/authority:
    5735 measured entries and 1690 unmeasured
  Getting moria1's vote from http://128.31.0.39:9131/tor/status-vote/current/authority:
    6647 measured entries and 625 unmeasured
  Getting maatuska's vote from http://171.25.193.9:443/tor/status-vote/current/authority:
    6313 measured entries and 1112 unmeasured

