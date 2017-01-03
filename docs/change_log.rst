Change Log
==========

The following is a log of all user-facing changes to Stem, both released and
unreleased. For a monthly report on work being done see my `development log
<http://blog.atagar.com/>`_.

* :ref:`versioning`
* :ref:`unreleased`
* :ref:`version_1.4`
* :ref:`version_1.3`
* :ref:`version_1.2`
* :ref:`version_1.1`
* :ref:`version_1.0`

.. _versioning:

Versioning
----------

Stem uses `semantic versioning <http://semver.org/>`_, which means that
**versions consist of three numbers** (such as '**1.2.4**'). These are used to
convey the kind of backward compatibility a release has...

 * The first value is the **major version**. This changes infrequently, and
   indicates that backward incompatible changes have been made (such as the
   removal of deprecated functions).

 * The second value is the **minor version**. This is the most common kind of
   release, and denotes that the improvements are backward compatible.

 * The third value is the **patch version**. When a Stem release has a major
   issue another release is made which fixes just that problem. These do not
   contain substantial improvements or new features. This value is sometimes
   left off to indicate all releases with a given major/minor version.

.. _unreleased:

Unreleased
----------

The following are only available within Stem's `git repository
<download.html>`_.

 * **Controller**

  * Dramatic, `300x performance improvement <https://github.com/DonnchaC/stem/pull/1>`_ for reading from the control port with python 3
  * Added `stem.manual <api/manual.html>`_, which provides information available about Tor from `its manual <https://www.torproject.org/docs/tor-manual.html.en>`_ (:trac:`8251`)
  * :func:`~stem.connection.connect` and :func:`~stem.control.Controller.from_port` now connect to both port 9051 (relay's default) and 9151 (Tor Browser's default) (:trac:`16075`)
  * :class:`~stem.exit_policy.ExitPolicy` support for *accept6/reject6* and *\*4/6* wildcards (:trac:`16053`)
  * Added `support for NETWORK_LIVENESS events <api/response.html#stem.response.events.NetworkLivenessEvent>`_ (:spec:`44aac63`)
  * Added support for basic authentication to :func:`~stem.control.Controller.create_ephemeral_hidden_service` (:spec:`c2865d9`)
  * Added support for non-anonymous services to :func:`~stem.control.Controller.create_ephemeral_hidden_service` (:spec:`b8fe774`)
  * Added :func:`~stem.control.event_description` for getting human-friendly descriptions of tor events (:trac:`19061`)
  * Added :func:`~stem.control.Controller.reconnect` to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.is_set` to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.is_user_traffic_allowed` to the :class:`~stem.control.Controller`
  * Added the replica attribute to the :class:`~stem.response.events.HSDescEvent` (:spec:`4989e73`)
  * Added the NoEdConsensus :data:`~stem.Flag` (:spec:`dc99160`)
  * Recognize listeners with IPv6 addresses in :func:`~stem.control.Controller.get_listeners`
  * :func:`~stem.process.launch_tor` could leave a lingering process during an unexpected exception (:trac:`17946`)
  * IPv6 addresses could trigger errors in :func:`~stem.control.Controller.get_listeners`, :class:`~stem.response.events.ORConnEvent`, and quite a few other things (:trac:`16174`)
  * Don't obscure stacktraces, most notably :class:`~stem.control.Controller` getter methods with default values
  * Classes with custom equality checks didn't provide a corresponding inequality method

 * **Descriptors**

  * `Shorthand functions for stem.descriptor.remote <api/descriptor/remote.html#stem.descriptor.remote.get_instance>`_
  * Added `fallback directory information <api/descriptor/remote.html#stem.descriptor.remote.FallbackDirectory>`_.
  * Support for ed25519 descriptor fields (:spec:`5a79d67`)
  * Support downloading microdescriptor consensus with :func:~stem.descriptor.remote.DescriptorDownloader.get_consensus` (:spec`e788b8f`)
  * Added consensus and vote's new shared randomness attributes (:spec:`9949f64`) 
  * Added server descriptor's new allow_tunneled_dir_requests attribute (:spec:`8bc30d6`)
  * Server descriptor validation fails with 'extra-info-digest line had an invalid value' from additions in proposal 228 (:trac:`16227`)
  * :class:`~stem.descriptor.server_descriptor.BridgeDescriptor` now has 'ntor_onion_key' like its unsanitized counterparts
  * Replaced the :class:`~stem.descriptor.microdescriptor.Microdescriptor` identifier and identifier_type attributes with an identifiers hash since it can now appear multiple times (:spec:`09ff9e2`)
  * Unable to read descriptors from data directories on Windows due to their CRLF newlines (:trac:`17051`)
  * TypeError under python3 when using 'use_mirrors = True' (:trac:`17083`)
  * Deprecated hidden service descriptor's *introduction_points_auth* field, which was never implemented in tor (:trac:`15190`, :spec:`9c218f9`)
  * Deprecated :func:`~stem.descriptor.remote.DescriptorDownloader.get_microdescriptors` as it was never implemented in tor (:trac:`9271`)
  * :func:`~stem.control.Controller.get_hidden_service_descriptor` errored when provided a *servers* argument (:trac:`18401`)
  * Fixed parsing of server descriptor's *allow-single-hop-exits* and *caches-extra-info* lines
  * Bracketed IPv6 addresses were mistreated as being invalid content
  * Better validation for non-ascii descriptor content
  * Updated dannenberg's v3ident (:trac:`17906`)
  * Removed urras as a directory authority (:trac:`19271`)

 * **Utilities**

  * IPv6 support in :func:`~stem.util.connection.get_connections` when resolving with proc, netstat, lsof, or ss (:trac:`18079`)
  * The 'ss' connection resolver didn't work on Gentoo (:trac:`18079`)
  * Recognize IPv4-mapped IPv6 addresses in our utils (:trac:`18079`)
  * Allow :func:`stem.util.conf.Config.set` to remove values when provided with a **None** value
  * Support prefix and suffix issue strings in :func:`~stem.util.test_tools.pyflakes_issues`
  * Additional information when :func:`~stem.util.system.call` fails through a :class:`~stem.util.system.CallError`
  * Added **stem.util.system.SYSTEM_CALL_TIME** with the total time spent on system calls
  * Added an **is_ipv6** value to :class:`~stem.util.connection.Connection` instances
  * Added LINES attribute to :data:`~stem.util.term.Attr`
  * Added :func:`~stem.util.system.pids_by_user`
  * Added :func:`~stem.util.connection.address_to_int`
  * Added :func:`~stem.util.term.encoding`
  * Added :func:`~stem.util.__init__.datetime_to_unix`

 * **Interpreter**

  * Added a '--tor [path]' argument to specify the tor binary to run.

 * **Website**

  * `Comparison of our descriptor parsing libraries <tutorials/mirror_mirror_on_the_wall.html#are-there-any-other-parsing-libraries>`_
  * Example for `custom path selection for circuits <tutorials/to_russia_with_love.html#custom-path-selection>`_ (:trac:`8728`)
  * Example for `persisting ephemeral hidden service keys <tutorials/over_the_river.html#ephemeral-hidden-services>`_

 * **Version 1.5.3** (December 5th, 2016) - including tests and site in the
   release tarball

 * **Version 1.5.4** (January 4th, 2017) - drop validation of the order of
   fields in the tor consensus (:trac:`21059`)

.. _version_1.4:

Version 1.4 (May 13th, 2015)
----------------------------

`Stem's 1.4 release <https://blog.torproject.org/blog/stem-release-14>`_ brings
with it new hidden service capabilities. Most notably, `ephemeral hidden
services <tutorials/over_the_river.html#ephemeral-hidden-services>`_ and the
ability to `read hidden service descriptors
<tutorials/over_the_river.html#hidden-service-descriptors>`_. This release also
changes descriptor validation to now be opt-in rather than opt-out. When
unvalidated content is lazy-loaded, `greatly improving our performance
<https://lists.torproject.org/pipermail/tor-dev/2015-January/008211.html>`_.

And last, Stem also now runs directly under both python2 and python3 without a
2to3 conversion (:trac:`14075`)!

 * **Controller**

  * Added :class:`~stem.control.Controller` methods for a new style of hidden services that don't touch disk: :func:`~stem.control.Controller.list_ephemeral_hidden_services`, :func:`~stem.control.Controller.create_ephemeral_hidden_service`, and :func:`~stem.control.Controller.remove_ephemeral_hidden_service` (:spec:`f5ff369`)
  * Added :func:`~stem.control.Controller.get_hidden_service_descriptor` and `support for HS_DESC_CONTENT events <api/response.html#stem.response.events.HSDescContentEvent>`_ (:trac:`14847`, :spec:`aaf2434`)
  * :func:`~stem.process.launch_tor_with_config` avoids writing a temporary torrc to disk if able (:trac:`13865`)
  * :class:`~stem.response.events.CircuitEvent` support for the new SOCKS_USERNAME and SOCKS_PASSWORD arguments (:trac:`14555`, :spec:`2975974`)
  * The 'strict' argument of :func:`~stem.exit_policy.ExitPolicy.can_exit_to` didn't behave as documented (:trac:`14314`)
  * Threads spawned for status change listeners were never joined on, potentially causing noise during interpreter shutdown
  * Added support for specifying the authentication type and client names in :func:`~stem.control.Controller.create_hidden_service` (:trac:`14320`)

 * **Descriptors**

  * Lazy-loading descriptors, improving performance by 25-70% depending on what type it is (:trac:`14011`)
  * Added `support for hidden service descriptors <api/descriptor/hidden_service_descriptor.html>`_ (:trac:`15004`)
  * When reading sanitised bridge descriptors (server or extrainfo), :func:`~stem.descriptor.__init__.parse_file` treated the whole file as a single descriptor
  * The :class:`~stem.descriptor.networkstatus.DirectoryAuthority` 'fingerprint' attribute was actually its 'v3ident'
  * Added consensus' new package attribute (:spec:`ab64534`)
  * Added extra info' new hs_stats_end, hs_rend_cells, hs_rend_cells_attr, hs_dir_onions_seen, and hs_dir_onions_seen_attr attributes (:spec:`ddb630d`)
  * Updating Faravahar's address (:trac:`14487`)

 * **Utilities**

  * Windows support for connection resolution (:trac:`14844`)
  * :func:`stem.util.connection.port_usage` always returned None (:trac:`14046`)
  * :func:`~stem.util.test_tools.stylistic_issues` and :func:`~stem.util.test_tools.pyflakes_issues` now provide namedtuples that also includes the line
  * Added :func:`stem.util.system.tail`
  * Proc connection resolution could fail on especially busy systems (:trac:`14048`)

 * **Website**

  * Added support and `instructions for tox <faq.html#how-do-i-test-compatibility-with-multiple-python-versions>`_ (:trac:`14091`)
  * Added OSX to our `download page <download.html>`_ (:trac:`8588`)
  * Updated our twitter example to work with the service's 1.1 API (:trac:`9003`)

 * **Version 1.4.1** (May 18th, 2015) - fixed issue where descriptors couldn't
   be unpickled (:trac:`16054`) and a parsing issue for router status entry
   bandwidth lines (:trac:`16048`)

.. _version_1.3:

Version 1.3 (December 22nd, 2014)
---------------------------------

With `Stem's 1.3 release <https://blog.torproject.org/blog/stem-release-13>`_
it's now much easier to `work with hidden services
<tutorials/over_the_river.html>`_, 40% faster to read decriptors, and includes
a myriad of other improvements. For a nice description of the changes this
brings see `Nathan Willis' LWN article <http://lwn.net/Articles/632914/>`_.

 * **Controller**

  * Added :class:`~stem.control.Controller` methods to more easily work with hidden service configurations: :func:`~stem.control.Controller.get_hidden_service_conf`, :func:`~stem.control.Controller.set_hidden_service_conf`, :func:`~stem.control.Controller.create_hidden_service`, and :func:`~stem.control.Controller.remove_hidden_service` (:trac:`12533`)
  * Added :func:`~stem.control.Controller.get_accounting_stats` to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.get_effective_rate` to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.BaseController.connection_time` to the :class:`~stem.control.BaseController`
  * Changed :func:`~stem.control.Controller.get_microdescriptor`, :func:`~stem.control.Controller.get_server_descriptor`, and :func:`~stem.control.Controller.get_network_status` to get our own descriptor if no fingerprint or nickname is provided.
  * Added :class:`~stem.exit_policy.ExitPolicy` methods for more easily handling 'private' policies (the `default prefix <https://www.torproject.org/docs/tor-manual.html.en#ExitPolicyRejectPrivate>`_) and the defaultly appended suffix. This includes :func:`~stem.exit_policy.ExitPolicy.has_private`, :func:`~stem.exit_policy.ExitPolicy.strip_private`, :func:`~stem.exit_policy.ExitPolicy.has_default`, and :func:`~stem.exit_policy.ExitPolicy.strip_default` :class:`~stem.exit_policy.ExitPolicy` methods in addition to :func:`~stem.exit_policy.ExitPolicyRule.is_private` and :func:`~stem.exit_policy.ExitPolicyRule.is_default` for the :class:`~stem.exit_policy.ExitPolicyRule`. (:trac:`10107`)
  * Added the reason attribute to the :class:`~stem.response.events.HSDescEvent` (:spec:`7908c8d`)
  * :func:`~stem.process.launch_tor_with_config` could cause a "Too many open files" OSError if called too many times (:trac:`13141`)
  * The :func:`~stem.control.Controller.get_exit_policy` method errored if tor couldn't determine our external address
  * The Controller's methods for retrieving descriptors could raise unexpected ValueErrors if tor didn't have any descriptors available
  * Throwing a new :class:`~stem.DescriptorUnavailable` exception type when the :class:`~stem.control.Controller` can't provide the descriptor for a relay (:trac:`13879`)

 * **Descriptors**

  * Improved speed for parsing consensus documents by around 40% (:trac:`12859` and :trac:`13821`)
  * Don't fail if consensus method 1 is not present, as it is no longer required (:spec:`fc8a6f0`)
  * Include '\*.new' files when reading from a Tor data directory (:trac:`13756`)
  * Updated the authorities we list, `replacing turtles with longclaw <https://lists.torproject.org/pipermail/tor-talk/2014-November/035650.html>`_ and `updating gabelmoo's address <https://lists.torproject.org/pipermail/tor-talk/2014-September/034898.html>`_
  * Noting if authorities are also a bandwidth authority or not
  * Microdescriptor validation issues could result in an AttributeError (:trac:`13904`)

 * **Utilities**

  * Added support for directories to :func:`stem.util.conf.Config.load`
  * Changed :func:`stem.util.conf.uses_settings` to only provide a 'config' keyword arument if the decorated function would accept it
  * Added :func:`stem.util.str_tools.crop`
  * Added :func:`stem.util.proc.file_descriptors_used`
  * Dropped the 'get_*' prefix from most function names. Old names will still work, but are a deprecated alias.

 * **Interpreter**

  * The /info command errored for relays without contact information

 * **Website**

  * Tutorial for `hidden services <tutorials/over_the_river.html>`_
  * Example for `writing descriptors to disk and reading them back <tutorials/mirror_mirror_on_the_wall.html#saving-and-loading-descriptors>`_ (:trac:`13774`)
  * Added Gentoo to our `download page <download.html>`_ and handful of testing revisions for that platform (:trac:`13904`)
  * Tests for our tutorial examples (:trac:`11335`)
  * Revised `GitWeb <https://gitweb.torproject.org/>`_ urls to work after its upgrade

.. _version_1.2:

Version 1.2 (June 1st, 2014)
----------------------------

`Stem release 1.2 <https://blog.torproject.org/blog/stem-release-12>`_
added our `interactive Tor interpreter <tutorials/down_the_rabbit_hole.html>`_
among numerous other improvements and fixes.

 * **Controller**

  * New, better :func:`~stem.connection.connect` function that deprecates :func:`~stem.connection.connect_port` and :func:`~stem.connection.connect_socket_file`
  * Added :func:`~stem.control.Controller.is_newnym_available` and :func:`~stem.control.Controller.get_newnym_wait` methods to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.get_ports` and :func:`~stem.control.Controller.get_listeners` methods to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.drop_guards` (:trac:`10032`, :spec:`7c6c7fc`)
  * Added the id attribute to the :class:`~stem.response.events.ORConnEvent` (:spec:`6f2919a`)
  * Added `support for CONN_BW events <api/response.html#stem.response.events.ConnectionBandwidthEvent>`_ (:spec:`6f2919a`)
  * Added `support for CIRC_BW events <api/response.html#stem.response.events.CircuitBandwidthEvent>`_ (:spec:`6f2919a`)
  * Added `support for CELL_STATS events <api/response.html#stem.response.events.CellStatsEvent>`_ (:spec:`6f2919a`)
  * Added `support for TB_EMPTY events <api/response.html#stem.response.events.TokenBucketEmptyEvent>`_ (:spec:`6f2919a`)
  * Added `support for HS_DESC events <api/response.html#stem.response.events.HSDescEvent>`_ (:trac:`10807`, :spec:`a67ac4d`)
  * Changed :func:`~stem.control.Controller.get_network_status` and :func:`~stem.control.Controller.get_network_statuses` to provide :class:`~stem.descriptor.router_status_entry.RouterStatusEntryMicroV3` if Tor is using microdescriptors (:trac:`7646`)
  * The :func:`~stem.connection.connect_port` and :func:`~stem.connection.connect_socket_file` didn't properly mark the Controller it returned as being authenticated, causing event listening among other things to fail
  * The :func:`~stem.control.Controller.add_event_listener` method couldn't accept event types that Stem didn't already recognize
  * The :class:`~stem.exit_policy.ExitPolicy` class couldn't be pickled
  * Tor instances spawned with :func:`~stem.process.launch_tor` and :func:`~stem.process.launch_tor_with_config` could hang due to unread stdout content, we now close stdout and stderr once tor finishes bootstrapping (:trac:`9862`)

 * **Descriptors**

  * Added tarfile support to :func:`~stem.descriptor.__init__.parse_file` (:trac:`10977`)
  * Added microdescriptor's new identifier and identifier_type attributes (:spec:`22cda72`)

 * **Utilities**

  * Added the `stem.util.test_tools <api/util/test_tools.html>`_ module
  * Started vending the `stem.util.tor_tools <api/util/tor_tools.html>`_ module
  * Added :func:`stem.util.connection.port_usage`
  * Added :func:`stem.util.system.files_with_suffix`

 * **Interpreter**

  * Initial release of our `interactive Tor interpreter <tutorials/down_the_rabbit_hole.html>`_!

 * **Website**

  * Added a section with `example scripts <tutorials/double_double_toil_and_trouble.html#scripts>`_.
  * Made FAQ and other sections quite a bit more succinct.

 * **Version 1.2.2** (June 7th, 2014) - fixed an issue where the stem.util.conf
   module would fail under Python 2.6 with an AttributeError (:trac:`12223`)

 * **Version 1.2.1** (June 3rd, 2014) - fixed an issue where descriptor
   parsersing would fail under Python 3.x with a TypeError (:trac:`12185`)

.. _version_1.1:

Version 1.1 (October 14th, 2013)
--------------------------------

`Stem release 1.1 <https://blog.torproject.org/blog/stem-release-11>`_
introduced `remote descriptor fetching <api/descriptor/remote.html>`_,
`connection resolution <tutorials/east_of_the_sun.html#connection-resolution>`_
and a myriad of smaller improvements and fixes.

 * **Controller**

  * :func:`~stem.control.Controller.get_network_status` and :func:`~stem.control.Controller.get_network_statuses` now provide v3 rather than v2 directory information (:trac:`7953`, :spec:`d2b7ebb`)
  * :class:`~stem.response.events.AddrMapEvent` support for the new CACHED argument (:trac:`8596`, :spec:`25b0d43`)
  * :func:`~stem.control.Controller.attach_stream` could encounter an undocumented 555 response (:trac:`8701`, :spec:`7286576`)
  * :class:`~stem.descriptor.server_descriptor.RelayDescriptor` digest validation was broken when dealing with non-unicode content with Python 3 (:trac:`8755`)
  * The :class:`~stem.control.Controller` use of cached content wasn't thread safe (:trac:`8607`)
  * Added :func:`~stem.control.Controller.get_user` method to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.get_pid` method to the :class:`~stem.control.Controller`
  * :class:`~stem.response.events.StreamEvent` didn't recognize IPv6 addresses (:trac:`9181`)
  * :func:`~stem.control.Controller.get_conf` mistakenly cached hidden service related options (:trac:`9792`)
  * Added `support for TRANSPORT_LAUNCHED events <api/response.html#stem.response.events.TransportLaunchedEvent>`_ (:spec:`48f6dd0`)

 * **Descriptors**

  * Added the `stem.descriptor.remote <api/descriptor/remote.html>`_ module.
  * Added support for `TorDNSEL exit lists <api/descriptor/tordnsel.html>`_ (:trac:`8255`)
  * The :class:`~stem.descriptor.reader.DescriptorReader` mishandled relative paths (:trac:`8815`)

 * **Utilities**

  * Connection resolution via the :func:`~stem.util.connection.get_connections` function (:trac:`7910`)
  * :func:`~stem.util.system.set_process_name` inserted spaces between characters (:trac:`8631`)
  * :func:`~stem.util.system.pid_by_name` can now pull for all processes with a given name
  * :func:`~stem.util.system.call` ignored the subprocess' exit status
  * Added :func:`stem.util.system.name_by_pid`
  * Added :func:`stem.util.system.user`
  * Added :func:`stem.util.system.start_time`
  * Added :func:`stem.util.system.bsd_jail_path`
  * Added :func:`stem.util.system.is_tarfile`
  * Added :func:`stem.util.connection.is_private_address`

 * **Website**

  * Overhaul of Stem's `download page <download.html>`_. This included several
    improvements, most notably the addition of PyPI, Ubuntu, Fedora, Slackware,
    and FreeBSD.
  * Replaced default sphinx header with a navbar menu.
  * Added this change log.
  * Added the `FAQ page <faq.html>`_.
  * Settled on a `logo
    <http://www.wpclipart.com/plants/assorted/P/plant_stem.png.html>`_ for
    Stem.
  * Expanded the `client usage tutorial <tutorials/to_russia_with_love.html>`_
    to cover SocksiPy and include an example for polling Twitter.
  * Subtler buttons for the frontpage (`before
    <https://www.atagar.com/transfer/stem_frontpage/before.png>`_ and `after
    <https://www.atagar.com/transfer/stem_frontpage/after.png>`_).

 * **Version 1.1.1** (November 9th, 2013) - fixed an issue where imports of stem.util.system
   would fail with an ImportError for pwd under Windows (:trac:`10072`)

.. _version_1.0:

Version 1.0 (March 26th, 2013)
------------------------------

This was the `initial release of Stem
<https://blog.torproject.org/blog/stem-release-10>`_.

 * **Version 1.0.1** (March 27th, 2013) - fixed an issue where installing with
   Python 3.x (python3 setup.py install) resulted in a stacktrace

