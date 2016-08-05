Mirror Mirror on the Wall
=========================

The following is an overview of **Tor descriptors**. If you're already familiar
with what they are and where to get them then you may want to skip to the end.

* :ref:`what-is-a-descriptor`
* :ref:`where-do-descriptors-come-from`
* :ref:`where-can-i-get-the-current-descriptors`
* :ref:`where-can-i-get-past-descriptors`
* :ref:`can-i-get-descriptors-from-the-tor-process`
* :ref:`validating-the-descriptors-content`
* :ref:`saving-and-loading-descriptors`
* :ref:`putting-it-together`
* :ref:`are-there-any-other-parsing-libraries`

.. _what-is-a-descriptor:

What is a descriptor?
---------------------

Tor is made up of two parts: the application and a distributed network of a few
thousand volunteer relays. Information about these relays is public, and made
up of documents called **descriptors**.

There are several different kinds of descriptors, the most common ones being...

================================================================================ ===========
Descriptor Type                                                                  Description
================================================================================ ===========
`Server Descriptor <../api/descriptor/server_descriptor.html>`_                  Information that relays publish about themselves. Tor clients once downloaded this information, but now they use microdescriptors instead.
`ExtraInfo Descriptor <../api/descriptor/extrainfo_descriptor.html>`_            Relay information that Tor clients do not need in order to function. This is self-published, like server descriptors, but not downloaded by default.
`Microdescriptor <../api/descriptor/microdescriptor.html>`_                      Minimalistic document that just includes the information necessary for Tor clients to work.
`Network Status Document <../api/descriptor/networkstatus.html>`_                Though Tor relays are decentralized, the directories that track the overall network are not. These central points are called **directory authorities**, and every hour they publish a document called a **consensus** (aka, network status document). The consensus in turn is made up of **router status entries**.
`Router Status Entry <../api/descriptor/router_status_entry.html>`_              Relay information provided by the directory authorities including flags, heuristics used for relay selection, etc.
`Hidden Service Descriptor <../api/descriptor/hidden_service_descriptor.html>`_  Information pertaining to a `Hidden Service <https://www.torproject.org/docs/hidden-services.html.en>`_. These can only be `queried through the tor process <over_the_river.html#hidden-service-descriptors>`_.
================================================================================ ===========

.. _where-do-descriptors-come-from:

Where do descriptors come from?
-------------------------------

Descriptors fall into two camps:

* **Server**, **extra-info**, and **hidden service** descriptors are
  **self-published documents**. Relays and hidden services publish these about
  themselves, and so naturally can indicate anything they'd like in them (true
  or not).
  
  These are **self contained documents**, bundling within themselves a
  signiture Stem can `optionally check
  <./mirror_mirror_on_the_wall.html#validating-the-descriptors-content>`_.

* **Network status documents** (aka **votes**, the **consensus**, and **router
  status entries** they contain) are created by the **directory authorities**.
  For a great overview on how this works see `Jordan Wright's article on how
  the consensus is made
  <https://jordan-wright.github.io/blog/2015/05/14/how-tor-works-part-three-the-consensus/>`_.

**Microdescriptors** are merely a distilled copy of a **server descriptor**,
and so belong to the first camp.

.. _where-can-i-get-the-current-descriptors:

Where can I get the current descriptors?
----------------------------------------

To work Tor needs to have up-to-date information about relays within the
network. As such getting current descriptors is easy: *just download it like
Tor does*.

The `stem.descriptor.remote <../api/descriptor/remote.html>`_ module downloads
descriptors from the tor directory authorities and mirrors. **Please show
some restraint when doing this**! This adds load to the network, and hence an
irresponsible script can make Tor worse for everyone.

Listing the current relays in the Tor network is as easy as...

.. literalinclude:: /_static/example/current_descriptors.py
   :language: python

If you want to see what the raw descriptors look like you can also curl this
information from the DirPort of directory authorities and mirrors...

::

  % curl 128.31.0.34:9131/tor/server/all
  router Unnamed 83.227.81.207 9001 0 9030
  identity-ed25519
  -----BEGIN ED25519 CERT-----
  AQQABj3aAV7JzKHjSJjocve8jvnMwmy/Pv2HsSKoymeepddNBU5iAQAgBABw1VVB
  965QDxs+wicWj4vNXMKIkKCN4gQhvzqG2UxsgmkaQlsKiEMrIxrzwlazP6od9+hi
  WZKl3tshd0ekgUB6AAKwlvsrxl9wfy0G/Bf8PVsBftvNCWPwLR4pI3nibQU=
  -----END ED25519 CERT-----
  master-key-ed25519 cNVVQfeuUA8bPsInFo+LzVzCiJCgjeIEIb86htlMbII
  ...

.. _where-can-i-get-past-descriptors:

Where can I get past descriptors?
---------------------------------

Descriptor archives are available from `CollecTor
<https://collector.torproject.org/>`_. These archives can be read with
the `DescriptorReader <../api/descriptor/reader.html>`_...

.. literalinclude:: /_static/example/past_descriptors.py
   :language: python

.. _can-i-get-descriptors-from-the-tor-process:

Can I get descriptors from the Tor process?
-------------------------------------------

If you already have Tor running on your system then it is already downloading
descriptors on your behalf. Reusing these is a great way to keep from burdening
the rest of the Tor network.

Tor only gets the descriptors that it needs by default, so if you're scripting
against Tor you may want to set some of the following in your `torrc
<https://www.torproject.org/docs/faq.html.en#torrc>`_. Keep in mind that these
add a small burden to the network, so don't set them in a widely distributed
application. And, of course, please consider `running Tor as a relay
<https://www.torproject.org/docs/tor-doc-relay.html.en>`_ so you give back to
the network!

.. code-block:: lighttpd

  # Descriptors have a range of time during which they're valid. To get the
  # most recent descriptor information, regardless of if Tor needs it or not,
  # set the following.

  FetchDirInfoEarly 1
  FetchDirInfoExtraEarly 1

  # If you aren't actively using Tor as a client then Tor will eventually stop
  # downloading descriptor information that it doesn't need. To prevent this
  # from happening set...

  FetchUselessDescriptors 1

  # Tor no longer downloads server descriptors by default, opting for
  # microdescriptors instead. If you want Tor to download server descriptors
  # then set...

  UseMicrodescriptors 0

  # Tor doesn't need extrainfo descriptors to work. If you want Tor to download
  # them anyway then set...

  DownloadExtraInfo 1

Now that Tor is happy chugging along, up-to-date descriptors are available
through Tor's control socket...

.. literalinclude:: /_static/example/descriptor_from_tor_control_socket.py
   :language: python

... or by reading directly from Tor's data directory...

.. literalinclude:: /_static/example/descriptor_from_tor_data_directory.py
   :language: python

.. _validating-the-descriptors-content:

Validating the descriptor's content
-----------------------------------

Stem can optionally validate descriptors, checking their integrity and
compliance with Tor's specs. This does the following...

* Checks that we have mandatory fields, and that their content conforms with
  what Tor's spec says they should have. This can be useful when data
  integrity is important to you since it provides an upfront assurance that
  the descriptor's correct (no need for 'None' checks).

* If you have **pycrypto** we'll validate signatures for descriptor types
  where that has been implemented (such as server and hidden service
  descriptors).

Prior to Stem 1.4.0 descriptors were validated by default, but this has become
opt-in since then.

General rule of thumb: if *speed* is your chief concern then leave it off, but
if *correctness* or *signature validation* is important then turn it on.
Validating is as simple as including **validate = True** in any method that
provides descriptors...

.. literalinclude:: /_static/example/validate_descriptor_content.py
   :language: python

.. _saving-and-loading-descriptors:

Saving and loading descriptors
------------------------------

Tor descriptors are just plaintext documents. As such, if you'd rather not use
`Pickle <https://wiki.python.org/moin/UsingPickle>`_ you can persist a
descriptor by simply writing it to disk, then reading it back later.

.. literalinclude:: /_static/example/saving_and_loading_descriptors.py
   :language: python

Our *server_descriptors* here is a list of
:class:`~stem.descriptor.server_descriptor.RelayDescriptor` instances. When we
write it to a file this looks like...

::

  router default 68.229.17.182 443 0 9030 
  platform Tor 0.2.4.23 on Windows XP
  protocols Link 1 2 Circuit 1
  published 2014-11-17 23:42:38
  fingerprint EE04 42C3 6DB6 6903 0816 247F 2607 382A 0783 2D5A
  uptime 63
  bandwidth 5242880 10485760 77824
  extra-info-digest 1ABA9FC6B912E755483D0F4F6E9BC1B23A2B7206
  ... etc...

We can then read it back with :func:`~stem.descriptor.__init__.parse_file`
by telling it the type of descriptors we're reading...

.. literalinclude:: /_static/example/read_with_parse_file.py
   :language: python

For an example of doing this with a consensus document `see here
<examples/persisting_a_consensus.html>`_.

.. _putting-it-together:

Putting it together...
----------------------

As discussed above there are four methods for reading descriptors...

* Download descriptors directly with `stem.descriptor.remote <../api/descriptor/remote.html>`_.
* Read a single file with :func:`~stem.descriptor.__init__.parse_file`.
* Read multiple files or an archive with the `DescriptorReader <../api/descriptor/reader.html>`_.
* Requesting them from Tor with :class:`~stem.control.Controller` methods like :func:`~stem.control.Controller.get_server_descriptors` and :func:`~stem.control.Controller.get_network_statuses`.

Now lets say you want to figure out who the *biggest* exit relays are. You
could use any of the methods above, but for this example we'll use
`stem.descriptor.remote <../api/descriptor/remote.html>`_...

.. literalinclude:: /_static/example/tor_descriptors.py
   :language: python

::

  % python example.py
  1. herngaard (40.95 MB/s)
  2. chaoscomputerclub19 (40.43 MB/s)
  3. chaoscomputerclub18 (40.02 MB/s)
  4. chaoscomputerclub20 (38.98 MB/s)
  5. wannabe (38.63 MB/s)
  6. dorrisdeebrown (38.48 MB/s)
  7. manning2 (38.20 MB/s)
  8. chaoscomputerclub21 (36.90 MB/s)
  9. TorLand1 (36.22 MB/s)
  10. bolobolo1 (35.93 MB/s)
  11. manning1 (35.39 MB/s)
  12. gorz (34.10 MB/s)
  13. ndnr1 (25.36 MB/s)
  14. politkovskaja2 (24.93 MB/s)
  15. wau (24.72 MB/s)

.. _are-there-any-other-parsing-libraries:

Are there any other parsing libraries?
--------------------------------------

Yup! Stem isn't the only game in town when it comes to parsing. `Metrics-lib
<https://gitweb.torproject.org/metrics-lib.git/>`_ is a highly mature parsing
library for Java, and `Zoossh
<https://gitweb.torproject.org/user/phw/zoossh.git/>`_ is available for Go.
Each library has its own capabilities...

.. role:: red
.. role:: green

=========================== ===================== =================== ==============
Capability                  Stem                  Metrics-lib         Zoossh
=========================== ===================== =================== ==============
Language                    :green:`Python`       :green:`Java`       :green:`Go`
Checks signatures           :green:`Mostly`       :red:`No`           :red:`No`
Create new descriptors      :red:`No`             :red:`No`           :red:`No`
Lazy parsing                :green:`Yes`          :red:`No`           :green:`Yes`
Type detection by @type     :green:`Yes`          :green:`Yes`        :green:`Yes`
Type detection by filename  :green:`Yes`          :red:`No`           :red:`No`
Packages                    :green:`Several`      :red:`None`         :red:`None`
**Can Read/Download From**
Files                       :green:`Yes`          :green:`Yes`        :green:`Yes`
Tarballs                    :green:`Yes`          :green:`Yes`        :red:`No`
Tor Process                 :green:`Yes`          :red:`No`           :red:`No`
Directory Authorities       :green:`Yes`          :green:`Yes`        :red:`No`
CollecTor                   :red:`No`             :green:`Yes`        :red:`No`
**Supported Types**
Server Descriptors          :green:`Yes`          :green:`Yes`        :green:`Partly`
Extrainfo Descriptors       :green:`Yes`          :green:`Yes`        :red:`No`
Microdescriptors            :green:`Yes`          :green:`Yes`        :red:`No`
Consensus                   :green:`Yes`          :green:`Yes`        :green:`Partly`
Bridge Descriptors          :green:`Yes`          :green:`Yes`        :red:`No`
Hidden Service Descriptors  :green:`Yes`          :red:`No`           :red:`No`
Bridge Pool Assignments     :red:`No`             :green:`Yes`        :red:`No`
Torperf                     :red:`No`             :green:`Yes`        :red:`No`
Tordnsel                    :green:`Yes`          :green:`Yes`        :red:`No`
**Benchmarks**
Server Descriptors          :green:`0.60 ms`      :green:`0.29 ms`    :green:`0.46 ms`
Extrainfo Descriptors       :green:`0.40 ms`      :green:`0.22 ms`    :red:`unsupported`
Microdescriptors            :green:`0.33 ms`      :green:`0.07 ms`    :red:`unsupported`
Consensus                   :green:`865.72 ms`    :green:`246.71 ms`  :green:`83.00 ms`
Benchmarked With Commit     :green:`c01a9cd`      :green:`8767f3e`    :green:`2380e55`
Language Interpreter        :green:`Python 3.5.1` :green:`Java 1.7.0` :green:`Go 1.5.2`
=========================== ===================== =================== ==============

Few things to note about these benchmarks...

* **Zoossh is the fastest.** Its benchmarks were at a disadvantage due to not
  reading from tarballs.

* Your Python version makes a very large difference for Stem. For instance,
  with Python 2.7 reading a consensus takes **1,290.84 ms** (almost twice as
  long).

* Metrics-lib and Stem can both read from compressed tarballs at a small
  performance cost. For instance, Metrics-lib can read an `lzma compressed
  <../faq.html#how-do-i-read-tar-xz-descriptor-archives>`_ consensus in
  **255.76 ms** and Stem can do it in **902.75 ms**.

So what does code with each of these look like?

Stem Example
------------

* `Benchmark Script <../.../../_static/example/benchmark_stem.py>`_

.. literalinclude:: /_static/example/benchmark_server_descriptor_stem.py
   :language: python

Metrics-lib Example
-------------------

* `Benchmark Script <../.../../_static/example/benchmark_metrics_lib.java>`_

.. literalinclude:: /_static/example/benchmark_server_descriptor_metrics_lib.java
   :language: java

Zoossh Example
--------------

* `Benchmark Script <../.../../_static/example/benchmark_zoossh.go>`_

.. literalinclude:: /_static/example/benchmark_server_descriptor_zoossh.go
   :language: go
