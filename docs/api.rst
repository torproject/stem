API
===

Controller
----------

* **Core**

 * `stem.control <api/control.html>`_ - **Controller used to talk with Tor**.
 * `stem.connection <api/connection.html>`_ - Connection and authentication to the Tor control socket.
 * `stem.socket <api/socket.html>`_ - Low level control socket used to talk with Tor.
 * `stem.process <api/process.html>`_ - Launcher for the Tor process.
 * `stem.response <api/response.html>`_ - Messages that Tor may provide the controller.

* **Types**

 * `stem.exit_policy <api/exit_policy.html>`_ - Relay policy for the destinations it will or won't allow traffic to.
 * `stem.manual <api/manual.html>`_ - Information available about Tor from `its manual <https://www.torproject.org/docs/tor-manual.html.en>`_.
 * `stem.version <api/version.html>`_ - Tor versions that can be compared to determine Tor's capabilities.

Descriptors
-----------

To read descriptors from disk use :func:`~stem.descriptor.__init__.parse_file` for
individual files and `stem.descriptor.reader
<api/descriptor/reader.html>`_ for batches. You can also use
`stem.descriptor.remote <api/descriptor/remote.html>`_ to download descriptors
remotely like Tor does.

* **Classes**

 * `stem.descriptor <api/descriptor/descriptor.html>`_ - Base class for descriptors.
 * `stem.descriptor.server_descriptor <api/descriptor/server_descriptor.html>`_ - Relay and bridge server descriptors.
 * `stem.descriptor.extrainfo_descriptor <api/descriptor/extrainfo_descriptor.html>`_ - Relay and bridge extrainfo descriptors.
 * `stem.descriptor.microdescriptor <api/descriptor/microdescriptor.html>`_ - Minimalistic counterpart for server descriptors.
 * `stem.descriptor.networkstatus <api/descriptor/networkstatus.html>`_ - Network status documents which make up the Tor consensus.
 * `stem.descriptor.router_status_entry <api/descriptor/router_status_entry.html>`_ - Relay entries within a network status document.
 * `stem.descriptor.hidden_service_descriptor <api/descriptor/hidden_service_descriptor.html>`_ - Descriptors generated for hidden services.
 * `stem.descriptor.tordnsel <api/descriptor/tordnsel.html>`_ - `TorDNSEL <https://www.torproject.org/projects/tordnsel.html.en>`_ exit lists.

* `stem.descriptor.reader <api/descriptor/reader.html>`_ - Reads and parses descriptor files from disk.
* `stem.descriptor.remote <api/descriptor/remote.html>`_ - Downloads descriptors from directory mirrors and authorities.
* `stem.descriptor.export <api/descriptor/export.html>`_ - Exports descriptors to other formats.

Utilities
---------

* `stem.util.conf <api/util/conf.html>`_ - Configuration file handling.
* `stem.util.connection <api/util/connection.html>`_ - Connection and IP related utilities.
* `stem.util.enum <api/util/enum.html>`_ - Enumeration class.
* `stem.util.str_tools <api/util/str_tools.html>`_ - String utilities.
* `stem.util.system <api/util/system.html>`_ - Tools related to the local system.
* `stem.util.term <api/util/term.html>`_ - Tools for interacting with the terminal.
* `stem.util.test_tools <api/util/test_tools.html>`_ - Static analysis checks and tools to help with test runs.
* `stem.util.tor_tools <api/util/tor_tools.html>`_ - Miscellaneous toolkit for working with tor.

