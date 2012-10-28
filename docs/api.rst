API
===

Controller
----------

* **Core**

 * `stem.connection <api/connection.html>`_ - Connection and authentication to the Tor control port or socket.
 * `stem.socket <api/socket.html>`_ - Low level control socket used to talk with Tor.

* **Types**

 * `stem.exit_policy <api/exit_policy.html>`_ - Relay policy for the destinations it will or won't allow traffic to.
 * `stem.version <api/version.html>`_ - Tor versions that can be compared to determine Tor's capablilites.

Descriptors
-----------

* **Classes**

 * `stem.descriptor <api/descriptor/descriptor.html>`_ - Base class for descriptors.
 * `stem.descriptor.server_descriptor <api/descriptor/server_descriptor.html>`_ - Relay and bridge server descriptors.
 * `stem.descriptor.extrainfo_descriptor <api/descriptor/extrainfo_descriptor.html>`_ - Relay and bridge extrainfo descriptors.
 * `stem.descriptor.networkstatus <api/descriptor/networkstatus.html>`_ - Network status documents which make up the Tor consensus.
 * `stem.descriptor.router_status_entry <api/descriptor/router_status_entry.html>`_ - Relay entries within a network status document.

* `stem.descriptor.reader <api/descriptor/reader.html>`_ - Reads and parses descriptor files from disk.
* `stem.descriptor.export <api/descriptor/export.html>`_ - Exports descriptors to other formats.

Utilities
---------

* `stem.util.conf <api/util/conf.html>`_ - Configuration file handling.
* `stem.util.connection <api/util/connection.html>`_ - Connection and IP related utilities.
* `stem.util.enum <api/util/enum.html>`_ - Enumeration class.
* `stem.util.log <api/util/log.html>`_ - Logging utilities.
* `stem.util.proc <api/util/proc.html>`_ - Tools to read a process' proc contents.
* `stem.util.str_tools <api/util/str_tools.html>`_ - String utilities.
* `stem.util.system <api/util/system.html>`_ - Tools related to the local system.
* `stem.util.term <api/util/term.html>`_ - Tools for interacting with the terminal.
* `stem.util.tor_tools <api/util/tor_tools.html>`_ - Helper functions for working with tor.

