API
===

Types
-----

* `stem.exit_policy <types/exit_policy.html>`_ - Relay policy for the destinations it will or won't allow traffic to.
* `stem.version <types/version.html>`_ - Tor versions that can be compared to determine Tor's capablilites.

Descriptors
-----------

* **Classes**

 * `stem.descriptor <descriptor/descriptor.html>`_ - Base class for descriptors.
 * `stem.descriptor.server_descriptor <descriptor/server_descriptor.html>`_ - Relay and bridge server descriptors.
 * `stem.descriptor.extrainfo_descriptor <descriptor/extrainfo_descriptor.html>`_ - Relay and bridge extrainfo descriptors.
 * `stem.descriptor.networkstatus <descriptor/networkstatus.html>`_ - Network status documents which make up the Tor consensus.
 * `stem.descriptor.router_status_entry <descriptor/router_status_entry.html>`_ - Relay entries within a network status document.

* `stem.descriptor.reader <descriptor/reader.html>`_ - Reads and parses descriptor files from disk.
* `stem.descriptor.export <descriptor/export.html>`_ - Exports descriptors to other formats.

Utilities
---------

* `stem.util.conf <util/conf.html>`_ - Configuration file handling.
* `stem.util.connection <util/connection.html>`_ - Connection and IP related utilities.
* `stem.util.enum <util/enum.html>`_ - Enumeration class.
* `stem.util.log <util/log.html>`_ - Logging utilities.
* `stem.util.proc <util/proc.html>`_ - Tools to read a process' proc contents.
* `stem.util.str_tools <util/str_tools.html>`_ - String utilities.
* `stem.util.system <util/system.html>`_ - Tools related to the local system.
* `stem.util.term <util/term.html>`_ - Tools for interacting with the terminal.
* `stem.util.tor_tools <util/tor_tools.html>`_ - Helper functions for working with tor.

