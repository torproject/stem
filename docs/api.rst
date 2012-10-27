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

* **Utilities**
 * `stem.descriptor.reader <descriptor/reader.html>`_ - Reads and parses descriptor files from disk.
 * `stem.descriptor.export <descriptor/export.html>`_ - Exports descriptors to other formats.

