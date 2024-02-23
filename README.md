# Stem Library Documentation

**Stem** is a Python controller library for **[Tor](https://www.torproject.org/)**, allowing you to interact with the Tor network. With Stem, you can use Tor's [control protocol](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt) to script against the Tor process and build applications with capabilities similar to [Nyx](https://nyx.torproject.org/). Stem's latest version is 1.8.1, released in September 2022.

For more detailed information, [tutorials](https://stem.torproject.org/tutorials.html), and examples, visit the [official Stem website](https://stem.torproject.org/index.html).

## Table of Contents
- [Getting Started](#getting-started)
- [API](#api)
- [Types](#types)
- [Descriptors](#descriptors)
- [Utilities](#utilities)
- [General Information](#general-information)
- [Development](#development)
- [FAQ](#faq)

---

## Getting Started

### Installation
Stem has minimal dependencies and only requires Python. If you need cryptography support for descriptor signature validation, you can install it separately. Make sure you have the required packages installed if you encounter issues during installation.

```bash
# Install cryptography (optional)
pip install cryptography

# On Debian and Ubuntu
sudo apt-get install python-dev libffi-dev
```

### Compatibility
Stem is compatible with Python 2.6 and greater, including the Python 3.x series.

### Connecting to Tor
You can connect to Tor's control interface directly using various methods. The details for connecting to Tor depend on the settings in your torrc file.

- If using a ControlPort, you can connect via Telnet.
- If using a ControlSocket, you can connect using `socat`.
- If using CookieAuthentication or HashedControlPassword, you can authenticate using the provided credentials.

For more information, refer to the [official Stem website](https://stem.torproject.org/index.html).

### Requesting a New Identity
To request a new identity from Tor, you can send the `NEWNYM` signal. You can do this using Telnet or Stem. Here's an example using Stem:

```python
from stem import Signal
from stem.control import Controller

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    controller.signal(Signal.NEWNYM)
```

### Reloading torrc
When you make changes to your torrc file, you can reload the configuration by sending a `HUP` signal to Tor. You can do this using Telnet or Stem. Here's an example using Stem:

```python
from stem import Signal
from stem.control import Controller

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    controller.signal(Signal.HUP)
```

---

## API

### Controller
- `stem.control` - Controller used to interact with Tor.

### Core
- `stem.connection` - Connection and authentication to the Tor control socket.
- `stem.socket` - Low-level control socket used to interact with Tor.
- `stem.process` - Launcher for the Tor process.
- `stem.response` - Messages that Tor may provide to the controller.

### Types
- `stem.exit_policy` - Relay policy for the destinations it will or won't allow traffic to.
- `stem.manual` - Information available about Tor from its manual.
- `stem.version` - Tor versions that can be compared to determine Tor's capabilities.

### Descriptors
- Use `stem.descriptor.reader` to read descriptors from disk for individual files and batches.
- Use `stem.descriptor.remote` to download descriptors remotely, similar to how Tor does.

#### Classes
- `stem.descriptor` - Base class for descriptors.
- `stem.descriptor.server_descriptor` - Relay and bridge server descriptors.
- `stem.descriptor.extrainfo_descriptor` - Relay and bridge extrainfo descriptors.
- `stem.descriptor.microdescriptor` - Minimalistic counterpart for server descriptors.
- `stem.descriptor.networkstatus` - Network status documents that make up the Tor consensus.
- `stem.descriptor.router_status_entry` - Relay entries within a network status document.
- `stem.descriptor.hidden_service` - Descriptors generated for hidden services.
- `stem.descriptor.bandwidth_file` - Bandwidth authority metrics.
- `stem.descriptor.tordnsel` - TorDNSEL exit lists.
- `stem.descriptor.certificate` - Ed25519 certificates.

#### Directory
- `stem.directory` - Directory authority and fallback directory information.

#### Reader
- `stem.descriptor.reader` - Reads and parses descriptor files from disk.

#### Remote
- `stem.descriptor.remote` - Downloads descriptors from directory mirrors and authorities.

#### Collector
- `stem.descriptor.collector` - Downloads past descriptors from CollecTor.

#### Export
- `stem.descriptor.export` - Exports descriptors to other formats.

---

## Utilities

- `stem.util.conf` - Configuration file handling.
- `stem.util.connection` - Connection and IP related utilities.
- `stem.util.enum` - Enumeration class.
- `stem.util.proc` - Resource and connection usage via proc contents.
- `stem.util.str_tools` - String utilities.
- `stem.util.system` - Tools related to the local system.
- `stem.util.term` - Tools for interacting with the terminal.
- `stem.util.test_tools` - Static analysis checks and tools to help with test runs.
- `stem.util.tor_tools` - Miscellaneous toolkit for working with Tor.

---

## General Information

### What is Stem?
Stem is a Python controller library for interacting with Tor. It allows you to write scripts and applications with capabilities similar to Nyx. Stem is a Python implementation of Tor's directory and control specifications.

### Dependencies
Stem has minimal dependencies. All you need to use Stem is Python. If you require cryptography for descriptor signature validation, you can install it separately. You may need additional packages for successful installation.

### Compatibility
Stem is compatible with Python 2.6 and greater, including the Python 3.x series.

### Interacting with Tor's Controller Interface
You can interact with Tor's controller interface directly, which is a great way to learn about its capabilities. The details for connecting to Tor depend on the ControlPort or ControlSocket settings in your torrc. You can use Telnet or Stem to interact with Tor's controller interface directly.

### Other Controller Libraries
There are other controller libraries available for interacting with Tor. Some alternatives to Stem include Txtorcon and TorCtl, which are written in Python. There are also libraries for other languages like PHP, Java, Go, and Rust.

### License
Stem is licensed under the LGPLv3.

### Where to Get Help
If you have questions or need assistance with Tor-related projects, you can find help on the tor-dev mailing list and IRC.

---

## Development

### Getting Started
To get started with Stem development, you can clone the Git repository and install the necessary test dependencies. You can contribute by working on open issues or new features. Follow these steps:

1. Clone the Git repository:
   ```
   git clone https://git.torproject.org/stem.git
   ```

2. Install test dependencies:
   ```
   sudo pip install mock pycodestyle pyflakes
   ```

3. Find an interesting bug or feature to work on.
4. When you have a contribution, set up a publicly accessible Stem repository (e.g., on GitHub).
5. File a Trac ticket with a short summary, a longer description, a link to your repository, and the appropriate type and priority.
6. The Stem maintainers will review your contribution, provide feedback, and work with you to ensure it aligns with the project's standards.
7. Once your contribution is approved, it will be merged into the official Stem repository.

### Running Tests
Stem includes three types of tests: unit tests, integration tests, and static tests.

- **Unit tests** provide good test coverage and are executed as follows:
   ```bash
   ~/stem$ ./run_tests.py --unit
   ```

- **Integration tests** run against a live Tor instance and check compatibility with new Tor releases. You need to have Tor installed. You can specify alternate Tor configurations using the `--target` argument.
   ```bash
   ~/stem$ ./run_tests.py --integ
   ~/stem$ ./run_tests.py --integ --tor /path/to/tor
   ~/stem$ ./run_tests.py --integ --target RUN_COOKIE
   ```

- **Static tests** use pyflakes for static error checking and pycodestyle for style checking. These tests run automatically as part of all test runs if you have the required tools installed.

For more details on running tests, refer to `run_tests.py --help`.

### Testing Compatibility with Multiple Python Versions
Stem supports Python 2.6 and above, including Python 3.x. To test compatibility with multiple Python versions, you can use `tox`. Install the required dependencies and run `tox` to test Stem with different Python versions installed on your system.

```bash
~/stem$ sudo apt-get install python-tox python2.7 python3.3 python-dev python3-dev
~/stem$ tox
```

You can also test specific Python versions and pass arguments to `run_tests.py` using `tox`.

### Building the Site
To build the Stem documentation, you need Sphinx version 1.1 or later. You can build the documentation as follows:

```bash
~$ cd stem/docs
~/stem/docs$ make html
```

After the documentation is built, you can access it by opening the generated HTML files in your browser.

### Copyright for Patches
Stem is under the LGPLv3 license, but if you submit a substantial patch, the Stem maintainers may ask if you are willing to put your contribution in the public domain. This allows for greater flexibility in sharing code across various projects without legal restrictions.

---

## FAQ
For answers to frequently asked questions and more general information about Stem, please refer to the [official Stem FAQ](https://stem.torproject.org/faq.html).

---

For detailed usage and examples, visit the official [Stem website](https://stem.torproject.org).

If you have questions or need further assistance with Stem, you can reach out to the Tor community on the tor-dev mailing list and IRC. 
Happy coding with Stem!
