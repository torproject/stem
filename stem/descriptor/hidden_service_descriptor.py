# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor hidden service descriptors as described in Tor's `rend-spec
<https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt>`_.

Unlike other descriptor types these describe a hidden service rather than a
relay. They're created by the service, and can only be fetched via relays with
the HSDir flag.

**Module Overview:**

::

  HiddenServiceDescriptor - Tor hidden service descriptor.
"""

# TODO: Add a description for how to retrieve them when tor supports that (#14847).

# TODO: We should add a '@type hidden-service-descriptor 1.0' annotation to
# CollecTor...
#
# https://collector.torproject.org/formats.html

from stem.descriptor import (
  PGP_BLOCK_END,
  Descriptor,
  _get_descriptor_components,
  _read_until_keywords,
  _value,
  _parse_simple_line,
  _parse_timestamp_line,
  _parse_key_block,
)

REQUIRED_FIELDS = (
  'rendezvous-service-descriptor',
  'version',
  'permanent-key',
  'secret-id-part',
  'publication-time',
  'protocol-versions',
  'signature',
)


def _parse_file(descriptor_file, validate = False, **kwargs):
  """
  Iterates over the hidden service descriptors in a file.

  :param file descriptor_file: file with descriptor content
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: iterator for :class:`~stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor`
    instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  while True:
    descriptor_content = _read_until_keywords('signature', descriptor_file)

    # we've reached the 'signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    descriptor_content += _read_until_keywords(block_end_prefix, descriptor_file, True)

    if descriptor_content:
      if descriptor_content[0].startswith(b'@type'):
        descriptor_content = descriptor_content[1:]

      yield HiddenServiceDescriptor(bytes.join(b'', descriptor_content), validate, **kwargs)
    else:
      break  # done parsing file


# TODO: For the 'version' and 'protocol-versions' lines should they be ints
# instead? Presently the spec says it's a 'version-number' which is an
# undefined type.

def _parse_protocol_versions_line(descriptor, entries):
  value = _value('protocol-versions', entries)
  descriptor.protocol_versions = value.split(',')

_parse_rendezvous_service_descriptor_line = _parse_simple_line('rendezvous-service-descriptor', 'descriptor_id')
_parse_version_line = _parse_simple_line('version', 'version')
_parse_permanent_key_line = _parse_key_block('permanent-key', 'permanent_key', 'RSA PUBLIC KEY')
_parse_secret_id_part_line = _parse_simple_line('secret-id-part', 'secret_id_part')
_parse_publication_time_line = _parse_timestamp_line('publication-time', 'published')
_parse_introduction_points_line = _parse_key_block('introduction-points', 'introduction_points_blob', 'MESSAGE')
_parse_signature_line = _parse_key_block('signature', 'signature', 'SIGNATURE')


class HiddenServiceDescriptor(Descriptor):
  """
  Hidden service descriptor.

  :var str descriptor_id: **\*** identifier for this descriptor, this is a base32 hash of several fields
  :var str version: **\*** hidden service descriptor version
  :var str permanent_key: **\*** long term key of the hidden service
  :var str secret_id_part: **\*** hash of the time period, cookie, and replica
    values so our descriptor_id can be validated
  :var datetime published: **\*** time in UTC when this descriptor was made
  :var list protocol_versions: **\*** versions that are supported when establishing a connection
  :var str introduction_points_blob: **\*** raw introduction points blob, if
    the hidden service uses cookie authentication this is encrypted
  :var str signature: signature of the descriptor content

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  ATTRIBUTES = {
    'descriptor_id': (None, _parse_rendezvous_service_descriptor_line),
    'version': (None, _parse_version_line),
    'permanent_key': (None, _parse_permanent_key_line),
    'secret_id_part': (None, _parse_secret_id_part_line),
    'published': (None, _parse_publication_time_line),
    'protocol_versions': ([], _parse_protocol_versions_line),
    'introduction_points_blob': (None, _parse_introduction_points_line),
    'signature': (None, _parse_signature_line),
  }

  PARSER_FOR_LINE = {
    'rendezvous-service-descriptor': _parse_rendezvous_service_descriptor_line,
    'version': _parse_version_line,
    'permanent-key': _parse_permanent_key_line,
    'secret-id-part': _parse_secret_id_part_line,
    'publication-time': _parse_publication_time_line,
    'protocol-versions': _parse_protocol_versions_line,
    'introduction-points': _parse_introduction_points_line,
    'signature': _parse_signature_line,
  }

  def __init__(self, raw_contents, validate = False):
    super(HiddenServiceDescriptor, self).__init__(raw_contents, lazy_load = not validate)
    entries = _get_descriptor_components(raw_contents, validate)

    if validate:
      for keyword in REQUIRED_FIELDS:
        if keyword not in entries:
          raise ValueError("Hidden service descriptor must have a '%s' entry" % keyword)
        elif keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in a hidden service descriptor" % keyword)

      if 'rendezvous-service-descriptor' != list(entries.keys())[0]:
        raise ValueError("Hidden service descriptor must start with a 'rendezvous-service-descriptor' entry")
      elif 'signature' != list(entries.keys())[-1]:
        raise ValueError("Hidden service descriptor must end with a 'signature' entry")

      self._parse(entries, validate)
    else:
      self._entries = entries
