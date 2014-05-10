"""
Integration tests for stem.descriptor.microdescriptor.
"""

import os
import unittest

import stem.descriptor
import stem.exit_policy
import test.runner

from test.integ.descriptor import get_resource

FIRST_ONION_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

SECOND_ONION_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALCOxZdpMI2WO496njSQ2M7b4IgAGATqpJmH3So7lXOa25sK6o7JipgP
qQE83K/t/xsMIpxQ/hHkft3G78HkeXXFc9lVUzH0HmHwYEu0M+PMVULSkG36MfEl
7WeSZzaG+Tlnh9OySAzVyTsv1ZJsTQFHH9V8wuM0GOMo9X8DFC+NAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

THIRD_ONION_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOWFQHxO+5kGuhwPUX5jB7wJCrTbSU0fZwolNV1t9UaDdjGDvIjIhdit
y2sMbyd9K8lbQO7x9rQjNst5ZicuaSOs854XQddSjm++vMdjYbOcVMqnKGSztvpd
w/1LVWFfhcBnsGi4JMGbmP+KUZG9A8kI9deSyJhfi35jA7UepiHHAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""


class TestMicrodescriptor(unittest.TestCase):
  def test_cached_microdescriptors(self):
    """
    Parses the cached microdescriptor file in our data directory, checking that
    it doesn't raise any validation issues and looking for unrecognized
    descriptor additions.
    """

    if test.runner.only_run_once(self, 'test_cached_microdescriptors'):
      return

    descriptor_path = test.runner.get_runner().get_test_dir('cached-microdescs')

    if not os.path.exists(descriptor_path):
      test.runner.skip(self, '(no cached microdescriptors)')
      return

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'microdescriptor 1.0'):
        unrecognized_lines = desc.get_unrecognized_lines()

        if unrecognized_lines:
          self.fail('Unrecognized microdescriptor content: %s' % unrecognized_lines)

  def test_local_microdescriptors(self):
    """
    Checks a small microdescriptor file with known contents.
    """

    descriptor_path = get_resource('cached-microdescs')

    with open(descriptor_path, 'rb') as descriptor_file:
      descriptors = stem.descriptor.parse_file(descriptor_file, 'microdescriptor 1.0')

      router = next(descriptors)
      self.assertEquals(FIRST_ONION_KEY, router.onion_key)
      self.assertEquals(None, router.ntor_onion_key)
      self.assertEquals([], router.or_addresses)
      self.assertEquals([], router.family)
      self.assertEquals(stem.exit_policy.MicroExitPolicy('reject 1-65535'), router.exit_policy)
      self.assertEquals({b'@last-listed': b'2013-02-24 00:18:36'}, router.get_annotations())
      self.assertEquals([b'@last-listed 2013-02-24 00:18:36'], router.get_annotation_lines())

      router = next(descriptors)
      self.assertEquals(SECOND_ONION_KEY, router.onion_key)
      self.assertEquals(u'r5572HzD+PMPBbXlZwBhsm6YEbxnYgis8vhZ1jmdI2k=', router.ntor_onion_key)
      self.assertEquals([], router.or_addresses)
      self.assertEquals(['$6141629FA0D15A6AEAEF3A1BEB76E64C767B3174'], router.family)
      self.assertEquals(stem.exit_policy.MicroExitPolicy('reject 1-65535'), router.exit_policy)
      self.assertEquals({b'@last-listed': b'2013-02-24 00:18:37'}, router.get_annotations())
      self.assertEquals([b'@last-listed 2013-02-24 00:18:37'], router.get_annotation_lines())

      router = next(descriptors)
      self.assertEquals(THIRD_ONION_KEY, router.onion_key)
      self.assertEquals(None, router.ntor_onion_key)
      self.assertEquals([(u'2001:6b0:7:125::242', 9001, True)], router.or_addresses)
      self.assertEquals([], router.family)
      self.assertEquals(stem.exit_policy.MicroExitPolicy('accept 80,443'), router.exit_policy)
      self.assertEquals({b'@last-listed': b'2013-02-24 00:18:36'}, router.get_annotations())
      self.assertEquals([b'@last-listed 2013-02-24 00:18:36'], router.get_annotation_lines())
