"""
Unit testing code for the stem.descriptor.export module
"""
import unittest
import stem.descriptor.export as export
import test.mocking as mocking

from collections import namedtuple
import stem.descriptor as desc
import cStringIO

# Create descriptor objects.
DESCR_DICT = {'average_bandwidth': 5242880, 'onion_key': 'RSA PUB = JAIK', 'address': '79.139.135.90', '_digest': None, 'exit_policy': ['reject *:*'], 'fingerprint': 'AAAAAAAAAAAAAAAAAAA'}
DESCR2_DICT = {'average_bandwidth': 5555555, 'onion_key': 'RSA PUB = GOUS', 'address': '100.1.1.1', '_digest': None, 'exit_policy': ['reject *:*'], 'fingerprint': 'BBBBBBBBBBBBBBBBBBBBB'}
DESCR3_DICT = {'bandwidth':12345,'average_bandwidth': 6666666, 'address': '101.0.0.1','extra_info':None}
RAW = 'router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon'

descriptor = desc.Descriptor(RAW)
descriptor.__dict__.update(DESCR_DICT)

descriptor2 = desc.Descriptor(RAW)
descriptor2.__dict__.update(DESCR2_DICT)

descriptor3 = desc.server_descriptor.RelayDescriptor(RAW, validate=False)
descriptor3.__dict__.update(DESCR3_DICT)

# Expected return csv strings.
SINGLE_ALL = '5242880,RSA PUB = JAIK,AAAAAAAAAAAAAAAAAAA,,router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon,[\'reject *:*\'],79.139.135.90,'
SINGLE_PART = '79.139.135.90,[\'reject *:*\']'
SINGLE_PART2 = '5242880,,router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon,[\'reject *:*\'],79.139.135.90,'
SINGLE_PART3 = '79.139.135.90,AAAAAAAAAAAAAAAAAAA'

DOUBLE_ALL = '5242880,RSA PUB = JAIK,AAAAAAAAAAAAAAAAAAA,,router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon,[\'reject *:*\'],79.139.135.90,\r\n5555555,RSA PUB = GOUS,BBBBBBBBBBBBBBBBBBBBB,,router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon,[\'reject *:*\'],100.1.1.1,\r\n'
DOUBLE_PART = '79.139.135.90,[\'reject *:*\']\r\n100.1.1.1,[\'reject *:*\']\r\n'
DOUBLE_PART2 = '5242880,,router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon,[\'reject *:*\'],79.139.135.90,\r\n5555555,,router TORsinn3r 46.17.96.217 9001 0 0 platform Tor 0.2.3.19-rc on Linux bandwidth 4 5 6 ...andonandon,[\'reject *:*\'],100.1.1.1,\r\n'

SINGLE_ALL_HEAD = 'average_bandwidth,onion_key,fingerprint,_digest,_raw_contents,exit_policy,address,_path\r\n' + SINGLE_ALL + '\r\n'
SINGLE_PART3_HEAD = 'address,fingerprint\r\n' + SINGLE_PART3
DOUBLE_ALL_HEAD = 'average_bandwidth,onion_key,fingerprint,_digest,_raw_contents,exit_policy,address,_path\r\n' + DOUBLE_ALL
DOUBLE_PART_HEAD = 'address,exit_policy\r\n' + DOUBLE_PART
DOUBLE_PART2_HEAD = 'average_bandwidth,_digest,_raw_contents,exit_policy,address,_path\r\n' + DOUBLE_PART2

class TestExport(unittest.TestCase):
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_export_csv(self):
    """
    Tests the export_csv function which takes a single descriptor object.
    """
    Fields = namedtuple('Fields', 'include_fields exclude_fields')
    
    # Descriptors must be an iterable
    # named tuples replace dictionaries as dict keys must immutable.
    ret_vals = {((descriptor,), Fields(include_fields=(), exclude_fields=())):SINGLE_ALL,
                ((descriptor,), Fields(include_fields=('address', 'exit_policy'),
                  exclude_fields=())):SINGLE_PART,
                ((descriptor,), Fields(include_fields=(),
                  exclude_fields=('onion_key', 'fingerprint'))):SINGLE_PART2,
                ((descriptor,), Fields(include_fields=('address', 'exit_policy', 'fingerprint'),
                  exclude_fields=('fingerprint',))):SINGLE_PART,
                ((descriptor,), Fields(include_fields=('address', 'fingerprint'),
                  exclude_fields=('_digest',))):SINGLE_PART3
                }
    mocking.mock(export.export_csvs, mocking.return_for_args(ret_vals, kwarg_type=Fields))
    
    # Used tuples for incl/exclude_fields for parameter matching with ret_vals dict.
    self.assertEqual(SINGLE_ALL, export.export_csv(descriptor))
    self.assertEqual(SINGLE_PART, export.export_csv(descriptor,
      include_fields=('address', 'exit_policy')))
    self.assertEqual(SINGLE_PART2, export.export_csv(descriptor,
      exclude_fields=('onion_key', 'fingerprint')))
    self.assertEqual(SINGLE_PART, export.export_csv(descriptor,
      include_fields=('address', 'exit_policy', 'fingerprint'), exclude_fields=('fingerprint',)))
    self.assertEqual(SINGLE_PART3, export.export_csv(descriptor,
      include_fields=('address', 'fingerprint'), exclude_fields=('_digest',)))
      
  
  def test_export_csvs(self):
    """
    Test the export_csvs function which takes a list of descriptor objects.
    """
    
    # Single descriptor
    self.assertEquals(SINGLE_ALL + "\r\n", export.export_csvs([descriptor]))
    self.assertEqual(SINGLE_PART + "\r\n", export.export_csvs([descriptor],
      include_fields=['address', 'exit_policy']))
    self.assertEqual(SINGLE_PART2 + "\r\n", export.export_csvs([descriptor],
      exclude_fields=['onion_key', 'fingerprint']))
    self.assertEqual(SINGLE_PART + "\r\n", export.export_csvs([descriptor],
      include_fields=['address', 'exit_policy', 'fingerprint'], exclude_fields=['fingerprint']))
    
    # Multiple descriptors
    self.assertEqual(DOUBLE_ALL, export.export_csvs([descriptor, descriptor2]))
    self.assertEqual(DOUBLE_PART, export.export_csvs([descriptor, descriptor2],
      include_fields=['address', 'exit_policy']))
    self.assertEqual(DOUBLE_PART2, export.export_csvs([descriptor, descriptor2],
      exclude_fields=['onion_key', 'fingerprint']))
    self.assertEqual(DOUBLE_PART, export.export_csvs([descriptor, descriptor2],
      include_fields=['address', 'exit_policy', 'fingerprint'], exclude_fields=['fingerprint']))
    
    # Tests with headers
    self.assertEqual(SINGLE_ALL_HEAD, export.export_csvs([descriptor], header=True))
    self.assertEqual(SINGLE_PART3_HEAD + "\r\n", export.export_csvs([descriptor],
      include_fields=['address', 'fingerprint'], exclude_fields=['_digest'], header=True))
    self.assertEqual(DOUBLE_ALL_HEAD, export.export_csvs([descriptor, descriptor2], header=True))
    self.assertEqual(DOUBLE_PART_HEAD, export.export_csvs([descriptor, descriptor2],
      include_fields=['address', 'exit_policy'], header=True))
    self.assertEqual(DOUBLE_PART2_HEAD, export.export_csvs([descriptor, descriptor2],
      exclude_fields=['onion_key', 'fingerprint'], header=True))
    
    # Other tests
    self.assertRaises(ValueError, export.export_csvs, [descriptor, descriptor3])
    self.assertRaises(ValueError, export.export_csvs, [descriptor, descriptor3],
      include_fields=['onion_key', 'address', 'fingerprint'], exclude_fields=['onion_key'])
      
  
  
  def test_export_csv_file(self):
    """
    Tests the export_csv_file function.
    """
    sample_csv_string = 'This, is, a, sample, string.\r\nline, two.\r\n'
    sample_csv_string2 = 'Another, sample\r\n,, second,\r\n'
    sample_file = cStringIO.StringIO()
    
    # Must use named tuples again for ret_vals dictionary.
    Fields = namedtuple('Fields', 'include_fields exclude_fields header')
    
    ret_vals = {((descriptor,), Fields(include_fields=(), exclude_fields=(), header=True)):sample_csv_string,
      ((descriptor,), Fields(include_fields=('address', 'onion_key'), exclude_fields=('address',), header=False)):sample_csv_string2}
    # TODO Ask Danner: mock it once then do both tests (not including assertRaises), or do separate mockings.
    #    the latter requires that we still include empty incl_fields and excl_fields parameters instead of
    #    letting them default to [].  Same for header.
    mocking.mock(export.export_csvs, mocking.return_for_args(ret_vals, kwarg_type=Fields))
    
    export.export_csv_file((descriptor,), sample_file)
    self.assertEqual(sample_csv_string, sample_file.getvalue())
    
    sample_file = cStringIO.StringIO()
    
    export.export_csv_file((descriptor,), sample_file, include_fields=('address', 'onion_key'), exclude_fields=('address',), header=False)
    self.assertEqual(sample_csv_string2, sample_file.getvalue())
    
    # Make sure error is Raised when necessary.
    self.assertRaises(AttributeError, export.export_csv_file, (descriptor,), sample_csv_string)
