"""
Unit testing code for the stem.descriptor.export module
"""
import unittest
import stem.descriptor.export as export
import test.mocking as mocking

SINGLE_DESCR_DICT = {'average_bandwidth': 5242880, 'onion_key': 'RSA PUB = JAIK', 'address': '79.139.135.90', '_digest': None, 'exit_policy': ['reject *:*'], 'fingerprint': '0045EB8B820DC410197B'}



class TestExport(unittest.TestCase):
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_export_csv(self):
    """
    Tests the export_csv function which takes a single descriptor object.
    """
    
    # TODO we should be passing descriptor objects not just dicts.
    csv_string = '5242880, RSA PUB = JAIK, 79.139.135.90,,[\'reject *:*\'], 0045EB8B820DC410197B'
    mocking.mock(export.export_csvs, mocking.return_value(csv_string))
    self.assertEqual(csv_string, export.export_csv(SINGLE_DESCR_DICT))
    
    csv_string = '79.139.135.90,,[\'reject *:*\'], 0045EB8B820DC410197B'
    mocking.mock(export.export_csvs, mocking.return_value(csv_string))
    self.assertEqual(csv_string, export.export_csv(SINGLE_DESCR_DICT, exclude_fields=['average_bandwidth', 'onion_key']))
    
    csv_string = 'RSA PUB = JAIK, 79.139.135.90,'
    mocking.mock(export.export_csvs, mocking.return_value(csv_string))
    self.assertEqual(csv_string, export.export_csv(SINGLE_DESCR_DICT, include_fields=['onion_key', 'address']))
    
    # TODO 1 or two more cases to handle (subcases of overlap/no overlap
    # incl & excl.)
    
    
    # TODO Make sure to undo mocking here or we won't be testing the next function.
    
  def test_export_csvs(self):
    """
    Test the export_csvs function which takes a list of descriptor objects.
    """
    pass
  
  def test_export_csv_file(self):
    """
    Tests the export_csv_file function.
    """
    pass
    # mocking.mock(open, mocking.return_for_args(##))
    # mocking.mock(export.export_csvs, ##)
