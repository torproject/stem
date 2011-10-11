"""
Unit tests for the types.ControlMessage parsing and class.
"""

import StringIO
import unittest
import stem.types

GETINFO_VERSION_REPLY = """250-version=0.2.2.23-alpha (git-b85eb949b528f4d7)\r
250 OK\r
"""

GETINFO_INFONAMES_REPLY = """250+info/names=\r
accounting/bytes -- Number of bytes read/written so far in the accounting interval.\r
accounting/bytes-left -- Number of bytes left to write/read so far in the accounting interval.\r
accounting/enabled -- Is accounting currently enabled?\r
accounting/hibernating -- Are we hibernating or awake?\r
stream-status -- List of current streams.\r
version -- The current version of Tor.\r
.\r
250 OK\r
"""

class TestMessageFunctions(unittest.TestCase):
  """
  Tests methods and functions related to 'types.ControlMessage'. This uses
  StringIO to make 'files' to mock socket input.
  """
  
  def test_getinfo_results(self):
    """
    Checks parsing against some actual GETINFO responses.
    """
    
    # GETINFO version (basic single-line results)
    message = self.assert_message_parses(GETINFO_VERSION_REPLY)
    self.assertEquals(2, len(list(message)))
    self.assertEquals(2, len(str(message).split("\n")))
    
    # manually checks the contents
    contents = message.content()
    self.assertEquals(2, len(contents))
    self.assertEquals(("250", "-", "version=0.2.2.23-alpha (git-b85eb949b528f4d7)"), contents[0])
    self.assertEquals(("250", " ", "OK"), contents[1])
    
    # GETINFO info/names (data entry)
    message = self.assert_message_parses(GETINFO_INFONAMES_REPLY)
    self.assertEquals(2, len(list(message)))
    self.assertEquals(8, len(str(message).split("\n")))
    
    # manually checks the contents
    contents = message.content()
    self.assertEquals(2, len(contents))
    
    first_entry = (contents[0][0], contents[0][1], contents[0][2][:contents[0][2].find("\n")])
    self.assertEquals(("250", "+", "info/names="), first_entry)
    self.assertEquals(("250", " ", "OK"), contents[1])
  
  def assert_message_parses(self, controller_reply):
    """
    Performs some basic sanity checks that a reply mirrors its parsed result.
    
    Returns:
      types.ControlMessage for the given input
    """
    
    message = stem.types.read_message(StringIO.StringIO(controller_reply))
    
    # checks that the raw_content equals the input value
    self.assertEqual(controller_reply, message.raw_content())
    
    # checks that the contents match the input
    message_lines = str(message).split("\n")
    controller_lines = controller_reply.split("\r\n")
    controller_lines.pop() # the ControlMessage won't have a trailing newline
    
    while controller_lines:
      line = controller_lines.pop(0)
      
      # mismatching lines with just a period are probably data termination
      if line == "." and (not message_lines or line != message_lines[0]):
        continue
      
      self.assertTrue(line.endswith(message_lines.pop(0)))
    
    return message

