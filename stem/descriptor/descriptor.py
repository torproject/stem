"""
Common functionality for descriptors.
"""

def parse_descriptors(path, descriptor_file):
  """
  Provides an iterator for the descriptors within a given file.
  
  Arguments:
    path (str)             - absolute path to the file's location on disk
    descriptor_file (file) - opened file with the descriptor contents
  
  Returns:
    iterator that parses the file's contents into descriptors
  
  Raises:
    TypeError if we can't match the contents of the file to a descriptor type
    IOError if unable to read from the descriptor_file
  """
  
  # TODO: implement actual descriptor type recognition and parsing
  # TODO: add integ test for non-descriptor text content
  yield Descriptor(path, descriptor_file.read())

class Descriptor:
  """
  Common parent for all types of descriptors.
  """
  
  def __init__(self, path, raw_contents):
    self._path = path
    self._raw_contents = raw_contents
  
  def get_path(self):
    """
    Provides the absolute path that we loaded this descriptor from.
    
    Returns:
      str with the absolute path of the descriptor source
    """
    
    return self._path
  
  def get_unrecognized_lines(self):
    """
    Provides a list of lines that were either ignored or had data that we did
    not know how to process. This is most common due to new descriptor fields
    that this library does not yet know how to process. Patches welcome!
    
    Returns:
      list of lines of unrecognized content
    """
    
    return []
  
  def __str__(self):
    return self._raw_contents

