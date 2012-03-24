"""
Package for parsing and processing descriptor data.

parse_file - Iterates over the descriptors in a file.
Descriptor - Common parent for all descriptor file types.
  |- get_path - location of the descriptor on disk if it came from a file
  |- get_unrecognized_lines - unparsed descriptor content
  +- __str__ - string that the descriptor was made from
"""

__all__ = ["descriptor", "reader", "server_descriptor", "parse_file", "Descriptor"]

import os

def parse_file(path, descriptor_file):
  """
  Provides an iterator for the descriptors within a given file.
  
  Arguments:
    path (str)             - absolute path to the file's location on disk
    descriptor_file (file) - opened file with the descriptor contents
  
  Returns:
    iterator for Descriptor instances in the file
  
  Raises:
    TypeError if we can't match the contents of the file to a descriptor type
    IOError if unable to read from the descriptor_file
  """
  
  import stem.descriptor.server_descriptor
  
  # The tor descriptor specifications do not provide a reliable method for
  # identifying a descriptor file's type and version so we need to guess
  # based on...
  # - its filename for resources from the tor data directory
  # - first line of our contents for files provided by metrics
  
  filename = os.path.basename(path)
  first_line = descriptor_file.readline()
  descriptor_file.seek(0)
  
  if filename == "cached-descriptors" or first_line.startswith("router "):
    for desc in stem.descriptor.server_descriptor.parse_file_v2(descriptor_file):
      desc._set_path(path)
      yield desc
  else:
    # unrecognized descritor type
    raise TypeError("Unable to determine the descriptor's type. filename: '%s', first line: '%s'" % (filename, first_line))

class Descriptor:
  """
  Common parent for all types of descriptors.
  """
  
  def __init__(self, contents):
    self._path = None
    self._raw_contents = contents
  
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
    
    raise NotImplementedError
  
  def _set_path(self, path):
    self._path = path
  
  def __str__(self):
    return self._raw_contents

