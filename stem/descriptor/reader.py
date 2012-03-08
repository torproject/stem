"""
Reads descriptors from local directories and archives.

Example:
  my_descriptors = [
    "/tmp/server-descriptors-2012-03.tar.bz2",
    "/tmp/archived_descriptors/",
  ]
  
  reader = DescriptorReader(my_descriptors)
  
  with reader:
    # prints all of the descriptor contents
    for descriptor in reader:
      print descriptor
"""

import os
import threading
import mimetypes
import Queue

def load_processed_files(path):
  """
  Loads a dictionary of 'path => last modified timestamp' mappings, as
  persisted by save_processed_files(), from a file.
  
  Arguments:
    path (str) - location to load the processed files dictionary from
  
  Returns:
    dict of 'path (str) => last modified timestamp (int)' mappings
  
  Raises:
    IOError if unable to read the file
    TypeError if unable to parse the file's contents
  """
  
  processed_files = {}
  
  with open(path) as input_file:
    for line in input_file.readlines():
      line = line.strip()
      
      if not line: continue # skip blank lines
      
      if not " " in line:
        raise TypeError("Malformed line: %s" % line)
      
      path, timestamp = line.rsplit(" ", 1)
      
      if not os.path.isabs(path):
        raise TypeError("'%s' is not an absolute path" % path)
      elif not timestamp.isdigit():
        raise TypeError("'%s' is not an integer timestamp" % timestamp)
      
      processed_files[path] = int(timestamp)
  
  return processed_files

def save_processed_files(processed_files, path):
  """
  Persists a dictionary of 'path => last modified timestamp' mappings (as
  provided by the DescriptorReader's get_processed_files() method) so that they
  can be loaded later and applied to another DescriptorReader.
  
  Arguments:
    processed_files (dict) - 'path => last modified' mappings
    path (str)             - location to save the processed files dictionary to
  
  Raises:
    IOError if unable to write to the file
    TypeError if processed_files is of the wrong type
  """
  
  # makes the parent directory if it doesn't already exist
  try:
    path_dir = os.path.dirname(path)
    if not os.path.exists(path_dir): os.makedirs(path_dir)
  except OSError, exc: raise IOError(exc)
  
  with open(path, "w") as output_file:
    for path, timestamp in processed_files.items():
      output_file.write("%s %i" % (path, timestamp))

class DescriptorReader(threading.Thread):
  """
  Iterator for the descriptor data on the local file system. This can process
  text files, tarball archives (gzip or bzip2), or recurse directories.
  
  This keeps track the last modified timestamps for descriptor files we have
  used, and if you call restart() then this will only provide descriptors from
  new files or files that have changed since them.
  
  You can also save this listing of processed files and later apply it another
  DescriptorReader. For instance, to only print the descriptors that have
  changed since the last ran...
  
    reader = DescriptorReader(["/tmp/descriptor_data"])
    
    try:
      processed_files = load_processed_files("/tmp/used_descriptors")
      reader.set_processed_files(processed_files)
    except: pass # could not load, mabye this is the first run
    
    # only prints descriptors that have changed since we last ran
    with reader:
      for descriptor in reader:
        print descriptor
    
    save_processed_files(reader.get_processed_files(), "/tmp/used_descriptors")
  
  This ignores files that cannot be processed (either due to read errors or
  because they don't contain descriptor data). The caller can be notified of
  files that are skipped by restering a listener with register_skip_listener().
  """
  
  def __init__(self, targets):
    self.targets = targets
    self.skip_listeners = []
    self.processed_files = {}
    self._stop_event = threading.Event()
  
  def stop(self):
    """
    Stops further reading of descriptors.
    """
    
    self._stop_event.set()
  
  def get_processed_files(self):
    """
    For each file we have provided descriptor data for this provides a mapping
    of the form...
    
    absolute_path (str) => modified_time (int)
    
    This includes entries set through the set_processed_files() method.
    
    Returns:
      dict with the paths and unix timestamp for the last modified times of the
      files we have processed
    """
    
    return dict(self.processed_files)
  
  def set_processed_files(self, processed_files):
    """
    Appends a dictionary of 'path => modified timestamp' mappings to our
    listing of processed files. With the get_processed_files() method this can
    be used to skip descriptors that we have already read. For instance...
    
    
    Arguments:
      processed_files (dict) - mapping of absolute paths (str) to unix
                               timestamps for the last modified time (int)
    """
    
    self.processed_files.update(processed_files)
  
  def register_skip_listener(self, listener):
    """
    Registers a listener for files that are skipped. This listener is expected
    to be a functor of the form...
    
    my_listener(path, exception)
    
    Arguments:
      listener (functor) - functor to be notified of files that are skipped to
                           read errors or because they couldn't be parsed as
                           valid descriptor data
    """
    
    self.skip_listeners.append(listener)
  
  def run(self):
    # os.walk(path, followlinks = True)
    #
    # >>> mimetypes.guess_type("/home/atagar/Desktop/control-spec.txt")
    # ('text/plain', None)
    #
    # >>> mimetypes.guess_type("/home/atagar/Desktop/server-descriptors-2012-03.tar.bz2")
    # ('application/x-tar', 'bzip2')
    
    while not self._stop_event.isSet():
      pass # TODO: implement
  
  def _notify_skip_listener(self, path, exception):
    for listener in self.skip_listeners:
      listener(path, exception)
  
  def __enter__(self):
    self.start()
  
  def __exit__(self, type, value, traceback):
    self.stop()
    self.join()

