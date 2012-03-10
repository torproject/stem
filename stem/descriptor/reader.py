"""
Utilities for reading descriptors from local directories and archives. This is
mostly done through the DescriptorReader class, which is an iterator for the
descriptor data in a series of destinations. For example...

  my_descriptors = [
    "/tmp/server-descriptors-2012-03.tar.bz2",
    "/tmp/archived_descriptors/",
  ]
  
  reader = DescriptorReader(my_descriptors)
  
  # prints the contents of all the descriptor files
  with reader:
    for descriptor in reader:
      print descriptor

This ignores files that cannot be processed due to read errors or unparsable
content. To be notified of skipped files you can register a listener with
register_skip_listener().

The DescriptorReader keeps track of the last modified timestamps for descriptor
files that it has read so it can skip unchanged files if ran again. This
listing of processed files can also be persisted and applied to other
DescriptorReaders. For instance, the following prints descriptors as they're
changed over the course of a minute, and picks up where it left off if ran
again...

  reader = DescriptorReader(["/tmp/descriptor_data"])
  
  try:
    processed_files = load_processed_files("/tmp/used_descriptors")
    reader.set_processed_files(processed_files)
  except: pass # could not load, mabye this is the first run
  
  with reader:
    start_time = time.time()
    
    while time.time() - start_time < 60:
      # prints any descriptors that have changed since last checked
      for descriptor in reader:
        print descriptor
      
      time.sleep(1)
  
  save_processed_files(reader.get_processed_files(), "/tmp/used_descriptors")


load_processed_files - Loads a listing of processed files.
save_processed_files - Saves a listing of processed files.

DescriptorReader - Iterator for descriptor data on the local file system.
  |- get_processed_files - provides the listing of files that we've processed
  |- set_processed_files - sets our tracking of the files we have processed
  |- start - begins reading descriptor data
  |- stop - stops reading descriptor data
  |- join - joins on the thread used to process descriptor data
  |- __enter__ / __exit__ - manages the descriptor reader thread in the context
  +- __iter__ - iterates over descriptor data in unread files
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
    dict of 'path (str) => last modified unix timestamp (int)' mappings
  
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
      if not os.path.isabs(path):
        raise TypeError("Only absolute paths are acceptable: %s" % path)
      
      output_file.write("%s %i\n" % (path, timestamp))

class DescriptorReader(threading.Thread):
  """
  Iterator for the descriptor data on the local file system. This can process
  text files, tarball archives (gzip or bzip2), or recurse directories.
  """
  
  def __init__(self, targets):
    self.targets = targets
    self.skip_listeners = []
    self.processed_files = {}
    self._stop_event = threading.Event()
  
  def get_processed_files(self):
    """
    For each file that we have read descriptor data from this provides a
    mapping of the form...
    
    absolute path (str) => last modified unix timestamp (int)
    
    This includes entries set through the set_processed_files() method.
    
    Returns:
      dict with the paths and unix timestamp for the last modified times of the
      files we have processed
    """
    
    return dict(self.processed_files)
  
  def set_processed_files(self, processed_files):
    """
    Sets the listing of the files we have processed. Most often this is useful
    as a method for pre-populating the listing of descriptor files that we have
    seen.
    
    Arguments:
      processed_files (dict) - mapping of absolute paths (str) to unix
                               timestamps for the last modified time (int)
    """
    
    self.processed_files = dict(processed_files)
  
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
  
  def stop(self):
    """
    Stops further reading of descriptor files.
    """
    
    self._stop_event.set()
  
  def run(self):
    # os.walk(path, followlinks = True)
    #
    # >>> mimetypes.guess_type("/home/atagar/Desktop/control-spec.txt")
    # ('text/plain', None)
    #
    # >>> mimetypes.guess_type("/home/atagar/Desktop/server-descriptors-2012-03.tar.bz2")
    # ('application/x-tar', 'bzip2')
    #
    # This only checks the file extension. To actually check the content (like
    # the 'file' command) an option would be pymagic...
    # https://github.com/cloudburst/pymagic
    
    
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

