import os, csv, sets, cStringIO


def export_csv(descriptor, include_fields=(), exclude_fields=()):
  """
  Takes a single descriptor object, puts it in a list, and passes it to
  descriptors_csv_exp to build a csv.
  
  :param object descriptor: single descriptor whose attributes will be returned as a string.
  :param list include_fields: list of attribute fields to include in the csv string.
  :param list exclude_fields: list of attribute fields to exclude from csv string.
  
  :returns: single csv line as a string with one descriptor attribute per cell.
  """
  
  descr = (descriptor,)
  return export_csvs(descr, include_fields=include_fields, exclude_fields=exclude_fields)


def export_csvs(descriptors, include_fields=[], exclude_fields=[], header=False):
  """
  Takes an iterable of descriptors, returns a string with one line per descriptor
  where each line is a comma separated list of descriptor attributes.
  
  :param list descrs: List of descriptor objects whose attributes will be written.
  :param list include_fields: list of attribute fields to include in the csv string.
  :param list exclude_fields: list of attribute fields to exclude from csv string.
  :param bool header: whether or not a header is requested.
  
  :returns: csv string with one descriptor per line and one attribute per cell.
  :raises: ValueError if more than one descriptor type (e.g. server_descriptor,
    extrainfo_descriptor) is provided in the iterable.
  """
  
  # Need a file object to write to with DictWriter.
  temp_file = cStringIO.StringIO()
  
  first = True
  
  for desc in descriptors:
    #umport sys
    attr = vars(desc)
    
    # Defining incl_fields and the dwriter object requires having access
    # to a descriptor object.
    if first:
      # All descriptor objects should be of the same type
      # (i.e. server_descriptor.RelayDesrciptor)
      desc_type = type(desc)
      
      # define incl_fields, 4 cases where final case is incl_fields already
      # defined and excl_fields left blank, so no action is necessary.
      if not include_fields and exclude_fields:
        incl = set(attr.keys())
        include_fields = list(incl.difference(exclude_fields))
      
      elif not include_fields and not exclude_fields:
        include_fields = attr.keys()
      
      elif include_fields and exclude_fields:
        incl = set(include_fields)
        include_fields = list(incl.difference(exclude_fields))
      
      dwriter = csv.DictWriter(temp_file, include_fields, extrasaction='ignore')
      
      if header:
        dwriter.writeheader()
      first = False
    
    if desc_type == type(desc):
      dwriter.writerow(attr)
    else:
      raise ValueError('More than one descriptor type provided. Started with a %s, and just got a %s' % (desc_type, type(desc)))
  
  return temp_file.getvalue()
  # cStringIO files are closed automatically when the current scope is exited.

def export_csv_file(descriptors, document, include_fields=(), exclude_fields=(), header=True):
  """
  Writes descriptor attributes to a csv file on disk.
  
  Calls get_csv_lines with the given argument, then writes the returned string
  to a file location specified by document_location.
  Precondition that param document has a 'write' attribute.
  
  :param list descriptors: descriptor objects with attributes to export as csv file.
  :param object document: File object to be written to.
  :param bool header: defaults to true, determines if document will have a header row.
  :param list include_fields: list of attribute fields to include in the csv line.
  :param list exclude_fields: list of attribute fields to exclude from csv line.
  """
  
  try:
    document.write(export_csvs(descriptors, include_fields=include_fields, exclude_fields=exclude_fields, header=header))
  except AttributeError:
    print "Provided %r object does not have a write() method." % document
    raise
