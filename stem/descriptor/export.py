import os, csv, sets, cStringIO


def export_csv(descriptor, include_fields=[], exclude_fields=[]):
  """
  Takes a single descriptor object, puts it in a list, and passes it to
  descriptors_csv_exp to build a csv.
  
  :param object descriptor: single descriptor whose.
  :param list include_fields: list of attribute fields to include in the csv string.
  :param list exclude_fields: list of attribute fields to exclude from csv string.
  
  :returns: single csv line as a string with one descriptor attribute per cell.
  """
  descr = [descriptor]
  return export_csvs(descr, include_fields=include_fields, exclude_fields=exclude_fields)


def export_csvs(descriptors, include_fields=[], exclude_fields=[], header=False):
  """
  Returns a string that is in csv format, ready to be placed in a .csv file.
  
  :param list descrs: List of descriptor objects whose attributes will be written.
  :param list include_fields: list of attribute fields to include in the csv string.
  :param list exclude_fields: list of attribute fields to exclude from csv string.
  :param bool header: whether or not a header is requested; probably won't be
    needed outside of csv_file_exp's call of this function.
  
  :returns: csv string with one descriptor per line and one attribute per cell.
  """
  
  _temp_file = cStringIO.StringIO()
  
  first = True
  
  for desc in descriptors:
    attr = vars(desc)
    
    # Defining incl_fields and the dwriter object requires having access
    # to a descriptor object.
    if first:
      # All descriptor objects should be of the same type
      # (i.e. server_descriptor.RelayDescriptor)
      desc_type = type(desc)
      
      # define incl_fields, 4 cases where final case is incl_fields already
      # defined and excl_fields left blank, so no action is necessary.
      if not include_fields and exclude_fields:
        _incl = sets.Set(attr.keys())
        include_fields = list(_incl.difference(exclude_fields))
      
      elif not include_fields and not exclude_fields:
        include_fields = attr.keys()
      
      elif include_fields and exclude_fields:
        _incl = sets.Set(include_fields)
        include_fields = list(_incl.difference(exclude_fields))
      
      dwriter = csv.DictWriter(_temp_file, include_fields, extrasaction='ignore')
      first = False
      
      if header:
        dwriter.writeheader()
    
    if desc_type == type(desc):
      dwriter.writerow(attr)
    else:
      raise ValueError('More than one type of descriptor was provided.')
  
  return _temp_file.getvalue()
  # cStringIO files are closed automatically when the current scope is exited.

def export_csv_file(descriptors, document_location, header=True, include_fields=[], exclude_fields=[]):
  """
  Writes descriptor attributes to a csv file on disk.
  
  Calls get_csv_lines with the given argument, then writes the returned string
  to a file location specified by document_location.
  
  :param list descrs: descriptor objects with attributes to export as csv file.
  :param str doc_loc: location and file name for csv file to be written to.
    This overwrites existing files.
  :param bool header: defaults to true, determines if doc will have a header row.
  :param list incl_f: list of attribute fields to include in the csv line.
  :param list excl_f: list of attribute fields to exclude from csv line.
  """
  doc = open(document_location, 'w')
  
  for line in export_csvs(descriptors, include_fields=include_fields, exclude_fields=exclude_fields, head=header):
    doc.write(line)
