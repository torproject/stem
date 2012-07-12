import os, csv, sets, cStringIO


def get_csv_line(descriptor, include_fields=[], exclude_fields=[]):
  """
  Takes a single descriptor object, puts it in a list, and passes it to
  descriptors_csv_exp to build a csv.

  :param object descr: single descriptor object to export as csv.
  """
  descr = [descriptor]
  for desc in get_csv_lines(descr, include_fields, exclude_fields):
    return desc


def get_csv_lines(descriptors, include_fields=[], exclude_fields=[], head=False):
  """
  Builds a csv file based on attributes of descriptors.

  :param list descrs: List of descriptor objects to export as a csv line.
  :param list incl_fields: list of attribute fields to include in the csv line.
  :param list excl_fields: list of attribute fields to exclude from csv line.
  :param bool head: whether or not a header is requested; shouldn't be needed
    outside of csv_file_exp's call of this function.

  :returns: generator for csv strings, one line per descr object.
  """

  _temp_file = cStringIO.StringIO()

  first = True

  for desc in descriptors:
    attr = vars(desc)

    # Defining incl_fields and the dwriter object requires having access
    # to a descriptor object.
    if first:
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

      dwriter = csv.DictWriter(_temp_file, include_fields)
      first = False

      if head:
        dwriter.writeheader()

    # Need to remove fields that aren't wanted for dwriter.
    final = {}
    for at in attr:
      if at in include_fields:
        final[at] = attr[at]

    dwriter.writerow(final)
    yield _temp_file.getvalue()
    
    # Clear cString wrapper for new descriptor.
    _temp_file.reset()
    _temp_file.truncate()

      
  _temp_file.close()

def csv_file_exp(descriptors, document_location, header=True, include_fields=[], exclude_fields=[]):
  """
  Writes descriptor attributes to a csv file on disk.

  :param list descrs: descriptor objects with attributes to export as csv file.
  :param str doc_loc: location and file name for csv file to be written to.
    This overwrites existing files.
  :param bool header: defaults to true, determines if doc will have a header row.
  :param list incl_f: list of attribute fields to include in the csv line.
  :param list excl_f: list of attribute fields to exclude from csv line.
  """
  doc = open(document_location, 'w')

  for line in get_csv_lines(descriptors, include_fields=include_fields, exclude_fields=exclude_fields, head=header):
    doc.write(line)

