from stem.descriptor.reader import DescriptorReader

with DescriptorReader(["/home/atagar/server-descriptors-2013-03.tar"]) as reader:
  for desc in reader:
    print("found relay %s (%s)" % (desc.nickname, desc.fingerprint))
