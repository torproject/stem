import time
import stem.descriptor

def measure_average_advertised_bandwidth(path):
  start_time = time.time()
  total_bw, count = 0, 0

  for desc in stem.descriptor.parse_file(path):
    total_bw += min(desc.average_bandwidth, desc.burst_bandwidth, desc.observed_bandwidth)
    count += 1

  runtime = time.time() - start_time
  print("Finished measure_average_advertised_bandwidth('%s')" % path)
  print('  Total time: %i seconds' % runtime)
  print('  Processed server descriptors: %i' % count)
  print('  Average advertised bandwidth: %i' % (total_bw / count))
  print('  Time per server descriptor: %0.5f seconds' % (runtime / count))
  print('')

def measure_countries_v3_requests(path):
  start_time = time.time()
  countries, count = set(), 0

  for desc in stem.descriptor.parse_file(path):
    if desc.dir_v3_responses:
      countries.update(desc.dir_v3_responses.keys())

    count += 1

  runtime = time.time() - start_time
  print("Finished measure_countries_v3_requests('%s')" % path)
  print('  Total time: %i seconds' % runtime)
  print('  Processed extrainfo descriptors: %i' % count)
  print('  Number of countries: %i' % len(countries))
  print('  Time per extrainfo descriptor: %0.5f seconds' % (runtime / count))
  print('')

def measure_average_relays_exit(path):
  start_time = time.time()
  total_relays, exits, consensuses = 0, 0, 0

  for consensus in stem.descriptor.parse_file(path, document_handler = stem.descriptor.DocumentHandler.DOCUMENT):
    for desc in consensus.routers.values():
      if 'Exit' in desc.flags:
        exits += 1

      total_relays += 1

    consensuses += 1

  runtime = time.time() - start_time
  print("Finished measure_average_relays_exit('%s')" % path)
  print('  Total time: %i seconds' % runtime)
  print('  Processed %i consensuses with %i router status entries' % (consensuses, total_relays))
  print('  Total exits: %i (%0.2f%%)' % (exits, float(exits) / total_relays))
  print('  Time per consensus: %0.5f seconds' % (runtime / consensuses))
  print('')

def measure_fraction_relays_exit_80_microdescriptors(path):
  start_time = time.time()
  exits, count = 0, 0

  for desc in stem.descriptor.parse_file(path):
    if desc.exit_policy.can_exit_to(port = 80):
      exits += 1

    count += 1

  runtime = time.time() - start_time
  print("Finished measure_fraction_relays_exit_80_microdescriptors('%s')" % path)
  print('  Total time: %i seconds' % runtime)
  print('  Processed microdescriptors: %i' % count)
  print('  Total exits to port 80: %i (%0.2f%%)' % (exits, float(exits) / count))
  print('  Time per microdescriptor: %0.5f seconds' % (runtime / count))
  print('')

measure_average_advertised_bandwidth('/home/atagar/Desktop/server-descriptors-2015-11.tar')
measure_countries_v3_requests('/home/atagar/Desktop/extra-infos-2015-11.tar')
measure_average_relays_exit('/home/atagar/Desktop/consensuses-2015-11.tar')
measure_fraction_relays_exit_80_microdescriptors('/home/atagar/Desktop/microdescs-2015-11.tar')

