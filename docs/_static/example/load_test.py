import os
import time

import stem.control
import stem.util.proc
import stem.util.str_tools

start_time = time.time()
samplings = []
last_sample = None

with stem.control.Controller.from_port() as controller:
  controller.authenticate()
  controller.add_event_listener(lambda *args: None, 'DEBUG')

  while True:
    utime, stime = stem.util.proc.stats(os.getpid(), stem.util.proc.Stat.CPU_UTIME, stem.util.proc.Stat.CPU_STIME)
    total_cpu_time = float(utime) + float(stime)

    if last_sample:
      samplings.append(total_cpu_time - last_sample)
      print '%0.1f%% (%s)' % (sum(samplings) / len(samplings) * 100, stem.util.str_tools.time_label(time.time() - start_time))

    last_sample = total_cpu_time
    time.sleep(1)
