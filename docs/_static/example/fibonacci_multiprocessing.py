import stem.util.system
import time

def fibonacci(n):
  if n < 2:
    return n
  else:
    return fibonacci(n-2) + fibonacci(n-1)

# calculate fibonacci sequences four times in parallel

start_time, threads = time.time(), []

for i in range(4):
  threads.append(stem.util.system.DaemonTask(fibonacci, (35,), start = True))

for t in threads:
  t.join()

print('took %0.1f seconds' % (time.time() - start_time))
