import threading
import time

def fibonacci(n):
  if n < 2:
    return n
  else:
    return fibonacci(n-2) + fibonacci(n-1)

# calculate fibonacci sequences four times in parallel

start_time, threads = time.time(), []

for i in range(4):
  t = threading.Thread(target = fibonacci, args = (35,))
  t.setDaemon(True)
  t.start()

  threads.append(t)

for t in threads:
  t.join()

print('took %0.1f seconds' % (time.time() - start_time))
