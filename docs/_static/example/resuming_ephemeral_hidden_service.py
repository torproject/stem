import os
from stem.control import Controller

key_path = os.path.expanduser('~/my_service_key')

with Controller.from_port() as controller:
  controller.authenticate()

  if not os.path.exists(key_path):
    service = controller.create_ephemeral_hidden_service({80: 5000}, await_publication = True)
    print("Started a new hidden service with the address of %s.onion" % service.service_id)

    with open(key_path, 'w') as key_file:
      key_file.write('%s:%s' % (service.private_key_type, service.private_key))
  else:
    with open(key_path) as key_file:
      key_type, key_content = key_file.read().split(':', 1)

    service = controller.create_ephemeral_hidden_service({80: 5000}, key_type = key_type, key_content = key_content, await_publication = True)
    print("Resumed %s.onion" % service.service_id)

  raw_input('press any key to shut the service down...')
  controller.remove_ephemeral_hidden_service(service.service_id)
