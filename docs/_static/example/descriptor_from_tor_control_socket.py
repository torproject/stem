from stem.control import Controller

with Controller.from_port(port = 9051) as controller:
  controller.authenticate()

  for desc in controller.get_network_statuses():
    print("found relay %s (%s)" % (desc.nickname, desc.fingerprint))
