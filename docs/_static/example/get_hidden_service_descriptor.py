from stem.control import Controller

with Controller.from_port(port = 9051) as controller:
  controller.authenticate()

  # descriptor of duck-duck-go's hidden service (http://3g2upl4pq6kufc4m.onion)

  print(controller.get_hidden_service_descriptor('3g2upl4pq6kufc4m'))
