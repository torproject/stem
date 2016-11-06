from stem.control import Controller
from flask import Flask

app = Flask(__name__)


@app.route('/')
def index():
  return "<h1>Hi Grandma!</h1>"


print(' * Connecting to tor')

with Controller.from_port() as controller:
  controller.authenticate()

  # Create a hidden service where visitors of port 80 get redirected to local
  # port 5000 (this is where Flask runs by default).

  response = controller.create_ephemeral_hidden_service({80: 5000}, await_publication = True)
  print(" * Our service is available at %s.onion, press ctrl+c to quit" % response.service_id)

  try:
    app.run()
  finally:
    print(" * Shutting down our hidden service")
