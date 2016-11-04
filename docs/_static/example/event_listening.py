import curses
import functools

from stem.control import EventType, Controller
from stem.util import str_tools

# colors that curses can handle

COLOR_LIST = {
  "red": curses.COLOR_RED,
  "green": curses.COLOR_GREEN,
  "yellow": curses.COLOR_YELLOW,
  "blue": curses.COLOR_BLUE,
  "cyan": curses.COLOR_CYAN,
  "magenta": curses.COLOR_MAGENTA,
  "black": curses.COLOR_BLACK,
  "white": curses.COLOR_WHITE,
}

GRAPH_WIDTH = 40
GRAPH_HEIGHT = 8

DOWNLOAD_COLOR = "green"
UPLOAD_COLOR = "blue"

def main():
  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    try:
      # This makes curses initialize and call draw_bandwidth_graph() with a
      # reference to the screen, followed by additional arguments (in this
      # case just the controller).

      curses.wrapper(draw_bandwidth_graph, controller)
    except KeyboardInterrupt:
      pass  # the user hit ctrl+c

def draw_bandwidth_graph(stdscr, controller):
  window = Window(stdscr)

  # (downloaded, uploaded) tuples for the last 40 seconds

  bandwidth_rates = [(0, 0)] * GRAPH_WIDTH

  # Making a partial that wraps the window and bandwidth_rates with a function
  # for Tor to call when it gets a BW event. This causes the 'window' and
  # 'bandwidth_rates' to be provided as the first two arguments whenever
  # 'bw_event_handler()' is called.

  bw_event_handler = functools.partial(_handle_bandwidth_event, window, bandwidth_rates)

  # Registering this listener with Tor. Tor reports a BW event each second.

  controller.add_event_listener(bw_event_handler, EventType.BW)

  # Pause the main thread until the user hits any key... and no, don't you dare
  # ask where the 'any' key is. :P

  stdscr.getch()

def _handle_bandwidth_event(window, bandwidth_rates, event):
  # callback for when tor provides us with a BW event

  bandwidth_rates.insert(0, (event.read, event.written))
  bandwidth_rates = bandwidth_rates[:GRAPH_WIDTH]  # truncate old values
  _render_graph(window, bandwidth_rates)

def _render_graph(window, bandwidth_rates):
  window.erase()

  download_rates = [entry[0] for entry in bandwidth_rates]
  upload_rates = [entry[1] for entry in bandwidth_rates]

  # show the latest values at the top

  label = "Downloaded (%s/s):" % str_tools.size_label(download_rates[0], 1)
  window.addstr(0, 1, label, DOWNLOAD_COLOR, curses.A_BOLD)

  label = "Uploaded (%s/s):" % str_tools.size_label(upload_rates[0], 1)
  window.addstr(0, GRAPH_WIDTH + 7, label, UPLOAD_COLOR, curses.A_BOLD)

  # draw the graph bounds in KB

  max_download_rate = max(download_rates)
  max_upload_rate = max(upload_rates)

  window.addstr(1, 1, "%4i" % (max_download_rate / 1024), DOWNLOAD_COLOR)
  window.addstr(GRAPH_HEIGHT, 1, "   0", DOWNLOAD_COLOR)

  window.addstr(1, GRAPH_WIDTH + 7, "%4i" % (max_upload_rate / 1024), UPLOAD_COLOR)
  window.addstr(GRAPH_HEIGHT, GRAPH_WIDTH + 7, "   0", UPLOAD_COLOR)

  # draw the graph

  for col in range(GRAPH_WIDTH):
    col_height = GRAPH_HEIGHT * download_rates[col] / max(max_download_rate, 1)

    for row in range(col_height):
      window.addstr(GRAPH_HEIGHT - row, col + 6, " ", DOWNLOAD_COLOR, curses.A_STANDOUT)

    col_height = GRAPH_HEIGHT * upload_rates[col] / max(max_upload_rate, 1)

    for row in range(col_height):
      window.addstr(GRAPH_HEIGHT - row, col + GRAPH_WIDTH + 12, " ", UPLOAD_COLOR, curses.A_STANDOUT)

  window.refresh()

class Window(object):
  """
  Simple wrapper for the curses standard screen object.
  """

  def __init__(self, stdscr):
    self._stdscr = stdscr

    # Mappings of names to the curses color attribute. Initially these all
    # reference black text, but if the terminal can handle color then
    # they're set with that foreground color.

    self._colors = dict([(color, 0) for color in COLOR_LIST])

    # allows for background transparency

    try:
      curses.use_default_colors()
    except curses.error:
      pass

    # makes the cursor invisible

    try:
      curses.curs_set(0)
    except curses.error:
      pass

    # initializes colors if the terminal can handle them

    try:
      if curses.has_colors():
        color_pair = 1

        for name, foreground in COLOR_LIST.items():
          background = -1  # allows for default (possibly transparent) background
          curses.init_pair(color_pair, foreground, background)
          self._colors[name] = curses.color_pair(color_pair)
          color_pair += 1
    except curses.error:
      pass

  def addstr(self, y, x, msg, color = None, attr = curses.A_NORMAL):
    # Curses throws an error if we try to draw a message that spans out of the
    # window's bounds (... seriously?), so doing our best to avoid that.

    if color is not None:
      if color not in self._colors:
        recognized_colors = ", ".join(self._colors.keys())
        raise ValueError("The '%s' color isn't recognized: %s" % (color, recognized_colors))

      attr |= self._colors[color]

    max_y, max_x = self._stdscr.getmaxyx()

    if max_x > x and max_y > y:
      try:
        self._stdscr.addstr(y, x, msg[:max_x - x], attr)
      except:
        pass  # maybe an edge case while resizing the window

  def erase(self):
    self._stdscr.erase()

  def refresh(self):
    self._stdscr.refresh()

if __name__ == '__main__':
  main()
