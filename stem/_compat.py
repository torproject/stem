import sys

PY27 = sys.version_info >= (2, 7)
PY3 = sys.version_info[0] >= 3
PY33 = sys.version_info >= (3, 3)
PY34 = sys.version_info >= (3, 4)

if PY3:
    unicode = str
else:
    unicode = unicode  # NOQA

if PY3:
    long = int
else:
    long = long  # NOQA
