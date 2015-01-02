import sys

PY27 = sys.version_info >= (2, 7)
PY3 = sys.version_info[0] >= 3
PY33 = sys.version_info >= (3, 3)
PY34 = sys.version_info >= (3, 4)

if PY3:
    str_type = str
else:
    str_type = unicode  # NOQA

if PY3:
    int_type = int
else:
    int_type = long  # NOQA
