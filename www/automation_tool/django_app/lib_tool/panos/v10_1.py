# PAN-OS 10.1: same API and field rules as 11.1 until the differences are checked
from .v11_1 import PanOS11_1


class PanOS10_1(PanOS11_1):
    pass
