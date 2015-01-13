# -*- coding: utf-8 -*-
from Structure import Structure
import struct


class DataDirectory(Structure):
    DATA_DIRECTORY_FORMAT = '< 2I'

    def __init__(self):
        Structure.__init__(self)
        self.RVA = None
        self.Size = None
        self.majorAttributes = ['RVA', 'Size']
        self.section = None
        self.info = None

    def parse(self, data, fp):
        (self.RVA, self.Size) = struct.unpack_from(DataDirectory.DATA_DIRECTORY_FORMAT, data, fp)
        fp += struct.calcsize(DataDirectory.DATA_DIRECTORY_FORMAT)
        return fp

    def serialize(self):
        data = struct.pack(DataDirectory.DATA_DIRECTORY_FORMAT, *(getattr(self, x) for x in self.majorAttributes))
        return data