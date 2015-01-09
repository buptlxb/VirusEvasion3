# -*- coding: utf-8 -*-
import struct
from Structure import Structure


class SectionHeader(Structure):
    SECTION_HEADER_FORMAT = '< 8s 6I 2H I'

    def __init__(self):
        Structure.__init__(self)
        self.Name = None
        self.VirtualSize = None
        self.VirtualAddress = None
        self.SizeOfRawData = None
        self.PointerToRawData = None
        self.PointerToRelocations = None
        self.PointerToLinenumbers = None
        self.NumberOfRelocations = None
        self.NumberOfLinenumbers = None
        self.Characteristics = None

        self.SectionData = None

        self.majorAttributes = [
            'Name', 'VirtualSize', 'VirtualAddress', 'SizeOfRawData', 'PointerToRawData', 'PointerToRelocations',
            'PointerToLinenumbers', 'NumberOfRelocations', 'NumberOfLinenumbers', 'Characteristics'
        ]

    def parse(self, data, fp):
        (self.Name, self.VirtualSize, self.VirtualAddress, self.SizeOfRawData, self.PointerToRawData, self.PointerToRelocations, self.PointerToLinenumbers,
         self.NumberOfRelocations, self.NumberOfLinenumbers, self.Characteristics) = struct.unpack_from(SectionHeader.SECTION_HEADER_FORMAT, data, fp)
        fp += struct.calcsize(SectionHeader.SECTION_HEADER_FORMAT)

        self.SectionData = data[self.PointerToRawData:self.PointerToRawData + self.SizeOfRawData]
        return fp

    def serialize(self):
        data = struct.pack(SectionHeader.SECTION_HEADER_FORMAT, *(getattr(self, x) for x in self.majorAttributes))
        return data

    def set_bytes_at_offset(self, offset, data):
        if len(data) > self.SizeOfRawData - offset:
            self.modifyMsgs.append('Setting {num:d} bytes at offset {offset} of {section} Section failed: no enough space'.format(num=len(data), offset=offset, section=self.Name))
        else:
            old_data = self.SectionData[offset:offset + len(data)]
            self.modifyMsgs.append('Setting {num:d} bytes at offset {offset} of {section} Section: {old} -> {new}'.format(num=len(data), offset=offset, section=self.Name, old=old_data.encode('hex'), new=data.encode('hex')))
            self.SectionData = self.SectionData[:offset] + data + self.SectionData[offset + len(data):]