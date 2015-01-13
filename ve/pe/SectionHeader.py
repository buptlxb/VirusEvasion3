# -*- coding: utf-8 -*-
import struct
from Structure import Structure


class SectionHeader(Structure):
    SECTION_HEADER_FORMAT = '< 8s 6I 2H I'
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_MEM_FARDATA = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_ALIGN_MASK = 0x00F00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000L

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
        self.dataDirectories = []

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

    def is_data_section(self):
        return self.Characteristics & SectionHeader.IMAGE_SCN_MEM_WRITE == 1 and self.Characteristics & SectionHeader.IMAGE_SCN_MEM_READ == 1 and self.Characteristics & SectionHeader.IMAGE_SCN_CNT_INITIALIZED_DATA == 1

    def get_loader_irrelvant_range(self):
        return []

    def get_bytes_at_offset(self, offset, size):
        assert offset < self.SizeOfRawData, 'Offset {offset:X} exceeds {name} Section'.format(offset=offset, name=self.Name)
        return self.SectionData[offset:offset + size]