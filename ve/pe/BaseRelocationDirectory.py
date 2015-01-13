# -*- coding: utf-8 -*-
from Structure import Structure
import struct


class BaseRelocationDirectoryTableEntry(Structure):
    BASE_RELOCATION_DIRECTORY_TABLE_ENTRY_FORMAT = '< 2I'
    OFFSET_BITS_NUM = 12
    OFFSET_MASK = (1 << 12) - 1

    RELOCATION_TYPE = [
        'ABSOLUTE', 'HIGH', 'LOW', 'HIGHLOW', 'HIGHADJ', 'MIPS_JMPADDR', 'SECTION', 'REL', 'UNKNOWN', 'MIPS_JMPADDR16',
        'DIR64', 'HIGH3ADJ'
    ]

    def __init__(self):
        Structure.__init__(self)
        self.PageRVA = None
        self.BlockSize = None
        self.majorAttributes = ['PageRVA', 'BlockSize']
        self.items = None

    def parse(self, data, fp):
        (self.PageRVA, self.BlockSize) = struct.unpack_from(BaseRelocationDirectoryTableEntry.BASE_RELOCATION_DIRECTORY_TABLE_ENTRY_FORMAT, data, fp)
        size = struct.calcsize(BaseRelocationDirectoryTableEntry.BASE_RELOCATION_DIRECTORY_TABLE_ENTRY_FORMAT)
        self.items = struct.unpack_from('< {num}H'.format(num=self.BlockSize - size >> 1), data, fp + size)
        fp += self.BlockSize
        return fp

    def __str__(self):
        s = ['{RVA:X} RVA, {Size:8X} SizeOfBlock\n'.format(RVA=self.PageRVA, Size=self.BlockSize)]
        s.extend([' {Offset:3X}  {Type:<17s}  {Value:08X}\n'.format(
            Offset=x & BaseRelocationDirectoryTableEntry.OFFSET_MASK,
            Type=BaseRelocationDirectoryTableEntry.RELOCATION_TYPE[x >> BaseRelocationDirectoryTableEntry.OFFSET_BITS_NUM],
            Value=0) for x in self.items])
        return ''.join(s)


class BaseRelocationDirectory(Structure):
    def __init__(self, data_directory):
        Structure.__init__(self)
        self.entrys = []
        self.data_directory = data_directory

    def parse(self, data, fp):
        end_fp = fp + self.data_directory.Size
        while fp < end_fp:
            brdte = BaseRelocationDirectoryTableEntry()
            fp = brdte.parse(data, fp)
            self.entrys.append(brdte)
        assert fp == end_fp, 'Data Directory Size does not match the Base Relocation Directory'
        return fp

    def __str__(self):
        return ''.join([str(x) for x in self.entrys])