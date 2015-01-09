# -*- coding: utf-8 -*-
from Structure import Structure
import struct


class ImportDirectoryTableEntry(Structure):

    IMPORT_DIRECTORY_TABLE_ENTRY_FORMAT = '< 5I'

    def __init__(self):
        Structure.__init__(self)
        self.ImportLookupTableRVA = None
        self.TimeStamp = None
        self.ForwardChain = None
        self.NameRVA = None
        self.ImportAddressTableRVA = None

        self.majorAttributes = ['ImportLookupTableRVA', 'TimeStamp', 'ForwardChain', 'NameRVA', 'ImportAddressTableRVA']

    def parse(self, data, fp):
        (self.ImportLookupTableRVA, self.TimeStamp, self.ForwardChain, self.NameRVA, self.ImportLookupTableRVA) = struct.unpack_from(data, fp)
        fp += struct.calcsize(ImportDirectoryTableEntry.IMPORT_DIRECTORY_TABLE_ENTRY_FORMAT)
        return fp