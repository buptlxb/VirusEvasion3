# -*- coding: utf-8 -*-
from Structure import Structure
import struct


class HintNameTableEntry(Structure):

    def __init__(self):
        Structure.__init__(self)
        self.Hint = None
        self.Name = None
        self.Pad = None
        self.majorAttributes = ['Hint', 'Name', 'Pad']

    def parse(self, pe, fp):
        data = pe.data
        (self.Hint,) = struct.unpack_from('< H', data, fp)
        fp += struct.calcsize('< H')

        # A trailing zero-pad byte may be there, so bugs may be there.
        size = struct.calcsize('< 2s')
        name = []
        while True:
            (two_chars, ) = struct.unpack_from('< 2s', data, fp)
            fp += size
            name.append(two_chars)
            if two_chars[-1] == '\x00':
                if two_chars[0] == '\x00':
                    self.Name = ''.join(name)[:-1]
                    self.Pad = '\x00'
                else:
                    self.Name = ''.join(name)
                break

        return fp

    def __str__(self):
        return '{Hint:8d} {Name}'.format(Hint=self.Hint, Name=self.Name)


class ImportAddressTableEntry(Structure):

    IMPORT_ADDRESS_TABLE_ENTRY_FORMAT = '< I'

    def __init__(self):
        Structure.__init__(self)
        self.entry = None
        self.info = None

    def parse(self, pe, fp):
        data = pe.data
        (self.entry, ) = struct.unpack_from(ImportAddressTableEntry.IMPORT_ADDRESS_TABLE_ENTRY_FORMAT, data, fp)
        if self.entry and self.is_import_by_name():
            self.info = HintNameTableEntry()
            self.info.parse(pe, pe.rva2fp(self.entry))
        fp += struct.calcsize(ImportAddressTableEntry.IMPORT_ADDRESS_TABLE_ENTRY_FORMAT)
        return fp

    def __str__(self):
        if self.is_import_by_name():
            return str(self.info)
        else:
            return '{entry:8X}'.format(entry=self.entry)

    def is_import_by_ordinal(self):
        return self.entry & 0x80000000 == 1

    def is_import_by_name(self):
        return self.entry & 0x80000000 == 0


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
        self.importLookupTable = []
        self.importAddressTable = []
        self.name = None

    def parse(self, pe, fp):
        data = pe.data
        (self.ImportLookupTableRVA, self.TimeStamp, self.ForwardChain, self.NameRVA, self.ImportAddressTableRVA) = struct.unpack_from(ImportDirectoryTableEntry.IMPORT_DIRECTORY_TABLE_ENTRY_FORMAT, data, fp)

        if self.ImportAddressTableRVA:
            sub_fp = pe.rva2fp(self.ImportAddressTableRVA)
            while True:
                iate = ImportAddressTableEntry()
                sub_fp = iate.parse(pe, sub_fp)
                self.importAddressTable.append(iate)
                if iate.is_all_zero():
                    break

        if self.ImportLookupTableRVA:
            sub_fp = pe.rva2fp(self.ImportAddressTableRVA)
            while True:
                ilte = ImportAddressTableEntry()
                sub_fp = ilte.parse(pe, sub_fp)
                self.importLookupTable.append(ilte)
                if ilte.is_all_zero():
                    break

        if self.NameRVA:
            size = struct.calcsize('< s')
            name = []
            sub_fp = pe.rva2fp(self.NameRVA)
            while True:
                (char, ) = struct.unpack_from('< s', data, sub_fp)
                sub_fp += size
                name.append(char)
                if char == '\x00':
                    break
            self.name = ''.join(name)
        fp += struct.calcsize(ImportDirectoryTableEntry.IMPORT_DIRECTORY_TABLE_ENTRY_FORMAT)
        return fp

    def __str__(self):
        s = '{Name}\n\t' \
            '{IAT:8X} Import Address Table\n\t' \
            '{ILT:8X} Import Lookup Table\n\t' \
            '{Timestamp:8d} Timestamp\n\t' \
            '{ForwardChain:8d} Forward Chain\n\t' \
            '{NameRVA:8X} Name RVA\n\n'.format(Name=self.name, IAT=self.ImportAddressTableRVA, ILT=self.ImportLookupTableRVA, Timestamp=self.TimeStamp, ForwardChain=self.ForwardChain, NameRVA=self.NameRVA)
        tmp = [s]
        tmp.extend(['{x}\n'.format(x=str(x)) for x in self.importAddressTable])
        return ''.join(tmp)


class ImportDirectory(Structure):
    def __init__(self, data_directory):
        Structure.__init__(self)
        self.entrys = []
        self.data_directory = data_directory

    def parse(self, pe, fp):
        while True:
            idte = ImportDirectoryTableEntry()
            fp = idte.parse(pe, fp)
            self.entrys.append(idte)
            if idte.is_all_zero():
                break
        return fp

    def __str__(self):
        return '\n'.join([str(x) for x in self.entrys])