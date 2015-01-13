# -*- coding: utf-8 -*-
import os
import mmap
import struct
import importlib

from PEException import *
from SectionHeader import SectionHeader
from Structure import Structure
from DataDirectory import DataDirectory
from BaseRelocationDirectory import BaseRelocationDirectoryTableEntry



class PE(Structure):
    data_directory_types = [
        ('DATA_DIRECTORY_EXPORT', 0),
        ('DATA_DIRECTORY_IMPORT', 1),
        ('DATA_DIRECTORY_RESOURCE', 2),
        ('DATA_DIRECTORY_EXCEPTION', 3),
        ('DATA_DIRECTORY_SECURITY', 4),
        ('DATA_DIRECTORY_BASE_RELOCATION', 5),
        ('DATA_DIRECTORY_DEBUG', 6),
        ('DATA_DIRECTORY_COPYRIGHT', 7),  # Architecture on non-x86 platforms
        ('DATA_DIRECTORY_GLOBAL_PTR', 8),
        ('DATA_DIRECTORY_TLS', 9),
        ('DATA_DIRECTORY_LOAD_CONFIG', 10),
        ('DATA_DIRECTORY_BOUND_IMPORT', 11),
        ('DATA_DIRECTORY_IAT', 12),
        ('DATA_DIRECTORY_DELAY_IMPORT', 13),
        ('DATA_DIRECTORY_COM_DESCRIPTOR', 14),
        ('DATA_DIRECTORY_RESERVED', 15)]

    DATA_DIRECTORY_DICT = dict([(e[1], e[0]) for e in data_directory_types] + data_directory_types)

    COFF_FILE_HEADER_FORMAT = '< 2H 3I 2H'

    OPTIONAL_HEADER_FORMAT = '< H 2B 9I 6H 4I 2H 6I'

    FILE_OFFSET_TO_PE_SIGNATURE = 0x3c

    def __init__(self, filename):
        Structure.__init__(self)
        # COFF File Header
        self.Machine = None
        self.NumberOfSections = None
        self.TimeDateStamp = None
        self.PointerToSymbolTable = None
        self.NumberOfSymbols = None
        self.SizeOfOptionalHeader = None
        self.Characteristics = None

        # Optional Header
        self.Magic = None
        self.MajorLinkerVersion = None
        self.MinorLinkerVersion = None
        self.SizeOfCode = None
        self.SizeOfInitializedData = None
        self.SizeOfUninitializedData = None
        self.AddressOfEntryPoint = None
        self.BaseOfCode = None
        self.BaseOfData = None
        self.ImageBase = None
        self.SectionAlignment = None
        self.FileAlignment = None
        self.MajorOperatingSystemVersion = None
        self.MinorOperatingSystemVersion = None
        self.MajorImageVersion = None
        self.MinorImageVersion = None
        self.MajorSubsystemVersion = None
        self.MinorSubsystemVersion = None
        self.Reserved = None
        self.SizeOfImage = None
        self.SizeOfHeaders = None
        self.CheckSum = None
        self.Subsystem = None
        self.DLLCharacteristics = None
        self.SizeOfStackReserve = None
        self.SizeOfStackCommit = None
        self.SizeOfHeapReserve = None
        self.SizeOfHeapCommit = None
        self.LoaderFlags = None
        self.NumberOfRvaAndSizes = None

        self.majorAttributes = [
            'Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader',
            'Characteristics', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
            'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
            'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
            'MajorSubsystemVersion', 'MinorSubsystemVersion', 'Reserved', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum',
            'Subsystem', 'DLLCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
            'LoaderFlags', 'NumberOfRvaAndSizes'
        ]

        # Data Directories
        self.DataDirectories = []

        # SectionHeaders
        self.SectionHeaders = []

        self.data = None
        self.fileName = filename
        self.fileno = None
        self.size = None
        self.parseMsgs = []
        self.serializeMsgs = []

        self.__load__(self.fileName)
        self.parse()

    def __load__(self, filename):
        if filename:
            stat = os.stat(filename)
            if stat.st_size == 0:
                raise PEFormatError('The file is empty')
            try:
                self.size = stat.st_size
                fd = file(filename, 'rb')
                self.fileno = fd.fileno()
                if hasattr(mmap, 'MAP_PRIVATE'):
                    # Unix
                    self.data = mmap.mmap(self.fileno, 0, mmap.MAP_PRIVATE)
                else:
                    # Windows
                    self.data = mmap.mmap(self.fileno, 0, access=mmap.ACCESS_READ)
            finally:
                fd.close()

    def __parse_dos_header(self):
        fp, = struct.unpack_from('I', self.data, PE.FILE_OFFSET_TO_PE_SIGNATURE)
        self.parseMsgs.append('File pointer at {offset} is 0x{fp:x}'.format(offset=PE.FILE_OFFSET_TO_PE_SIGNATURE, fp=fp))
        signature, = struct.unpack_from('4s', self.data, fp)
        self.parseMsgs.append('Signature at 0x{fp:x} is {signature}'.format(fp=fp, signature=repr(signature)))
        if signature != 'PE\x00\x00':
            raise PEException('The file is not a PE file!')
        fp += 4
        return fp

    def __parse_coff_header(self, fp):
        pending_msg = 'Parsing COFF File Header from 0x{fp:x} ... '.format(fp=fp)
        (self.Machine, self.NumberOfSections, self.TimeDateStamp, self.PointerToSymbolTable, self.NumberOfSymbols, self.SizeOfOptionalHeader,
         self.Characteristics) = struct.unpack_from(PE.COFF_FILE_HEADER_FORMAT, self.data, fp)
        size = struct.calcsize(PE.COFF_FILE_HEADER_FORMAT)
        pending_msg += ' {size:d} bytes done'.format(size=size)
        self.parseMsgs.append(pending_msg)
        fp += size
        return fp

    def __parse_optional_header(self, fp):
        pending_msg = 'Parsing Optional Header from 0x{fp:x} ... '.format(fp=fp)
        (self.Magic, self.MajorLinkerVersion, self.MinorLinkerVersion, self.SizeOfCode, self.SizeOfInitializedData, self.SizeOfUninitializedData,
         self.AddressOfEntryPoint, self.BaseOfCode, self.BaseOfData, self.ImageBase, self.SectionAlignment, self.FileAlignment,
         self.MajorOperatingSystemVersion, self.MinorOperatingSystemVersion, self.MajorImageVersion, self.MinorImageVersion, self.MajorSubsystemVersion,
         self.MinorSubsystemVersion, self.Reserved, self.SizeOfImage, self.SizeOfHeaders, self.CheckSum, self.Subsystem, self.DLLCharacteristics,
         self.SizeOfStackReserve, self.SizeOfStackCommit, self.SizeOfHeapReserve, self.SizeOfHeapCommit, self.LoaderFlags,
         self.NumberOfRvaAndSizes) = struct.unpack_from(PE.OPTIONAL_HEADER_FORMAT, self.data, fp)
        size = struct.calcsize(PE.OPTIONAL_HEADER_FORMAT)
        fp += size

        class_names = {PE.DATA_DIRECTORY_DICT['DATA_DIRECTORY_BASE_RELOCATION']: 'BaseRelocationDirectory'}
        for i in range(self.NumberOfRvaAndSizes):
            data_directory = DataDirectory()
            fp = data_directory.parse(self.data, fp)
            class_name = class_names.get(i, None)
            if class_name is not None:
                m = importlib.import_module('ve.pe.{0}'.format(class_name))
                c = getattr(m, class_name)
                data_directory.info = c(data_directory)
            self.DataDirectories.append(data_directory)
        size += struct.calcsize(DataDirectory.DATA_DIRECTORY_FORMAT) * self.NumberOfRvaAndSizes
        pending_msg += ' {size:d} bytes done'.format(size=size)
        self.parseMsgs.append(pending_msg)
        return fp

    def __parse_section_header(self, fp):
        pending_msg = 'Parsing {num:d} Section Headers from 0x{fp:x} ... '.format(num=self.NumberOfSections, fp=fp)
        for i in range(self.NumberOfSections):
            section_header = SectionHeader()
            fp = section_header.parse(self.data, fp)
            self.SectionHeaders.append(section_header)
        pending_msg += '{size:d}*{num:d} bytes done'.format(size=struct.calcsize(SectionHeader.SECTION_HEADER_FORMAT), num=self.NumberOfSections)
        self.parseMsgs.append(pending_msg)
        return fp

    def __parse_data_directory(self):
        for section_header in self.SectionHeaders:
            section_header.dataDirectories = [x for x in self.DataDirectories if section_header.VirtualAddress <= x.RVA and section_header.VirtualAddress + section_header.VirtualSize >= x.RVA + x.Size]
            for dd in section_header.dataDirectories:
                dd.section = section_header
                if dd.info is not None:
                    dd.info.parse(self.data, self.rva2fp(dd.RVA))

    def parse(self):
        # base parser
        fp = self.__parse_dos_header()
        fp = self.__parse_coff_header(fp)
        fp = self.__parse_optional_header(fp)
        fp = self.__parse_section_header(fp)
        # re-parser
        self.__parse_data_directory()

        return fp

    def __serialize_dos_header(self):
        fp, = struct.unpack_from('I', self.data, PE.FILE_OFFSET_TO_PE_SIGNATURE)
        fp += 4
        data = self.data[:fp]
        self.serializeMsgs.append('Serializing Dos Header to 0x0 ...  {size:d} bytes done'.format(size=fp))
        return data, fp

    def __serialize_coff_header(self, data, fp):
        pending_msg = 'Serializing COFF File Header to 0x{fp:x} ... '.format(fp=fp)
        data += struct.pack(PE.COFF_FILE_HEADER_FORMAT, self.Machine, self.NumberOfSections, self.TimeDateStamp, self.PointerToSymbolTable,
                            self.NumberOfSymbols, self.SizeOfOptionalHeader, self.Characteristics)
        size = struct.calcsize(PE.COFF_FILE_HEADER_FORMAT)
        fp += size
        pending_msg += ' {size:d} bytes done'.format(size=size)
        self.serializeMsgs.append(pending_msg)
        return data, fp

    def __serialize_optional_header(self, data, fp):
        pending_msg = 'Serializing Optional Header to 0x{fp:x} ... '.format(fp=fp)
        data += struct.pack(PE.OPTIONAL_HEADER_FORMAT, self.Magic, self.MajorLinkerVersion, self.MinorLinkerVersion, self.SizeOfCode,
                            self.SizeOfInitializedData, self.SizeOfUninitializedData,
                            self.AddressOfEntryPoint, self.BaseOfCode, self.BaseOfData, self.ImageBase, self.SectionAlignment, self.FileAlignment,
                            self.MajorOperatingSystemVersion, self.MinorOperatingSystemVersion, self.MajorImageVersion, self.MinorImageVersion,
                            self.MajorSubsystemVersion,
                            self.MinorSubsystemVersion, self.Reserved, self.SizeOfImage, self.SizeOfHeaders, self.CheckSum, self.Subsystem,
                            self.DLLCharacteristics,
                            self.SizeOfStackReserve, self.SizeOfStackCommit, self.SizeOfHeapReserve, self.SizeOfHeapCommit, self.LoaderFlags,
                            self.NumberOfRvaAndSizes)
        size = struct.calcsize(PE.OPTIONAL_HEADER_FORMAT)
        for data_directory in self.DataDirectories:
            data += data_directory.serialize()
            size += struct.calcsize(DataDirectory.DATA_DIRECTORY_FORMAT)
        fp += size
        pending_msg += ' {size:d} bytes done'.format(size=size)
        self.serializeMsgs.append(pending_msg)
        return data, fp

    def __serialize_section_header(self, data, fp):
        pending_msg = 'Serializing Section Header to 0x{fp:x} ... '.format(fp=fp)
        size = 0
        for section_header in self.SectionHeaders:
            data += section_header.serialize()
            size += struct.calcsize(SectionHeader.SECTION_HEADER_FORMAT)
            fp += struct.calcsize(SectionHeader.SECTION_HEADER_FORMAT)
        size += self.SectionHeaders[0].PointerToRawData - fp
        data += '\x00' * (self.SectionHeaders[0].PointerToRawData - fp)
        fp = self.SectionHeaders[0].PointerToRawData
        pending_msg += ' {size:d} bytes done'.format(size=size)
        self.serializeMsgs.append(pending_msg)
        return data, fp

    def __serialize_section_data(self, data, fp):
        for section_header in self.SectionHeaders:
            pending_msg = 'Serializing Section Data to 0x{fp:x} ... '.format(fp=fp)
            assert fp == section_header.PointerToRawData, "Incorrect serialization location"
            data += section_header.SectionData
            fp += section_header.SizeOfRawData
            pending_msg += ' {size:d} bytes done'.format(size=section_header.SizeOfRawData)
            self.serializeMsgs.append(pending_msg)
        return data, fp

    def serialize(self):
        data, fp = self.__serialize_dos_header()
        data, fp = self.__serialize_coff_header(data, fp)
        data, fp = self.__serialize_optional_header(data, fp)
        data, fp = self.__serialize_section_header(data, fp)
        data, fp = self.__serialize_section_data(data, fp)
        assert fp == self.size
        return data

    def write(self, filename):
        with open(filename, 'wb') as out:
            out.write(self.serialize())

    def rva2fp(self, rva):
        fp = []
        for sh in self.SectionHeaders:
            if sh.VirtualAddress <= rva <= sh.VirtualAddress + sh.VirtualSize:
                offset = rva - sh.VirtualAddress
                if offset < sh.SizeOfRawData:
                    fp.append(offset + sh.PointerToRawData)
        assert len(fp) == 1
        return fp[0]

    def fp2rva(self, fp):
        rva = []
        for sh in self.SectionHeaders:
            if sh.PointerToRawData <= fp < sh.PointerToRawData + sh.SizeOfRawData:
                offset = fp - sh.PointerToRawData
                if offset < sh.VirtualSize:
                    rva.append(offset + sh.VirtualAddress)
        assert len(rva) == 1
        return rva[0]

    def get_section_header_by_rva(self, rva):
        for sh in self.SectionHeaders:
            if sh.VirtualAddress <= rva < sh.VirtualAddress + sh.VirtualSize:
                return sh
        else:
            return None

    def get_data_sections(self):
        return [sh for sh in self.SectionHeaders if sh.is_data_section()]

    def dump_modify_msgs(self):
        for msg in self.modifyMsgs:
            print msg
        for sh in self.SectionHeaders:
            sh.dump_modify_msgs()
        for dd in self.DataDirectories:
            dd.dump_modify_msgs()

    def get_loader_irrelvant_range(self, sh):
        if sh.loaderIrrelvantRange is None:
            assert self.SectionAlignment == 0x1000, 'Section Alignment is not 0x1000'
            base_relocation_directory = self.DataDirectories[PE.DATA_DIRECTORY_DICT['DATA_DIRECTORY_BASE_RELOCATION']].info
            fixup_rva = [block.PageRVA + BaseRelocationDirectoryTableEntry.offset(item)
                         for block in base_relocation_directory.entrys if sh.VirtualAddress <= block.PageRVA < sh.VirtualAddress + sh.VirtualSize
                         for item in block.items if item != 0]
            fixup_rva.sort()
            lirange = [[sh.VirtualAddress, sh.VirtualSize]]
            for rva in fixup_rva:
                for i in range(len(lirange)):
                    start = lirange[i][0]
                    size = lirange[i][1]
                    if start < rva < start + size:
                        lirange[i][1] = rva - start
                        if size > 4:
                            new_start = rva + 4
                            new_size = start + size - new_start
                            lirange.append([new_start, new_size])
                        break
                    elif start == rva:
                        if size > 4:
                            lirange[i][0] += 4
                            lirange[i][1] -= 4
                        elif size == 4:
                            del lirange[i]
                        else:
                            print "Warning: loader irrelevant range size is less than 4."
                        break
            sh.loaderIrrelvantRange = lirange

        return sh.loaderIrrelvantRange

if __name__ == "__main__":
    pe = PE(r'C:\Users\ICT-LXB\Desktop\asm-test\hello\hello.EXE')

    print pe

    pe.write(r'C:\Users\ICT-LXB\Desktop\asm-test\hello\tmp.EXE')
    pe.dump_modify_msgs()

    print pe.DataDirectories[PE.DATA_DIRECTORY_DICT['DATA_DIRECTORY_BASE_RELOCATION']].info
    print pe.get_loader_irrelvant_range(pe.SectionHeaders[0])