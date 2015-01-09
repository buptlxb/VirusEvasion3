#!/usr/bin/env python
import pe
import struct


class Core():
    def __init__(self, options):
        self.__options = options
        self.__binary = pe.PE(self.__options.binary)
        print '[+] Parsing PE file completed.'

    def __checks_before_manipulations(self):
        return self.__binary is not None

    def obfuscate(self):
        print '[+] Obfuscation start:'
        if not self.__checks_before_manipulations():
            return False
        if self.__options.entry and not self.__obfuscate_entry():
            return False
        if self.__options.data and not self.__obfuscate_data():
            return False
        print '[+] Obfuscation completed.'
        self.__binary.write(self.__options.output)
        print '[+] Writing new PE completed.'

        return True

    def __obfuscate_entry(self):
        # get entry point virtual address
        entry = self.__binary.AddressOfEntryPoint
        # get index of the section which entry resides
        sh = self.__binary.get_section_header_by_rva(entry)
        # get the relative virtual address of junk code
        boundary = struct.pack('<I', 0xbadbeef)
        if sh.SectionData.count(boundary) != 2:
            print 'Boundary (0xbadbeef) appears {num:d} times in the original file!'.format(num=sh.SectionData.count(boundary))
            exit(-1)
        start = sh.SectionData.index(boundary)
        start_rva = sh.VirtualAddress + start + 4
        # adjust junk code to jump to original entry
        end = sh.SectionData.rindex(boundary)
        sh.set_bytes_at_offset(end - 10, struct.pack('<I', self.__binary.ImageBase + entry))

        # modify the entry point
        self.__binary.AddressOfEntryPoint = start_rva
        print '\t[*] PE entry(0x{0:x}) obfuscation completed.'.format(end-start-4)
        return True

    def __obfuscate_data(self):
        data_size = 0
        print '\t[*] PE data(0x{0:x}) obfuscation completed.'.format(data_size)
        return True