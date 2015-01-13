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
        start = sh.SectionData.find(boundary)
        start_rva = sh.VirtualAddress + start + struct.calcsize('<I') + 10
        end = sh.SectionData.rindex(boundary)
        # adjust junk code to jump to original entry
        sh.set_bytes_at_offset(start + struct.calcsize('<I'), struct.pack('<I', self.__binary.ImageBase + entry))

        # modify the entry point
        self.__binary.AddressOfEntryPoint = start_rva
        print '\t[*] PE entry(0x{0:x}) obfuscation completed.'.format(end - start - struct.calcsize('<I'))
        return True

    def __obfuscate_data(self):
        # get entry point virtual address
        entry = self.__binary.AddressOfEntryPoint

        data_shs = self.__binary.get_data_sections()
        boundary = struct.pack('<I', 0xbadbeef)
        for data_sh in data_shs:
            if data_sh.SectionData.count(boundary) != 2:
                continue
            start = data_sh.SectionData.index(boundary)
            data_sh.set_bytes_at_offset(start + struct.calcsize('<I'), struct.pack('<I', 0))
            lirange = data_sh.get_loader_irrelvant_range()
            data_size = self.__write_range(data_sh, lirange)
            self.__encrypt_section(data_sh, lambda x: x ^ 0xffffffff)
            break
        else:
            print 'No data section contains the boundary'
            return False
        # get index of the section which entry resides
        code_sh = self.__binary.get_section_header_by_rva(entry)
        start_rva = code_sh.VirtualAddress + start + struct.calcsize('<I') + 10
        code_sh.set_bytes_at_offset(start + struct.calcsize('<I'), struct.pack('<I', self.__binary.ImageBase + entry))

        # modify the entry point
        self.__binary.AddressOfEntryPoint = start_rva
        print '\t[*] PE data(0x{0:x}) obfuscation completed.'.format(data_size)
        return True

    def __encrypt_section(self, sh, encryptor):
        pass

    def __write_range(self, sh, range_data):
        return 0