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
        obfuscation_num = [0]
        if self.__options.entry and not self.__obfuscate_entry(obfuscation_num):
            return False
        if self.__options.data and not self.__obfuscate_data(obfuscation_num):
            return False
        print '[+] {num:d} kinds of obfuscation completed.'.format(num=obfuscation_num[0])
        self.__binary.write(self.__options.output)
        print '[+] Writing new PE completed.'
        return True

    def __obfuscate_entry(self, ordinal):
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
        end = sh.SectionData.rindex(boundary)
        # adjust junk code to jump to original entry
        if ordinal[0] == 0:
            start_rva = sh.VirtualAddress + start + struct.calcsize('<I') + 10
            sh.set_bytes_at_offset(start + struct.calcsize('<I'), struct.pack('<I', self.__binary.ImageBase + entry))
            # modify the entry point
            self.__binary.AddressOfEntryPoint = start_rva

        ordinal[0] += 1
        print '\t[*] PE entry(0x{0:x}) obfuscation completed.'.format(end - start - struct.calcsize('<I'))
        return True

    def __obfuscate_data(self, ordinal):
        # get entry point virtual address
        entry = self.__binary.AddressOfEntryPoint
        # get data sections
        data_shs = self.__binary.get_data_sections()
        # TODO: Current boundary is hard-coded
        boundary = struct.pack('<I', 0xbadbeef)
        # obfuscation every data section
        for data_sh in data_shs:
            # Boundary in data section should appear exactly twice.
            if data_sh.SectionData.count(boundary) != 2:
                continue
            start = data_sh.SectionData.index(boundary)
            end = data_sh.SectionData.rindex(boundary)
            # clear the sentinel field, which is used to get the delta between preferred image base and real image base
            data_sh.set_bytes_at_offset(start + struct.calcsize('<I'), struct.pack('<I', 0))
            # overwrite part of data hole to store ranges to te decrypted in runtime
            data_size = self.__write_range(data_sh, data_sh, start + struct.calcsize('< 2I'), end - start - struct.calcsize('<I'))
            # TODO: Current encryptor is xor
            self.__encrypt_section(data_sh, lambda x: x ^ 0xff)
            break
        else:
            print 'No data section contains the boundary'
            return False
        # get index of the section which entry resides
        code_sh = self.__binary.get_section_header_by_rva(entry)
        code_start = code_sh.SectionData.find(boundary)
        # adjust junk code to return to the original entry if ordinal is zero
        if ordinal[0] == 0:
            start_rva = code_sh.VirtualAddress + code_start + struct.calcsize('<I') + 10
            code_sh.set_bytes_at_offset(code_start + struct.calcsize('<I'), struct.pack('<I', self.__binary.ImageBase + entry))
            # modify the entry point
            self.__binary.AddressOfEntryPoint = start_rva

        ordinal[0] += 1
        print '\t[*] PE data(0x{0:x}) obfuscation completed.'.format(data_size)
        return True

    def __encrypt_section(self, sh, encryptor):
        range_data = self.__binary.get_loader_irrelvant_range(sh)
        for rd in range_data:
            data = sh.get_bytes_at_offset(rd[0] - sh.VirtualAddress, rd[1])
            data = ''.join([chr(encryptor(ord(char))) for char in data])
            sh.set_bytes_at_offset(rd[0] - sh.VirtualAddress, data)

    def __write_range(self, data_sh, sh, offset, max_length):
        size = 0
        flat_range = []
        range_data = self.__binary.get_loader_irrelvant_range(sh)
        assert len(range_data) <= max_length >> 3, 'Range data is too large to be written to Data Section'

        for rd in range_data:
            size += rd[1]
            flat_range.extend([rd[0] + self.__binary.ImageBase, rd[1]])
        data = struct.pack('< {num:d}I'.format(num=len(flat_range)), *flat_range)
        data_sh.set_bytes_at_offset(offset, data)
        return size