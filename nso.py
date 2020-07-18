from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from .generic_binary import *
from lz4.block import decompress
from struct import *

class NSOView(GenericBinary):
    name       = "NSO"
    long_name  = "Nintendo Static Object" # This is a guess at the name
    base = 0x7100000000
    MAGIC      = "NSO0"
    HDR_SIZE   = 0x100
    

    def __init__(self, data):
        super().__init__(data)
        
        self.hdr_read_offset = 0xC
        flags = self.hdr_read(4)

        compressed = []
        for segm in range(3):
            compressed.append(((flags >> segm) & 1) == 1)
        
        flags &= 0b0111

        self.hdr_read_offset = 0x10
        text_file_offset, self.text_offset, self.text_size = self.hdr_read(0x4, times=3)
        
        self.hdr_read_offset = 0x20
        rodata_file_offset, self.rodata_offset, self.rodata_size = self.hdr_read(0x4, times=3)
        
        self.hdr_read_offset = 0x30
        data_file_offset, self.data_offset, self.data_size, self.bss_size = self.hdr_read(0x4, times=4)
        
        self.hdr_read_offset = 0x60
        text_file_size, rodata_file_size, data_file_size = self.hdr_read(0x4, times=3)
        
        offset = self.HDR_SIZE
        text_raw = self.raw.read(text_file_offset, text_file_size)
        if compressed[self.TEXT]:
            self.log(f"Decompressing .text")
            text_raw = decompress(text_raw, uncompressed_size=self.text_size)
            flags &= 0b0011_1110
            self.hdr_write(4, 0x18, self.page_align_up(self.text_size))
            self.hdr_write(4, 0x60, self.page_align_up(self.text_size))
        
        self.hdr_write(4, 0x10, offset)
        offset += self.page_align_up(self.text_size)
        
        rodata_raw = self.raw.read(rodata_file_offset, rodata_file_size)
        if compressed[self.RODATA]:
            self.log("Decompressing .rodata")
            rodata_raw = decompress(rodata_raw, uncompressed_size=self.rodata_size)
            flags &= 0b0011_1101
            self.hdr_write(4, 0x28, self.page_align_up(self.rodata_size))
            self.hdr_write(4, 0x64, self.page_align_up(self.rodata_size))
        
        self.hdr_write(4, 0x20, offset)
        offset += self.page_align_up(self.rodata_size)
        
        data_raw = self.raw.read(data_file_offset, data_file_size)
        if compressed[self.DATA]:
            self.log("Decompressing .data")
            data_raw = decompress(data_raw, uncompressed_size=self.data_size)
            flags &= 0b0011_1011
            self.hdr_write(4, 0x38, self.page_align_up(self.data_size))
            self.hdr_write(4, 0x68, self.page_align_up(self.data_size))
        
        self.hdr_write(4, 0x30, offset)
        offset += self.page_align_up(self.data_size)

        self.hdr_write(1, 0xC, flags)

        binary  = self.hdr
        binary += self.page_pad(text_raw)
        binary += self.page_pad(rodata_raw)
        binary += self.page_pad(data_raw)
        binary += b'\x00' * self.page_align_up(self.bss_size)

        self.text_offset   += self.base
        self.rodata_offset += self.base
        self.data_offset   += self.base

        self.raw = binary
        data.write(0, binary)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)