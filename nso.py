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
    base       = 0x7100000000
    MAGIC      = b"NSO0"
    HDR_SIZE   = 0x100
    

    def __init__(self, data):
        super().__init__(data)
        
        self.reader.seek(0xC)
        flags = self.reader.read32()

        compressed = []
        for segm in range(3):
            compressed.append(((flags >> segm) & 1) == 1)
        
        flags &= 0b0111

        self.reader.seek(0x10)
        text_file_offset = self.reader.read32()
        self.text_offset = self.reader.read32()
        self.text_size = self.reader.read32()
        
        self.reader.seek(0x20)
        rodata_file_offset = self.reader.read32()
        self.rodata_offset = self.reader.read32()
        self.rodata_size = self.reader.read32()
        
        self.reader.seek(0x30)
        data_file_offset = self.reader.read32()
        self.data_offset = self.reader.read32()
        self.data_size = self.reader.read32()
        self.bss_size = self.reader.read32()
        
        self.reader.seek(0x60)
        text_file_size = self.reader.read32()
        rodata_file_size = self.reader.read32()
        data_file_size = self.reader.read32()
        
        offset = self.HDR_SIZE
        self.reader.seek(text_file_offset)
        text_raw = self.reader.read(text_file_size)
        if compressed[self.TEXT]:
            self.log(f"Decompressing .text")
            text_raw = decompress(text_raw, uncompressed_size=self.text_size)
        
        flags &= 0b0011_1110
        text_raw = self.page_pad(text_raw)
        self.text_size = len(text_raw)
        self.writer.seek(0x18)
        self.writer.write32(self.text_size)
        self.writer.seek(0x60)
        self.writer.write32(self.text_size)

        self.writer.seek(0x10)
        self.writer.write32(offset)
        offset += self.text_size
        
        self.reader.seek(rodata_file_offset)
        rodata_raw = self.reader.read(rodata_file_size)
        if compressed[self.RODATA]:
            self.log("Decompressing .rodata")
            rodata_raw = decompress(rodata_raw, uncompressed_size=self.rodata_size)

        flags &= 0b0011_1101
        rodata_raw = self.page_pad(rodata_raw)
        self.rodata_size = len(rodata_raw)
        self.writer.seek(0x28)
        self.writer.write32(self.rodata_size)
        self.writer.seek(0x64)
        self.writer.write32(self.rodata_size)

        self.writer.seek(0x20)
        self.writer.write32(offset)
        offset += self.rodata_size
        
        self.reader.seek(data_file_offset)
        data_raw = self.reader.read(data_file_size)
        if compressed[self.DATA]:
            self.log("Decompressing .data")
            data_raw = decompress(data_raw, uncompressed_size=self.data_size)
        
        flags &= 0b0011_1011
        data_raw = self.page_pad(data_raw)
        self.data_size = len(data_raw)
        self.writer.seek(0x38)
        self.writer.write32(self.data_size)
        self.writer.seek(0x68)
        self.writer.write32(self.data_size)
        
        self.writer.seek(0x30)
        self.writer.write32(offset)
        offset += self.data_size

        self.writer.seek(0xC)
        self.writer.write8(flags)

        self.reader.seek(0)
        self.raw  = self.reader.read(self.HDR_SIZE)
        self.raw += text_raw
        self.raw += rodata_raw
        self.raw += data_raw

        text_raw = b''
        rodata_raw = b''
        data_raw = b''

        data.write(0, self.raw)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)