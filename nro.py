from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from .generic_binary import *
from lz4.block import decompress

class NROView(GenericBinary):
    name       = 'NRO'
    long_name  = name
    base       = 0x7100000000
    entrypoint = base + 0x80
    MAGIC      = b"NRO0"
    HDR_SIZE   = 0

    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0x10, 4) == cls.MAGIC

    def __init__(self, data):
        super().__init__(data)

        self.reader.seek(0x20)
        self.text_offset   = self.reader.read32()
        self.text_size     = self.reader.read32()
        self.rodata_offset = self.reader.read32()
        self.rodata_size   = self.reader.read32()
        self.data_offset   = self.reader.read32()
        self.data_size     = self.reader.read32()
        self.bss_size      = self.reader.read32()

        self.reader.seek(self.text_offset)
        self.raw  = self.reader.read(self.text_size)
        self.reader.seek(self.rodata_offset)
        self.raw += self.reader.read(self.rodata_size)
        self.reader.seek(self.data_offset)
        self.raw += self.reader.read(self.data_size)

        data.write(0, self.raw)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
