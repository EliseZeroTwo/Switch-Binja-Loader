from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info
from .generic_binary import *
from struct import *

class SegmentHeader():
    offset      = 0
    memory_size = 0
    binary_size = 0
    attrtibute  = 0

    _memory_offset = 0


class KIPView(GenericBinary):
    name       = "KIP"
    long_name  = "Kernel Initialized Process"
    compressed = [False, False, False, False]
    base = 0x7100000000
    MAGIC      = "KIP1"
    HDR_SIZE   = 0x100
    

    def __init__(self, data):
        self.raw = data
        self.init_common()

        self.hdr_read_offset = 0x4
        self.app_name        = self.hdr_read(0xC)
        self.titleID         = self.hdr_read(0x8)
        self.hdr_read_offset = 0x1F

        self.flags = self.hdr_read(1)
        for segm in range(3):
            self.compressed[segm] = ((self.flags >> segm) & 1) == 1

        offset                = 0
        self.text_offset      = self.base + self.hdr_read(4)
        self.text_size        = self.hdr_read(4)
        text_bin_size         = self.hdr_read(4)
        self.hdr_read_offset += 4
        self.rodata_offset    = self.base + self.hdr_read(4)
        self.rodata_size      = self.hdr_read(4)
        rodata_bin_size       = self.hdr_read(4)
        self.hdr_read_offset += 4
        self.data_offset      = self.base + self.hdr_read(4)
        self.data_size        = self.hdr_read(4)
        data_bin_size         = self.hdr_read(4)
        self.hdr_read_offset += 4
        self.bss_offset       = self.hdr_read(4)
        self.bss_size         = self.hdr_read(4)

        binary  = self.page_pad(self.raw.read(0x100, text_bin_size))                                   # Read .text
        binary += self.page_pad(self.raw.read(0x100 + text_bin_size, rodata_bin_size))                 # Read .rodata
        binary += self.page_pad(self.raw.read(0x100 + text_bin_size + rodata_bin_size, data_bin_size)) # Read .data
        binary += b'\x00' * self.bss_size                                                              # Add .bss

        replacement_parent = BinaryView.new(data=binary)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=replacement_parent)
        self.binary = binary