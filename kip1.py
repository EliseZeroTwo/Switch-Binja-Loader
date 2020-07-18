from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info
from .generic_binary import *
from struct import *


# Taken from https://github.com/reswitched/loaders/blob/master/nxo64.py
def kip1_blz_decompress(compressed):
    iter_range = range
    bytes_to_list = lambda b: list(b)
    list_to_bytes = lambda l: bytes(l)
    compressed_size, init_index, uncompressed_addl_size = unpack('<III', compressed[-0xC:])
    decompressed = compressed[:] + b'\x00' * uncompressed_addl_size
    decompressed_size = len(decompressed)
    if len(compressed) != compressed_size:
        assert len(compressed) > compressed_size
        compressed = compressed[len(compressed) - compressed_size:]
    if not (compressed_size + uncompressed_addl_size):
        return b''
    compressed = bytes_to_list(compressed)
    decompressed = bytes_to_list(decompressed)
    index = compressed_size - init_index
    outindex = decompressed_size
    while outindex > 0:
        index -= 1
        control = compressed[index]
        for i in iter_range(8):
            if control & 0x80:
                if index < 2:
                    raise ValueError('Compression out of bounds!')
                index -= 2
                segmentoffset = compressed[index] | (compressed[index+1] << 8)
                segmentsize = ((segmentoffset >> 12) & 0xF) + 3
                segmentoffset &= 0x0FFF
                segmentoffset += 2
                if outindex < segmentsize:
                    raise ValueError('Compression out of bounds!')
                for j in iter_range(segmentsize):
                    if outindex + segmentoffset >= decompressed_size:
                        raise ValueError('Compression out of bounds!')
                    data = decompressed[outindex+segmentoffset]
                    outindex -= 1
                    decompressed[outindex] = data
            else:
                if outindex < 1:
                    raise ValueError('Compression out of bounds!')
                outindex -= 1
                index -= 1
                decompressed[outindex] = compressed[index]
            control <<= 1
            control &= 0xFF
            if not outindex:
                break
    return list_to_bytes(decompressed)


class KIPView(GenericBinary):
    name       = "KIP"
    long_name  = "Kernel Initialized Process"
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

        flags = self.hdr_read(1)
        compressed = []
        for segm in range(3):
            compressed.append(((flags >> segm) & 1) == 1)

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
        self.bss_offset       = self.base + self.hdr_read(4)
        self.bss_size         = self.hdr_read(4)
        
        text_raw = self.raw.read(0x100, text_bin_size)
        if compressed[self.TEXT]:
            self.log("Decompressing .text")
            text_raw = kip1_blz_decompress(text_raw)
            flags &= 0b0011_1110
            self.hdr_write(4, 0x24, self.page_align_up(self.text_size))
            self.hdr_write(4, 0x28, self.page_align_up(self.text_size))

        rodata_raw = self.raw.read(0x100 + text_bin_size, rodata_bin_size)
        if compressed[self.RODATA]:
            self.log("Decompressing .rodata")
            rodata_raw = kip1_blz_decompress(rodata_raw)
            flags &= 0b0011_1101
            self.hdr_write(4, 0x34, self.page_align_up(self.rodata_size))
            self.hdr_write(4, 0x38, self.page_align_up(self.rodata_size))


        data_raw = self.raw.read(0x100 + text_bin_size + rodata_bin_size, data_bin_size)
        if compressed[self.DATA]:
            self.log("Decompressing .data")
            data_raw = kip1_blz_decompress(data_raw)
            flags &= 0b0011_1011
            self.hdr_write(4, 0x44, self.page_align_up(self.data_size))
            self.hdr_write(4, 0x48, self.page_align_up(self.data_size))
        
        self.hdr_write(1, 0x1F, flags)

        binary  = self.hdr
        binary += self.page_pad(text_raw)
        binary += self.page_pad(rodata_raw)
        binary += self.page_pad(data_raw)
        binary += b'\x00' * self.bss_size

        self.raw = binary
        data.write(0, binary)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)