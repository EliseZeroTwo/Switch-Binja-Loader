from binaryninja.architecture   import Architecture
from binaryninja.binaryview     import BinaryView
from binaryninja.types          import Symbol
from binaryninja.enums          import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log            import log_error, log_info
from struct                     import *

U8_MAX  = 0xFF
U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF
U64_MAX = 0xFFFFFFFFFFFFFFFF

LE = '<'
BE = '>'
CHAR   = 'b'
BYTE   = 'B'
SHORT  = 'h'
USHORT = 'H'
INT    = 'i'
UINT   = 'I'
LONG   = 'q'
ULONG  = 'Q'

UNSIGNED_SIZE_MAP = { 1: BYTE, 2: USHORT, 4: UINT, 8: ULONG }
SIGNED_SIZE_MAP   = { 1: CHAR, 2: SHORT, 4: INT, 8: LONG }

class GenericBinary(BinaryView):
    MAGIC = ''
    HDR_SIZE = 0
    ARCH = 'aarch64'
    TEXT       = 0
    RODATA     = 1
    DATA       = 2
    BSS        = 3
    app_name = ''
    base = 0
    dynamic_offset = 0
    eh_frame_hdr_start = 0
    eh_frame_hdr_size = 0
    hdr = b''
    hdr_read_offset = 0
    text_offset = 0
    text_size = 0
    rodata_offset = 0
    rodata_size = 0
    data_offset = 0
    data_size = 0
    bss_offset = 0
    bss_size = 0

    def __init__(self, data):
        self.raw = data
        self.init_common()

    def init_common(self):
        self.hdr = self.raw.read(0, self.HDR_SIZE)

    @classmethod
    def is_valid_for_data(cls, data):
        magic = data.read(0, 4).decode('ascii')
        return magic == cls.MAGIC

    def page_align_up(self, value):
        return (value + 0xfff) // 0x1000 * 0x1000
    
    def page_align_down(self, value):
        return value // 0x1000 * 0x1000
    
    def page_pad(self, binary):
        return binary + b'\x00' * (self.page_align_up(len(binary)) - len(binary))

    def generic_read(self, data, size, offset, times=1, signed=False):
        ret = ''
        if size in UNSIGNED_SIZE_MAP:
            if signed:
                ret = unpack(LE + SIGNED_SIZE_MAP[size] * times, data[offset:offset + size * times])
            else:
                ret = unpack(LE + UNSIGNED_SIZE_MAP[size] * times, data[offset:offset + size * times])
        else:
            ret = data[offset:offset + size].decode('ascii')
            null_byte_offset = ret.find('\x00')
            if null_byte_offset != -1:
                ret = ret[:null_byte_offset]

        if type(ret) == tuple:
            return ret if times > 1 else ret[0]
        return ret
    
    def log(self, msg, error=False):
        msg = f'[Switch-Binja-Loader] {msg}'
        if not error:
            log_info(msg)
        else:
            log_error(msg)

    def hdr_read(self, size, times=1):
        self.hdr_read_offset += size
        return self.generic_read(self.hdr, size, self.hdr_read_offset - size, times=times)
    
    def hdr_write(self, size, offset, value):
        b = b''
        if type(value) == int:
            b = pack(LE + UNSIGNED_SIZE_MAP[size], value)
        else:
            raise Exception("Invalid type for hdr_write")
        tmp = list(self.hdr)
        tmp[offset:offset + size] = list(b)
        self.hdr = bytes(tmp)

    def init(self):
        self.log(f'Loading {self.name} {self.app_name}')

        self.platform = Architecture[self.ARCH].standalone_platform

        mod_offset = self.HDR_SIZE + self.generic_read(self.raw, 4, self.HDR_SIZE + 4)

        offset = self.HDR_SIZE
        self.text_offset = self.page_align_down(self.text_offset)
        self.text_size = self.page_align_up(self.text_size)
        self.log(f'Mapping .text {hex(self.text_offset)}-{hex(self.text_offset + self.text_size)}')
        self.add_user_segment(self.text_offset, self.text_size, offset, self.text_size, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
        self.add_user_section('.text', self.text_offset, self.text_size, SectionSemantics.ReadOnlyCodeSectionSemantics)
        offset += self.text_size

        self.rodata_offset = self.page_align_down(self.rodata_offset)
        self.rodata_size = self.page_align_up(self.rodata_size)
        self.log(f'Mapping .rodata {hex(self.rodata_offset)}-{hex(self.rodata_offset + self.rodata_size)}')
        self.add_user_segment(self.rodata_offset, self.rodata_size, offset, self.rodata_size, SegmentFlag.SegmentReadable)
        self.add_user_section('.rodata', self.rodata_offset, self.rodata_size, SectionSemantics.ReadOnlyDataSectionSemantics)
        offset += self.rodata_size

        self.data_offset = self.page_align_down(self.data_offset)
        self.data_size = self.page_align_up(self.data_size)
        self.log(f'Mapping .data {hex(self.data_offset)}-{hex(self.data_offset + self.data_size)}')
        self.add_user_segment(self.data_offset, self.data_size, offset, self.data_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_user_section('.data', self.data_offset, self.data_size, SectionSemantics.ReadWriteDataSectionSemantics)
        offset += self.data_size


        if self.raw[mod_offset:mod_offset + 4].decode('ascii') != 'MOD0':
            self.log(f'MOD0(@ {hex(mod_offset)}) Magic invalid')
        else:
            self.log('Parsing MOD0')
            self.dynamic_offset = self.generic_read(self.raw, 4, mod_offset + 0x4)
            if self.bss_offset == 0:
                self.bss_offset = self.base + mod_offset + self.generic_read(self.raw, 4, mod_offset + 0x8, signed=True)
            
            if self.bss_size == 0:
                self.bss_size = self.base + mod_offset + self.generic_read(self.raw, 4, mod_offset + 0xC, signed=True) - self.bss_offset
                self.raw += b'\x00' * self.bss_size
                
            self.eh_frame_hdr_start = mod_offset + self.generic_read(self.raw, 4, mod_offset + 0x10)
            eh_frame_hdr_end = mod_offset +self.generic_read(self.raw, 4, mod_offset + 0x14)
            self.eh_frame_hdr_size = self.eh_frame_hdr_start - eh_frame_hdr_end

        self.bss_offset = self.page_align_down(self.bss_offset)
        self.bss_size = self.page_align_up(self.bss_size)
        self.log(f'Mapping .bss {hex(self.bss_offset)}-{hex(self.bss_offset + self.bss_size)}')
        self.add_user_segment(self.bss_offset, self.bss_size, offset, self.bss_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_user_section('.bss', self.bss_offset, self.bss_size, SectionSemantics.ReadWriteDataSectionSemantics)
        
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.text_offset, "_start"))
        self.add_entry_point(self.text_offset)

        return True


        



