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

LE_BYTE  = '<B'
LE_SHORT = '<H'
LE_INT   = '<I'
LE_LONG  = '<Q'

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
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    def init_common(self):
        self.hdr = self.raw.read(0, self.HDR_SIZE)

    @classmethod
    def is_valid_for_data(cls, data):
        magic = data.read(0, 4).decode('ascii')
        if magic != cls.MAGIC:
            log_error("Magic not valid")
            return False
        return True

    def page_align_up(self, value):
        return (value + 0xfff) // 0x1000 * 0x1000
    
    def page_align_down(self, value):
        return value // 0x1000 * 0x1000
    
    def page_pad(self, binary):
        return binary + b'\x00' * (self.page_align_up(len(binary)) - len(binary))

    def generic_read(self, data, size, offset, raw=False):
        SIZE_MAP = { 1: LE_BYTE, 2: LE_SHORT, 4: LE_INT, 8: LE_LONG }
        ret = ''
        if raw:
            ret = data[offset:offset + size]
        else:
            if size in SIZE_MAP:
                ret = unpack(SIZE_MAP[size], data[offset:(offset + size)])[0]
            else:
                ret = data[offset:offset + size].decode('ascii')
                null_byte_offset = ret.find('\x00')
                if null_byte_offset != -1:
                    ret = ret[:null_byte_offset]
        
        return ret
    
    def log(self, msg):
        log_info(f'[Switch-Binja-Loader] {msg}')
    
    def hdr_read(self, size, raw=False):
        self.hdr_read_offset += size
        return self.generic_read(self.hdr, size, self.hdr_read_offset - size, raw)
    
    def hdr_write(self, size, offset, value):
        b = b''
        if type(value) == int:
            SIZE_MAP = { 1: LE_BYTE, 2: LE_SHORT, 4: LE_INT, 8: LE_LONG }
            b = pack(SIZE_MAP[size], value)
        else:
            raise Exception("Invalid type for hdr_write")
        tmp = list(self.hdr)
        tmp[offset:offset + size] = list(b)
        self.hdr = bytes(tmp)

    def init(self):
        self.log(f'Loading {self.name} {self.app_name}')

        self.platform = Architecture[self.ARCH].standalone_platform

        mod_offset = self.HDR_SIZE + self.generic_read(self.raw, 4, self.HDR_SIZE + 4)

        if self.generic_read(self.raw, 4, mod_offset, raw=True).decode('ascii') != 'MOD0':
            self.log(f'MOD0(@ {hex(mod_offset)}) Magic invalid')
        else:
            # TODO: Get Symbols
            self.log('Parsing MOD0')

        offset = self.HDR_SIZE
        self.log(f'Mapping .text {hex(self.text_offset)}-{hex(self.text_offset + self.text_size)}')
        self.add_user_segment(self.text_offset, self.text_size, offset, self.text_size, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
        self.add_user_section('.text', self.text_offset, self.text_size, SectionSemantics.ReadOnlyCodeSectionSemantics)
        offset += self.text_size

        self.log(f'Mapping .rodata {hex(self.rodata_offset)}-{hex(self.rodata_offset + self.text_size)}')
        self.add_user_segment(self.rodata_offset, self.rodata_size, offset, self.rodata_size, SegmentFlag.SegmentReadable)
        self.add_user_section('.rodata', self.rodata_offset, self.rodata_size, SectionSemantics.ReadOnlyDataSectionSemantics)
        offset += self.rodata_size

        self.log(f'Mapping .data {hex(self.data_offset)}-{hex(self.data_offset + self.data_size)}')
        self.add_user_segment(self.data_offset, self.data_size, offset, self.data_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_user_section('.data', self.data_offset, self.data_size, SectionSemantics.ReadWriteDataSectionSemantics)
        offset += self.data_size

        self.log(f'Mapping .bss {hex(self.bss_offset)}-{hex(self.bss_offset + self.bss_size)}')
        self.add_user_segment(self.bss_offset, self.bss_size, offset, self.bss_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_user_section('.bss', self.bss_offset, self.bss_size, SectionSemantics.ReadWriteDataSectionSemantics)
        
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.text_offset, "_start"))
        self.add_entry_point(self.text_offset)

        return True


        



