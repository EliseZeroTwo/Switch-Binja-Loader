from binaryninja.architecture   import Architecture
from binaryninja.binaryview     import BinaryView, BinaryReader, BinaryWriter
from binaryninja.types          import Symbol
from binaryninja.enums          import Endianness, SegmentFlag, SectionSemantics, SymbolType
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

# https://github.com/reswitched/loaders/blob/30a2f1f1d6c997a46cc4225c1f443c19d21fc66c/nxo64.py#L123
(DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ,
 DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI, DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL,
 DT_RELSZ, DT_RELENT, DT_PLTREL, DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY,
 DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS) = range(31)
DT_GNU_HASH = 0x6ffffef5
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa
DT_FLAGS_1 = 0x6ffffffb
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

R_ARM_ABS32 = 2
R_ARM_TLS_DESC = 13
R_ARM_GLOB_DAT = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23

R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027
R_AARCH64_TLSDESC = 1031

MULTIPLE_DTS = set([DT_NEEDED])

class GenericBinary(BinaryView):
    MAGIC = b''
    HDR_SIZE = 0
    ARCH = 'aarch64'
    TEXT       = 0
    RODATA     = 1
    DATA       = 2
    BSS        = 3
    app_name = ''
    base = 0
    dynamic = { x: [] for x in MULTIPLE_DTS }
    dynamic_offset = 0
    dynstr = '\x00'
    eh_frame_hdr_size = 0
    eh_frame_hdr_start = 0
    hdr = b''
    hdr_read_offset = 0
    text_offset = 0
    text_size = 0
    reader = BinaryReader
    rodata_offset = 0
    rodata_size = 0
    data_offset = 0
    data_size = 0
    bss_offset = 0
    bss_size = 0
    writer = BinaryWriter

    def log(self, msg, error=False):
        msg = f'[Switch-Binja-Loader] {msg}'
        if not error:
            log_info(msg)
        else:
            log_error(msg)

    # Common Constructor
    def __init__(self, data):
        self.raw = data
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        self.writer = BinaryWriter(data, Endianness.LittleEndian)


    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0, 4) == cls.MAGIC

    def page_align_up(self, value):
        return (value + 0xfff) // 0x1000 * 0x1000
    
    def page_align_down(self, value):
        return value // 0x1000 * 0x1000
    
    def page_pad(self, binary):
        return binary + b'\x00' * (self.page_align_up(len(binary)) - len(binary))
    
    def up_signed(self, val, size):
        return unpack(LE + SIGNED_SIZE_MAP[size], val)[0]

    def make_section(self, name, offset, size):
        FLAGS = { '.text': SectionSemantics.ReadOnlyCodeSectionSemantics, '.rodata': SectionSemantics.ReadOnlyDataSectionSemantics }
        self.log(f"Making section {name} {hex(offset)}-{hex(offset + size)} (len: {hex(size)})")
        self.add_user_section(name, offset, size, FLAGS[name] if name in FLAGS else SectionSemantics.ReadWriteDataSectionSemantics)
    
    def make_segment(self, name, memory_offset, file_offset, size, empty=False):
        FLAGS = { '.text': SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable, '.rodata': SegmentFlag.SegmentReadable, \
                  '.data': SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable, '.bss': SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable }
        self.add_user_segment(memory_offset, size, file_offset, size if not empty else 0, FLAGS[name])
        self.make_section(name, memory_offset, size)
    
    def get_dynstr(self, o):
        return self.dynstr[o:self.dynstr.index(b'\x00', o)]

    def init(self):
        self.log(f'Loading {self.name} {self.app_name}')

        self.raw = b''
        self.platform = Architecture[self.ARCH].standalone_platform

        self.reader.seek(self.HDR_SIZE + 4)
        mod_offset = self.reader.read32()
        mod_file_offset = self.HDR_SIZE + mod_offset

        offset = self.HDR_SIZE
        self.make_segment('.text', self.base + self.text_offset, offset, self.text_size)
        offset += self.text_size

        self.make_segment('.rodata', self.base + self.rodata_offset, offset, self.rodata_size)
        offset += self.rodata_size

        self.make_segment('.data', self.base + self.data_offset, offset, self.data_size)
        offset += self.data_size

        self.reader.seek(mod_file_offset)
        if self.reader.read(4) != b'MOD0':
            self.log(f'MOD0(@ {hex(mod_offset)}) Magic invalid')
        else:
            self.log('Parsing MOD0')
            self.dynamic_offset = mod_offset + self.up_signed(self.reader.read(4), 4)
            dynamic_file_offset = self.HDR_SIZE + self.dynamic_offset
            if self.bss_offset == 0:
                self.bss_offset = mod_offset + self.up_signed(self.reader.read(4), 4)

            dynamic_size = self.bss_offset - self.dynamic_offset
            if self.bss_size == 0:
                bss_end = mod_offset + self.up_signed(self.reader.read(4), 4)
                self.bss_size = bss_end - self.bss_offset
            
            self.reader.seek(mod_file_offset + 0x10)
            self.eh_frame_hdr_start = mod_offset + self.up_signed(self.reader.read(4), 4)
            eh_frame_hdr_end = mod_offset + self.up_signed(self.reader.read(4), 4)
            self.eh_frame_hdr_size = eh_frame_hdr_end - self.eh_frame_hdr_start

            self.reader.seek(dynamic_file_offset)
            tag1 = self.reader.read64()
            self.reader.seek_relative(8)
            tag2 = self.reader.read64()
            self.reader.seek(dynamic_file_offset)
            armv7 = tag1 > 0xFFFFFFFF or tag2 > 0xFFFFFFFF

            self.reader.seek(dynamic_file_offset)
            for index in range(dynamic_size // 0x10):
                if armv7:
                    tag = self.reader.read32()
                    val = self.reader.read32()
                else:
                    tag = self.reader.read64()
                    val = self.reader.read64()

                if tag == DT_NULL:
                    break

                if tag in MULTIPLE_DTS:
                    self.dynamic[tag].append(val)
                else:
                    self.dynamic[tag] = val
            self.make_section('.dynamic', self.base + self.dynamic_offset, dynamic_size)

            if DT_STRTAB in self.dynamic and DT_STRSZ in self.dynamic:
                self.log("Reading .dynstr")
                self.reader.seek(self.HDR_SIZE + self.dynamic[DT_STRTAB])
                self.dynstr = self.reader.read(self.dynamic[DT_STRSZ])

            for start_key, size_key, name in [
                (DT_STRTAB, DT_STRSZ, '.dynstr'),
                (DT_INIT_ARRAY, DT_INIT_ARRAYSZ, '.init_array'),
                (DT_FINI_ARRAY, DT_FINI_ARRAYSZ, '.fini_array'),
                (DT_RELA, DT_RELASZ, '.rela.dyn'),
                (DT_REL, DT_RELSZ, '.rel.dyn'),
                (DT_JMPREL, DT_PLTRELSZ, ('.rel.plt' if armv7 else '.rela.plt')),
            ]:
                if start_key in self.dynamic and size_key in self.dynamic:
                    self.make_section(name, self.base + self.dynamic[start_key], self.dynamic[size_key])
            needed = [self.get_dynstr(i) for i in self.dynamic[DT_NEEDED]]
            
        self.bss_offset = self.bss_offset
        self.bss_size = self.page_align_up(self.bss_size)
        self.make_segment('.bss', self.base + self.bss_offset, 0, self.bss_size, empty=True)
        
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.base + self.text_offset, "_start"))
        self.add_entry_point(self.base + self.text_offset)

        return True