from binaryninja.architecture   import Architecture
from binaryninja.binaryview     import BinaryView, BinaryReader, BinaryWriter
from binaryninja.demangle       import demangle_gnu3, get_qualified_name
from binaryninja.types          import Symbol, Type
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

# https://github.com/reswitched/loaders/blob/30a2f1f1d6c997a46cc4225c1f443c19d21fc66c/nxo64.py#249
class ElfSym(object):
    def __init__(self, name, info, other, shndx, value, size):
        self.name = name
        self.shndx = shndx
        self.value = value
        self.size = size

        self.vis = other & 3
        self.type = info & 0xF
        self.bind = info >> 4

    def __repr__(self):
        return 'Sym(name=%r, shndx=0x%X, value=0x%X, size=0x%X, vis=%r, type=%r, bind=%r)' % (
            self.name, self.shndx, self.value, self.size, self.vis, self.type, self.bind)

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
    bss_offset = 0
    bss_size = 0
    data_offset = 0
    data_size = 0
    dynamic = { }
    dynamic_offset = 0
    dynstr = b'\x00'
    entrypoint = 0
    eh_frame_hdr_size = 0
    eh_frame_hdr_start = 0
    hdr = b''
    hdr_read_offset = 0
    plt_entries = []
    reader = BinaryReader
    relocations = []
    rodata_offset = 0
    rodata_size = 0
    text_offset = 0
    text_size = 0
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

    def perform_get_address_size(self):
        return self.arch.address_size

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
    
    def process_relocations(self, offset, size):
        locations = set()
        self.reader.seek(self.HDR_SIZE + offset)
        relocation_size = 8 if self.armv7 else 0x18
        for x in range(size // relocation_size):
            if self.armv7:
                offset = self.reader.read32()
                info = self.reader.read32()
                addend = None
                r_type = info & 0xFF
                r_sym = info >> 8
            else:
                offset = self.reader.read64()
                info = self.reader.read64()
                addend = self.up_signed(self.reader.read(8), 8)
                r_type = info & 0xFFFFFFFF
                r_sym = info >> 32
            
            sym = self.syms[r_sym] if r_sym != 0 else None

            if r_type != R_AARCH64_TLSDESC and r_type != R_ARM_TLS_DESC:
                locations.add(offset)
            self.relocations.append((offset, r_type, sym, addend))
        return locations
    
    def try_unmangle(self, value):
        if value[:2] != b'_Z':
            return (None, value)

        decoded_name = value.decode('ascii')
        demangled_type, demangled_name = demangle_gnu3(Architecture[self.ARCH], decoded_name)
        decoded_name = get_qualified_name(demangled_name)
        return (demangled_type, decoded_name)
        

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
            self.module_offset = mod_offset + self.up_signed(self.reader.read(4), 4)

            libnx = False
            if self.reader.read(4) == b'LNY0':
                libnx = True
                libnx_got_start = mod_offset + self.up_signed(self.reader.read(4), 4)
                libnx_got_end   = mod_offset + self.up_signed(self.reader.read(4), 4)
                self.make_section('.got', self.base + libnx_got_start, libnx_got_end - libnx_got_start)

            self.reader.seek(dynamic_file_offset)
            tag1 = self.reader.read64()
            self.reader.seek(dynamic_file_offset + 0x10)
            tag2 = self.reader.read64()
            self.reader.seek(dynamic_file_offset)
            self.armv7 = tag1 > 0xFFFFFFFF or tag2 > 0xFFFFFFFF
            offset_size = 4 if self.armv7 else 8
            self.reader.seek(dynamic_file_offset)
            self.dynamic = { x: [] for x in MULTIPLE_DTS }
            for index in range(dynamic_size // 0x10):
                if self.armv7:
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
                (DT_JMPREL, DT_PLTRELSZ, ('.rel.plt' if self.armv7 else '.rela.plt')),
            ]:
                if start_key in self.dynamic and size_key in self.dynamic:
                    self.make_section(name, self.base + self.dynamic[start_key], self.dynamic[size_key])
            
            needed = [self.get_dynstr(i) for i in self.dynamic[DT_NEEDED]]
            
            self.syms = [] # symbols, symbols is already an attribute for BinaryView
            if DT_SYMTAB in self.dynamic and DT_STRTAB in self.dynamic:
                self.reader.seek(self.HDR_SIZE + self.dynamic[DT_SYMTAB])
                while True:
                    if self.dynamic[DT_SYMTAB] < self.dynamic[DT_STRTAB] and self.reader.offset - self.HDR_SIZE >= self.dynamic[DT_STRTAB]:
                        break

                    if self.armv7:
                        st_name = self.reader.read32()
                        st_value = self.reader.read32()
                        st_size = self.reader.read32()
                        st_info = self.reader.read8()
                        st_other = self.reader.read8()
                        st_shndx = self.reader.read16()
                    else:
                        st_name = self.reader.read32()
                        st_info = self.reader.read8()
                        st_other = self.reader.read8()
                        st_shndx = self.reader.read16()
                        st_value = self.reader.read64()
                        st_size = self.reader.read64()
                    
                    if st_name > len(self.dynstr):
                        break
                    
                    self.syms.append(ElfSym(self.get_dynstr(st_name), st_info, st_other, st_shndx, st_value, st_size))
                self.make_section('.dynsym', self.base + self.dynamic[DT_SYMTAB], (self.reader.offset - self.HDR_SIZE) - self.dynamic[DT_SYMTAB])
            
            locations = set()
            plt_got_end = None
            if DT_REL in self.dynamic and DT_RELSZ in self.dynamic:
                locations |= self.process_relocations(self.dynamic[DT_REL], self.dynamic[DT_RELSZ])
            
            if DT_RELA in self.dynamic and DT_RELASZ in self.dynamic:
                locations |= self.process_relocations(self.dynamic[DT_RELA], self.dynamic[DT_RELASZ])
            
            if DT_JMPREL in self.dynamic and DT_PLTRELSZ in self.dynamic:
                plt_locations = self.process_relocations(self.dynamic[DT_JMPREL], self.dynamic[DT_PLTRELSZ])
                locations |= plt_locations

                plt_got_start = min(plt_locations)
                plt_got_end = max(plt_locations) + offset_size
                if DT_PLTGOT in self.dynamic:
                    self.make_section('.got.plt', self.base + self.dynamic[DT_PLTGOT], plt_got_end - plt_got_start)

                if not self.armv7:
                    self.reader.seek(self.HDR_SIZE)
                    text = self.reader.read(self.text_size)
                    last = 12
                    while True: # This block was straight copy pasted from https://github.com/reswitched/loaders/blob/30a2f1f1d6c997a46cc4225c1f443c19d21fc66c/nxo64.py#L406
                        pos = text.find(pack('<I', 0xD61F0220), last)
                        if pos == -1: break
                        last = pos+1
                        if (pos % 4) != 0: continue
                        off = pos - 12
                        a, b, c, d = unpack_from('<IIII', text, off)
                        if d == 0xD61F0220 and (a & 0x9f00001f) == 0x90000010 and (b & 0xffe003ff) == 0xf9400211:
                            base = off & ~0xFFF
                            immhi = (a >> 5) & 0x7ffff
                            immlo = (a >> 29) & 3
                            paddr = base + ((immlo << 12) | (immhi << 14))
                            poff = ((b >> 10) & 0xfff) << 3
                            target = paddr + poff
                            if plt_got_start <= target < plt_got_end:
                                self.plt_entries.append((off, target))
                    text = b''
                    plt_start = min(self.plt_entries)[0]
                    plt_end = max(self.plt_entries)[0] + 0x10
                    self.make_section('.plt', self.base + plt_start, plt_end - plt_start)
                
                if not libnx:
                    if plt_got_end is not None:
                        got_ok = False
                        got_end = plt_got_end + offset_size
                        while got_end in locations and (DT_INIT_ARRAY not in self.dynamic or got_end < self.dynamic[DT_INIT_ARRAY]):
                            got_ok = True
                            got_end += offset_size

                        if got_ok:
                            self.make_section('.got', self.base + plt_got_end, got_end - plt_got_end)
            else:
                plt_got_start = 0
                plt_got_end = 0
                
        self.bss_offset = self.bss_offset
        self.bss_size = self.page_align_up(self.bss_size)
        self.make_segment('.bss', self.base + self.bss_offset, 0, self.bss_size, empty=True)
        
        undefined_count = 0
        for sym in self.syms:
            if not sym.shndx and sym.name:
                undefined_count += 1
        last_ea = max([self.base + seg.end for seg in self.segments])

        undef_ea = self.page_align_up(last_ea) + 8
        undef_offset = self.base + plt_got_start
        for idx, symbol in enumerate(self.syms):
            if symbol.name:
                symbol.resolved = self.base + symbol.value
                decoded_type, decoded_name = self.try_unmangle(symbol.name)
                
                if symbol.shndx:
                    if symbol.type == STT_FUNC:
                        self.create_user_function(symbol.resolved)
                        self.define_user_symbol(Symbol(SymbolType.FunctionSymbol, symbol.resolved, decoded_name))
                        
                        if decoded_type is not None:
                            self.get_function_at(symbol.resolved).set_user_type(decoded_type)
                    else:
                        if decoded_type is not None:
                            self.define_data_var(symbol.resolved, decoded_type)
                        self.define_user_symbol(Symbol(SymbolType.DataSymbol, symbol.resolved, decoded_name))
                else:
                    self.define_user_symbol(Symbol(SymbolType.ImportedFunctionSymbol, undef_ea, decoded_name))
                    undef_ea += offset_size

        got_name_lookup = {}
        for offset, r_type, symbol, addend in self.relocations:
            target = self.base + offset
            if symbol != None:            
                decoded_type, decoded_name = self.try_unmangle(symbol.name)
                if decoded_type != None:
                    self.define_data_var(target, Type.pointer(Architecture[self.ARCH], decoded_type))
                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, target, decoded_name))
            else:
                decoded_type = decoded_name = None
            
            packed = None
            offset_raw = None
            if r_type in [R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_ABS32]:
                if symbol:
                    offset_raw = symbol.resolved
                    packed = pack(LE + UNSIGNED_SIZE_MAP[4], offset_raw)
            elif r_type == R_ARM_RELATIVE:
                self.reader.seek(target)
                offset_raw = self.base + self.reader.read32()
                packed = pack(LE + UNSIGNED_SIZE_MAP[4], offset_raw)
            elif r_type in [R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64]:
                offset_raw = symbol.resolved + addend
                packed = pack(LE + UNSIGNED_SIZE_MAP[8], offset_raw)
                if addend == 0:
                    got_name_lookup[offset] = symbol.name
            elif r_type == R_AARCH64_RELATIVE:
                offset_raw = self.base + addend
                packed = pack(LE + UNSIGNED_SIZE_MAP[8], offset_raw)
            
            if packed is not None:
                if offset_raw != self.base and offset_raw != self.base + 0x10 and offset_raw < self.base + self.text_offset + self.text_size:
                    self.create_user_function(offset_raw)
                    if decoded_type is not None:
                        self.get_function_at(offset_raw).set_user_type(decoded_type)
                    self.write(target, packed)

        
        for func, target in self.plt_entries:
            if target in got_name_lookup:
                addr = self.base + func
                decoded_type, decoded_name = self.try_unmangle(got_name_lookup[target])
                self.define_user_symbol(Symbol(SymbolType.ImportedFunctionSymbol, addr, decoded_name))

        # Try to find entrypoint if not already set
        if self.entrypoint == 0:
            for sym in self.syms:
                if sym.name == b'_init':
                    self.entrypoint = sym.resolved
                    break
        if self.entrypoint != 0:
            self.add_entry_point(self.entrypoint)

        return True
