#!/usr/bin/env python3
from __future__ import print_function
import argparse
import bisect
import pefile
import struct
import math
import sys
import os
import re
from progressbar import * 
import traceback

widgets = ['Progress: ', Percentage(), ' ', Bar(marker='#',left='[',right=']'), ' ', ETA()] #see docs for other options

pe=None
args=None
ida=None
code_loc = None

p64 = lambda v: struct.pack('<Q', v)
p32 = lambda v: struct.pack('<I', v)
p16 = lambda v: struct.pack('<H', v)
u64 = lambda v: struct.unpack('<Q', v)[0]
u32 = lambda v: struct.unpack('<I', v)[0]
u16 = lambda v: struct.unpack('<H', v)[0]
new_name = lambda s: s.Name.strip(b'\x00')[:-1]+b'2'
align_sec = lambda v: int(math.ceil(v / float(pe.OPTIONAL_HEADER.SectionAlignment))) * pe.OPTIONAL_HEADER.SectionAlignment
align_file = lambda v: int(math.ceil(v / float(pe.OPTIONAL_HEADER.FileAlignment))) * pe.OPTIONAL_HEADER.FileAlignment
check32 = lambda v: -0x80000000 <= v < 0x80000000
check64 = lambda v: -0x8000000000000000 <= v < 0x8000000000000000
is_exe = lambda s: bool(s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) if hasattr(s, 'Characteristics') else False
is_driver = lambda s: '.sys' in s or 'ntoskrnl' in s
is_32 = lambda : True if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else False
is_64 = lambda : True if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else False
strrep = lambda s1, idx, s2: s1[:idx] + s2 + s1[idx+len(s2):]
va2rva = lambda v: (v - pe.OPTIONAL_HEADER.ImageBase)
va2ofs = lambda v: pe.get_offset_from_rva(v - pe.OPTIONAL_HEADER.ImageBase)
rva2ofs = lambda v: pe.get_offset_from_rva(v)
ofs2rva = lambda v: pe.get_rva_from_offset(v)
ofs2va = lambda v: pe.get_rva_from_offset(v) + pe.OPTIONAL_HEADER.ImageBase
get_sec_by_name = lambda v: [s for s in pe.sections if s.Name.startswith(v)][0]
get_sec_by_ofs = lambda v: pe.get_section_by_offset(v)
get_sec_by_rva = lambda v: pe.get_section_by_rva(v)
get_sec_by_va = lambda v: pe.get_section_by_rva(v-pe.OPTIONAL_HEADER.ImageBase)

class RELA:
    def __init__(self, target, op, imm, opnd, tlen):
        self.target = target
        self.op = op 
        self.imm = imm
        self.opnd = opnd
#        if self.opnd == 0:
#            assert False, "should not happen 0x{:x} {} {} {} {} {}".format(target, op, imm, oplen, tlen, len(op))
        self.tlen = tlen
    def __str__(self):
        return str([hex(self.target), self.op, self.imm, self.opnd, self.tlen])

class CODE:
    def __init__(self, va, exp, align, code, tlen):
        self.va = va 
        self.exp = exp
        self.align = align
        self.code = code
        self.tlen = tlen
    def __str__(self):
        return str([hex(self.va), self.exp, self.align, self.code, self.tlen])

class ADDR:
    def __init__(self, diff, code_len):
        self.diff = diff
        self.code_len = code_len
    def __str__(self):
        return str([hex(self.diff), self.code_len])

def LOG(*args_):
    if args.verbose:
        print(' '.join(list(args_)))

def INFO(s):
    print('[*] ' + s)

def clear_stub():
    if '.no_stub' not in pe.path:
        # leave space for section table
        import clear_stub
        name = clear_stub.go(pe.path)
        print('cleared DOS stub {}'.format(name))
        load_pe(name)

def check_certificate():
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if d.VirtualAddress:
        import remove_certificate
        name = remove_certificate.go(pe.path)
        print('removed certificate, new name is : {}'.format(name))
        load_pe(name)

def in_range(val, pair):
    for a,b in pair:
        if a <= val < b:
            return True
    return False

def get_last(seq, val):
    if val < seq[0]:
        return None
    return seq[bisect.bisect_right(seq, val) - 1]

injected = {}
def inject_code(addr, code=b'', expand=b'', verbose=False):
    # expand is a partial operand for expanding from short jump to long jump
    v,s = va2ofs(addr), get_sec_by_va(addr)
    assert is_exe(s), 'v is out of executable section'

    if verbose:
        print ("injecting code  @0x{:x} code={} expand={} ***********************".format(addr, code, expand))

    # instrument with word-aligned
    align = b''
    if expand == b'':
        code += b'\x90' * (len(code)%2)
    else:
        align = b'\x90' * (len(expand)%2)

    if v in injected:
        if verbose:
            print ("v in injected")
        i = injected[v]
        i.exp = expand
        i.align = align
        # multiple injection is allowed 
        i.code = code + i.code
        i.tlen = len(i.code + i.exp + i.align)
    else:
        if verbose:
            print ("v NOT in injected 0x{:x} (OFS 0x{:x})  {}  {}  {} ({})".format(addr, v, expand, align, code, len(expand+code+align)))
        injected[v] = CODE(*[addr, expand, align, code, len(expand+code+align)])
        if verbose:
            if v in injected:
                print ("now, v (0x{:x}) is in injected expand = {}".format(v, expand))
        # for optimization
        if not hasattr(s, 'addr_set'):
            s.addr_set = []
        bisect.insort(s.addr_set, v)

def build_map(sec=None):
    # for optimization
    if sec == None:
        sec = sorted(pe.sections, key=lambda s: s.PointerToRawData)
    else:
        sec = [sec]
    for s in sec:
        if hasattr(s, 'addr_map'):
            diff = 0
            for i in s.addr_set:
                tlen = injected[i].tlen
                s.addr_map[i] = ADDR(*[i+diff+len(injected[i].exp), tlen - len(injected[i].exp)])
                diff += tlen

def get_last_section(type):
    rva = 0;fa = 0;tbl = 0
    for s in pe.sections:
        rva = max(rva, s.VirtualAddress+s.Misc_VirtualSize)
        fa = max(fa, s.PointerToRawData+s.SizeOfRawData)
        tbl = max(tbl, s.get_file_offset()+s.sizeof())
    LOG('[get_last_section]', str(s.Name), hex(rva), hex(fa), hex(tbl))
    if type == 'rva':
        return align_sec(rva)
    elif type == 'fa':
        return align_file(fa)
    elif type == 'tbl':
        return tbl

def get_text_diff_by_rva(rva, verbose=False):
    s = get_sec_by_rva(rva)
    ofs = rva2ofs(rva)
    diff = 0 #(0 - ofs)

    assert s != None, "get_text_diff_by_rva: no section for RVA 0x{:x}".format(rva)

    '''
    if rva >= 0x0F4F2 and rva <= 0x0F500:
        verbose = True
        #traceback.print_stack(file=sys.stdout)
    '''

    if verbose:
        print ('=========================================================================')
        print ('get_text_diff_by_rva: {}'.format(s.Name.strip(b'\x00')))
        print ('                    : rva = 0x{:x}, ofs = 0x{:x}'.format(rva, ofs))

    if hasattr(s, 'addr_map'):
        if ofs in s.addr_map:
            diff = s.addr_map[ofs].diff - ofs
            if verbose:
                print ("                    : OFS 0x{:x} IS IN s.addr_map".format(ofs))
                print ("                    : s.addr_map[ofs] = 0x{:x}, diff = 0x{:x}".format(s.addr_map[ofs].diff, diff))
        else:
            last_old = get_last(s.addr_set, ofs)
            if verbose:
                print ("                    : OFS 0x{:x} is NOT in s.addr_map".format(ofs))
                print ("                    : last_old = 0x{:x}".format(last_old))
                print ("                    : s.addr_map[last_old].diff = 0x{:x}".format(s.addr_map[last_old].diff))
                print ("                    : s.a.addr_map[last_old].code_len = 0x{:x}".format(s.addr_map[last_old].code_len))
            if last_old:
                diff = s.addr_map[last_old].diff - last_old + s.addr_map[last_old].code_len
    elif verbose:
        print ('                    : no addr_map in section {}'.format(s.Name.strip(b'\x00')))
    
    if verbose:
        print ("                    : diff = 0x{:x}".format(diff))
    return diff

def get_data_diff_by_rva(fa):
    s = get_sec_by_rva(fa)
    diff = 0

    if s == None:
        assert "Should not happen"
    
    if hasattr(s, 'addr_set'):
        last_old = get_last(s.addr_set, rva2ofs(fa))
        if last_old:
            diff = s.addr_map[last_old].diff - last_old + s.addr_map[last_old].code_len
    
    return diff



def new_reloc_entry(addr, type):
    entry = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_ENTRY_format__)
    assert (0 <= type <= 11) , 'invalid type'
    setattr(entry, 'Data', (addr&0xFFF)+(type<<12))
    entry.set_file_offset(0)
    return pefile.RelocationData(struct = entry, type = type, base_rva = addr&~0xFFF, rva = addr)

updated_reloc = []
def add_to_reloc(addr, type):
    for x in updated_reloc:
        if (addr&~0xFFF) == x.struct.VirtualAddress:
            # insert new entry into existed base reloc
            x.entries.append(new_reloc_entry(addr, type))
            x.struct.SizeOfBlock += 2
            return
    
    # new a entry 
    s = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__)
    setattr(s, 'VirtualAddress', addr&~0xFFF)
    setattr(s, 'SizeOfBlock', 8+2)
    s.set_file_offset(0)

    # insert new base reloc
    entries = []
    entries.append(new_reloc_entry(addr, type))
    updated_reloc.append(pefile.BaseRelocationData(struct = s, entries = entries))


def write_reloc():
    #IMAGE_REL_BASED_ABSOLUTE        No operation relocation. Used for padding.
    #IMAGE_REL_BASED_HIGHLOW         Add the delta between the ImageBase and the allocated memory block to the 32 bits found at the offset. 
    #IMAGE_REL_BASED_DIR64           Add the delta between the ImageBase and the allocated memory block to the 64 bits found at the offset. 
    updated_reloc.sort(key=lambda x: x.struct.VirtualAddress)
    # append IMAGE_REL_BASED_ABSOLUTE for padding
    for x in updated_reloc:
        if (x.struct.SizeOfBlock/2)%2:
            x.entries.append(new_reloc_entry(0, 0))
            x.struct.SizeOfBlock += 2

    def debug_reloc(r):
        LOG('[debug_reloc]')
        for base_reloc in r:
            print ("-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-")
            LOG('\n'.join(base_reloc.struct.dump()))
            for reloc in base_reloc.entries:
                LOG('0x%08X %s' % (reloc.rva, pefile.RELOCATION_TYPE[reloc.type][16:]))
    if args.verbose:
        debug_reloc(updated_reloc)

    reloc = get_sec_by_name(b'.reloc')
    ofs = reloc.PointerToRawData
    end = ofs + reloc.SizeOfRawData     # end is file aligned
    update_reloc_raw = b''
    for base_reloc in updated_reloc:
        d = p32(base_reloc.struct.VirtualAddress) + p32(base_reloc.struct.SizeOfBlock)
        print ("--------------------------------------------")
        print (hex(base_reloc.struct.VirtualAddress))
        print (d)
        print (update_reloc_raw)
        update_reloc_raw += d
        for rr in base_reloc.entries:
            print (' ... 0x{:x}'.format(rr.struct.Data))
            d = p16(rr.struct.Data)
            update_reloc_raw += d

    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
    d.Size = len(update_reloc_raw)
    d.VirtualAddress = reloc.VirtualAddress
    update_reloc_raw += b'\x00'*(0x200-len(update_reloc_raw)%0x200) 	# padding
    reloc.Misc_VirtualSize = reloc.SizeOfRawData = len(update_reloc_raw)
    
    reloc.raw = p32(4) + update_reloc_raw

    return update_reloc_raw

def update_reloc_raw(type, raw, v):
    if type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
        addr = u32(raw[v:v+4])
        # use rva rather than offset here, due to some undefined data between data sections
        s = pe.get_section_by_rva(addr-pe.OPTIONAL_HEADER.ImageBase)
        if is_exe(s) and not in_range(va2ofs(addr), ida['idata']):
            LOG('[update_reloc_raw]', hex(addr))
            if va2ofs(addr) in injected:
                last = get_last(code_loc, addr)
                if last and last <= addr < ida['code_loc'][last]:
                    diff3 = get_text_diff_by_rva(addr)
                else:
                    diff3 = get_data_diff_by_rva(addr)
            else:
                diff3 = get_data_diff_by_rva(addr)
            vv = addr + s.sec_diff + diff3
            assert check32(vv), 'vv is out of range'
            return strrep(raw, v, p32(vv))
        else:
            return raw
    elif type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:

        # need to patch QWORD (VA) @ v

        addr = u64(raw[v:v+8])
        print ("======================")
        print (hex(addr))
        # use rva rather than offset here, due to some undefined data between data sections
        s = pe.get_section_by_rva(addr-pe.OPTIONAL_HEADER.ImageBase)

        if is_exe(s): # and not in_range(va2ofs(addr), ida['idata']):
            diff3 = get_text_diff_by_rva(addr-pe.OPTIONAL_HEADER.ImageBase)
            vv = addr + s.sec_diff + diff3
            return strrep(raw, v, p64(vv))
        else:
            if hasattr(s, 'sec_diff'):
                vv = addr + s.sec_diff + get_data_diff_by_rva(addr-pe.OPTIONAL_HEADER.ImageBase)
            else:
                vv = addr + get_data_diff_by_rva(addr-pe.OPTIONAL_HEADER.ImageBase)
            print ("PATCHING @ OFS 0x{:x} with: 0x{:x}".format(v, vv))
            return strrep(raw, v, p64(vv))
    else:
        assert False, 'TODO'


def update_and_verify_section_table():
    # update .reloc in section table
    old_reloc_size = 0
    try:
        idx = [i for i,j in enumerate(pe.sections) if b'.reloc' in j.Name][0]
        reloc = pe.sections.pop(idx)
        old_reloc_size = reloc.SizeOfRawData
        reloc.VirtualAddress = get_last_section('rva')
        reloc.PointerToRawData = get_last_section('fa')
        reloc.set_file_offset(get_last_section('tbl'))
        pe.sections.append(reloc)
    except:
        # no reloc section
        pass    

    # confirm all sections have to stick together, don't overlap or seperate
    rva = 0
    fa = 0
    for s in pe.sections:
        if rva != 0 and fa != 0:
            assert rva == s.VirtualAddress and (0 == s.PointerToRawData or fa == s.PointerToRawData)
            prev_s.next_section_virtual_address = s.VirtualAddress #, (hex(s.VirtualAddress), hex(s.PointerToRawData))
        prev_s = s
        rva = align_sec(s.VirtualAddress+s.Misc_VirtualSize)
        fa = align_file(s.PointerToRawData+s.SizeOfRawData)
    s.next_section_virtual_address = s.VirtualAddress+s.Misc_VirtualSize
    return old_reloc_size

# fa = RVA
def get_relative_diff(from_fa, to_fa, verbose=False):
#      get_relati     +----------------+
#           |                v           I = injected
#     +---+-+-+              +---+---+   C = original code
#     | I | C |              | I | C |
#     ----+---+              +---+-+-+
#     ^                            |
#     +----------------------------+
    from_s = get_sec_by_rva(from_fa)
    
    from_ofs = rva2ofs(from_fa)
    to_ofs = rva2ofs(to_fa)

    if verbose:
        print ('*** OFF: 0x{:x} 0x{:x}     RVA: 0x{:x} 0x{:x}'.format(from_ofs, to_ofs, from_fa, to_fa))

    if to_fa == 0:
        diff = 0 - (from_fa+get_text_diff_by_rva(from_fa)-from_s.VirtualAddress)
        #if from_fa in from_s.addr_set:
            #diff -= from_s.addr_map[from_fa].code_len
        if from_ofs in from_s.addr_set:
            diff -= from_s.addr_map[from_ofs].code_len
        if hasattr(from_s, 'sec_diff'):
            from_s_diff = from_s.sec_diff
        else:
            from_s_diff = 0
        sec_diff = 0 - (from_s.VirtualAddress+from_s_diff)
        return from_fa + diff + sec_diff

    else:
        to_s = get_sec_by_rva(to_fa)
        if from_s != to_s:
            # for inter-section
            diff = (to_fa+get_text_diff_by_rva(to_fa)-to_s.VirtualAddress) - (from_fa+get_text_diff_by_rva(from_fa)-from_s.VirtualAddress)
    ###        diff = (to_fa+get_text_diff(to_fa)-to_s.PointerToRawData) - (from_fa+get_text_diff(from_fa)-from_s.PointerToRawData)
#            if from_fa in from_s.addr_set:
#                diff -= from_s.addr_map[from_fa].code_len
            if from_ofs in from_s.addr_set:
                diff -= from_s.addr_map[from_ofs].code_len

            if hasattr(to_s, 'sec_diff'):
                to_s_diff = to_s.sec_diff
            else:
                to_s_diff = 0
            if hasattr(from_s, 'sec_diff'):
                from_s_diff = from_s.sec_diff
            else:
                from_s_diff = 0

            sec_diff = (to_s.VirtualAddress+to_s_diff) - (from_s.VirtualAddress+from_s_diff)
            return from_fa + diff + sec_diff

    # for intra-section
    diff = get_text_diff_by_rva(to_fa, verbose=verbose) - get_text_diff_by_rva(from_fa, verbose=verbose)
    if verbose:
            print ('    diff_by_rva(from_fa = 0x{:x}) = 0x{:x}'.format(from_fa, get_text_diff_by_rva(from_fa)))
            print ('    diff_by_rva(to_fa   = 0x{:x}) = 0x{:x}'.format(to_fa, get_text_diff_by_rva(to_fa)))
            print ('    diff: 0x{:x}'.format(diff))
            for x in from_s.addr_set:
                print (hex(x))
    if from_ofs in from_s.addr_set:
        diff -= from_s.addr_map[from_ofs].code_len
        if verbose:
            print (' *** diff: 0x{:x}'.format(diff))
    return to_fa + diff

def update_instr(op, operand_len, v, imm):
    assert check32(v), 'v is out of range'

    if -0x80 <= v < 0x80:
        if operand_len != 1:
            # instruction will not be shorter
            return expand_instr(op, v, imm)
        else:
            return op + "{:02x}".format(v&0xFF) # no imm anyway
    else:
        return expand_instr(op, v, imm)

def expand_instr(op, v, imm):
    assert check32(v), 'v is out of range'
    dword = lambda v: p32(v&0xFFFFFFFF).hex()
    mpx = ''
    '''
    if op.startswith('f2'):
        mpx = 'f2'
        #assert False, "Should not happen {}".format(op)
        op = op[2:]
    ''' 

    supported = [
                    '48ff15',   # call [rel32]
                    'ff15',     # call [rel32]
                    'ff25',     # jmp [rel32]
                    '8b05',     # mov eax, [rel32]
                    '8b0d',     # mov ecx, [rel32]
                    '8b15',     # mov edx, [rel32]

                    '448925',   # mov [rel32], r12d

                    '48211d',   # and [rel32], rbx

                    '483b05',   # cmp rax, [rel32]
                    '483b0d',   # cmp rcx, [rel32]
                    '483b15',   # cmp rdx, [rel32]
                    '483b1d',   # cmp rbx, [rel32]

                    '483905',   # cmp [rel32],rax
                    '48390d',   # cmp [rel32],rcx
                    '483915',   # cmp [rel32],rdx
                    '48391d',   # cmp [rel32],rbx
                    
                    '488905',   # mov [rel32], rax

                    '488b05',   # mov rax, [rel32]
                    '488b0d',   # mov rcx, [rel32]
                    '488b15',   # mov rdx, [rel32]
                    '488b1d',   # mov rbx, [rel32]
                    '488b3d',   # mov rdi, [rel32]

                    '488905',   # mov [rel32], rax
                    '48890d',   # mov [rel32], rcx
                    '488915',   # mov [rel32], rdx
                    '48891d',   # mov [rel32], rbx

                    '488d05',   # lea rax, rel32
                    '488d0d',   # lea rcx, rel32
                    '488d15',   # lea rdx, rel32
                    '488d1d',   # lea rbx, rel32
                    '488d35',   # lea rsi, rel32
                    '488d3d',   # lea rdi, rel32

                    '4c8905',   # mov [rel32], r8
                    '4c892d',   # mov [rel32],r13

                    '4c8b05',   # mov r8, rel32
                    '4c8b0d',   # mov r9, rel32
                    '4c8b15',   # mov r10,[rel32]
                    '4c8b1d',   # mov r11,[rel32]

                    '48870d',   # xchg rcx,[rel32]

                    '488d2d',   # lea rbp, [rel32]
                    '4c8d05',   # lea r8, rel32
                    '4c8d0d',   # lea r9, rel32
                    '4c8d15',   # lea r10, rel32
                    '4c8d1d',   # lea r11, rel32
                    '4c8d25',   # lea r12, rel32
                    '4c8d2d',   # lea r13, rel32
                    '4c8d35',   # lea r10, rel32
                    '4c8d3d',   # lea r15, rel32                    

                    '8705',     # xchg eax,[rel32]
                    '8905',     # mov [rel32], eax
                    '890d',     # mov [rel32], ecx
                    '8915',     # mov [rel32], edx

                    #'48833d',   # mov [rel32], 
                    '48893d',   # mov [rel32], rdi

                    '48ff25',   # jmp [rel32]

                    '0f4415',   # cmovz edx,[rel32]
                    '0fb705',   # movzx eax, [rel32]
                    '0fb715',   # movzx edx, [rel32]
                    '0f1005',   # movups  xmm0, xmmword [rel32]
                    '0f1105',   # movups oword [rel32], xmm0
                    'f20f1105', # movsd qword [rel32], xmm0
                    '0f100d',   # movups  xmm1, xmmword [rel32]
                    '4c6305',   # movsxd r8,dword [rel32]

                    '6644890d', # mov word [rel32], r9w
                    '668905',   # mov [rel32],ax
                    '66892d',   # mov [rel32],bp

                    '668935',   # mov word [rel32], si
                    '0f2905',   # movaps oword [rel32],xmm0
                    '0f290d',   # movaps oword [rel32],xmm1

                    'f00fb10d',     # lock cmpxchg [rel32],ecx
                    'f0480fb11d',   # lock cmpxchg [rel32],rbx
    ]

    supported_imm = [
                    '488325',   # and qword [rel32], imm8
                    '48833d',   # cmp byte [rel32], imm8
                    '833d',     # cmp byte [rel32], imm8
                    'f605',     # test byte [rel32], imm8
                    'c705',     # mov [rel32], imm32
    ]

    if op == 'e2':              		    # loop rel8
        assert mpx == '', 'unsupport op ' + op
        return '4975' + dword(v)		    # dec ecx ; jnz label
    elif op == 'e3':                                # jecxz rel8
        assert mpx == '', 'unsupport op ' + op
        return '85c974' + dword(v)		    # test ecx, ecx ; jz label
    elif op == 'eb':                                # jmp rel8
        return mpx + 'e9' + dword(v)
    elif op == 'e9':                                # jmp rel32
        return mpx + 'e9' + dword(v)
    elif op == 'e8':                                # call
        return mpx + 'e8' + dword(v)
    elif op[0] == '7':                              # jxx rel8
        return mpx + '0f8' + op[-1] + dword(v)
    elif op[:3] == '0f8':                           # jxx rel32
        return mpx + op + dword(v)
    else:
        if op in supported:
            return op + dword(v)
        if op in supported_imm:
            return op + dword(v) + imm
        assert False, "operand not in list : {} v = {} / {}".format(op, dword(v), (imm))

def seh_padding():
    # SEHandlerTable have to align with 4-byte
    is_padded = False
    ###d = pe.parse_directory_load_config('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG')

    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']]

    ofs = rva2ofs(d.VirtualAddress)
    if not hasattr(get_sec_by_ofs(ofs), 'addr_set'):
        return is_padded
    delta = get_data_diff_by_rva(d.VirtualAddress) % 4
    if delta:
        is_padded = True
        LOG('[seh_padding]', hex(d.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase))
        # pad NOP in the last injected
        s = get_sec_by_ofs(ofs)
        addr = ofs2va(get_last(s.addr_set, ofs))
        inject_code(addr, b'\x90'*(4-delta))
        build_map(s)
        print('SEHandlerTable is padded')
    return is_padded

def pdata_update():
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']]
    s = get_sec_by_rva(d.VirtualAddress)

    #print ("pdata: {}".format(d))
    start = s.PointerToRawData
    end = start + s.SizeOfRawData
#    setattr(s, 'raw', p32(start) + b'\x00'*(start-4) + pe.get_raw()[start:end])
    pdata = pe.get_raw()[start:end]

    i = 0

    pdata2 = b''

    while True:
        a, b, c = struct.unpack('III', pdata[i:i+12])
        if a == 0:
            break

        A = update_addr(a)
        B = update_addr(b)
        #print ("pdata: 0x{:x} 0x{:x} => 0x{:x} 0x{:x}".format(a, b, A, B))

        d = struct.pack('III', A, B, c)
        pdata2 += d

        i += 12

    pe.get_raw()[start:start+i] = pdata2
    return

def update_addr(addr):
    s = get_sec_by_rva(addr)
    if hasattr(s, 'sec_diff'):
        return addr + s.sec_diff + get_text_diff_by_rva(addr)
    else:
        return addr

def config_cov_sec(s):
    s.PointerToRawData = 0
    s.SizeOfRawData = 0
    LOG('configured section {}'.format(s.Name.strip(b'\x00')))
    return s

def dup_sec(sec, name=None, size=0):
    s = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    s.__unpack__(sec.__pack__())
    if name:
        s.Name = name
    else:
        s.Name = (new_name(sec)).ljust(8, b'\x00')
    # skip .reloc if necessary
    diff = get_sec_by_name(b'.reloc').SizeOfRawData if b'.reloc' in pe.sections[-1].Name else 0
    s.VirtualAddress = get_last_section('rva') - align_sec(diff)
    s.PointerToRawData = get_last_section('fa') - align_file(diff)
    ss = size if size else sec.SizeOfRawData*args.enlarge
    s.Misc_VirtualSize = align_sec(ss)
    s.SizeOfRawData = align_file(ss)
    diff = s.sizeof() if b'.reloc' in pe.sections[-1].Name else 0
    s.set_file_offset(get_last_section('tbl') - diff)
    s.next_section_virtual_address = s.VirtualAddress + s.Misc_VirtualSize
    assert s.get_file_offset() + 40 <= pe.OPTIONAL_HEADER.SizeOfHeaders, 'TODO'
    pe.__structures__.append(s)
    pe.sections.append(s)
    print('added section', s.Name.strip(b'\x00'))
    return s

def build_text_raw():
    for s in pe.sections:
        if is_exe(s) and (s.Name.strip(b'\x00')[-1] != b'2'[0]):
            start = s.PointerToRawData
            end = start + s.SizeOfRawData
            setattr(s, 'raw', p32(start) + b'\x00'*(start-4) + pe.get_raw()[start:end])
            '''
            s.raw = [START ADDR 32bits] [ 0000000000 ... 0000 ] + section
            '''
            name = s.Name.strip(b'\x00')
            LOG("found section {} @ 0x{:x} ~ 0x{:x}".format(name, start, end))

def update_load_config_tbl(tbl, cnt, pe_size, append, align=4):
    tbl2 = update_addr(tbl - pe.OPTIONAL_HEADER.ImageBase)
    ofs,s = rva2ofs(tbl2), get_sec_by_rva(tbl2)
    if hasattr(s, 'raw'): # original section
        for n in range(cnt):
            s.raw = strrep(s.raw, ofs+n*align, p32(update_addr(u32(s.raw[ofs+n*align:ofs+n*align+4]))))
    else: # new section
        append = b'\x00'*pe_size + append
        for n in range(cnt):
            append = strrep(append, ofs+n*align, p32(update_addr(u32(append[ofs+n*align:ofs+n*align+4]))))
        append = append[pe_size:]
    return append

def process_pe():
    process_reloc = True
    # update section table
    # add new section entry, size of new section is affected by args.enlarge
### TODO: check this
    if not b'.reloc' in pe.sections[-1].Name:
        print ('.reloc is not at the end')
        process_reloc = False
    #assert pe.get_length() == get_last_section('fa'), 'overlays is behind PE'
    for sec in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        if is_exe(sec):
            # empty inject is for triggering the data update later
            if not hasattr(sec, 'addr_set'):
                inject_code(sec.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase)
            s = dup_sec(sec)
            setattr(sec, 'sec_diff', s.VirtualAddress - sec.VirtualAddress)
            setattr(sec, 'addr_map', {})

    try:
        s = get_sec_by_name(b'.bss')
    except:
        s = get_sec_by_name(b'.data')
    #assert not is_driver(pe.path) or s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_NOT_PAGED'], 'any non page memory ?'
    if hasattr(args, 'pe_afl'):
        #dup_sec(s, name=b'.cov', size=0x10fff))
        config_cov_sec(dup_sec(s, name=b'.cov', size=0x10fff))

    cut_reloc_size = update_and_verify_section_table()
    #assert cut_reloc_size == 0

    # update relative address
    print('loading relative ...')
    jmp_map = {}
    relative = {}

    pbar = ProgressBar(widgets=widgets, maxval=len(ida['relative']))
    pbar.start()

    for index, k in enumerate(sorted(ida['relative'])):
        if k == 0x14000F500:
            print ("Ignoring @ 0x{:x}".format(k))
            continue

        relative[k] = RELA(*ida['relative'][k])
        pbar.update(index)
    pbar.finish()
    print

    print('building jump map ...')
    pbar = ProgressBar(widgets=widgets, maxval=len(relative))
    pbar.start()

    '''
        builds jmp_map

        iterate through all relatives (k)

        jmp_map[i] = [ x1, x2, ... , xi_n ], x_j are VAs

            i is a VA between VA k and VA target(k)

            x in jmp_map[i] <=> VA x is an instruction using a relative address that goes over VA i

            ex: 
            0x10112233 lea rax, [0x10112255]

            jmp_map[0x10112233] = [0x10112233]
            jmp_map[0x10112234] = [0x10112233]
            [...]
            jmp_map[0x10112255] = [0x10112233]

    '''
    for index, k in enumerate(sorted(relative)):
        pbar.update(index)

        if relative[k].opnd == 1: # short jmp
            order = -1 if k>relative[k].target else 1

            if k == 0x015008A160:
                print ("")
                print ("@ 0x{:x} ...... {}".format(k, relative[k].opnd))
                print ("@ 0x{:x} ...... {}-{}-{}".format(k, relative[k].op, relative[k].imm, relative[k].opnd))
                print (order)
                print (i == k ) #HERE
                print (i == relative[k].target)
                '''
                if i not in jmp_map:
                    jmp_map[i] = [k]
                else:
                    jmp_map[i].append(k)
                '''

            for i in range(k, relative[k].target+order, order):
                ''' CHANGED THIS
                if order == 1 and (i == k or i == relative[k].target):
                    continue
                '''
                if i not in jmp_map:
                    jmp_map[i] = [k]
                else:
                    jmp_map[i].append(k)
    pbar.finish()
    print
    print ("Jump map len is: {}".format(len(jmp_map)))

    print ("building expand list")
    expand_list = []
    pbar = ProgressBar(widgets=widgets, maxval=len(injected))
    pbar.start()

    '''
        builds expand_list
        list of every relative instruction VA that has to be modified due to injected code
    '''
    for index, i in enumerate(injected):
        if injected[i].va in jmp_map:
            expand_list += jmp_map[injected[i].va]
        pbar.update(index)
    pbar.finish()
    print

    print ("adding jump map to expand list...")
    expand_list = list(set(expand_list)) # no dupes

    pbar = ProgressBar(widgets=widgets, maxval=len(expand_list))
    pbar.start()

    for index, i in enumerate(expand_list):

        if i not in jmp_map:
            continue
        for j in jmp_map[i]:
            if j not in expand_list:
                expand_list.append(j)
        pbar.update(index)
    pbar.finish()
    print

    print ("expanding...")
    pbar = ProgressBar(widgets=widgets, maxval=len(expand_list))
    pbar.start()

    '''
        Extend short jumps from this list to long jumps (not always necessary, but simpler way to do this)
    '''
    for index, k in enumerate(expand_list):

        cmd_len = relative[k].tlen
        e = int(len(expand_instr(relative[k].op, 0, b''))/2-cmd_len)
        # the expanded byte is stored in the next instruction
        if k == 0x14000F500:
            print (" ********************************************************** ")
            print (" expanding {} bytes @ 0x{:x} cmd_len={}".format(e, k, cmd_len))
            inject_code(k+cmd_len, expand=b'\x01'*e, verbose=True)
        else:
            inject_code(k+cmd_len, expand=b'\x01'*e)

        pbar.update(index)
    pbar.finish()
    print

    print('expanded %d of %d branches ' % (len(expand_list), len(relative)))

    build_map()
    seh_padding()
    pdata_update()
    print('updating relative ...')
#   for i in injected:
#        print ("0x{:x} -> {}".format(i, injected[i]))


    for k in ida['absolute']:
        # just patch absolute addresses
        ofs = rva2ofs(k)
        s = get_sec_by_ofs(ofs)
        previous_rva = u32(s.raw[ofs:ofs+4])
        new_rva = get_text_diff_by_rva(previous_rva) + previous_rva + s.sec_diff
        print ("jump table @ 0x{:x} (ofs 0x{:x} in {}) prev = 0x{:x}, new = 0x{:x}".format(k, ofs, s.Name.strip(b'\x00'), previous_rva, new_rva))
        s.raw = strrep(s.raw, ofs, p32(new_rva))

    for k in sorted(relative):
        #print ("Relative: k = 0x{:x}, target = 0x{:x}".format(k, relative[k].target))
        from_ofs = va2ofs(k)
        from_rva = va2rva(k)
        to_rva = va2rva(relative[k].target)
        if (to_rva < 0): 
            print ('VA 0x{:x} {} => VA 0x{:x} (RVA 0x{:x})'.format(k, relative[k].op, relative[k].target, to_rva))
            assert len(relative[k].op)/2 == 4
            continue

        #print ('VA 0x{:x} (OFS 0x{:x}, RVA 0x{:x}) => VA 0x{:x} (RVA 0x{:x})'.format(k, from_ofs, from_rva, relative[k].target, to_rva))

        '''
        if k == 0x1400A00BF:
            delta_rva = get_relative_diff(from_rva, to_rva, verbose = True)
            rva = k - 0x140000000
            s = get_sec_by_rva(rva)
            print ('    [update relative]', hex(k), hex(relative[k].target), hex(to_rva), hex(delta_rva), str(relative[k].tlen))
            print ('    from_rva = 0x{:x}'.format(from_rva))
            print ('    to_rva = 0x{:x}'.format(to_rva))
            print ('    delta_rva = 0x{:x}'.format(delta_rva))
            print ('    delta_rva-rva = 0x{:x}'.format(delta_rva-rva))
            print ('    text diff DST 0x{:x} => 0x{:x}'.format(relative[k].target, get_text_diff_by_rva(relative[k].target - 0x140000000)))
            print ('    get_text_diff_by_rva(0x{:x}) = 0x{:x}'.format((rva), get_text_diff_by_rva(rva)))
            print ('    delta = 0x{:x}'.format(get_text_diff_by_rva(relative[k].target - 0x140000000) - get_text_diff_by_rva(rva)))
            print ('    0x{:x}'.format(delta_rva-(from_rva+cmd_len+expand_len)))
            assert s != None
        '''

        delta_rva = get_relative_diff(from_rva, to_rva)

        cmd_len = relative[k].tlen
        expand_len = 0

        # next_ofs is the offset to next instruction or data
        next_ofs = va2ofs(k+cmd_len)

        '''
        if k == 0x1400A00BF:
            print ("next_ofs = 0x{:x}".format(next_ofs))
        '''

        #if next_ofs == 0x2805:
        #    print (injected[0x2805])
        if next_ofs in injected:
            if next_ofs == 0x2803 or next_ofs == 0x2805:
                print ("next_ofs 0x{:x} in injected".format(next_ofs))
                print ("expand_len = {}".format(expand_len))
            expand_len = len(injected[next_ofs].exp)
                
        else:
#            print ("next_ofs 0x{:x} NOT in injected".format(next_ofs))
            pass
        #print ("0x{:x}".format(delta_rva-(from_rva+cmd_len+expand_len)))

        #print (hex(k))
        instr = bytes.fromhex(update_instr(relative[k].op, relative[k].opnd+expand_len, delta_rva-(from_rva+cmd_len+expand_len), relative[k].imm))
#        print ("new instruction: {}".format(instr.hex()))

        assert len(instr) == cmd_len + expand_len, "0x{:x} 0x{:x} 0x{:x} @ 0x{:x}".format(len(instr), cmd_len , expand_len, k)

        if instr[cmd_len:] != b'': # update expand
            injected[next_ofs].exp = instr[cmd_len:]
        s = get_sec_by_ofs(from_ofs)
        s.raw = strrep(s.raw, from_ofs, instr[:cmd_len])

    # update .reloc entry

    if process_reloc:

        print('updating relocation ...')

        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:

            for k in base_reloc.entries:
                print ("reloc: 0x{:x} ({})".format(k.rva, k.type))


            for reloc in base_reloc.entries:
                if reloc.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                    continue

                v,s = rva2ofs(reloc.rva), get_sec_by_rva(reloc.rva)
                print ("reloc offset: 0x{:x} in section {}".format(v, s.Name.strip(b'\x00')))
                if is_exe(s) and not in_range(v, ida['idata']):
                    # assume that all relocation are data here
                    diff2 = get_data_diff_by_rva(reloc.rva)
                    LOG('[update reloc] %08Xh %s' % (reloc.rva, pefile.RELOCATION_TYPE[reloc.type][16:]) + ', diff2 = ' + hex(diff2))
                    add_to_reloc(reloc.rva + s.sec_diff + diff2, reloc.type)
                    s.raw = update_reloc_raw(reloc.type, s.raw, v)
                else:
                    LOG('[update reloc] %08Xh %s' % (reloc.rva, pefile.RELOCATION_TYPE[reloc.type][16:]))
                    add_to_reloc(reloc.rva, reloc.type)
                    if not hasattr(s, 'raw'):
                        setattr(s, 'raw', p32(s.PointerToRawData) + b'\x00'*(s.PointerToRawData-4) + s.get_data()) # give a padding
                    s.raw = update_reloc_raw(reloc.type, s.raw, v)

        write_reloc()


    # patching code with relative adresses (not reloc like in 32 bits)
    if hasattr(args, 'pe_afl') and not args.nop:
        print('patching instrumented code ...')
        t = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'] if is_32() else pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']
        afl_area_ptr = get_sec_by_name(b'.cov').VirtualAddress
        afl_prev_loc = afl_area_ptr + 0x10000
        if args.callback:
            assert True, "TODO"
            rr = [afl_prev_loc+0x10, afl_prev_loc+0x20]
        elif args.filter:
            assert True, "TODO"
            rr = [afl_prev_loc+0x10, afl_prev_loc, afl_area_ptr, afl_prev_loc]
        else: # single and multi
            rr = [afl_prev_loc, afl_area_ptr, afl_prev_loc]
        for v in sorted(injected):
            if injected[v].tlen < args.snip_len:
                continue
            m = [i + len(injected[v].exp + injected[v].align) for i in args.snip_reloc]
            s = get_sec_by_ofs(v)
            addr = ofs2rva(v) + s.sec_diff + get_text_diff_by_rva(ofs2rva(v))
            addr -= len(injected[v].exp)

            #print ("@0x{:x}    0x{:x}/0x{:x}  ({})   0x{:x}   ".format(update_addr(v) ,afl_area_ptr, afl_prev_loc, len(injected[v].align), (rr[0]-(len(injected[v].align)+update_addr(v)+args.snip_sizes[0]+args.snip_reloc[0]))))
            for i in range(len(m)):
                #### 64 bits: relative addresses from RIP
                injected[v].code = strrep(injected[v].code, args.snip_reloc[i], p32(rr[i]-(len(injected[v].align)+update_addr(ofs2rva(v))+args.snip_sizes[i]+args.snip_reloc[i])))
             #   print (" ... 0x{:05x}".format((rr[i]-(len(injected[v].align)+update_addr(v)+args.snip_sizes[i]+args.snip_reloc[i]))))

                #### 32 bits: Virtual addresses
                ####injected[v].code = strrep(injected[v].code, args.snip_reloc[i], p32(rr[i] + pe.OPTIONAL_HEADER.ImageBase))
                #add_to_reloc(addr + m[i], t)
    print('finalizing ...')
    append = b''
    mapping_txt = ''
    pe_size = len(pe.get_raw()) - cut_reloc_size
    s2 = [s for s in sorted(pe.sections, key=lambda s: s.PointerToRawData) if hasattr(s, 'addr_set')]
    for i,s in enumerate(s2):
       new_s = get_sec_by_name(new_name(s))
       old_idx = s.PointerToRawData
       for idx in s.addr_set:
           append += s.raw[old_idx:idx] + injected[idx].exp + injected[idx].align + injected[idx].code
           tt = pe_size+len(append)-injected[idx].tlen+len(injected[idx].exp)
           tts = get_sec_by_ofs(tt)
           #LOG('[merge] idx =', hex(idx), hex(tt))
           mapping_txt += hex(idx-s.PointerToRawData+s.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase).strip('L') + '\t'
           mapping_txt += hex(tt-tts.PointerToRawData+tts.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase).strip('L') + '\n'
           old_idx = idx
       append += s.raw[idx:]
       end = new_s.PointerToRawData + new_s.SizeOfRawData
       assert len(append)+pe_size <= end, 'injection too large, use -l {} to enlarge and try again'.format(args.enlarge+1)
       assert i == len(s2)-1 or end == get_sec_by_name(new_name(s2[i+1])).PointerToRawData, 'Some space is unexpected'
       append += b'\x00'*(end - len(append) - pe_size)
       delattr(s, 'raw')
    if hasattr(args, 'pe_afl'):
        append += b'\x00'*0x11000    # reserved for __afl_area_ptr and __afl_prev_loc
        if args.callback or args.filter:
            append = strrep(append, len(append)-0x1000+0x10, p32(0xffffffff))
    
    # log mapping to file, it can be used in IDA directly
    with open(args.IDA_DUMP.replace('dump', 'mapping'), 'w+') as ff:
        ff.write(mapping_txt)

    build_text_raw()

    # update export table
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            s = get_sec_by_rva(e.address)
            if not is_exe(s):
                continue
            s = get_sec_by_ofs(e.address_offset)
            if not hasattr(s, 'raw'):
                setattr(s, 'raw', p32(s.PointerToRawData) + b'\x00'*(s.PointerToRawData-4) + s.get_data()) # padding
            s.raw = strrep(s.raw, e.address_offset, p32(update_addr(e.address)))

    # update SEHHandlerTable and GuardCFFunctionTable
    #d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG')
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']]
    if d.VirtualAddress:
        s = get_sec_by_rva(d.VirtualAddress)
        if is_exe(s):
            d.VirtualAddress = update_addr(d.VirtualAddress)
        append = update_load_config_tbl(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable, pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount, pe_size, append)
        if pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size > 0x60:
            extra = (pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags & 0xF0000000)>>28
            append = update_load_config_tbl(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable, pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount, pe_size, append, align=extra+4)

    # update TLS directory
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']]
    if d.VirtualAddress:
        s = get_sec_by_rva(d.VirtualAddress)
        if is_exe(s):
            d.VirtualAddress = update_addr(d.VirtualAddress)

    # update PE header
    pe.OPTIONAL_HEADER.SizeOfImage = get_last_section('rva')
    pe.FILE_HEADER.NumberOfSections += len([s for s in pe.sections if hasattr(s, 'sec_diff')])
    if hasattr(args, 'pe_afl'):
        pe.FILE_HEADER.NumberOfSections += 1

    print('   AddressOfEntryPoint='+hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))

    addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    s = get_sec_by_rva(addr)
    print ("get_sec_by_rva(0x{:x})".format(addr))
    if hasattr(s, 'sec_diff'):
        print ("has attr sec_diff: 0x{:x}".format(s.sec_diff))
        print ("get_text_diff_by_rva(0x{:x}) = 0x{:x}".format(addr, get_text_diff_by_rva(addr)))
    else:
        assert False, "wtf"

    pe.OPTIONAL_HEADER.AddressOfEntryPoint = update_addr(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    print('   SizeOfImage='+hex(pe.OPTIONAL_HEADER.SizeOfImage))
    #print('   NumberOfSections='+hex(pe.FILE_HEADER.NumberOfSections))
    print('   AddressOfEntryPoint='+hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    # clear Bound Import Directory in order to get more space for new section
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']]
    d.VirtualAddress = 0
    d.Size = 0
   
    # handle the rest of raw
    for i in sorted(injected):
        s = get_sec_by_ofs(i)
        s.raw = strrep(s.raw, i, b'\xCC')   # for debug use
    for s in pe.sections:
        if hasattr(s, 'raw'):
            s.raw = s.raw[u32(s.raw[:4]):]
            if not is_exe(s):
                assert len(s.raw) == s.SizeOfRawData, 'Section size has changed from {} to {}'.format(s.SizeOfRawData, len(s.raw))
            print('updated {}'.format(s.Name.strip(b'\x00')))

    return cut_reloc_size, append

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Print debug log', action='store_true')
    parser.add_argument('-i', '--ins', help='Instrument code, ie. -e"{1:9090,}"')
    parser.add_argument('-l', '--enlarge', help='Enlarge section size, default=4')
    parser.add_argument('PE', help='Target PE for instrument')
    parser.add_argument('IDA_DUMP', help='dump.txt from IDAPython')
    return parser.parse_args()

def load_pe(fname):
    global pe
    if pe and ('.no_stub' in pe.path or '.no_certificate' in pe.path):
        pe.close()
        os.remove(pe.path)
    try:
        pe = pefile.PE(fname)
        print ("PE size = 0x{:x}".format(len(pe.get_raw())))
        pe.path = fname
    except:
        print('Invalid PE file @', fname)
        quit()

def start(a):
    global args, pe, ida, code_loc
    args=a

    args.enlarge = int(args.enlarge) if args.enlarge else 4

    load_pe(args.PE)
    check_certificate()
    clear_stub()
    build_text_raw()

    # import dump.txt from IDA

    # TODO: horrible
    with open(args.IDA_DUMP) as f:
        ida = eval(f.read().replace('L','').strip())

    code_loc = sorted(ida['code_loc'].keys())
    return pe,ida

def end():
    global ida
    ida['idata'] = map(lambda v: [va2ofs(v[0]), va2ofs(v[1])], ida['idata'])

    cut_size, append = process_pe()

    fname = os.path.abspath(pe.path).split('.')
    fname = fname[0]+'.instrumented.'+fname[-1]

    pe.write(filename=fname, append=append, cut=cut_size)
    '''
    pe.write(filename=fname)
    pe.close()
    with open(fname, 'rb') as f:
        data = f.read() #[:-cut_size]
        print ("file length before append: 0x{:x}".format(len(data)))
        data += append
    with open(fname, 'wb') as f:
        f.write(data)
    '''

    print('fixing PE checksum ...')
    load_pe(fname)
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(filename=fname)
    INFO('instrumented binary at '+fname)

if __name__ == '__main__':
    print ("hello")
    args = parse_arg()

    pe,ida=start(args)

    ##################
    # instrument here

    # instrument entry point with 2 NOP
    #inject_code(pe.OPTIONAL_HEADER.AddressOfEntryPoint+pe.OPTIONAL_HEADER.ImageBase, '9090'.decode('hex'))
    if args.ins:
        d = eval(args.ins)
        for k in d:
            LOG('[inject_code]', hex(k), d[k])
            inject_code(k, d[k].decode('hex'))
    ##################

    end()

