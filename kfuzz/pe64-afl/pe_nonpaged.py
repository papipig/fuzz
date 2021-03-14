#!/usr/bin/env python3
from __future__ import print_function
import pefile
import sys

'''
    add IMAGE_SCN_MEM_NON_PAGED to these sections
'''
sections = [
 b'.bss\x00\x00\x00\x00',
 #b'.data\x00\x00\x00',
 #b'.rdata\x00\x00',
 #b'.pdata\x00\x00',
 #b'.xdata\x00\x00',
]

def patch(fname):
    pe = pefile.PE(fname)

    for s in pe.sections:
        if s.Name in sections:
            s.Characteristics = s.Characteristics | pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_NOT_PAGED']
            print ("{} => NON_PAGED flag added".format(s.Name.decode()))

    pe.write(filename=fname)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage:', sys.argv[0], '<(IN/OUT) PE file name>')
    else:
        patch(sys.argv[1])
