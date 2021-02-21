from __future__ import print_function
import pefile
import sys

def go(fname):
    pe = pefile.PE(fname)
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    assert d.VirtualAddress + d.Size == len(pe.__data__), 'some overlays behind certificate'
    s = d.Size
    d.VirtualAddress = 0
    d.Size = 0
    name = fname[:-4]+'.no_certificate'+fname[-4:]
    pe.write(filename=name)
    pe.close()
    
    print ("cuttin 0x{:x} bytes".format(s))

    # trim file
    with open(name, 'rb') as f:
        data = f.read()[:-s]
    with open(name, 'wb') as f:
        f.write(data)
    return name

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage:', sys.argv[0], '<PE>')
        quit()
    go(sys.argv[1])
