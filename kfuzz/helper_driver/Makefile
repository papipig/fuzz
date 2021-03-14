OBJECTS = helper.o
TARGET = helper.unsigned.sys
SIGNEDTARGET = helper.sys
CFLAGS = -I/usr/i686-w64-mingw32/include/ddk -DMINGW -std=c99 -Wall -m64 -shared
CC = x86_64-w64-mingw32-gcc
BINDIR := .

all: $(TARGET)
clean:
	rm -f ${OBJECTS} $(TARGET) $(SIGNEDTARGET) ../../vm_shared/$(SIGNEDTARGET)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

$(TARGET): ${OBJECTS}
	rm -rf $(TARGET) $(SIGNEDTARGET)
	rm -rf $(BINDIR)/$(SIGNEDTARGET)
	$(CC) $(CFLAGS) -Wl,--subsystem,native -Wl,--image-base,0x10000 \
-Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
-Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat \
-nostartfiles -nostdlib -o $(TARGET) \
$(OBJECTS) -lntoskrnl -lhal 
	strip $(TARGET)
	winsign -d sha256 ${TARGET} $(BINDIR)/${SIGNEDTARGET} --certs ../cert/openssl.crt --key ../cert/openssl.key  -v 2> /dev/null ; ls -la *.sys

