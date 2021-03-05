OBJECTS = target.o
TARGET = target.sys
SIGNEDTARGET = target.signed.sys
CFLAGS = -I/usr/i686-w64-mingw32/include/ddk -DMINGW -std=c99 -Wall -m64 -shared
CC = x86_64-w64-mingw32-gcc

all: $(TARGET)
clean:
	rm -f $(OBJECTS) $(TARGET) $(SIGNEDTARGET)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	rm -rf /home/user/proj/fuzz/vm_shared/target.sys
	rm -rf /home/user/proj/fuzz/vm_shared/target.signed.sys
	$(CC) $(CFLAGS) -Wl,--subsystem,native -Wl,--image-base,0x10000 \
-Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
-Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat \
-nostartfiles -nostdlib -o $(TARGET) \
$(OBJECTS) -lntoskrnl -lhal
	strip $(TARGET)
	###../pe_nonpaged.py ${TARGET}
	winsign -d sha256 ${TARGET} ${SIGNEDTARGET} --certs openssl.crt --key openssl.key  -v
	cp ${SIGNEDTARGET} /home/user/proj/fuzz/vm_shared/target.signed.sys
	cp ${TARGET} /home/user/proj/fuzz/vm_shared/target.sys
	
