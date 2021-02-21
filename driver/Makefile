OBJECTS = ddk.o
TARGET = ddk.sys
CFLAGS = -I/usr/i686-w64-mingw32/include/ddk -DMINGW -std=c99 -Wall -m64 -shared
CC = x86_64-w64-mingw32-gcc

all: $(TARGET)
clean:
	rm -f ddk.o $(TARGET)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): ddk.o
	$(CC) $(CFLAGS) -Wl,--subsystem,native -Wl,--image-base,0x10000 \
-Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
-Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat \
-nostartfiles -nostdlib -o $(TARGET) \
$(OBJECTS) -lntoskrnl -lhal

