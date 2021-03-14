OBJECTS = interface.o persistent.o main.o
TARGET = test.exe
CFLAGS = -I/usr/i686-w64-mingw32/include/ -DMINGW -std=c99 -Wall -m64 -municode #-shared
CC = x86_64-w64-mingw32-gcc

all: $(TARGET)
clean:
	rm -f ${OBJECTS} $(TARGET)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

$(TARGET): ${OBJECTS}
	rm -rf ../../../vm_shared/$(TARGET)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)
	strip $(TARGET)
	cp $(TARGET) ../../../vm_shared/


