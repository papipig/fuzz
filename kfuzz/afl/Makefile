OBJECTS_SHOW = test.o interface.o persistent.o afl-showmap.o
OBJECTS_FUZZ = test.o interface.o persistent.o afl-fuzz.o 
TARGETFUZZ = afl-fuzz.exe
TARGETSHOW = afl-showmap.exe
CFLAGS = -DMINGW -std=c99 -Wunused-function -m64
CC = x86_64-w64-mingw32-gcc
BINDIR := .

all: $(TARGETSHOW) $(TARGETFUZZ) 
clean:
	rm -f ${OBJECTS_SHOW} ${OBJECTS_FUZZ} $(BINDIR)/$(TARGETSHOW) $(BINDIR)/$(TARGETFUZZ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

$(TARGETSHOW): $(OBJECTS_SHOW)
	$(CC) $(OBJECTS_SHOW) -o $(BINDIR)/$@ 

$(TARGETFUZZ): $(OBJECTS_FUZZ)
	$(CC) $(OBJECTS_FUZZ) -o $(BINDIR)/$@ 
