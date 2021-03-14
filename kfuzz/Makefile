SUBDIRS = target_driver helper_driver afl
MAKE = make
SWITCHES = -DDEBUG
BINDIR = /hdd/proj/fuzz/vm_shared

MYMAKEFLAGS = 'BINDIR=$(BINDIR)' 'SWITCHES=$(SWITCHES)'

all:
	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; $(MAKE) $(MYMAKEFLAGS) all); done

clean:
	@for i in $(SUBDIRS); do \
	echo "Installing in $$i..."; \
	(cd $$i; $(MAKE) $(MYMAKEFLAGS) clean); done