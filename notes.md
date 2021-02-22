# TODO

updated pefile.py
0x111E8 : lea -> string "[TARGET]..." that was not modified
Entry point / DriverEntry should be 0x1941C (instead of 0x1835C)

# Lab setup

## VM setup
`apt install virtualbox`
install debugger VM and target VM

On debugger VM: install Windbg (windows store)

On target VM:
```
bcdedit /set nointegritychecks on
bcdedit /debug on
bcdedit /set testsigning on
bcdedit /dbgsettings net hostip:w.x.y.z port:n
bcdedit /set "{dbgsettings}" busparams b.d.f
```
where: 
* `w.x.y.z` = debugger's ip
* `n` = tcp port
* `b.d.f` = bus/device/function as seen in Device Manager (look at the network adapter's general tab)

Remarks:
* enable firewalling rules for debugging to work
* not every adapter will be compatible, virtualbox virtual adapters will be though

Source: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection


## Allow sysinternals dbgview to see DbgPrint() in Windows 10

* add a new key (if it does not exist) `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter`
* add a new double word (32 bits) value equal to `0xf`
* reboot



# Compiling and testing windows drivers on Linux

## Installing tools
```
apt install mingw-w64
apt install gcc-mingw-w64-i686
```

May need to patch a ddk include file:
```
--- a/mingw-w64-headers/ddk/include/ddk/wdm.h
+++ b/mingw-w64-headers/ddk/include/ddk/wdm.h
@@ -371,6 +371,10 @@ InterlockedExchangeAdd(
 
 #if defined(_M_AMD64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)
 //#if !defined(_X86AMD64_) // FIXME: what's _X86AMD64_ used for?
+
+#undef InterlockedAdd64
+// We provide a version of our own here in this case
+
 FORCEINLINE
```

## Example windows driver

### hello world driver (ddk.c)
```
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Hello from driver!\n");
    return STATUS_SUCCESS;
}
```

### Makefile

```
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
```

## Generate certificate for code signing

`openssl req -x509 -nodes -newkey rsa:4096 -sha256 -keyout openssl.key -out openssl.crt -subj "/CN=company.co.nz" -days 600`

## Sign a driver on Linux
* `pip3 install winsign`
* `apt install osslsigncode`
* `winsign -d sha256  target.sys target.signed.sys --certs openssl.crt --key openssl.key`

## Launch driver

Two options:
* `osrloader` (GUI tool)
* command line with `sc.exe`
```
sc.exe stop drvname
sc.exe delete drvname
sc.exe create drvname type= kernel start= demand error= normal binPath= C:\XXX\target.sys DisplayName= drvname
```



# pe-afl

## prerequisites

Get latest `pefile.py` (`https://github.com/erocarrera/pefile`, no need for the entire repository, main python is stand-alone)

## ida_dumper.py
					rip_inst : [] 
					idata : []
stack frames 		stk_frame : {}

code locations		code_loc : {a1 : b1, a2 : b2, ...}
					range between ai and bi is code
					everything that is not in these is NOT code
basic blocks 		bb : [ x1, x2, x3, ... ]
					@xi, there is a jump landing

relative jumps		relative : {a : [b, 'e8', 4, 5], ...}
					@a, there is a 0xe8 + rel32 that points to b
					a has to be in bb list
