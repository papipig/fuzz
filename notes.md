# TODO

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


### use of `donttouch` variable

Add VA to `donttouch` list to avoid adding bootstrap code to them.

### lea used for computation

This opcode uses `lea` with address `8`. We have to *guess* that `8` is no RVA, and that we are only dealing with arithmetics here...
```
.text:000000014000D080                  lea     rax, ds:8[rax*8]
```

### absolute use of base address

In the following example, we must consider `cs:140000000h` as absolute. Left unmodified.

```
.text:000000014000307F                 lea     rdx, cs:140000000h
```

### jump tables

In the following example, we have to consider `(byte_1400030B8 - 140000000h)` as RVA, but also `dd offset loc_14000309C - 140000000h` as RVAs. So we detect jump table thanks to IDA comments, and we mark every RVAs for patching.

```
.text:000000014000307D                 ja      short def_14000309A ; jumptable 000000014000309A default case, cases 13,15,17,19,24-35
.text:000000014000307F                 lea     rdx, cs:140000000h
.text:0000000140003086                 cdqe
.text:0000000140003088                 movzx   eax, ds:(byte_1400030B8 - 140000000h)[rdx+rax]
.text:0000000140003090                 mov     ecx, ds:(jpt_14000309A - 140000000h)[rdx+rax*4]
.text:0000000140003097                 add     rcx, rdx
.text:000000014000309A                 jmp     rcx             ; switch jump
.text:000000014000309C ; ---------------------------------------------------------------------------
[...]
.text:00000001400030AA ; ---------------------------------------------------------------------------
.text:00000001400030AB                 align 4
.text:00000001400030AC jpt_14000309A   dd offset loc_14000309C - 140000000h
.text:00000001400030AC                                         ; DATA XREF: sub_140003074+1C↑r
.text:00000001400030AC                 dd offset loc_1400030A2 - 140000000h ; jump table for switch statement
.text:00000001400030AC                 dd offset def_14000309A - 140000000h
```

### jump reg

Another way of making a jump table, but goes undetected by IDA.
```
.text:000000014000F4EC                 neg     r9
.text:000000014000F4EF                 inc     r10
.text:000000014000F4F2                 lea     r11, loc_14000F4FD+2 ; *******
.text:000000014000F4F9                 lea     r11, [r11+r9*4] ;  ***********
.text:000000014000F4FD
.text:000000014000F4FD loc_14000F4FD:
.text:000000014000F4FD                 jmp     r11
.text:000000014000F500 ; ---------------------------------------------------------------------------
.text:000000014000F500
.text:000000014000F500 loc_14000F500:
.text:000000014000F500
.text:000000014000F500                 mov     [rcx], rdx
.text:000000014000F503                 mov     [rcx+8], rdx
```

Instructions like `jmp reg` will be pointed out by the script, allowing user to take appropriate actions (like using `donttouch` variable for example).

## pe-afl.py / instrument.py

The snippet has been recoded (64-bits code).

### how does it work?

1. Goes through basic blocks, and run `inject_code` on each block. This populates `injected` indexed with *offsets* (not RVA). Adds a `addr_set` for each section, containing *offsets* within section where code is inserted
2. builds `jmp_map`. VA `x` is in `jmp_map[i]` <=> VA `x` is an instruction using a relative address that goes over VA `i`
3. builds `expand_list` i.e list of every relative instruction VA that has to be modified due to injected code (should be named : altered_list, because not all will be extended)
4. Extend short jumps from this list to long jumps (not always necessary, but simpler way to do this), with `expand_instr` then `inject_code`
5. Runs `build_map` that creates a map for each section. `s.addr_map[offset]` contains `diff` + instruction length.
6. updates `pdata` section (pointers to code stuffs)
7. Performs a loop `for k in sorted(relative)` to update relative offsets by computing deltas between origin and destination RVAs (sections may have moved, RVAs may have changed, we need to compute everything)
8. Patch jump tables


### parse_relative

`parse_relative` has been completely recoded

64-bit code uses a lot of `rip`-relative addressing, whereas 32-bit code uses relocations.

# Fuzzing setup

## Compilation and instrumentation

```
make
```

Run `ida_dumper.py` on compiled `target.sys`. This will produce `target.sys.dump.txt`.

```
./pe-afl.py <path to>/target.sys <path to>/target.sys.dump.txt
```

Will produce : `target.instrumented.sys`. We need to sign it:

```
winsign -d sha256 <path to>/target.instrumented.sys <path to>/target.instrumented.signed.sys --certs cert/openssl.crt --key cert/openssl.key  -v
```

## Fuzzing

* Load `helper.sys` driver
* Load target driver (ex : `target.instrumented.signed.sys `)
* Check with `afl-showmap.exe` that instrumentation is successful

Example (with HackSysExtremeVulnerableDriver as a target, `a.txt` being some random short ascii string):
```
E:\>afl-showmap.exe -p HEVD.instrumented.signed.sys -j ioctl -K 2236419 -E \\.\GLOBALROOT\Device\HackSysExtremeVulnerableDriver -o out.txt -A E:\a.txt
afl-showmap for Windows 2.36b by <0vercl0k@tuxfamily.org>
Based on WinAFL 2.36b by <ifratric@google.com>
Based on AFL 2.36b by <lcamtuf@google.com>
[*] Starting

[+] Captured 27 tuples in 'out.txt'.

E:\>type out.txt
000767:1
006936:1
008421:1
009581:1
009797:1
010110:1
013766:1
018055:1
018780:14
020856:1
021368:1
022936:1
024043:1
024149:1
024807:6
032825:1
033254:1
037013:1
038131:1
040823:1
041511:1
041995:1
047696:1
050102:1
051569:1
051630:1
062107:1
E:\
```

Then fuzzing:

```
E:\>afl-fuzz.exe -p HEVD.instrumented.signed.sys -j ioctl -K 2236419 -E \\.\GLOBALROOT\Device\HackSysExtremeVulnerableDriver -i E:\in -o E:\out -t 5000
WinAFL 1.16b by <ifratric@google.com>
Based on AFL 2.43b by <lcamtuf@google.com>
[+] You have 1 CPU cores and 0 runnable tasks (utilization: 0%).
[*] Setting up output directories...
[+] Output directory exists but deemed OK to reuse.
[*] Deleting old session data...
[+] Output dir cleanup successful.
[*] Scanning 'E:\in'...
[+] No auto-generated dictionary tokens to reuse.
[*] Creating hard links for all input files...
[*] Attempting dry run with 'id_000000'...
    len = 8, map size = 25, exec speed = 10322 us
[+] All test cases processed.

[+] Here are some useful stats:

    Test case count : 1 favored, 0 variable, 1 total
       Bitmap range : 25 to 25 bits (average: 25.00 bits)
        Exec timing : 10.3k to 10.3k us (average: 10.3k us)

[+] All set and ready to roll!

         WinAFL 1.16b based on AFL 2.43b (HEVD.instrumented.signed.sys)

+- process timing -------------------------------------+- overall results ----+
|        run time : 0 days, 0 hrs, 0 min, 54 sec       |  cycles done : 0     |
|   last new path : 0 days, 0 hrs, 0 min, 26 sec       |  total paths : 15    |
| last uniq crash : none seen yet                      | uniq crashes : 0     |
|  last uniq hang : none seen yet                      |   uniq hangs : 0     |
+- cycle progress --------------------+- map coverage -+----------------------+
|  now processing : 0 (0.00%)         |    map density : 0.04% / 0.06%        |
| paths timed out : 0 (0.00%)         | count coverage : 1.21 bits/tuple      |
+- stage progress --------------------+ findings in depth --------------------+
|  now trying : havoc                 | favored paths : 1 (6.67%)             |
| stage execs : 2030/16.4k (12.39%)   |  new edges on : 6 (40.00%)            |
| total execs : 3287                  | total crashes : 0 (0 unique)          |
|  exec speed : 139.2/sec             |  total tmouts : 0 (0 unique)          |
+- fuzzing strategy yields -----------+---------------+- path geometry -------+
|   bit flips : 0/64, 0/63, 0/61                      |    levels : 2         |
|  byte flips : 0/8, 0/7, 0/5                         |   pending : 15        |
| arithmetics : 0/448, 0/0, 0/0                       |  pend fav : 1         |
|  known ints : 0/41, 0/238, 0/200                    | own finds : 14        |
|  dictionary : 0/0, 0/0, 0/0                         |  imported : n/a       |
|       havoc : 0/0, 0/0                              | stability : 100.00%   |
|        trim : 0.00%/1, 0.00%                        +-----------------------+
------------------------------------------------------+             [cpu:  0%]
```

Will find a crash in a couple of minutes.

```
afl-showmap.exe -p NNSPIHSW.instrumented.signed4.sys -j ioctl -K 2248224 -E \\.\GLOBALROOT\Device\NNS_pihs -A E:\in\a.txt -o out.txt
afl-fuzz.exe -p NNSPIHSW.instrumented.signed4.sys -j ioctl -K 2248224 -E \\.\GLOBALROOT\Device\NNS_pihs -i E:\in -o E:\out -t 5000
```

