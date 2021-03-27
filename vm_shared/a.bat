set AFL_TARGET=target.instrumented.signed.sys
test.exe \\.\GLOBALROOT\Device\t4rg3t 2231428 a.txt


afl-showmap.exe -p target.instrumented.signed.sys -j ioctl -K 2231428  -E \\.\GLOBALROOT\Device\t4rg3t -o out.txt -A E:\a.txt
afl-fuzz.exe -p target.instrumented.signed.sys -j ioctl -K 2231428 -E \\.\GLOBALROOT\Device\t4rg3t -i E:\in -o E:\out -t 5000




afl-showmap.exe -p HEVD.instrumented.signed.sys -j ioctl -K 2236419 -E \\.\GLOBALROOT\Device\HackSysExtremeVulnerableDriver -o out.txt  -A E:\a.txt
afl-fuzz.exe -p HEVD.instrumented.signed.sys -j ioctl -K 2236419 -E \\.\GLOBALROOT\Device\HackSysExtremeVulnerableDriver -i E:\in -o E:\out -t 5000