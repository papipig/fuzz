/*

x86_64-w64-mingw32-gcc sendioctl.c -o sendioctl.exe -DMINGW -std=c99 -Wunused-function -m64
*/

#include <windows.h>
#include <stdio.h>

void usage(char *app) {
    printf("Usage: %s <driver endpoint> <IOCTL> <filename> <outputlen>\n", app);
    exit(1);
}

#define MAXOUTLEN   100000

int main(char argc, char ** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    BOOL status = FALSE;                 
    DWORD bytesReturned = 0;
    CHAR inBuffer[1024] = {0};
    CHAR outBuffer[MAXOUTLEN] = {0};
    size_t filesize = 0;


    if (argc != 5) {
        usage(argv[0]);
    }

    FILE *fd = fopen(argv[3], "rb");
    if (fd == NULL) {
        printf_s("fopen() error\n");
        exit(1);
    }

    filesize = fread(inBuffer, 1, 128, fd);
    printf_s("> read %d bytes\n", filesize);

    device = CreateFileA(argv[1], MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    
    if (device == INVALID_HANDLE_VALUE)
    {
        printf_s("> Could not open device: 0x%x\n", GetLastError());
        return FALSE;
    }

    if (atoi(argv[4]) >= MAXOUTLEN) {
        printf_s("> Buffer len too high (increase maximum: %d)\n", atoi(argv[4]));
    }

    printf_s("> Issuing IOCTL 0x%x\n", atoi(argv[2]));
    status = DeviceIoControl(device, atoi(argv[2]), inBuffer, filesize, outBuffer, atoi(argv[4]), &bytesReturned, (LPOVERLAPPED)NULL);
    printf_s("> IOCTL 0x%x issued\n", atoi(argv[2]));
    printf_s("> Received from the kernel land: %s. Received buffer size: %d\n", outBuffer, bytesReturned);

    CloseHandle(device);
}