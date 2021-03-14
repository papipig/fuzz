#ifndef __MAIN_H__
#define __MAIN_H__

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tchar.h>
//#include <stdio.h>

#include "helper.h"

#define PFATAL_GLE(msg) { _tprintf(_T("%s, GLE=%d\n"), msg, GetLastError()); exit(1); }
#define PFATAL(msg) { _tprintf(_T("%s\n"), msg); exit(1); }

void INIT();
void PRE();
void POST();
void FINI();
extern DWORD PERSISTENT_COUNT;
extern HANDLE hHelper;
PUCHAR HELPER_GetModuleSectionAddress(PTCHAR pBuffer);
DWORD HELPER_ReadMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen);
DWORD HELPER_WriteMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen);
DWORD HELPER_AllocateMemory(DWORD dwPoolType, DWORD dwTag, DWORD dwLen);
DWORD HELPER_FreeMemory(PBYTE dwAddr, DWORD dwTag);
DWORD HELPER_MapMemory(PBYTE dwAddr, DWORD dwLen, PBYTE* ptrUserAddr, PBYTE* ptrMdl);
DWORD HELPER_UnmapMemory(PBYTE ptrUserAddr, PBYTE ptrMdl);
DWORD HELPER_ResetBuffer();

static void LOG(LPCTSTR format, ...)
{
    LPTSTR OutputBuf;
    OutputBuf = (LPTSTR)LocalAlloc(LMEM_ZEROINIT,   \
            (size_t)(4096 * sizeof(TCHAR)));
    va_list args;
    va_start(args, format);
    int nBuf;
    _vstprintf_s(OutputBuf, 4095, format, args);
    OutputDebugString(OutputBuf);
    //_tprintf(_T("%s"), OutputBuf);
    va_end(args);
    LocalFree(OutputBuf); // tyvm @sam shaw
}

static void hexDump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		_tprintf(_T("%s:\n"), desc);

	if (len == 0) {
		_tprintf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		_tprintf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				_tprintf(_T("  %s\n"), buff);

			// Output the offset.
			_tprintf(_T("  %04x "), i);
		}

		// Now the hex code for the specific character.
		_tprintf(_T(" %02x"), pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		_tprintf(_T("   "));
		i++;
	}

	// And print the final ASCII bit.
	_tprintf(_T("  %s\n"), buff);
}

#endif
