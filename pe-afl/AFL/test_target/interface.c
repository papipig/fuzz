#include "header.h"

PUCHAR HELPER_GetModuleSectionAddress(PTCHAR pBuffer)
{
	DWORD dwRet = 0, dwOutLen = 0, dwInLen = 0;
	PUCHAR qwData = 0;
	BOOLEAN bRet = 0;

	dwInLen = (DWORD)_tcsclen(pBuffer) + 1;
	dwInLen *= 2;
	dwOutLen = sizeof(qwData);
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_GET_SECTION_ADDRESS, pBuffer, dwInLen, &qwData, dwOutLen, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_GetModuleSectionAddress(%s) failed, GLE(%x)\n"), pBuffer, GetLastError());
	}
	return qwData;
}

DWORD HELPER_ReadMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_READ_MEMORY, &dwAddr, dwLen, pRetBuffer, dwLen, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_ReadMemory(%p, %p, %x) failed, GLE(%x)\n"), dwAddr, pRetBuffer, dwLen, GetLastError());
	}
	return dwRet;
}

DWORD HELPER_WriteMemory(PBYTE dwAddr, PBYTE pRetBuffer, DWORD dwLen)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_WRITE_MEMORY, &dwAddr, dwLen, pRetBuffer, dwLen, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_WriteMemory(%p, %p, %x) failed, GLE(%x)\n"), dwAddr, pRetBuffer, dwLen, GetLastError());
	}
	return dwRet;
}

DWORD HELPER_AllocateMemory(DWORD dwPoolType, DWORD dwLen, DWORD dwTag)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;
	DWORD dwData = 0;

	DWORD in[] = { dwPoolType, dwLen, dwTag };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_ALLOCATE_MEMORY, in, sizeof(in), &dwData, sizeof(&dwData), &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_AllocateMemory(%x, %x, 0x%x) failed, GLE(%x)\n"), dwPoolType, dwLen, dwTag, GetLastError());
	}
	return dwData;
}

DWORD HELPER_FreeMemory(PBYTE dwAddr, DWORD dwTag)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	DWORD64 in[] = { (DWORD64)dwAddr, (DWORD64)dwTag };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_FREE_MEMORY, in, sizeof(in), NULL, NULL, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_FreeMemory(%p, %x) failed, GLE(%x)\n"), dwAddr, dwTag, GetLastError());
	}
	return dwRet;
}

DWORD HELPER_MapMemory(PBYTE dwAddr, DWORD dwLen, PBYTE *ptrUserAddr, PBYTE *ptrMdl)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	DWORD64 in[] = { (DWORD64)dwAddr, dwLen };
	PBYTE out[2] = { 0 };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_MAP_MEMORY, in, sizeof(in), out, sizeof(out), &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_MapMemory(0x%I64X, %x, %I64X, %I64X) failed, GLE(%x)\n"), dwAddr, dwLen, ptrUserAddr, ptrMdl, GetLastError());
	}
	*ptrUserAddr = (PBYTE)out[0];
	*ptrMdl = (PBYTE)out[1];
	return dwRet;
}

DWORD HELPER_UnmapMemory(PBYTE ptrUserAddr, PBYTE ptrMdl)
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	DWORD64 in[] = { (DWORD64)ptrUserAddr, (DWORD64)ptrMdl };
	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_UNMAP_MEMORY, in, sizeof(in), NULL, 0, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_UnmapMemory(%p, %p) failed, GLE(%x)\n"), ptrUserAddr, ptrMdl);
	}
	return dwRet;
}

DWORD HELPER_ResetBuffer()
{
	DWORD dwRet = 0;
	BOOLEAN bRet = 0;

	bRet = DeviceIoControl(hHelper, IOCTL_HELPER_DUMP_AND_RESET_CALLBACK, NULL, NULL, NULL, 0, &dwRet, NULL);
	if (!bRet) {
		LOG(_T("HELPER_ResetBuffer() failed, GLE(%x)\n"), GetLastError());
	}
	return dwRet;
}