#include "header.h"
#include <ktmw32.h>
#include <stdlib.h>

DWORD g_szFile;
HANDLE g_hDev;

struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	const wchar_t* Buffer;
};

/*
already defined
struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	_LSA_UNICODE_STRING*           ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
};
*/

BOOL analyze_potential_leaks(PVOID buffer, UINT size) {
	BOOL result = FALSE;
	UINT i;
	if (size < 8) {
		return FALSE;
	}

	for (i = 0; i + sizeof(DWORD64) <= size; i += sizeof(DWORD64)) {
		DWORD64 content = ((DWORD64*)buffer)[i / sizeof(DWORD64)];
		if ((content >= 0xFFFF800000000000 && content <= 0xFFFFFFFFFFFFFFFF) && content != 0xFFFFFFFFFFFFFFFF) {
			LOG(_T("LEAK? %i: %I64d\n"), i, content);
		}
		result = TRUE;
	}

	return result;
}

PVOID mapInputFile(TCHAR* filepath)
{
	HANDLE hFile, hMap;
	PVOID pView = NULL;

	g_szFile = 0;

	// Open file
	hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {

		// Create the file mapping object
		hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hMap) {
			pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
			if (pView) {
				LOG(_T("Successfully mapped view of file %ws as input\n"), filepath);

				g_szFile = GetFileSize(hFile, NULL);
				if (g_szFile == INVALID_FILE_SIZE) {
					LOG(_T("Failed to get file size with error %x\n"), GetLastError());
				}
			}
			else {
				LOG(_T("Failed to map view of file %ws with error %x\n"), filepath, GetLastError());
			}
			CloseHandle(hMap);
		}
		else {
			LOG(_T("Failed to create file mapping for %ws with error %x\n"), filepath, GetLastError());
		}
		CloseHandle(hFile);
	}
	else {
		LOG(_T("Failed to open file %ws with error %#.8x\n"), filepath, GetLastError());
	}
	return pView;
}
HANDLE openDev(LPCTSTR deviceName) {
	HANDLE hDev;

	hDev = CreateFile(deviceName, MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDev == INVALID_HANDLE_VALUE) {
		LOG(_T("Device file %ws open failed with GetLastError %#x\n"), deviceName, GetLastError());
		exit(1);
	}

/*
	else {

		NTSTATUS
			(NTAPI
			*ntCreateFile)(
			_Out_     PHANDLE FileHandle,
			_In_      ACCESS_MASK DesiredAccess,
			_In_      struct _OBJECT_ATTRIBUTES* ObjectAttributes,
			_Out_     PVOID IoStatusBlock,
			_In_opt_  PLARGE_INTEGER AllocationSize,
			_In_      ULONG FileAttributes,
			_In_      ULONG ShareAccess,
			_In_      ULONG CreateDisposition,
			_In_      ULONG CreateOptions,
			_In_      PVOID EaBuffer,
			_In_      ULONG EaLength
			);

		HMODULE ntdll = GetModuleHandleA("ntdll");
		*(void**)&ntCreateFile = GetProcAddress(ntdll, "NtCreateFile");

		_LSA_UNICODE_STRING name;
		name.Buffer = deviceName;
		name.Length = name.MaximumLength = _tcslen(deviceName) * 2;

		_OBJECT_ATTRIBUTES attr;
		attr.Length = sizeof(attr);
		attr.RootDirectory = 0;
		attr.ObjectName = &name;
		attr.Attributes = 64;
		attr.SecurityDescriptor = 0;
		attr.SecurityQualityOfService = 0;

		UINT64 tmp[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

		NTSTATUS ns = ntCreateFile(&hDev, MAXIMUM_ALLOWED, &attr, tmp, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0, 0, 0);
		if (ns) {
			LOG(_T("Device file %ws open failed with NTSTATUS %#x\n"), deviceName, ns);
			exit(2);
		}
	}
*/
	LOG(_T("Device file %ws opened successfully\n"), deviceName);
	return hDev;
}

DWORD sendIoctl(HANDLE hDev, DWORD iocode, PVOID inbuf, DWORD inlen, PVOID outbuf, DWORD outlen)
{
	BOOL bResult, bSent = FALSE, bAddress = FALSE;
	LPTSTR errormessage;
	DWORD bytesreturned = 0;
	DWORD error;

	if (!iocode) {
		LOG(_T("empty ioctl\n"));
		return 0;
	}
	
	if (inbuf) {
		//LOG(_T("Sending ioctl %#.8x\n"), iocode);
		bResult = DeviceIoControl(hDev, iocode, inbuf, inlen, outbuf, outlen, &bytesreturned, NULL);
		error = bResult ? ERROR_SUCCESS : GetLastError();
		bSent = TRUE;
	}

	if (bSent) {
		if (error == ERROR_SUCCESS) {
			//LOG(_T("IOCTL completed SUCCESSFULLY, returned %u bytes\n"), bytesreturned);
		}
		else {
			// Verbose error
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0, (LPTSTR)&errormessage, 4, NULL);
			LOG(_T("IOCTL FAILED with error %x: %ws\n"), error, errormessage);
			LocalFree(errormessage);
		}
	}

	if (bSent) {
		//hexDump(NULL, outbuf, bytesreturned);
		//analyze_potential_leaks(outbuf, bytesreturned);
	}
	
	return bytesreturned;
}

void init_device(TCHAR* name) {
	g_hDev = openDev(name);
}

void process(HANDLE hDev, DWORD iocode, PTCHAR input_path, int ioctl_recbuf_size) {
	TCHAR* outbuf = NULL;

	PVOID inbuf = mapInputFile(input_path);
	if (!inbuf || !g_szFile) {
		if (inbuf) {
			UnmapViewOfFile(inbuf);
		}
		return;
	}

	if (ioctl_recbuf_size <= 0 || ioctl_recbuf_size > (1024 * 1024)) {
		LOG(_T("Invalid ioctl_recbuf_size %d\n"), ioctl_recbuf_size);
		UnmapViewOfFile(inbuf);
		return;
	}

	outbuf = (TCHAR*)malloc((size_t)ioctl_recbuf_size);
	if (!outbuf) {
		LOG(_T("Failed to allocate IOCTL output buffer\n"));
		UnmapViewOfFile(inbuf);
		return;
	}

	sendIoctl(hDev, iocode, inbuf, g_szFile, outbuf, ioctl_recbuf_size);
	free(outbuf);
	UnmapViewOfFile(inbuf);
}

int _ioctl_code = 0;
int _ioctl_recbuf_size = 0;

void init_ioctl(char *ioctl_endpoint, int ioctl_code, char *afl_target, char *shm_name, int ioctl_recbuf_size) {
//    LOG(_T("CODE: 0x%x\n"), CTL_CODE(FILE_DEVICE_UNKNOWN, 801, METHOD_BUFFERED, FILE_ANY_ACCESS));
    INIT(afl_target, shm_name);
    init_device(ioctl_endpoint);

    _ioctl_code = ioctl_code;
    _ioctl_recbuf_size = ioctl_recbuf_size;
}

void process_ioctl(char *at_file) {
	PRE();
    process(g_hDev, _ioctl_code, at_file, _ioctl_recbuf_size);
    POST();
 }


void init_clfs(char *afl_target, char *shm_name) {
    INIT(afl_target, shm_name);
}

/*
std::wstring Str2Wstr(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}
*/

void process_clfs(char *at_file) {
	PRE();

	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &at_file[0], strlen(at_file), NULL, 0);
	wchar_t name[size_needed + 10];
	MultiByteToWideChar(CP_UTF8, 0, &at_file[0], strlen(at_file), &name[0], size_needed);

	HANDLE rc = CreateTransactionManager(NULL, name, 0, 0);
	if (rc == INVALID_HANDLE_VALUE) {
//		LOG(_T("CreateTransactionManager(): %d\n"), GetLastError());
	}
	else {
//		LOG(_T("Success\n"));
	}

	RecoverTransactionManager(rc);
	CloseHandle(rc);

    POST();

 }