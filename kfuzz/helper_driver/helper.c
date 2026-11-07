#include <ntddk.h>
#include <ntstrsafe.h>

#ifdef WITHEXCEPT
typedef LONG (WINAPI *PVECTORED_EXCEPTION_HANDLER) (PEXCEPTION_POINTERS);

#include <errhandlingapi.h>
#endif

#include "helper.h"

#define DRIVER_NAME                       L"\\Device\\helper"
#define DEVICE_NAME                       L"\\DosDevices\\helper"
#define IMAGE_SIZEOF_SHORT_NAME           8
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16
#define IMAGE_NT_SIGNATURE                0x00004550  // PE00
#define IMAGE_DOS_SIGNATURE               0x5A4D      // MZ

#define HELPER_MAX_RW_SIZE                (1024 * 1024)
#define HELPER_MAX_ALLOC_SIZE             (16 * 1024 * 1024)
#define HELPER_MAX_MAP_SIZE               (16 * 1024 * 1024)

#ifndef KF_HELPER_ALLOW_DANGEROUS_IOCTL
#define KF_HELPER_ALLOW_DANGEROUS_IOCTL   1
#endif

#define NonPagedPoolNx	512

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONG BaseOfData;
	ULONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Reserved1;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONG SizeOfStackReserve;
	ULONG SizeOfStackCommit;
	ULONG SizeOfHeapReserve;
	ULONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
}IMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	}Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_DOS_HEADER { // DOS .EXE header
	USHORT e_magic;                 // Magic number
	USHORT e_cblp;                  // Bytes on last page of file
	USHORT e_cp;                    // Pages in file
	USHORT e_crlc;                  // Relocations
	USHORT e_cparhdr;               // Size of header in paragraphs
	USHORT e_minalloc;              // Minimum extra paragraphs needed
	USHORT e_maxalloc;              // Maximum extra paragraphs needed
	USHORT e_ss;                    // Initial (relative) SS value
	USHORT e_sp;                    // Initial SP value
	USHORT e_csum;                  // Checksum
	USHORT e_ip;                    // Initial IP value
	USHORT e_cs;                    // Initial (relative) CS value
	USHORT e_lfarlc;                // File address of relocation table
	USHORT e_ovno;                  // Overlay number
	USHORT e_res[4];                // Reserved words
	USHORT e_oemid;                 // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;               // OEM information; e_oemid specific
	USHORT e_res2[10];              // Reserved words
	ULONG e_lfanew;                 // File address of new exe header
}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define MAX_PATH_LEN 1024

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY
 {
     HANDLE Section;
     PVOID  MappedBase;
     PVOID  ModuleBaseAddress;
     ULONG  ImageSize;
     ULONG  Flags;
     USHORT LoadOrderIndex;
     USHORT InitOrderIndex;
     USHORT LoadCount;
     USHORT ModuleNameOffset;
     UCHAR  ModuleName[256];
 } SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

/*
typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONG  Unused;
	ULONG  Always0;
	PVOID  ModuleBaseAddress;
	ULONG  ModuleSize;
	ULONG  Unknown;
	ULONG  ModuleEntryIndex;
	USHORT ModuleNameLength;
	USHORT ModuleNameOffset;
	CHAR   ModuleName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;
*/

// Class 11
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG  Unknown1;
	ULONG  Unknown2;
#ifdef _WIN64
	ULONG Unknown3;
	ULONG Unknown4;
#endif
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  PathLength;
	CHAR  ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

//extern "C" 
NTKERNELAPI  NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

static NTSTATUS CopyModuleNameFromIoctlBuffer(PVOID buffer, ULONG input_len, CHAR* out_name, SIZE_T out_name_len)
{
	ULONG i = 0;
	const WCHAR* wname;
	ULONG wchar_count;

	if (!buffer || !out_name || out_name_len < 2 || input_len < sizeof(WCHAR)) {
		return STATUS_INVALID_PARAMETER;
	}

	out_name[0] = '\0';
	wname = (const WCHAR*)buffer;
	wchar_count = input_len / sizeof(WCHAR);

	for (i = 0; i < wchar_count && i < (ULONG)(out_name_len - 1); i++) {
		WCHAR ch = wname[i];
		if (ch == L'\0') {
			out_name[i] = '\0';
			return i ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
		}
		if (ch > 0x7f) {
			return STATUS_OBJECT_NAME_INVALID;
		}
		out_name[i] = (CHAR)ch;
	}

	out_name[(out_name_len - 1)] = '\0';
	return STATUS_BUFFER_OVERFLOW;
}

PVOID
KernelGetModuleBase(
	PCHAR  pModuleName
)
{
	PVOID pModuleBase = NULL;
	PULONG pSystemInfoBuffer = NULL;

#ifdef WITHEXCEPT
		__try1 (EXCEPTION_EXECUTE_HANDLER)
#endif
	{
		NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
		ULONG    SystemInfoBufferSize = 0;

		status = ZwQuerySystemInformation(SystemModuleInformation,
			&SystemInfoBufferSize,
			0,
			&SystemInfoBufferSize);

		if (!SystemInfoBufferSize)
			return NULL;

		pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

		if (!pSystemInfoBuffer)
			return NULL;


		memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);
		
		status = ZwQuerySystemInformation(SystemModuleInformation,
			pSystemInfoBuffer,
			SystemInfoBufferSize * 2,
			&SystemInfoBufferSize);

		if (NT_SUCCESS(status))
		{
			PSYSTEM_MODULE_ENTRY pSysModuleEntry = (PSYSTEM_MODULE_ENTRY)
				((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
			ULONG i;

			for (i = 0; i <((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
			{
				/*
				DbgPrint("[HELPER][KernelGetModuleBase] %I64X + %I64X\n", pSysModuleEntry[i].ModuleName, pSysModuleEntry[i].ModuleNameOffset);
				DbgPrint("[HELPER][KernelGetModuleBase] %s\n", pSysModuleEntry[i].ModuleName + pSysModuleEntry[i].ModuleNameOffset);
				*/
				if (_stricmp(pSysModuleEntry[i].ModuleName +
					pSysModuleEntry[i].ModuleNameOffset, pModuleName) == 0)
				{
					pModuleBase = pSysModuleEntry[i].ModuleBaseAddress;
					break;
				}

			}
		}

	}
#ifdef WITHEXCEPT
	__except1 
	{
		pModuleBase = NULL;
	}
#endif
	
	if (pSystemInfoBuffer) {
		ExFreePool(pSystemInfoBuffer);
	}

	return pModuleBase;
} // end KernelGetModuleBase()

void Unload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	DbgPrint("[HELPER] helper driver unloaded !\n");
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoDeleteSymbolicLink(&usSymboName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS WriteMemory(PVOID ulAddr, UCHAR* pData, ULONG ulLen)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
#ifdef WITHEXCEPT
		__try1 (EXCEPTION_EXECUTE_HANDLER)
#endif
		{
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					KdPrint(("MmProtectMdlSystemAddress successed\n"));
					RtlCopyMemory(ptrBuffer, pData, ulLen);
					KdPrint(("Write data complete\n"));
				}
				else {
					KdPrint(("MmProtectMdlSystemAddress failed 0x%X\n", status));
				}
			}
		}
#ifdef WITHEXCEPT
	__except1 
		{
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}
#endif

		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			MmUnlockPages(ptrMdl);
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}

NTSTATUS ReadMemory(PVOID ulAddr, UCHAR* pData, ULONG ulLen)
{
	PMDL ptrMdl = NULL;
	PVOID ptrBuffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (ptrMdl == NULL) {
		KdPrint(("IoAllocateMdl failed\n"));
		return status;
	}
	else {
#ifdef WITHEXCEPT
		__try1 (EXCEPTION_EXECUTE_HANDLER)
#endif
		{
			MmProbeAndLockPages(ptrMdl, KernelMode, IoModifyAccess);
			ptrBuffer = MmMapLockedPagesSpecifyCache(ptrMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
			if (ptrBuffer == NULL) {
				KdPrint(("MmMapLockedPagesSpecifyCache failed\n"));
			}
			else {
				status = MmProtectMdlSystemAddress(ptrMdl, PAGE_EXECUTE_READWRITE);
				if (status == STATUS_SUCCESS) {
					KdPrint(("MmProtectMdlSystemAddress successed\n"));
					RtlCopyMemory(pData, ptrBuffer, ulLen);
					KdPrint(("Read data complete\n"));
				}
				else {
					KdPrint(("MmProtectMdlSystemAddress failed 0x%X\n", status));
				}
			}
		}
#ifdef WITHEXCEPT
	__except1 
		{
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}
#endif
		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}

		if (ptrMdl) {
			MmUnlockPages(ptrMdl);
			IoFreeMdl(ptrMdl);
		}
	}
	return status;
}

NTSTATUS MapMemory(PVOID ulAddr, ULONG ulLen, PVOID *ptrBuffer, PMDL *ptrMdl)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	*ptrMdl = IoAllocateMdl((PVOID)ulAddr, ulLen, FALSE, FALSE, NULL);
	if (*ptrMdl == NULL) {
		DbgPrint("IoAllocateMdl failed\n");
		return status;
	}
	else {
		#ifdef WITHEXCEPT
		__try1 (EXCEPTION_EXECUTE_HANDLER)
		#endif
		{
			MmBuildMdlForNonPagedPool(*ptrMdl);
			*ptrBuffer = MmMapLockedPagesSpecifyCache(*ptrMdl, UserMode, MmCached, NULL, FALSE, HighPagePriority);
			if (*ptrBuffer == NULL) {
				DbgPrint("MmMapLockedPagesSpecifyCache failed\n");
			}
			return STATUS_SUCCESS;
		}
#ifdef WITHEXCEPT
	__except1 

		{
			status = GetExceptionCode();
			DbgPrint("Exception code: 0x%X\n", status);
		}
#endif
		/*
		if (ptrBuffer) {
			MmUnmapLockedPages(ptrBuffer, ptrMdl);
		}
		if (ptrMdl) {
			IoFreeMdl(ptrMdl);
		}
		*/
	}
	return status;
}
VOID UnmapMemory(PVOID ptrBuffer, PMDL ptrMdl)
{
	if (ptrBuffer) {
		MmUnmapLockedPages(ptrBuffer, ptrMdl);
	}
	if (ptrMdl) {
		IoFreeMdl(ptrMdl);
	}
}

#define DllExport __declspec(dllexport)
DWORD tbl_size = 0x100;
DllExport DWORD tbl_idx = 0;
DllExport PVOID* tbl = NULL;
DllExport NTSTATUS callback() {
	if (!tbl) tbl = ExAllocatePoolWithTag(NonPagedPoolNx, tbl_size * sizeof(PVOID), 0x41414141);
	if (tbl_idx >= tbl_size) {
		PVOID* old_tbl = tbl;
		tbl_size *= 2;
		tbl = ExAllocatePoolWithTag(NonPagedPoolNx, tbl_size * sizeof(PVOID), 0x41414141);
		memcpy(tbl, old_tbl, tbl_size * sizeof(PVOID) / 2);
		ExFreePoolWithTag(old_tbl, 0x41414141);
	}
	//tbl[tbl_idx++] = (PVOID)_ReturnAddress();
	return 0;
}

void dump_and_reset_callback() {
	for (DWORD i = 0; i < tbl_idx; i++) {
		KdPrint(("%x\n", tbl[i]));
	}
	if (tbl) {
		ExFreePoolWithTag(tbl, 0x41414141);
		tbl = NULL;
		tbl_size = 0x100;
		tbl_idx = 0;
	}
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	ULONG i = 0, code = 0, len = 0, size = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID ptrBaseAddr = 0, ptrRetAddr = 0;

	ULONG ptrRetRVA = 0;
	
	ULONG ptrTag = 0, ptrType = 0;
	PVOID ptrUserAddr = 0, ptrMdl = 0;
	PIO_STACK_LOCATION stack = NULL;
	ANSI_STRING cov = { 4,5,".cov" };
	ANSI_STRING data = { 5,6,".data" };
	ANSI_STRING secName;
	CHAR name[MAX_PATH_LEN] = { 0 };
	HELPER_SECTION_RANGE range = {0};
	NTSTATUS name_status = STATUS_SUCCESS;

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;
	switch (code) {
	case IOCTL_HELPER_GET_DATA_SECTION_ADDRESS:
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HELPER_SECTION_RANGE) ||
			!pIrp->AssociatedIrp.SystemBuffer ||
			!stack->Parameters.DeviceIoControl.InputBufferLength) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		name_status = CopyModuleNameFromIoctlBuffer(
			pIrp->AssociatedIrp.SystemBuffer,
			stack->Parameters.DeviceIoControl.InputBufferLength,
			name,
			sizeof(name));
		if (!NT_SUCCESS(name_status)) {
			status = name_status;
			break;
		}
		DbgPrint("Get Data Section Address: %s\n", name);

		ptrBaseAddr = KernelGetModuleBase(name);
		DbgPrint("KernelGetModuleBase(%s) = %I64x\n", name, ptrBaseAddr);

		if (ptrBaseAddr && (((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
			IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
			IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
			IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
			IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
			IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
			for (i = 0; i<pFileheader->NumberOfSections; i++) {
				RtlInitAnsiString(&secName, (PCSZ)sectionHeader->Name);
				if (RtlCompareString(&secName, &data, TRUE) == 0) {
					ptrRetRVA = sectionHeader->VirtualAddress;
					size = sectionHeader->Misc.VirtualSize;

					DbgPrint("------------------------------------------------------------------\n");
					DbgPrint("Section Name = %s\n", sectionHeader->Name);
					DbgPrint("Virtual Offset = %X\n", sectionHeader->VirtualAddress);
					DbgPrint("Virtual Size = %X\n", sectionHeader->Misc.VirtualSize);
					DbgPrint("Raw Offset = %X\n", sectionHeader->PointerToRawData);
					DbgPrint("Raw Size = %X\n", sectionHeader->SizeOfRawData);
					DbgPrint("Characteristics = %X\n", sectionHeader->Characteristics);
					DbgPrint("------------------------------------------------------------------\n");
				}
				sectionHeader++;
			}
		}

		if(ptrRetRVA) ptrRetAddr = ptrBaseAddr + ptrRetRVA;

		range.addr = (ULONG *)ptrRetAddr;
		range.size = size;

		memcpy((HELPER_SECTION_RANGE *)pIrp->AssociatedIrp.SystemBuffer, &range, sizeof(range));

		len = sizeof(HELPER_SECTION_RANGE);

		DbgPrint("[HELPER] .data Address: 0x%I64X\n", ptrRetAddr);
		DbgPrint("[HELPER] ptrRetAddr: 0x%I64X\n", ptrRetAddr);
		DbgPrint("[HELPER] ptrBaseAddr: 0x%I64X\n", ptrBaseAddr);
		DbgPrint("[HELPER] len : %d\n", len);

		break;
	case IOCTL_HELPER_GET_COV_SECTION_ADDRESS:
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PVOID) ||
			!pIrp->AssociatedIrp.SystemBuffer ||
			!stack->Parameters.DeviceIoControl.InputBufferLength) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		name_status = CopyModuleNameFromIoctlBuffer(
			pIrp->AssociatedIrp.SystemBuffer,
			stack->Parameters.DeviceIoControl.InputBufferLength,
			name,
			sizeof(name));
		if (!NT_SUCCESS(name_status)) {
			status = name_status;
			break;
		}
		DbgPrint("Get COV Section Address: %s\n", name);

		ptrBaseAddr = KernelGetModuleBase(name);
		DbgPrint("KernelGetModuleBase(%s) = %I64x\n", name, ptrBaseAddr);

		if (ptrBaseAddr && (((PUCHAR)ptrBaseAddr)[0] == 'M') && (((PUCHAR)ptrBaseAddr)[1] == 'Z')) {
			IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)ptrBaseAddr;
			IMAGE_NT_HEADERS *pImageNTHeader = (IMAGE_NT_HEADERS*)((PUCHAR)ptrBaseAddr + pDosHeader->e_lfanew);
			IMAGE_FILE_HEADER *pFileheader = &pImageNTHeader->FileHeader;
			IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &pImageNTHeader->OptionalHeader;
			IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER*)((PUCHAR)pImageOptionalHeader + pFileheader->SizeOfOptionalHeader);
			for (i = 0; i<pFileheader->NumberOfSections; i++) {
				RtlInitAnsiString(&secName, (PCSZ)sectionHeader->Name);
				if (RtlCompareString(&secName, &cov, TRUE) == 0) {
					ptrRetRVA = sectionHeader->VirtualAddress;

					DbgPrint("------------------------------------------------------------------\n");
					DbgPrint("Section Name = %s\n", sectionHeader->Name);
					DbgPrint("Virtual Offset = %X\n", sectionHeader->VirtualAddress);
					DbgPrint("Virtual Size = %X\n", sectionHeader->Misc.VirtualSize);
					DbgPrint("Raw Offset = %X\n", sectionHeader->PointerToRawData);
					DbgPrint("Raw Size = %X\n", sectionHeader->SizeOfRawData);
					DbgPrint("Characteristics = %X\n", sectionHeader->Characteristics);
					DbgPrint("------------------------------------------------------------------\n");
				}
				sectionHeader++;
			}
		}

		if(ptrRetRVA) ptrRetAddr = ptrBaseAddr + ptrRetRVA;
		*((PVOID*)pIrp->AssociatedIrp.SystemBuffer) = (ULONG *)ptrRetAddr;

		len = sizeof(ULONG *);

		DbgPrint("[HELPER] .cov Address: 0x%I64X\n", ptrRetAddr);
		DbgPrint("[HELPER] ptrRetAddr: 0x%I64X\n", ptrRetAddr);
		DbgPrint("[HELPER] ptrBaseAddr: 0x%I64X\n", ptrBaseAddr);
		DbgPrint("[HELPER] len : %d\n", len);

		break;
	case IOCTL_HELPER_READ_MEMORY:
		if (!KF_HELPER_ALLOW_DANGEROUS_IOCTL) {
			status = STATUS_ACCESS_DENIED;
			break;
		}

		if (!pIrp->AssociatedIrp.SystemBuffer) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HELPER_MEMORY_RW)) {
			HELPER_MEMORY_RW* req = (HELPER_MEMORY_RW*)pIrp->AssociatedIrp.SystemBuffer;
			ptrBaseAddr = (PVOID)(ULONG_PTR)req->addr;
			size = req->size;
		} else if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PVOID)) {
			ptrBaseAddr = *(PVOID*)pIrp->AssociatedIrp.SystemBuffer;
			size = stack->Parameters.DeviceIoControl.OutputBufferLength;
		} else {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		if (!ptrBaseAddr || !size) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (size > HELPER_MAX_RW_SIZE) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		if (size > stack->Parameters.DeviceIoControl.OutputBufferLength) {
			size = stack->Parameters.DeviceIoControl.OutputBufferLength;
		}

		KdPrint(("Read memory: addr 0x%p, size %lu\n", ptrBaseAddr, size));
		status = ReadMemory(ptrBaseAddr, (UCHAR*)pIrp->AssociatedIrp.SystemBuffer, size);
		if (!NT_SUCCESS(status)) {
			break;
		}
		len = size;
		break;
	case IOCTL_HELPER_WRITE_MEMORY:
		if (!KF_HELPER_ALLOW_DANGEROUS_IOCTL) {
			status = STATUS_ACCESS_DENIED;
			break;
		}

		if (!pIrp->AssociatedIrp.SystemBuffer) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HELPER_MEMORY_RW)) {
			HELPER_MEMORY_RW* req = (HELPER_MEMORY_RW*)pIrp->AssociatedIrp.SystemBuffer;
			UCHAR* payload = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer + sizeof(HELPER_MEMORY_RW);
			ptrBaseAddr = (PVOID)(ULONG_PTR)req->addr;
			size = req->size;
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HELPER_MEMORY_RW) + size) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			if (!ptrBaseAddr || !size) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (size > HELPER_MAX_RW_SIZE) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			DbgPrint("Write memory: addr 0x%p, size %lu\n", ptrBaseAddr, size);
			status = WriteMemory(ptrBaseAddr, payload, size);
			if (!NT_SUCCESS(status)) {
				break;
			}
		} else if (stack->Parameters.DeviceIoControl.InputBufferLength > sizeof(PVOID)) {
			UCHAR* payload = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer + sizeof(PVOID);
			ptrBaseAddr = *(PVOID*)pIrp->AssociatedIrp.SystemBuffer;
			size = stack->Parameters.DeviceIoControl.InputBufferLength - sizeof(PVOID);
			if (size > HELPER_MAX_RW_SIZE) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			DbgPrint("Write memory(legacy): addr 0x%p, size %lu\n", ptrBaseAddr, size);
			status = WriteMemory(ptrBaseAddr, payload, size);
			if (!NT_SUCCESS(status)) {
				break;
			}
		} else {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		len = 0;
		break;
	case IOCTL_HELPER_ALLOCATE_MEMORY:
		if (!KF_HELPER_ALLOW_DANGEROUS_IOCTL) {
			status = STATUS_ACCESS_DENIED;
			break;
		}

		if (!pIrp->AssociatedIrp.SystemBuffer || stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) * 3) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		ptrType = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		size = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer+1);
		ptrTag = *((ULONG*)pIrp->AssociatedIrp.SystemBuffer+2);
		if (!size || size > HELPER_MAX_ALLOC_SIZE) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		DbgPrint("Allocate memory: pooltype 0x%x, tag %X, size 0x%x\n", ptrType, ptrTag, size);
		*((PVOID*)pIrp->AssociatedIrp.SystemBuffer) = (PVOID)ExAllocatePoolWithTag(ptrType, size, ptrTag);
		if (!*((PVOID*)pIrp->AssociatedIrp.SystemBuffer)) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		len = sizeof(ULONG *);
		break;
	case IOCTL_HELPER_FREE_MEMORY:
		if (!KF_HELPER_ALLOW_DANGEROUS_IOCTL) {
			status = STATUS_ACCESS_DENIED;
			break;
		}

		if (!pIrp->AssociatedIrp.SystemBuffer || stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONGLONG) * 2) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONGLONG) * 2) {
			ULONGLONG* in64 = (ULONGLONG*)pIrp->AssociatedIrp.SystemBuffer;
			ptrBaseAddr = (PVOID)(ULONG_PTR)in64[0];
			ptrTag = (ULONG)in64[1];
		} else if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PVOID) + sizeof(ULONG)) {
			ptrBaseAddr = *(PVOID*)pIrp->AssociatedIrp.SystemBuffer;
			ptrTag = *((ULONG*)((UCHAR*)pIrp->AssociatedIrp.SystemBuffer + sizeof(PVOID)));
		} else {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		if (!ptrBaseAddr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		DbgPrint("free memory: tag %X, address 0x%I64X\n", ptrTag, ptrBaseAddr);
		ExFreePoolWithTag((PVOID)ptrBaseAddr, ptrTag);
		len = 0;
		break;
	case IOCTL_HELPER_MAP_MEMORY:
		if (!KF_HELPER_ALLOW_DANGEROUS_IOCTL) {
			status = STATUS_ACCESS_DENIED;
			break;
		}

		if (!pIrp->AssociatedIrp.SystemBuffer || stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PVOID) * 2) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HELPER_MAP_MEMORY_IN)) {
			HELPER_MAP_MEMORY_IN* req = (HELPER_MAP_MEMORY_IN*)pIrp->AssociatedIrp.SystemBuffer;
			ptrBaseAddr = (PVOID)(ULONG_PTR)req->addr;
			size = req->size;
		} else if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PVOID) * 2) {
			ptrBaseAddr = *(PVOID*)pIrp->AssociatedIrp.SystemBuffer;
			size = (ULONG)*((PVOID*)pIrp->AssociatedIrp.SystemBuffer + 1);
		} else {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		if (!ptrBaseAddr || !size) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (size > HELPER_MAX_MAP_SIZE) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		DbgPrint("Kernel Address: 0x%I64X\n", ptrBaseAddr);
		DbgPrint("Size: 0x%X\n", size);

		NTSTATUS ns = MapMemory(ptrBaseAddr, size, (PVOID*)&ptrUserAddr, (PMDL*)&ptrMdl);
		if (ns == STATUS_SUCCESS) {
			DbgPrint("Mapped User Address: 0x%I64X\n", ptrUserAddr);
			DbgPrint("MDL Address: 0x%I64X\n", ptrMdl);
		} else {
			status = ns;
			break;
		}

		*((PVOID*)pIrp->AssociatedIrp.SystemBuffer) = ptrUserAddr;
		*((PVOID*)pIrp->AssociatedIrp.SystemBuffer+1) = ptrMdl;
		len = sizeof(ULONG *)*2;
		break;
	case IOCTL_HELPER_UNMAP_MEMORY:
		if (!KF_HELPER_ALLOW_DANGEROUS_IOCTL) {
			status = STATUS_ACCESS_DENIED;
			break;
		}

		if (!pIrp->AssociatedIrp.SystemBuffer) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HELPER_UNMAP_MEMORY_IN)) {
			HELPER_UNMAP_MEMORY_IN* req = (HELPER_UNMAP_MEMORY_IN*)pIrp->AssociatedIrp.SystemBuffer;
			ptrUserAddr = (PVOID)(ULONG_PTR)req->user_addr;
			ptrMdl = (PVOID)(ULONG_PTR)req->mdl;
		} else if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PVOID) * 2) {
			ptrUserAddr = *(PVOID*)pIrp->AssociatedIrp.SystemBuffer;
			ptrMdl = *((PVOID*)pIrp->AssociatedIrp.SystemBuffer + 1);
		} else {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		if (!ptrUserAddr || !ptrMdl) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		DbgPrint("Unmapped User Address: 0x%p\n", ptrUserAddr);
		DbgPrint("MDL Address: 0x%p\n", ptrMdl);
		UnmapMemory((PVOID)ptrUserAddr, (PMDL)ptrMdl);
		len = 0;
		break;
	case IOCTL_HELPER_DUMP_AND_RESET_CALLBACK:
		dump_and_reset_callback();
		len = 0;
		break;
	default:
		DbgPrint("Invalid IOCTL code: 0x%X\n", code);
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	pIrp->IoStatus.Information = len;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;
	UNREFERENCED_PARAMETER(pRegPath);

	DbgPrint("[HELPER] helper driver loaded\n");
	RtlInitUnicodeString(&usDeviceName, DRIVER_NAME);
	IoCreateDevice(pDrvObj, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pFunObj);
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoCreateSymbolicLink(&usSymboName, &usDeviceName);

	pDrvObj->MajorFunction[IRP_MJ_CREATE] =
		pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDrvObj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
