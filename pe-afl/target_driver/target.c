#include <ntddk.h>
#include "target.h"

#define DRIVER_NAME                       L"\\Device\\t4rg3t"
#define DEVICE_NAME                       L"\\DosDevices\\t4rg3t"

void Unload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	DbgPrint("[TARGET] target driver unloaded !\n");
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

int global = 0;

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	ULONG code = 0, size = 0;
	PIO_STACK_LOCATION stack = NULL;
	UCHAR data[10] = {0};

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;
	size = stack->Parameters.DeviceIoControl.InputBufferLength;
	switch (code) {
	case IOCTL_TARGET_SEND_DATA:
		DbgPrint("[TARGET] Read memory: size %d\n", size);
		if (size > 4) {
			RtlCopyMemory((UCHAR*)data, (UCHAR*)pIrp->AssociatedIrp.SystemBuffer, size);
			if (data[0] == 'B') {
				if (data[0] == 'L') {
					if (data[0] == 'A') {
						if (data[0] == 'H') {
							DbgPrint("[TARGET] reached all code (%x)\n", global++);
						}
					}
				}	
			}

		}
		break;
	default:
		DbgPrint("[TARGET] Invalid IOCTL code: 0x%X\n", code);
		break;
	}

	pIrp->IoStatus.Information = size;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;
	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint("[TARGET] target driver loaded\n");
	DbgPrint("[TARGET] target driver loaded\n");

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
