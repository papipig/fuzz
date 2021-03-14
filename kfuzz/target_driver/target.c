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

	PAGED_CODE();

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;
	size = stack->Parameters.DeviceIoControl.InputBufferLength;
	switch (code) {
	case IOCTL_TARGET_SEND_DATA:
		if (size >= 8) {
			RtlCopyMemory((UCHAR*)data, (UCHAR*)pIrp->AssociatedIrp.SystemBuffer, 8);
			if (data[0] == 'B') {
				if (data[1] == 'L') {
					if (data[2] == 'A') {
						if (data[3] == 'H') {
							if (data[4] == 'B') {
								if (data[5] == 'L') {
									if (data[6] == 'A') {
										if (data[7] == 'H') {
											DbgPrint("[TARGET] reached all code #1 (%x)\n", global++);
											//KeBugCheck(0xdeadbeef);
										}
									}
								}
							}
						}
					}
				}	
			}

			if (data[0] == 'b') {
				if (data[1] == 'l') {
					if (data[2] == 'a') {
						if (data[3] == 'h') {
							if (data[4] == 'b') {
								if (data[5] == 'l') {
									if (data[6] == 'a') {
										if (data[7] == 'h') {
											DbgPrint("[TARGET] reached all code #2 (%x)\n", global++);
											//KeBugCheck(0xdeadbeef);
										}
									}
								}
							}
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
