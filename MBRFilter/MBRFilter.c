/*++
  MBRFilter

  This is a simple disk filter based on Microsoft's diskperf example driver.
  The goal of this filter is to prevent writing to Sector 0 on Physical Drive 0. 
  This is useful to prevent malware that overwrites the MBR like Petya.

  While the MBR could be on another disk, we try to remain minimally intrusive: writing to 
  sector 0 on other drives might be desirable. This can easily be changed by modifying 
  the if statement at line 237.

  To install: double click the inf file and reboot.
  To access sector 0 on drive 0: boot into Safe Mode. 
  To compile: make sure to set:
	MBRFilter properties -> Configuration properties -> Driver Signing -> General
		Sign mode: Test Sign
		Test certificate: generate or select one from your store.

  Written by Yves Younan, Cisco Talos
  Copyright (C) 2016 Cisco Systems Inc


  Thanks to Aaron Adams for reviewing the code. 

--*/

#pragma warning(disable: 4100)
#define INITGUID

#include "ntddk.h"
#include "ntdddisk.h"
#include "stdarg.h"
#include "stdio.h"
#include <ntddvol.h>

#include <mountdev.h>
#include "wmistr.h"
#include "wmidata.h"
#include "wmiguid.h"
#include "wmilib.h"

#include "ntstrsafe.h"

#include "Guid.h"


extern PULONG InitSafeBootMode; 

#ifdef POOL_TAGGING
#ifdef ExAllocatePool
#undef ExAllocatePool
#endif
#define ExAllocatePool(a,b) ExAllocatePoolWithTag(a,b,'FRBM')
#endif

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT TargetDeviceObject;
    PDEVICE_OBJECT PhysicalDeviceObject;
    IO_REMOVE_LOCK RemoveLock;
    LONG		   DiskNumber;
	LONG		   PartitionNumber;
	WCHAR          StorageManagerName[8];
    UNICODE_STRING PhysicalDeviceName;
    WCHAR          PhysicalDeviceNameBuffer[64];
    WMILIB_CONTEXT WmilibContext;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define DEVICE_EXTENSION_SIZE sizeof(DEVICE_EXTENSION)
UNICODE_STRING MBRFRegistryPath;

WMIGUIDREGINFO MBRFGuidList[] =
{
    {&MBRFilterGuid, 1, 0}
};

#define MBRFGuidCount (sizeof(MBRFGuidList) / sizeof(WMIGUIDREGINFO))


NTSTATUS MBRFNextDrv (IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PDEVICE_EXTENSION   deviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
} 

NTSTATUS MBRFIoCompletion(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp,IN PVOID Context) {
    PDEVICE_EXTENSION  deviceExtension   = DeviceObject->DeviceExtension;
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
	IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
    return STATUS_SUCCESS;
} 

NTSTATUS MBRFIrpCompletion(_In_ PDEVICE_OBJECT DeviceObject,_In_ PIRP Irp,_In_reads_opt_(_Inexpressible_("varies")) PVOID Context) {
    PKEVENT Event = (PKEVENT) Context;
    if (Event) {
        KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS MBRFForwardIrpSynchronous(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
    PDEVICE_EXTENSION   deviceExtension;
    KEVENT				event;
    NTSTATUS			status;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, MBRFIrpCompletion,&event, TRUE, TRUE, TRUE);

    status = IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = Irp->IoStatus.Status;
    }
    return status;
}


#define FILTER_DEVICE_PROPOGATE_CHARACTERISTICS (FILE_REMOVABLE_MEDIA |  \
                                                 FILE_READ_ONLY_DEVICE | \
                                                 FILE_FLOPPY_DISKETTE)

VOID MBRFSyncFilterWithTarget(IN PDEVICE_OBJECT FilterDevice, IN PDEVICE_OBJECT TargetDevice) {
    ULONG propFlags;
    propFlags = TargetDevice->Characteristics & FILTER_DEVICE_PROPOGATE_CHARACTERISTICS;
    FilterDevice->Characteristics |= propFlags;
}

NTSTATUS MBRFRegisterDevice(IN PDEVICE_OBJECT DeviceObject) {
    NTSTATUS                status;
    IO_STATUS_BLOCK         ioStatus;
    KEVENT                  event;
    PDEVICE_EXTENSION       deviceExtension;
    PIRP                    irp;
    STORAGE_DEVICE_NUMBER   number;
    ULONG                   registrationFlag = 0;

    deviceExtension = DeviceObject->DeviceExtension;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER, deviceExtension->TargetDeviceObject, 
		  NULL, 0, &number, sizeof(number), FALSE, &event, &ioStatus);
    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(deviceExtension->TargetDeviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }

    if (NT_SUCCESS(status)) {
        deviceExtension->DiskNumber = number.DeviceNumber;
		deviceExtension->PartitionNumber = number.PartitionNumber;
        RtlStringCbPrintfW(deviceExtension->PhysicalDeviceNameBuffer,sizeof(deviceExtension->PhysicalDeviceNameBuffer),
            L"\\Device\\Harddisk%d\\Partition%d", number.DeviceNumber, number.PartitionNumber);
        RtlInitUnicodeString(&deviceExtension->PhysicalDeviceName, &deviceExtension->PhysicalDeviceNameBuffer[0]);
        RtlCopyMemory(&(deviceExtension->StorageManagerName[0]), L"PhysDisk", 8 * sizeof(WCHAR));
		status = IoWMIRegistrationControl(DeviceObject, WMIREG_ACTION_REGISTER | registrationFlag);
	}
    return status;
}


NTSTATUS MBRFStartDevice(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
    PDEVICE_EXTENSION   deviceExtension;
    NTSTATUS            status;

    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    status = MBRFForwardIrpSynchronous(DeviceObject, Irp);
    MBRFSyncFilterWithTarget(DeviceObject, deviceExtension->TargetDeviceObject);

    MBRFRegisterDevice(DeviceObject);
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}


NTSTATUS MBRFRemoveDevice(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
    NTSTATUS            status;
    PDEVICE_EXTENSION   deviceExtension;
    PWMILIB_CONTEXT     wmilibContext;

    deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    IoWMIRegistrationControl(DeviceObject, WMIREG_ACTION_DEREGISTER);
    wmilibContext = &deviceExtension->WmilibContext;
    InterlockedExchange((PLONG) &(wmilibContext->GuidCount), (LONG) 0);
    RtlZeroMemory(wmilibContext, sizeof(WMILIB_CONTEXT));
    IoReleaseRemoveLockAndWait(&deviceExtension->RemoveLock, Irp);
    status = MBRFNextDrv(DeviceObject, Irp);
   
    IoDetachDevice(deviceExtension->TargetDeviceObject);
    IoDeleteDevice(DeviceObject);
    return status;
}

NTSTATUS MBRFCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
} 
NTSTATUS NTAPI ExRaiseHardError(IN NTSTATUS ErrorStatus, IN ULONG NumberOfParameters, IN ULONG UnicodeStringParameterMask,
				IN PULONG_PTR Parameters,IN ULONG ValidResponseOptions, OUT PULONG Response);

NTSTATUS MBRFReadWrite(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
    PDEVICE_EXTENSION  deviceExtension   = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION currentIrpStack   = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS		   status;
    ULONG			   response;
    UNICODE_STRING	   title, text;
	ULONG_PTR		   param[3];

    status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);

    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    if (deviceExtension->PhysicalDeviceNameBuffer[0] == 0) {   
        status = MBRFNextDrv(DeviceObject, Irp);
        IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
        return (status);
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
	if ((currentIrpStack->MajorFunction == IRP_MJ_WRITE) && currentIrpStack->Parameters.Write.Length) {
		if (currentIrpStack->Parameters.Write.ByteOffset.QuadPart / 512 == 0 && deviceExtension->DiskNumber == 0 && deviceExtension->PartitionNumber == 0) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MBRF: write sector 0 (disk %d, partition %d)\n", deviceExtension->DiskNumber, deviceExtension->PartitionNumber);
			RtlInitUnicodeString(&title, L"Cisco Talos MBRFilter");
			RtlInitUnicodeString(&text, L"Cannot write to sector 0 on drive 0. Please reboot in Safe Mode if you wish to do this.");
			param[0]= (ULONG_PTR) &text;
			param[1]= (ULONG_PTR) &title;
			param[2]= 0x40;
			ExRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, param, 1, &response);
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
	        IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_ACCESS_DENIED;
		}
	}

	IoSetCompletionRoutine(Irp,MBRFIoCompletion,DeviceObject,TRUE,TRUE,TRUE);
    return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
}


NTSTATUS MBRFWmi(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
    NTSTATUS                status;
    PWMILIB_CONTEXT         wmilibContext;
    SYSCTL_IRP_DISPOSITION  disposition;
    PDEVICE_EXTENSION       deviceExtension = DeviceObject->DeviceExtension;

    wmilibContext = &deviceExtension->WmilibContext;
    status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);

    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    if (wmilibContext->GuidCount == 0) {
        IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
        return MBRFNextDrv(DeviceObject, Irp);
    }

    status = WmiSystemControl(wmilibContext,DeviceObject,Irp,&disposition);
    switch (disposition) {
        case IrpProcessed:
            break;

        case IrpNotCompleted:
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            break;

		default:
            IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
            return MBRFNextDrv(DeviceObject, Irp);
            break;
    }

    IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
    return status;
}

NTSTATUS MBRFDispatchPnp(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp) {
    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS            status = Irp->IoStatus.Status;
    PDEVICE_EXTENSION   deviceExtension = DeviceObject->DeviceExtension;

	status = IoAcquireRemoveLock(&deviceExtension->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    switch(irpSp->MinorFunction) {
        case IRP_MN_START_DEVICE:
            status = MBRFStartDevice(DeviceObject, Irp);
            break;
        case IRP_MN_REMOVE_DEVICE:
            return MBRFRemoveDevice(DeviceObject, Irp);
            break;
        default:
            status = MBRFNextDrv(DeviceObject, Irp);
    }

    IoReleaseRemoveLock(&deviceExtension->RemoveLock, Irp);
    return status;
}


NTSTATUS MBRFQueryWmiRegInfo(IN PDEVICE_OBJECT DeviceObject,OUT ULONG *RegFlags,OUT PUNICODE_STRING InstanceName,OUT PUNICODE_STRING *RegistryPath,
    OUT PUNICODE_STRING MofResourceName,OUT PDEVICE_OBJECT *Pdo) {
    USHORT			   size;
    NTSTATUS		   status;
    PDEVICE_EXTENSION  deviceExtension = DeviceObject->DeviceExtension;

	size = deviceExtension->PhysicalDeviceName.Length + sizeof(UNICODE_NULL);
    InstanceName->Buffer = ExAllocatePool(PagedPool, size);
    if (InstanceName->Buffer) {
        *RegistryPath = &MBRFRegistryPath;
        *RegFlags = WMIREG_FLAG_INSTANCE_PDO | WMIREG_FLAG_EXPENSIVE;
        *Pdo = deviceExtension->PhysicalDeviceObject;
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    return status;
}


NTSTATUS MBRFQueryWmiDataBlock(_Inout_ PDEVICE_OBJECT DeviceObject,_Inout_ PIRP Irp,_In_ ULONG GuidIndex,_In_ ULONG InstanceIndex,_In_ ULONG InstanceCount,
    _Out_writes_opt_(InstanceCount) PULONG InstanceLengthArray,_In_ ULONG BufferAvail,_Out_writes_bytes_opt_(BufferAvail) PUCHAR Buffer) {
    NTSTATUS status;
	if (InstanceLengthArray) {
		*InstanceLengthArray = 0;
	}
	status = WmiCompleteRequest(DeviceObject,Irp,STATUS_SUCCESS,0,IO_NO_INCREMENT);
    return status;
}


NTSTATUS MBRFAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject) {
    NTSTATUS                status;
    PDEVICE_OBJECT          filterDeviceObject;
    PDEVICE_EXTENSION       deviceExtension;
    PWMILIB_CONTEXT         wmilibContext;

	// Disable the driver in Safe Mode
	if (*InitSafeBootMode > 0) { 
		return STATUS_SUCCESS;
	}

    status = IoCreateDevice(DriverObject, DEVICE_EXTENSION_SIZE, NULL,
                            FILE_DEVICE_DISK, FILE_DEVICE_SECURE_OPEN, FALSE,&filterDeviceObject);

    if (!NT_SUCCESS(status)) {
       return status;
    }

    filterDeviceObject->Flags |= DO_DIRECT_IO;
    deviceExtension = (PDEVICE_EXTENSION) filterDeviceObject->DeviceExtension;
    RtlZeroMemory(deviceExtension, DEVICE_EXTENSION_SIZE);
	deviceExtension->DiskNumber = -1;
	deviceExtension->PartitionNumber = -1;
    deviceExtension->PhysicalDeviceObject = PhysicalDeviceObject;

	deviceExtension->TargetDeviceObject = IoAttachDeviceToDeviceStack(filterDeviceObject, PhysicalDeviceObject);
    if (!deviceExtension->TargetDeviceObject) {
        IoDeleteDevice(filterDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    IoInitializeRemoveLock(&deviceExtension->RemoveLock, 'fRBM', 1, 0);
    deviceExtension->DeviceObject = filterDeviceObject;
    deviceExtension->PhysicalDeviceName.Buffer = deviceExtension->PhysicalDeviceNameBuffer;

    wmilibContext = &deviceExtension->WmilibContext;
    RtlZeroMemory(wmilibContext, sizeof(WMILIB_CONTEXT));
    wmilibContext->GuidCount = MBRFGuidCount;
    wmilibContext->GuidList = MBRFGuidList;
    wmilibContext->QueryWmiRegInfo = MBRFQueryWmiRegInfo;
    wmilibContext->QueryWmiDataBlock = MBRFQueryWmiDataBlock;

	filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

VOID MBRFUnload(IN PDRIVER_OBJECT DriverObject) {
    return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {

    ULONG               i;
    PDRIVER_DISPATCH    *dispatch;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"MBRF: loading\n");
    MBRFRegistryPath.MaximumLength = RegistryPath->Length + sizeof(UNICODE_NULL);
    MBRFRegistryPath.Buffer = ExAllocatePool(PagedPool,MBRFRegistryPath.MaximumLength);
    if (!MBRFRegistryPath.Buffer) {
        RtlCopyUnicodeString(&MBRFRegistryPath, RegistryPath);
    } else {
        MBRFRegistryPath.Length = 0;
        MBRFRegistryPath.MaximumLength = 0;
    }

    for (i = 0, dispatch = DriverObject->MajorFunction; i <= IRP_MJ_MAXIMUM_FUNCTION; i++, dispatch++)
        *dispatch = MBRFNextDrv;

    DriverObject->MajorFunction[IRP_MJ_CREATE]          = MBRFCreate;
    DriverObject->MajorFunction[IRP_MJ_READ]            = MBRFReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE]           = MBRFReadWrite;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]  = MBRFWmi;
    DriverObject->MajorFunction[IRP_MJ_PNP]             = MBRFDispatchPnp;

    DriverObject->DriverExtension->AddDevice            = MBRFAddDevice;
    DriverObject->DriverUnload                          = MBRFUnload;

    return STATUS_SUCCESS;

}
