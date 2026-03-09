#pragma once

#include <ntddk.h>

//
// Custom IOCTL code for communicating with our hijacked driver.
// Device type: FILE_DEVICE_UNKNOWN (0x22)
// Function: 0x800+ (user-defined range)
// Method: METHOD_BUFFERED
// Access: FILE_ANY_ACCESS
//
#define IOCTL_HIJACK_PING       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIJACK_READ_MEM   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIJACK_WRITE_MEM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Structures for kernel R/W requests
//
typedef struct _KERNEL_READ_REQUEST {
    ULONG64 SourceAddress;
    ULONG64 TargetAddress; // User-mode buffer
    SIZE_T  Size;
    NTSTATUS Status;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    ULONG64 SourceAddress; // User-mode buffer
    ULONG64 TargetAddress;
    SIZE_T  Size;
    NTSTATUS Status;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

//
// Undocumented: ObReferenceObjectByName
//
extern NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   AccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID*          Object
);

extern POBJECT_TYPE* IoDriverObjectType;
