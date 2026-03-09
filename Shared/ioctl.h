#pragma once

//
// Shared IOCTL codes between Driver and Mapper.
// Must match Driver/main.h
//

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define IOCTL_HIJACK_PING                                                      \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIJACK_READ_MEM                                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIJACK_WRITE_MEM                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KERNEL_READ_REQUEST {
  unsigned long long SourceAddress;
  unsigned long long TargetAddress;
  unsigned long long Size;
  long Status;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
  unsigned long long SourceAddress;
  unsigned long long TargetAddress;
  unsigned long long Size;
  long Status;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;
