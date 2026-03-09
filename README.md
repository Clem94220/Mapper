# Null.sys Hijack Mapper

## Project Structure

```
Mapper/
├── CMakeLists.txt          # Build system for the user-mode mapper
├── Driver/
│   ├── main.h              # Driver header (IOCTLs, undocumented APIs)
│   └── main.c              # Kernel driver (DriverEntry + Null.sys hijack)
├── Mapper/
│   ├── mapper.cpp           # Manual mapper (PE loader + entry)
│   ├── pe.h                 # PE parsing utilities
│   └── kernel_access.h      # Kernel R/W primitives (PLACEHOLDER)
├── Shared/
│   └── ioctl.h              # Shared IOCTL codes between driver and mapper
└── README.md
```

## How It Works

1. **Mapper** (`mapper.exe`) reads the compiled driver (`.sys` file)
2. It allocates kernel memory, maps sections, resolves imports against `ntoskrnl.exe`, and processes relocations
3. It calls the driver's `DriverEntry`
4. **Driver** finds `\Driver\Null` using `ObReferenceObjectByName`
5. It swaps `MajorFunction[IRP_MJ_DEVICE_CONTROL]` with our hook
6. Now any IOCTL sent to `\\.\NUL` is intercepted by our driver

## Available IOCTLs

| IOCTL | Code | Description |
|-------|------|-------------|
| `IOCTL_HIJACK_PING` | `0x222000` | Check if driver is alive |
| `IOCTL_HIJACK_READ_MEM` | `0x222004` | Read kernel memory |
| `IOCTL_HIJACK_WRITE_MEM` | `0x222008` | Write kernel memory |

## Building

### Mapper (User-mode)

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Driver (Kernel-mode)

Requires the Windows Driver Kit (WDK).

**Option A: Visual Studio + WDK**
Create a WDM driver project and add `Driver/main.c` and `Driver/main.h`.

**Option B: Command line**
```cmd
cl.exe /kernel /GS- /Oi /W4 /D_AMD64_ /DAMD64 ^
    /I"C:\Program Files (x86)\Windows Kits\10\Include\<ver>\km" ^
    Driver\main.c ^
    /link /SUBSYSTEM:NATIVE /DRIVER ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\<ver>\km\x64" ^
    ntoskrnl.lib /OUT:hijack.sys /ENTRY:DriverEntry
```

## Usage

```bash
# Map the driver
mapper.exe hijack.sys

# Test if hijack is active
mapper.exe --test
```

## ⚠️ Important

- **`kernel_access.h`** contains **placeholder** functions. You MUST implement your own kernel R/W primitives using your preferred method (vulnerable driver, physical memory access, etc.)
- This requires **administrator privileges** and **DSE disabled** (or a bypass)
- Test in a **virtual machine** first to avoid BSODs
