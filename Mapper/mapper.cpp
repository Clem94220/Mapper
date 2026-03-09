#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

#include "../Shared/ioctl.h"
#include "kernel_access.h"
#include "pe.h"

// ============================================================================
// Multi-module kernel export resolver
// Resolves exports from ANY loaded kernel module (ntoskrnl, WDFLDR, etc.)
// ============================================================================
namespace KernelResolver {

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef NTSTATUS(NTAPI *fnNtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

// Cached module info: local HMODULE + real kernel base
struct CachedModule {
  HMODULE hLocal;
  uint64_t kernelBase;
};

inline fnNtQuerySystemInformation g_NtQSI = nullptr;
inline std::vector<uint8_t> g_ModuleBuffer;
inline std::unordered_map<std::string, CachedModule> g_ModuleCache;

// Convert a string to lowercase for case-insensitive comparison
inline std::string ToLower(const std::string &s) {
  std::string out = s;
  for (auto &c : out)
    c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  return out;
}

// Extract just the filename from a full kernel path like
// \SystemRoot\system32\ntoskrnl.exe
inline std::string ExtractFilename(const char *fullPath) {
  std::string path(fullPath);
  auto pos = path.find_last_of("\\/");
  if (pos != std::string::npos)
    return path.substr(pos + 1);
  return path;
}

inline bool Initialize() {
  g_NtQSI = (fnNtQuerySystemInformation)GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
  if (!g_NtQSI) {
    std::cerr << "[!] Failed to get NtQuerySystemInformation.\n";
    return false;
  }

  // Query all loaded kernel modules
  ULONG neededSize = 0;
  g_NtQSI(11, nullptr, 0, &neededSize);
  g_ModuleBuffer.resize(neededSize);
  NTSTATUS status = g_NtQSI(11, g_ModuleBuffer.data(), neededSize, &neededSize);
  if (status != 0) {
    std::cerr << "[!] NtQuerySystemInformation failed: 0x" << std::hex << status
              << std::dec << "\n";
    return false;
  }

  auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(g_ModuleBuffer.data());
  std::cout << "[+] " << modules->NumberOfModules
            << " kernel modules detected.\n";

  if (modules->NumberOfModules > 0) {
    std::cout << "[+] Kernel base: 0x" << std::hex
              << reinterpret_cast<uint64_t>(modules->Modules[0].ImageBase)
              << std::dec << "\n";
  }

  return true;
}

// Find a kernel module's base address by its name (e.g. "WDFLDR.SYS")
inline uint64_t GetModuleKernelBase(const std::string &moduleName) {
  auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(g_ModuleBuffer.data());
  std::string targetLower = ToLower(moduleName);

  for (ULONG i = 0; i < modules->NumberOfModules; i++) {
    std::string fileName = ExtractFilename(
        reinterpret_cast<const char *>(modules->Modules[i].FullPathName));
    if (ToLower(fileName) == targetLower) {
      return reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);
    }
  }
  return 0;
}

// Get or create a cached module entry for resolving exports
inline CachedModule *GetCachedModule(const std::string &moduleName) {
  std::string key = ToLower(moduleName);

  // Check cache first
  auto it = g_ModuleCache.find(key);
  if (it != g_ModuleCache.end())
    return &it->second;

  // Find the real kernel base address of this module
  uint64_t kernelBase = GetModuleKernelBase(moduleName);
  if (kernelBase == 0) {
    std::cerr << "[!] Module not loaded in kernel: " << moduleName << "\n";
    return nullptr;
  }

  // Try to load it locally as a data file to read exports
  // First try the module name directly (works for system32 modules)
  std::wstring wName(moduleName.begin(), moduleName.end());
  HMODULE hLocal =
      LoadLibraryExW(wName.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);

  if (!hLocal) {
    // Try with full system32\drivers path
    std::wstring driverPath = L"C:\\Windows\\System32\\drivers\\" + wName;
    hLocal = LoadLibraryExW(driverPath.c_str(), nullptr,
                            DONT_RESOLVE_DLL_REFERENCES);
  }

  if (!hLocal) {
    // Try system32 path
    std::wstring sysPath = L"C:\\Windows\\System32\\" + wName;
    hLocal =
        LoadLibraryExW(sysPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
  }

  if (!hLocal) {
    std::cerr << "[!] Cannot load " << moduleName
              << " locally for export resolution.\n";
    return nullptr;
  }

  CachedModule cm{hLocal, kernelBase};
  g_ModuleCache[key] = cm;

  std::cout << "[+] Cached module: " << moduleName << " @ 0x" << std::hex
            << kernelBase << std::dec << "\n";

  return &g_ModuleCache[key];
}

// Resolve a specific export from a specific module
inline uint64_t ResolveExportFrom(const std::string &moduleName,
                                  const char *functionName) {
  auto *cm = GetCachedModule(moduleName);
  if (!cm)
    return 0;

  auto localBase = reinterpret_cast<uint8_t *>(cm->hLocal);
  auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(localBase);
  auto ntHeaders =
      reinterpret_cast<PIMAGE_NT_HEADERS>(localBase + dosHeader->e_lfanew);

  auto exportDirAddr =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
  auto exportDirSize =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .Size;

  if (exportDirAddr == 0 || exportDirSize == 0)
    return 0;

  auto exportDir =
      reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(localBase + exportDirAddr);

  auto names = reinterpret_cast<DWORD *>(localBase + exportDir->AddressOfNames);
  auto ordinals =
      reinterpret_cast<WORD *>(localBase + exportDir->AddressOfNameOrdinals);
  auto functions =
      reinterpret_cast<DWORD *>(localBase + exportDir->AddressOfFunctions);

  uint32_t funcRva = 0;

  for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
    const char *name = reinterpret_cast<const char *>(localBase + names[i]);
    if (strcmp(name, functionName) == 0) {
      funcRva = functions[ordinals[i]];
      break;
    }
  }

  if (funcRva == 0)
    return 0;

  // Check if it's a forwarded export
  if (funcRva >= exportDirAddr && funcRva < exportDirAddr + exportDirSize) {
    std::string forwardedName =
        reinterpret_cast<const char *>(localBase + funcRva);
    auto dotPos = forwardedName.find('.');
    if (dotPos == std::string::npos)
      return 0;

    std::string targetModule = forwardedName.substr(0, dotPos) + ".exe";
    std::string targetFunc = forwardedName.substr(dotPos + 1);

    // Some forwarders omit the extension, commonly .exe for ntoskrnl
    // Let's also check .sys
    if (ToLower(targetModule) != "ntoskrnl.exe" &&
        ToLower(targetModule) != "hal.dll") {
      targetModule = forwardedName.substr(0, dotPos) + ".sys";
    }

    std::cout << "[*] Forwarded export detected: " << functionName << " -> "
              << targetModule << "!" << targetFunc << "\n";

    return ResolveExportFrom(targetModule, targetFunc.c_str());
  }

  return cm->kernelBase + funcRva;
}

inline void Cleanup() {
  for (auto &pair : g_ModuleCache) {
    if (pair.second.hLocal)
      FreeLibrary(pair.second.hLocal);
  }
  g_ModuleCache.clear();
  g_ModuleBuffer.clear();
}

} // namespace KernelResolver

// ============================================================================
// Manual Mapper Logic
// ============================================================================
namespace Mapper {
// Typedef for the DriverEntry function
using DriverEntryFn = NTSTATUS(__stdcall *)(void *DriverObject,
                                            void *RegistryPath);

// -------------------------------------------------------------------
// Process relocations
// -------------------------------------------------------------------
bool ProcessRelocations(uint8_t *localImage, PIMAGE_NT_HEADERS nt,
                        uint64_t remoteDelta) {
  auto relocDir =
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (relocDir->Size == 0)
    return true; // No relocations needed

  auto relocBase = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
      localImage + relocDir->VirtualAddress);

  while (relocBase->VirtualAddress) {
    DWORD numEntries =
        (relocBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    WORD *entries = reinterpret_cast<WORD *>(
        reinterpret_cast<uint8_t *>(relocBase) + sizeof(IMAGE_BASE_RELOCATION));

    for (DWORD i = 0; i < numEntries; i++) {
      WORD type = entries[i] >> 12;
      WORD offset = entries[i] & 0xFFF;

      if (type == IMAGE_REL_BASED_DIR64) {
        uint64_t *patchAddr = reinterpret_cast<uint64_t *>(
            localImage + relocBase->VirtualAddress + offset);
        *patchAddr += remoteDelta;
      } else if (type == IMAGE_REL_BASED_HIGHLOW) {
        uint32_t *patchAddr = reinterpret_cast<uint32_t *>(
            localImage + relocBase->VirtualAddress + offset);
        *patchAddr += static_cast<uint32_t>(remoteDelta);
      }
      // IMAGE_REL_BASED_ABSOLUTE (0) = padding, skip
    }

    relocBase = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        reinterpret_cast<uint8_t *>(relocBase) + relocBase->SizeOfBlock);
  }

  return true;
}

// -------------------------------------------------------------------
// Resolve imports
// -------------------------------------------------------------------
bool ResolveImports(uint8_t *localImage, PIMAGE_NT_HEADERS nt) {
  auto importDir =
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (importDir->Size == 0)
    return true; // No imports

  auto importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
      localImage + importDir->VirtualAddress);

  while (importDesc->Name) {
    const char *moduleName =
        reinterpret_cast<const char *>(localImage + importDesc->Name);

    std::cout << "[*] Resolving imports from: " << moduleName << "\n";

    // For kernel drivers, imports are typically from ntoskrnl.exe or HAL.dll
    // We resolve them all against ntoskrnl for simplicity
    // (HAL exports are also present in ntoskrnl on modern Windows)

    auto thunkRef = reinterpret_cast<PIMAGE_THUNK_DATA>(
        localImage + importDesc->OriginalFirstThunk);
    auto funcRef = reinterpret_cast<PIMAGE_THUNK_DATA>(localImage +
                                                       importDesc->FirstThunk);

    for (; thunkRef->u1.AddressOfData; thunkRef++, funcRef++) {
      if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Ordinal)) {
        std::cerr << "[!] Import by ordinal not supported.\n";
        return false;
      }

      auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
          localImage + thunkRef->u1.AddressOfData);

      uint64_t funcAddr =
          KernelResolver::ResolveExportFrom(moduleName, importByName->Name);

      if (!funcAddr) {
        std::cerr << "[!] Failed to resolve import: " << importByName->Name
                  << "\n";
        return false;
      }

      funcRef->u1.Function = funcAddr;
    }

    importDesc++;
  }

  return true;
}

// -------------------------------------------------------------------
// Map the driver into kernel memory
// -------------------------------------------------------------------
bool MapDriver(const std::string &driverPath) {
  std::cout << "[*] Reading driver: " << driverPath << "\n";

  // 1. Read the raw PE file
  auto rawData = PE::ReadFile(driverPath);
  if (rawData.empty()) {
    std::cerr << "[!] Failed to read driver file.\n";
    return false;
  }

  auto nt = PE::GetNtHeaders(rawData.data());
  if (!nt) {
    std::cerr << "[!] Invalid PE file.\n";
    return false;
  }

  size_t imageSize = nt->OptionalHeader.SizeOfImage;
  uint64_t preferredBase = nt->OptionalHeader.ImageBase;

  std::cout << "[+] Image size: 0x" << std::hex << imageSize << "\n";
  std::cout << "[+] Preferred base: 0x" << preferredBase << std::dec << "\n";

  // 2. Allocate a local buffer for the mapped image
  auto localImage = std::vector<uint8_t>(imageSize, 0);

  // Copy headers
  memcpy(localImage.data(), rawData.data(), nt->OptionalHeader.SizeOfHeaders);

  // Copy sections
  auto sections = PE::GetSections(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (sections[i].SizeOfRawData == 0)
      continue;

    memcpy(localImage.data() + sections[i].VirtualAddress,
           rawData.data() + sections[i].PointerToRawData,
           sections[i].SizeOfRawData);

    std::cout << "[+] Mapped section: "
              << reinterpret_cast<const char *>(sections[i].Name)
              << " -> RVA 0x" << std::hex << sections[i].VirtualAddress << " ("
              << std::dec << sections[i].SizeOfRawData << " bytes)\n";
  }

  // 3. Initialize kernel resolver
  if (!KernelResolver::Initialize()) {
    std::cerr << "[!] Failed to initialize kernel resolver.\n";
    return false;
  }

  // 4. Resolve imports (before allocation so we fix the local copy)
  if (!ResolveImports(localImage.data(), nt)) {
    std::cerr << "[!] Failed to resolve imports.\n";
    KernelResolver::Cleanup();
    return false;
  }

  // 5. Allocate kernel memory
  uint64_t kernelBase = KernelAccess::AllocateKernelMemory(imageSize);
  if (kernelBase == 0) {
    std::cerr << "[!] Failed to allocate kernel memory.\n";
    std::cerr
        << "    You need to implement KernelAccess::AllocateKernelMemory!\n";
    KernelResolver::Cleanup();
    return false;
  }

  std::cout << "[+] Kernel allocation at: 0x" << std::hex << kernelBase
            << std::dec << "\n";

  // 6. Process relocations
  uint64_t delta = kernelBase - preferredBase;
  if (delta != 0) {
    std::cout << "[*] Processing relocations (delta: 0x" << std::hex << delta
              << std::dec << ")\n";

    if (!ProcessRelocations(localImage.data(), nt, delta)) {
      std::cerr << "[!] Failed to process relocations.\n";
      KernelAccess::FreeKernelMemory(kernelBase);
      KernelResolver::Cleanup();
      return false;
    }
  }

  // 7. Write the mapped image to kernel memory
  std::cout << "[*] Writing mapped image to kernel...\n";
  if (!KernelAccess::WriteKernelMemory(kernelBase, localImage.data(),
                                       imageSize)) {
    std::cerr << "[!] Failed to write to kernel memory.\n";
    std::cerr << "    You need to implement KernelAccess::WriteKernelMemory!\n";
    KernelAccess::FreeKernelMemory(kernelBase);
    KernelResolver::Cleanup();
    return false;
  }

  // 8. Call DriverEntry
  uint64_t entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
  uint64_t entryPoint = kernelBase + entryPointRva;

  std::cout << "[*] Calling DriverEntry at: 0x" << std::hex << entryPoint
            << std::dec << "\n";

  // Call DriverEntry(NULL, NULL) via kernel execution primitive
  uint64_t driverResult = KernelAccess::CallDriverEntry(entryPoint);

  std::cout << "[+] ============================================\n";
  std::cout << "[+] Driver mapped successfully!\n";
  std::cout << "[+]   Base:       0x" << std::hex << kernelBase << "\n";
  std::cout << "[+]   Entry:      0x" << entryPoint << "\n";
  std::cout << "[+]   Size:       0x" << imageSize << std::dec << "\n";
  std::cout << "[+]   Result:     0x" << std::hex << driverResult << std::dec
            << "\n";
  std::cout << "[+] ============================================\n";

  KernelResolver::Cleanup();
  return true;
}
} // namespace Mapper

// ============================================================================
// Test: Send PING IOCTL to the hijacked Null device
// ============================================================================
bool TestPing() {
  HANDLE hDevice = CreateFileW(L"\\\\.\\NUL", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);

  if (hDevice == INVALID_HANDLE_VALUE) {
    std::cerr << "[!] Failed to open \\\\.\\NUL: " << GetLastError() << "\n";
    return false;
  }

  DWORD bytesReturned = 0;
  BOOL result = DeviceIoControl(hDevice, IOCTL_HIJACK_PING, nullptr, 0, nullptr,
                                0, &bytesReturned, nullptr);

  CloseHandle(hDevice);

  if (result) {
    std::cout << "[+] PING successful! Driver is alive.\n";
    return true;
  } else {
    std::cout << "[-] PING failed. Driver not hijacked yet (error: "
              << GetLastError() << ")\n";
    return false;
  }
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char *argv[]) {
  std::cout << R"(
  _   _ _    _ _     _          _____  ____  
 | \ | | |  | | |   | |        / ____|/ __ \ 
 |  \| | |  | | |   | |       | (___ | |  | |
 | . ` | |  | | |   | |        \___ \| |  | |
 | |\  | |__| | |___| |____    ____) | |__| |
 |_| \_|\____/|_____|______|  |_____/ \____/ 
                   Null.sys Hijack Mapper
    )" << "\n\n";

  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <driver.sys> [--test]\n\n";
    std::cout << "Options:\n";
    std::cout << "  <driver.sys>   Path to the compiled kernel driver (.sys)\n";
    std::cout << "  --test         Send a PING IOCTL to check if hijack is "
                 "active\n\n";
    system("pause");
    return 1;
  }

  std::string arg1 = argv[1];

  // Test mode
  if (arg1 == "--test") {
    TestPing();
    return 0;
  }

  // Initialize kernel access
  std::cout << "[*] Initializing kernel access...\n";
  if (!KernelAccess::Initialize()) {
    std::cerr << "[!] Failed to initialize kernel access.\n";
    system("pause");
    return 1;
  }

  // Map the driver
  std::cout << "[*] Mapping driver: " << arg1 << "\n\n";
  bool success = Mapper::MapDriver(arg1);

  KernelAccess::Cleanup();

  if (!success) {
    std::cerr << "\n[!] Driver mapping failed.\n";
    system("pause");
    return 1;
  }

  // Optionally test
  if (argc >= 3 && std::string(argv[2]) == "--test") {
    std::cout << "\n[*] Testing PING...\n";
    TestPing();
  }

  std::cout << "\n";
  system("pause");
  return 0;
}
