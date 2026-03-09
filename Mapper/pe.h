#pragma once

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>


// ============================================================================
// Portable Executable structures & helpers for manual mapping
// ============================================================================

namespace PE {
// Load a raw .sys file into memory
inline std::vector<uint8_t> ReadFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    return {};

  auto size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(static_cast<size_t>(size));
  file.read(reinterpret_cast<char *>(buffer.data()), size);
  return buffer;
}

// Get the NT Headers from a PE buffer
inline PIMAGE_NT_HEADERS GetNtHeaders(uint8_t *base) {
  auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return nullptr;

  auto ntHeaders =
      reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    return nullptr;

  return ntHeaders;
}

// Get the first section header
inline PIMAGE_SECTION_HEADER GetSections(PIMAGE_NT_HEADERS nt) {
  return IMAGE_FIRST_SECTION(nt);
}
} // namespace PE
