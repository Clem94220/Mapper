cmake_minimum_required(VERSION 3.20)
project(NullMapper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# User-mode Mapper executable
# ============================================================================
add_executable(mapper
    Mapper/mapper.cpp
)

target_include_directories(mapper PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# Link ntdll for NtQuerySystemInformation
target_link_libraries(mapper PRIVATE ntdll)

# Require admin privileges (SE_DEBUG_NAME)
if(MSVC)
    set_target_properties(mapper PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

# ============================================================================
# NOTE: The kernel driver (Driver/) must be compiled separately using
# the Windows Driver Kit (WDK) or a kernel-mode build environment.
# 
# A simple way to compile the driver:
#   cl.exe /kernel /GS- /Oi /W4 /D_AMD64_ /DAMD64 
#          /I"C:\Program Files (x86)\Windows Kits\10\Include\<version>\km"
#          Driver/main.c 
#          /link /SUBSYSTEM:NATIVE /DRIVER 
#          /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\<version>\km\x64"
#          ntoskrnl.lib /OUT:hijack.sys /ENTRY:DriverEntry
# ============================================================================
