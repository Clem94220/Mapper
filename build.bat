@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: Null.sys Hijack Mapper - Build Script
:: ============================================================================

set PROJECT_ROOT=%~dp0
set BUILD_DIR=%PROJECT_ROOT%build
set BIN_DIR=%PROJECT_ROOT%bin

echo [*] Initializing build environment...

:: 1. Try to find Visual Studio
if not defined DevEnvDir (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set VS_PATH=%%i
    )
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" (
        call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo [!] Error: Could not find Visual Studio 64-bit build tools.
        exit /b 1
    )
)

:: 2. Build User-mode Mapper
echo.
echo [*] Building Mapper (User-mode)...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

cmake .. -A x64
if %errorlevel% neq 0 (
    echo [!] CMake configuration failed.
    exit /b 1
)

cmake --build . --config Release
if %errorlevel% neq 0 (
    echo [!] Mapper build failed.
    exit /b 1
)

if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
copy /y Release\mapper.exe "%BIN_DIR%\" >nul
echo [+] Mapper built: %BIN_DIR%\mapper.exe

:: 3. Build Kernel Driver
echo.
echo [*] Building Driver (Kernel-mode)...
echo [!] Note: Requires Windows Driver Kit (WDK) to be installed.

:: Attempt to find WDK path
set WDK_PATH_FOUND=0
set "WDK_BASE=%ProgramFiles(x86)%\Windows Kits\10\Include"
for /f "usebackq tokens=*" %%i in (`dir /b "%WDK_BASE%" 2^>nul`) do (
    set WDK_VER=%%i
    if exist "%WDK_BASE%\!WDK_VER!\km" (
        set "WDK_INC=%WDK_BASE%\!WDK_VER!\km"
        set "WDK_LIB=%ProgramFiles(x86)%\Windows Kits\10\Lib\!WDK_VER!\km\x64"
        set "WDK_SHARED=%WDK_BASE%\!WDK_VER!\shared"
        set WDK_PATH_FOUND=1
        :: We take the first one found
        goto :WDK_FOUND
    )
)

:WDK_FOUND
if "%WDK_PATH_FOUND%"=="1" (
    echo [+] Found WDK version: !WDK_VER!
    
    cd /d "%PROJECT_ROOT%"
    cl.exe /nologo /kernel /GS- /Oi /W4 /D_AMD64_ /DAMD64 /Fo"%BUILD_DIR%\\" ^
        /I"!WDK_INC!" ^
        /I"!WDK_SHARED!" ^
        Driver\main.c ^
        /link /nologo /SUBSYSTEM:NATIVE /DRIVER /OPT:REF /OPT:ICF ^
        /LIBPATH:"!WDK_LIB!" ^
        ntoskrnl.lib /OUT:"%BIN_DIR%\hijack.sys" /ENTRY:DriverEntry
    
    if %errorlevel% equ 0 (
        echo [+] Driver built: %BIN_DIR%\hijack.sys
    ) else (
        echo [!] Driver build failed. Check if WDK is installed correctly.
    )
) else (
    echo [!] Error: Could not find Windows Driver Kit ^(WDK^) inclusion paths.
    echo     Please compile the driver manually using the instructions in README.md.
)

:: 4. Testing Options
echo.
echo ============================================================================
echo DONE. Binaries are in: %BIN_DIR%
echo ============================================================================
echo.
echo To map the driver, run:
echo   bin\mapper.exe bin\hijack.sys
echo.
echo To test the hijack (ping), run:
echo   bin\mapper.exe --test
echo.
set /p CHOICE="Would you like to run the ping test now? (y/n): "
if /i "%CHOICE%"=="y" (
    "%BIN_DIR%\mapper.exe" --test
)

pause
exit /b 0
