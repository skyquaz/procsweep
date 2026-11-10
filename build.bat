@echo off
rem Builds build\procsweep.exe and build\selftest.exe (x64) with MSVC.
setlocal
cd /d "%~dp0"

where cl >nul 2>nul && goto build

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto nomsvc
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto nomsvc
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

:build
if not exist build mkdir build
set "CFLAGS=/nologo /std:c++17 /O2 /EHsc /W4 /permissive- /DUNICODE /D_UNICODE /MT"
cl %CFLAGS% src\procsweep.cpp /Fobuild\ /Febuild\procsweep.exe || exit /b 1
cl %CFLAGS% tests\selftest.cpp /Fobuild\ /Febuild\selftest.exe || exit /b 1
echo.
echo Built build\procsweep.exe and build\selftest.exe
exit /b 0

:nomsvc
echo MSVC not found. Install Visual Studio Build Tools with the "Desktop development with C++" workload.
exit /b 1
