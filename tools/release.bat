REM Meant to be run by CI from the root directory of one of the repos
REM Usage: cd Killerbeez; tools\release
REM      : cd killerbeez-mutators; ..\Killerbeez\tools\release
REM      : cd killerbeez-utils; ..\Killerbeez\tools\release

if "%RADAMSA_URL%" == "" (
  set RADAMSA_URL=https://gitlab.com/akihe/radamsa.git
)
if "%DYNAMORIO_URL%" == "" (
  set DYNAMORIO_URL=https://storage.googleapis.com/chromium-dynamorio/builds/DynamoRIO-Windows-6.2.17295-0xa77808f.zip
)
if "%CI_PROJECT_DIR%" == "" (
  set CI_PROJECT_DIR=%cd%
)

REM Change to the root of the KILLERBEEZ hierarchy
pushd ..

rmdir /s /q build

if not exist radamsa (
  git clone %RADAMSA_URL% || exit /b 1
) else (
  cd radamsa
  git checkout master || exit /b 1
  git pull || exit /b 1
  cd ..
)

if not exist dynamorio (
  powershell.exe -nologo -noprofile -command "& { Add-Type -A 'System.IO.Compression.FileSystem'; $wc = New-Object System.Net.WebClient; $wc.DownloadFile('%DYNAMORIO_URL%', '.\dynamorio.zip'); [IO.Compression.Zipfile]::ExtractToDirectory('.\dynamorio.zip', '.\dynamorio-unzip'); }"
  move dynamorio-unzip\DynamoRIO* dynamorio
  rmdir dynamorio-unzip
  del dynamorio.zip
)

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86

call :compile Killerbeez || exit /b 1

set oldpath=%path%
set path=C:\cygwin\bin\;%oldpath%
make -C radamsa clean || exit /b 1
make -C radamsa || exit /b 1
set path=%oldpath%

call :package X86

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

call :compile Killerbeez || exit /b 1

set oldpath=%path%
set path=C:\cygwin64\bin\;%oldpath%
make -C radamsa clean || exit /b 1
make -C radamsa || exit /b 1
set path=%oldpath%

call :package x64

popd
exit /b 0

:compile
rmdir /s /q cmaketmp
mkdir cmaketmp
cd cmaketmp
REM Make Ninja build files
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" -G "Ninja" -DCMAKE_CXX_COMPILER="cl.exe"  -DCMAKE_C_COMPILER="cl.exe"  -DCMAKE_BUILD_TYPE="Release" -DCMAKE_MAKE_PROGRAM="C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" "..\%1" || exit /b 1
REM Run Ninja to build
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" || exit /b 1
cd ..
rmdir /s /q cmaketmp
exit /b 0

:package
set platform=%1
set relname=killerbeez-%platform%
set distdir=dist\%relname%
rmdir /s /q %distdir%
mkdir %distdir%

xcopy /s /exclude:%~dp0\release_excludes.txt build\%platform%\Release\* %distdir%
if "%platform%" == "x64" (
  xcopy /s /exclude:%~dp0\release_excludes.txt build\X86\Release\killerbeez\bin32\* %distdir%\killerbeez\bin32\
)
xcopy /s /i killerbeez\docs %distdir%\docs

mkdir %distdir%\radamsa
xcopy /s /i radamsa\bin %distdir%\radamsa\bin
xcopy radamsa\LICENCE %distdir%\radamsa
if "%platform%" == "x64" (
  xcopy C:\cygwin64\bin\cygwin1.dll %distdir%\radamsa\bin
) else (
  xcopy C:\cygwin\bin\cygwin1.dll %distdir%\radamsa\bin
  xcopy C:\cygwin\bin\cyggcc_s-1.dll %distdir%\radamsa\bin
)

mkdir %distdir%\dynamorio
xcopy /s /i dynamorio\bin32 %distdir%\dynamorio\bin32
xcopy /s /i dynamorio\bin64 %distdir%\dynamorio\bin64
xcopy /s /i dynamorio\lib32 %distdir%\dynamorio\lib32
xcopy /s /i dynamorio\lib64 %distdir%\dynamorio\lib64
xcopy /s /i dynamorio\ext %distdir%\dynamorio\ext
xcopy dynamorio\License.txt %distdir%\dynamorio
xcopy dynamorio\ACKNOWLEDGEMENTS %distdir%\dynamorio

if "%platform%" == "x64" (
  mkdir %distdir%\server\skel\windows_x86_64
  REM Include wrapper binary, stored in C:\killerbeez on the runner
  xcopy C:\killerbeez\wrapper_26014_windows_x86_64.exe %distdir%\server\skel\windows_x86_64
  REM Include license files from the BOINC repo
  xcopy killerbeez\server\boinc\COPYING %distdir%\server\skel\windows_x86_64
  xcopy killerbeez\server\boinc\COPYING.LESSER %distdir%\server\skel\windows_x86_64
  xcopy killerbeez\server\boinc\README.md %distdir%\server\skel\windows_x86_64
)

set releasezip=%CI_PROJECT_DIR%\release\%relname%.zip
echo Creating %releasezip%
mkdir "%CI_PROJECT_DIR%\release"
del "%releasezip%"
powershell.exe -nologo -noprofile -command "& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.Zipfile]::CreateFromDirectory('%distdir%', '%releasezip%', [IO.Compression.CompressionLevel]::Optimal, 1); }"

exit /b 0
