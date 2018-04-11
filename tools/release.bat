REM Run under the "Developer Command Prompt for VS 2017"
REM Usage: release [x86|x64]

REM Change to the root of the KILLERBEEZ hierarchy
pushd %~dp0\..\..

set platform=%1
if "%platform%" == "" (set platform=x64)

msbuild utils\utils.sln /p:configuration=Release /p:platform=%platform% || exit /b
msbuild mutators\mutators.sln /p:configuration=Release /p:platform=%platform% || exit /b
msbuild fuzzer\fuzzer.sln /p:configuration=Release /p:platform=%platform% || exit /b
C:\cygwin64\bin\make -C radamsa || exit /b

set relname=killerbeez-%platform%
set distdir=dist\%relname%
rmdir /s /q %distdir%
mkdir %distdir%

if "%platform%" == "x64" (
	xcopy /s /exclude:fuzzer\tools\release_excludes.txt build\x64\Release\* %distdir%
) else (
	xcopy /s /exclude:fuzzer\tools\release_excludes.txt build\Release\* %distdir%
)

mkdir %distdir%\radamsa
xcopy /s /i radamsa\bin %distdir%\radamsa\bin
xcopy radamsa\LICENCE %distdir%\radamsa
xcopy C:\cygwin64\bin\cygwin1.dll %distdir%\radamsa\bin

mkdir %distdir%\dynamorio
xcopy /s /i dynamorio\bin32 %distdir%\dynamorio\bin32
xcopy /s /i dynamorio\bin64 %distdir%\dynamorio\bin64
xcopy /s /i dynamorio\lib32 %distdir%\dynamorio\lib32
xcopy /s /i dynamorio\lib64 %distdir%\dynamorio\lib64
xcopy /s /i dynamorio\ext %distdir%\dynamorio\ext
xcopy dynamorio\License.txt %distdir%\dynamorio
xcopy dynamorio\ACKNOWLEDGEMENTS %distdir%\dynamorio

del "%relname%.zip"
powershell.exe -nologo -noprofile -command "& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.Zipfile]::CreateFromDirectory('%distdir%', '%relname%.zip', [IO.Compression.CompressionLevel]::Optimal, 1); }"

popd
