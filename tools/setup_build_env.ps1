param($build_env = $PSScriptRoot, $cygwin_mirror = "http://mirrors.kernel.org/sourceware/cygwin/", $vs_version = "2019")
Set-PSDebug -Trace 1
pushd $build_env

$ErrorActionPreference = "Stop"
Add-Type -A 'System.IO.Compression.FileSystem'

if ($env:DNS_SERVER) {
  netsh interface ip set dns Ethernet static $env:DNS_SERVER
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient

if (!(Test-Path "C:\Gitlab-Runner\gitlab-runner-windows-amd64.exe")) {
  mkdir -Force C:\Gitlab-Runner
  $url = "https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-windows-amd64.exe"
  $wc.DownloadFile($url, "C:\Gitlab-Runner\gitlab-runner-windows-amd64.exe")
}

# Install cygwin 32 and 64 bit
mkdir -Force installers
$url = "https://cygwin.com/setup-x86_64.exe"
$wc.DownloadFile($url, "$build_env\installers\cygwin-x86_64.exe")
$ret = Start-Process "installers\cygwin-x86_64.exe" -ArgumentList "--arch","x86_64","--packages","gcc-core,make,wget","--upgrade-also","--root","C:\cygwin64","--site","$cygwin_mirror","--quiet-mode" -Wait -PassThru -RedirectStandardOutput "$build_env\cygwin-x86_64-stdout" -RedirectStandardError "$build_env\cygwin-x86_64-stderr"
if ($ret.ExitCode) {
  throw "Cygwin 64-bit install failed"
}
$ret = Start-Process "installers\cygwin-x86_64.exe" -ArgumentList "--arch","x86","--packages","gcc-core,make,wget","--upgrade-also","--root","C:\cygwin","--site","$cygwin_mirror","--quiet-mode" -Wait -PassThru -RedirectStandardOutput "$build_env\cygwin-x86-stdout" -RedirectStandardError "$build_env\cygwin-x86-stderr"
if ($ret.ExitCode) {
  throw "Cygwin 32-bit install failed"
}

# Install Visual Studio
echo "Beginning Visual Studio install"
if ($vs_version -eq "2017") {
    $url = "https://aka.ms/vs/15/release/vs_community.exe"
    $vs_exe = "$build_env\installers\vs_community.exe"
    $example_file = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat"
    $extra_args = @()
} else {
    $url = "https://aka.ms/vs/16/release/vs_community.exe"
    $vs_exe = "$build_env\installers\vs_community.exe"
    $example_file = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    $extra_args = "--add","Microsoft.VisualStudio.Component.Windows10SDK.18362"
}
$wc.DownloadFile($url, $vs_exe)
if (Test-Path $example_file) {
  $ret = Start-Process $vs_exe -ArgumentList "update","--passive" -Wait -PassThru
} else {
  $ret = Start-Process $vs_exe -ArgumentList ("--add","Microsoft.VisualStudio.Component.VC.Tools.x86.x64","--add","Microsoft.VisualStudio.Component.VC.CMake.Project","--add","Microsoft.VisualStudio.Component.Git","--passive","--norestart" + $extra_args) -Wait -PassThru
}

if ($ret.ExitCode) {
  throw "Visual Studio install failed"
}
echo "Visual Studio install complete"

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

popd
