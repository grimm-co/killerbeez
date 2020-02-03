param($version, $bitness, $vs_version)
Set-PSDebug -Trace 1

$name = "kb-windows-$version-$bitness-vs$vs_version"
pushd C:\Gitlab-Runner

# Quit if already registered
if (& C:\Gitlab-Runner\gitlab-runner-windows-amd64.exe list | Select-String -Quiet $name) {
    exit 0
}

foreach($line in (Get-Content /killerbeez/runner_vars)) {
  $key, $val = $line.Split("=")
  New-Item -Name $key -Value $val -ItemType Variable -Path Env: -Force
}

$env:RUNNER_EXECUTOR = "shell"
$env:RUNNER_SHELL = "cmd"  # Workaround for https://gitlab.com/gitlab-org/gitlab-runner/issues/4814
$env:RUNNER_NAME = $name
$env:RUNNER_TAG_LIST = "windows,windows-$version,$bitness,vs$vs_version"

& C:\Gitlab-Runner\gitlab-runner-windows-amd64.exe register
& C:\Gitlab-Runner\gitlab-runner-windows-amd64.exe install
& C:\Gitlab-Runner\gitlab-runner-windows-amd64.exe start

popd
