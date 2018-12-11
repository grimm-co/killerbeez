# Build/CI Tools

## Windows
* **setup_build_env.ps1** - script that installs build dependencies on a Windows machine (to set it up as a CI runner)
* **update_repos.bat** - script run by CI to ensure associated repos are present and at the right version
* **release.bat** - script run by CI to build a binary release of Killerbeez for windows
* **release_excludes.txt** - file used by release.bat during packaging step

## Linux
Files:
* **Dockerfile** - build environment for killerbeez

Setting up a CI runner:
```
docker build -t killerbeez-builder .
```