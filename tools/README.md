# Build/CI Tools

## Windows
* **setup_build_env.ps1** - script that installs build dependencies on a Windows machine (to set it up as a CI runner)
* **release_vs2017.bat** - script run by CI to build a binary release of Killerbeez for windows on Visual Studio 2017
* **release_vs2019.bat** - script run by CI to build a binary release of Killerbeez for windows on Visual Studio 2019
* **release_excludes.txt** - file used by `release_*.bat` during packaging step
