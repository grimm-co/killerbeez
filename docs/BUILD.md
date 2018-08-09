# Build Instructions

This document describes the process of compiling Killerbeez on Linux and
Windows.

## Windows

### Prerequisites

To build Killerbeez on Windows you will need Microsoft Visual Studio 2017,
Cygwin, Radamsa, and DynamoRIO. Unless otherwise noted, all of the snippets
below use cmd.exe.

### Installation
1. Install [Visual Studio 2017
Community](https://www.visualstudio.com/downloads/). Version 15.5.7 has
been tested to work with Killerbeez. Anything later should also work.
Earlier versions which support cmake will likely work but have not been
tested and may require slight changes to the build settings.
  + The following workloads/components will be needed to build Killerbeez.
They can be added with the Visual Studio Installer.
      1. Desktop development with C++
      2. Linux development with C++
      3. Visual C++ tools for CMake

2. Install [Cygwin](https://cygwin.com/install.html) (only required for
the radamsa mutator).
  + Use `C:\cygwin64` as the installation directory.
  + Make sure the packages `gcc-core`, `make`, `git`, and `wget` are being
installed.
  + Add the Cygwin `bin/` (e.g. `C:\cygwin64\bin`) to your PATH environment
variable.

3. Create a working directory to store all of the Killerbeez components,
for example `C:\killerbeez`

```
mkdir C:\killerbeez
set WORKDIR=C:/killerbeez
:: We'll use forward slashes for minimal escaping, Windows doesn't care
```

4. Build [Radamsa](https://gitlab.com/akihe/radamsa) (optional).
  + Clone the Radamsa repository into %WORKDIR% from a Cygwin terminal and
build:

        ```
        cd /cydrive/c/killerbeez
        git clone https://gitlab.com/akihe/radamsa.git
        cd radamsa
        make
        ```

5. Install [DynamoRIO](http://dynamorio.org/). Use the [latest build
available](https://console.cloud.google.com/storage/browser/chromium-dynamorio/builds).
A direct link to the latest build as of 3/14/18 can be found
[here](https://storage.googleapis.com/chromium-dynamorio/builds/DynamoRIO-Windows-6.2.17295-0xa77808f.zip).
  + Download the zip file and extract it so that the main directory (the
one containing bin32/ and bin64/ directories) is `%WORKDIR%/dynamorio`
  + *Note:* The reason we have to use the latest build is that [commit
c575ad](https://github.com/DynamoRIO/dynamorio/commit/c575ad16f8943eb6946e8c875eb248d948390537)
is needed to support binaries built with VS 2017 on Windows 10. This commit
is not included in the 7.0.0-RC1 release.

6. Download the Killerbeez source code

    ```
    cd %WORKDIR%
    git clone https://github.com/grimm-co/killerbeez.git
    git clone https://github.com/grimm-co/killerbeez-mutators.git
    git clone https://github.com/grimm-co/killerbeez-utils.git
    ```

7. Build Killerbeez
  + Open the repository `killerbeez` within Visual Studio (File -> Open ->
CMake..) and build it using (CMake -> Build All).  This should build the
fuzzer and its dependencies from the other repos.  If successful, you'll
see an aggregate `build/` directory in the root of your working directory.
In it, the compiled executables and libraries from all three projects will
be found in folders named after the architecture (e.g. x64) and build type
(e.g. Debug).
  + The fuzzer.exe executable can be found at
`%WORKDIR%/build/x64/Debug/killerbeez/fuzzer.exe`

## Linux and Mac

### Prerequisites

To build Killerbeez on Linux/Mac you will need a compiler (gcc or clang), make, and
cmake.

### Installation

Clone the killerbeez, killerbeez-mutators and killerbeez-utils repos.

```
WORKDIR=~/killerbeez
mkdir $WORKDIR
cd $WORKDIR
git clone https://github.com/grimm-co/killerbeez.git
git clone https://github.com/grimm-co/killerbeez-mutators.git
git clone https://github.com/grimm-co/killerbeez-utils.git

# Make a build directory and compile the code.
mkdir build; cd build; cmake ../killerbeez; make
```

If everything compiled, the fuzzer and other Killerbeez
files will be in `build/killerbeez`, and the mutators will be 
under `build/mutators`.

