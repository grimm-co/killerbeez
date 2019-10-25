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
      4. Git for Windows

2. Install [Cygwin](https://cygwin.com/install.html) (only required for
the radamsa mutator).
  + Use `C:\cygwin64` as the installation directory.
  + Make sure the packages `gcc-core`, `make`, `git`, and `wget` are being
installed.
  + Add the Cygwin `bin/` (e.g. `C:\cygwin64\bin`) to your PATH environment
variable.

3. Download the Killerbeez source code

    ```
    set WORKDIR=C:/
    :: We'll use forward slashes (Windows doesn't care) to avoid escaping backslashes
    cd %WORKDIR%
    git clone https://github.com/grimm-co/killerbeez.git
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
one containing bin32/ and bin64/ directories) is `%WORKDIR%/killerbeez/dynamorio`
  + *Note:* The reason we have to use the latest build is that [commit
c575ad](https://github.com/DynamoRIO/dynamorio/commit/c575ad16f8943eb6946e8c875eb248d948390537)
is needed to support binaries built with VS 2017 on Windows 10. This commit
is not included in the 7.0.0-RC1 release.

6. Build Killerbeez
  + Open the repository `killerbeez` within Visual Studio (File -> Open ->
CMake..) and build it using (CMake -> Build All).  This should build the
fuzzer and its dependencies from the other repos.  If successful, you'll
see an aggregate `build/` directory in the root of your working directory.
In it, the compiled executables and libraries from all three projects will
be found in folders named after the architecture (e.g. x64) and build type
(e.g. Debug).
  + The fuzzer.exe executable can be found at
`%WORKDIR%/killerbeez/build/x64/Debug/killerbeez/fuzzer.exe`

## Linux and Mac

### Prerequisites

To build Killerbeez on Linux/Mac you will need a compiler (gcc or clang), make,
and cmake.  To build the AFL instrumentation with gcc, clang, and qemu, there
are a few extra packages needed.  The dependency lists below will make sure
you can compile everything to get all the cool features.

macOS (brew)
```
brew install autoconf automake libtool gcc cmake pkg-config
```

Debian 9 (stretch) / Ubuntu 18.04 (bionic) / Ubuntu 16.04 (xenial):
```
sudo apt install llvm clang libtool-bin build-essential cmake automake bison flex libglib2.0-dev libc6-dev-i386 libpixman-1-dev
```

Ubuntu 14.04 (trusty)
```
sudo apt install llvm clang libtool build-essential cmake automake bison flex libglib2.0-dev libc6-dev-i386 git
```

Fedora (tested on 29 and 30):
```
sudo dnf install llvm clang llvm-devel libtool libstdc++-static cmake bison flex glib2-devel glibc-devel.i686 zlib-devel
```

Notes:
Ubuntu 12.04 (precise) doesn't have a recent enough version of CMake (it
has 2.8.7, but 2.8.8 needed) in the repositories.  It should work if you compile
CMake 2.8.8 or later yourself, but it is not a tested distribution.

Debian 8 (jessie) fails to build/install due to what looks like a bug in
CMake, though we did not take the time to figure out the specific error.

Debian 10 (buster) and Ubuntu 18.04 both have versions of clang which do not
currently work with the version of the llvm instrumentation from AFL.  This
will be fixed when we replace the standard AFL programs with the ones from
AFL++.

On macOS (at least on 10.13.4 (High Sierra)), Apple has reportedly removed the
ability to load dylibs using relative paths.[1]  There are reports that SIP
needs to be disabled[2] to fix this, however setting DYLD_LIBRARY_PATH to
point to the location of the .dylib files (usually $REPOROOT/build/killerbeez)
was sufficient in our tests.  For now, just set this environment variable if
there are errors about RPATH or loading .dylibs.  In the long run, we'll be
investigating what other projects have done[3] to work around this issue.

[1] https://github.com/tensorflow/tensorflow/issues/6729#issuecomment-272583349
[2] https://github.com/BVLC/caffe/issues/3227
[3] https://github.com/alexgkendall/caffe-segnet/pull/68/commits/f282c0f784e95460d55e18d68933f2ef66bd3b47

### Installation

Clone the killerbeez repo

```
# the --recursive is needed to check out submodules
git clone --recursive https://github.com/grimm-co/killerbeez.git
cd killerbeez

# Make a build directory and compile the code.
mkdir build; cd build; cmake ..; make radamsa all
# radamsa isn't in "all" by default because of Windows
```

If everything compiled, the fuzzer and other Killerbeez
files will be in `build/killerbeez`, and the mutators will be 
under `build/mutators`.

