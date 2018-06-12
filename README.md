# Killerbeez
Killerbeez is a fuzzing framework which aims to bring together as many of the awesome tools out there as possible into a standard format.  The goal is not just to get them to work with this project, but ideally each other as well, which can be accomplished by writing things to a common API.  As a side effect, it means writing cross-platform tools should be easier as well on account of encouraging clean interfaces which inherently discourages spaghetti code.

## Getting Started

These instructions will get you a copy of Killerbeez up and running on your local machine. Currently only the standalone client is available, server coming soon!

### Standalone Client - Windows

#### Prerequisites

To build Killerbeez on Windows you will need Microsoft Visual Studio 2017, Cygwin, Radamsa, and DynamoRIO. See below for more detailed installation instructions.

#### Installation
1. Install [Visual Studio 2017 Community](https://www.visualstudio.com/downloads/). Version 15.5.7 has been tested to work with Killerbeez. Anything later should also work. Earlier versions which support cmake will likely work but have not been tested and may require slight changes to the build settings.
  + The following workloads/components will be needed to build Killerbeez. They can be added with the Visual Studio Installer.
      1. Desktop development with C++
      2. Linux development with C++
      3. Visual C++ tools for CMake

2. Install [Cygwin](https://cygwin.com/install.html).
  + Use `C:\cygwin64` as the installation directory.
  + Make sure the packages `gcc-core`, `make`, `git`, and `wget` are being installed.
  + Add the Cygwin `bin/` (e.g. `C:\cygwin64\bin`) to your PATH environment variable.
  
3. Create a working directory to store all of the Killerbeez components, for example `WORKDIR=C:\killerbeez`

4. Build [Radamsa](https://github.com/aoh/radamsa).
  + Clone the Radamsa repository into %WORKDIR% from a Cygwin terminal and build: 
 
        ```
        cd /cydrive/c/killerbeez
        git clone https://github.com/aoh/radamsa.git
        cd radamsa
        make
        ```

5. Install [DynamoRIO](http://dynamorio.org/). Use the [latest build available](https://console.cloud.google.com/storage/browser/chromium-dynamorio/builds). A direct link to the latest build as of 3/14/18 can be found [here](https://storage.googleapis.com/chromium-dynamorio/builds/DynamoRIO-Windows-6.2.17295-0xa77808f.zip).
  + Download the zip file and extract it so that the main directory (the one containing bin32/ and bin64/ directories) is `%WORKDIR%\dynamorio`
  + *Note:* The reason we have to use the latest build is that [commit c575ad](https://github.com/DynamoRIO/dynamorio/commit/c575ad16f8943eb6946e8c875eb248d948390537) is needed to support binaries built with VS 2017 on Windows 10. This commit is not included in the 7.0.0-RC1 release.

6. Download the Killerbeez source code  

    ```
    cd %WORKDIR%
    git clone https://github.com/grimm-co/Killerbeez.git
    git clone https://github.com/grimm-co/killerbeez-mutators.git
    git clone https://github.com/grimm-co/killerbeez-utils.git
    ```

7. Build Killerbeez
  + In order to build the fuzzer, you will first need to build the dependencies. Open the repositories `killerbeez-utils` and `killerbeez-mutators`  within Visual Studio (File -> Open -> CMake..) and build using (CMake -> Build All). Once they are built, you can build the `Killerbeez` project in the same way. Ensure that all of the projects are using the same build profile (Windows vs Linux, debug vs release, x86 vs x64).  If successful, you'll see an aggregate `build/` directory in the root of your working directory.  In it, the compiled executables and libraries from all three projects will be found in folders named after the architecture (x64) and build type (i.e. Debug). 
  + The fuzzer.exe executable can be found at `%WORKDIR%\build\x64\Debug\killerbeez\fuzzer.exe`

#### Binary Release
If you don't want to build the project from source, give the binary release a try. The latest release can be found [here](https://github.com/grimm-co/Killerbeez/releases) and has been tested with the following operating systems:

| Windows Version|    64-Bit        |    32-Bit        | 
| -------------- | ------------     | ---------------  |
| Windows 7      | Not Working [1]  | Not Working [1]  |
| Windows 8      | Working          | Experimental [2] |
| Windows 8.1    | Working          | Experimental [2] |
| Windows 10     | Experimental [2] | Experimental [2] |

You will also need to install the 2017 Microsoft Visual C++ Redistributable. Please note that if you are running Killerbeez on a 64-bit host, you will need to install both the 64-bit and the 32-bit versions of the redistributable.
- [64-Bit Redistributable Download](https://aka.ms/vs/15/release/vc_redist.x64.exe)
- [32-Bit Redistributable Download](https://aka.ms/vs/15/release/vc_redist.x86.exe)

[1] This is due to a compatibility problem with Windows 7 and DynamoRIO see [this issue](https://github.com/DynamoRIO/dynamorio/issues/2658) for more info.  
[2] Experimental status means that most of the features are working as expected, and a few are not. 
#### Quickstart and Examples

Let's start by fuzzing a test program first, to keep things simple.
```
fuzzer.exe file dynamorio radamsa -n 20 -sf "%WORKDIR%\Killerbeez\corpus\test\inputs\input.txt" -d "{\"timeout\":20,\"path\":\"%WORKDIR%\\Killerbeez\\corpus\\test\\test.exe\",\"arguments\":\"@@\"}" -i "{\"coverage_modules\":[\"test.exe\"],\"timeout\":2000,\"target_path\":\"%WORKDIR%\\Killerbeez\\corpus\\test\\test.exe\"}"
```

For the next example, download a small video file you would like to use as a seed file and you can quickly fuzz Windows Media Player with the below example command.  Be sure to replace the seed file argument `-sf` with the path to the video file you just downloaded.  Note that because `wmplayer.exe` is a 32-bit executable you'll either need to use the 32-bit fuzzer.exe, or manually specify the path to the 32-bit `winafl.dll` with the instrumentation's `winafl_dir` option. Additionally, the `-target_offset` argument that is passed to the instrumentation will need to be updated depending on your Windows version. In this case we are just using the entry point of wmplayer.exe, below there is a table to use as reference but it is best to verify the entry point of your binary.

|   WMP Version   | Offset |
| --------------- | ------ |
| 12.0.7601       | 0x176D |
| 12.0.9200       | 0x1BAD |
| 12.0.9600       | 0x1F00 |
| 12.0.17134      | 0x1F20 |

```
fuzzer.exe wmp dynamorio nop -n 3 -sf "C:\Users\<user>\Desktop\test.mp4" -d "{\"timeout\":20}" -i "{\"timeout\":5000,\"coverage_modules\":[\"wmp.DLL\"],\"target_path\":\"C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe\"}"
```
You may need to modify these parameters to match your environment.  In order to speed up fuzzing, it may be useful to enable persistence mode.  See PersistenceMode.md for instructions.

## Documentation
Documentation can be found in the docs folder.  It's written in LaTeX which
can be used to generate a PDF, HTML, or various other formats.  PDFs are also
included so the documentation is easy to read for those who do not have a LaTeX
typesetting environment set up.

## Troubleshooting
Q: The target program doesn't start   
A: Windows Media Player won't automatically play media the first time is run.
   There's a pop-up which requires you to configure some settings.  Just run it
   manually once and you should be good to go after that.

Q: I'm getting an error about a pipe timing out  
A: This is related to the instrumentation and the target taking too long to
   start up.  If running it again doesn't work, try increasing the "timeout" on
   the -i argument and that should take care of it.

## Still Having a Problem?

Please create an issue on GitHub and we will address it as soon as possible.

## Have questions? Wanna chat?

Feel free to join the mailing list! Send a request to join to `killerbeez-join@lists.grimm-co.com` then post your questions to `killerbeez@lists.grimm-co.com`!

## License

This project is licensed under the UIUC License - see the [LICENSE](LICENSE) file for details.  Some parts of this project have been included from other software and will be under different licenses, where marked.
