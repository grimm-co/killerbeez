# Killerbeez

Killerbeez is a modular fuzzing framework that aims to bring awesome tools
together into a standard format. 

## Table of Contents
* [Motivation](#motivation)
* [Getting Started](#getting-started)
 * [Windows](#windows)
 * [Linux and Mac](#linux-and-mac)
* [Documentation](#documentation)
* [Troubleshooting](#troubleshooting)

## Motivation

Many fuzzing tools are "research-quality" code, which means they're difficult to
incorporate with each other or make changes to short of forking.  Killerbeez
seeks to reduce the engineering effort required to bring these tools together.
By writing things to a common API, we hope to encourage clean interfaces, which
should discourage spaghetti code and make writing cross-platform tools easier.

## Getting Started

We provide build instructions for Windows and Linux, and binaries for Windows.
For instructions building Killerbeez from source, see the [BUILD
instructions](docs/BUILD.md). Currently only the standalone client is available,
server coming soon!

### Windows

#### [Binary Releases](https://github.com/grimm-co/killerbeez/releases)
If you don't want to build the project from source, you can try the [binary
releases](https://github.com/grimm-co/killerbeez/releases) (though be
warned they are likely out of date).  They have been tested on the
following operating systems.

| Windows Version|    64-Bit        |    32-Bit        | 
| -------------- | ------------     | ---------------  |
| Windows 7      | Not Working [1]  | Not Working [1]  |
| Windows 8      | Working          | Experimental [2] |
| Windows 8.1    | Working          | Experimental [2] |
| Windows 10     | Experimental [2] | Experimental [2] |

You will also need to install the 2017 Microsoft Visual C++
Redistributable. Please note that if you are running Killerbeez on a 64-bit
host, you will need to install both the 64-bit and the 32-bit versions of
the redistributable.
- [64-Bit Redistributable Download](https://aka.ms/vs/15/release/vc_redist.x64.exe)
- [32-Bit Redistributable Download](https://aka.ms/vs/15/release/vc_redist.x86.exe)

[1] This is due to a compatibility problem with Windows 7 and DynamoRIO see
[this issue](https://github.com/DynamoRIO/dynamorio/issues/2658) for more
info.  
[2] Experimental status means that most of the features are working as
expected, and a few are not. 

#### Quickstart and Examples

##### Fuzzing a simple test program:
```
REM Paste this into cmd.exe.
REM Assuming you: set WORKDIR=C:/killerbeez
REM Note: if using backslashes, they need to be escaped to be proper JSON.

cd %WORKDIR%/build/x64/Debug/killerbeez
fuzzer.exe file debug bit_flip -n 9 ^
	-sf "%WORKDIR%/killerbeez/corpus/test/inputs/close.txt" ^
	-d "{\"path\":\"%WORKDIR%/killerbeez/corpus/test/test.exe\",\"arguments\":\"@@\"}"
```

Successful output should look like
```
Wed Aug  8 18:27:08 2018 - INFO     - Logging Started
Wed Aug  8 18:27:09 2018 - CRITICAL - Found crashes
Wed Aug  8 18:27:09 2018 - INFO     - Ran 9 iterations in 1 seconds
```

##### Fuzzing Windows Media Player
Download a small video file you would like to use as a seed file (e.g.
`youtube-dl --format mp4 --output test.mp4 your-favorite-video`).
Be sure to replace the seed file argument `-sf` with the path to the video file
you just downloaded. 

Note that because `wmplayer.exe` is a 32-bit executable you'll either need
to use the 32-bit `fuzzer.exe`, or manually specify the path to the 32-bit
`winafl.dll` with the instrumentation's `winafl_dir` option. Additionally,
the `-target_offset` argument that is passed to the instrumentation will
need to be updated depending on your Windows version. In this case we are
just using the entry point of `wmplayer.exe`, below there is a table to use
as reference but it is best to verify the entry point of your binary.

|   WMP Version   | Offset |
| --------------- | ------ |
| 12.0.7601       | 0x176D |
| 12.0.9200       | 0x1BAD |
| 12.0.9600       | 0x1F00 |
| 12.0.17134      | 0x1F20 |

```
fuzzer.exe wmp dynamorio nop -n 3 -sf "C:\Users\<user>\Desktop\test.mp4" -d "{\"timeout\":20}" -i "{\"timeout\":5000,\"coverage_modules\":[\"wmp.DLL\"],\"target_path\":\"C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe\"}"
```
You may need to modify these parameters to match your environment.  In
order to speed up fuzzing, it may be useful to enable persistence mode.
See [PersistenceMode.md](docs/PersistenceMode.md) for instructions.

### Linux and Mac

Once you've built Killerbeez following the [BUILD
instructions](docs/BUILD.md#linux-and-mac), you should be ready to change
into the right directory and run the fuzzer.  Here's an example of running
it on a test program from our corpus.

```
# assuming that you're in $WORKDIR/build/killerbeez
cd ../build/killerbeez/
./fuzzer file return_code honggfuzz -n 20 -sf /bin/bash -d '{"path":"corpus/test-linux","arguments":"@@"}'
```

If it ran correctly, you should see something like this:
```
Thu Jul 19 09:40:46 2018 - INFO     - Logging Started
Thu Jul 19 09:40:46 2018 - INFO     - Ran 20 iterations in 0 seconds
```

In the example above, we're using the **file** driver, the **return\_code**
instrumentation, and the **honggfuzz** mutator module.  We are only going to do 20
executions and our seed file is /bin/bash, because why not?

The -d option are for the driver.  We need to give it the path to our executable
and the command line arguments, which in our case is just the filename,
represented by "@@" here.

We don't need to specify any options for the mutator or the instrumentation, so
we'll rely on default values instead.  To see the options available, you can use
the `-h` help flag. Some examples:

```
./fuzzer -h
./fuzzer -h driver
```

Looking at the results in the "output" directory, we see that it didn't find
any crashes, hangs or new paths.  At first glance, it might seem like it didn't
work.  However, we were using the return\_code instrumentation, which does not
actually track code coverage, so it can not determine the execution path, thus
it can't determine if a new path was hit.  Instead, it just looks at the return
code to determine if the process crashed or not.  It's very efficient, however
this is effectively dumb fuzzing.  In order to track coverage on Linux,
Killerbeez has support for Intel Processor Trace.  See [IPT.md](docs/IPT.md) for
more details.

To see a crash, we can just change our seed file to be close to the file which
will cause a crash.  It's cheating, but it works well to demonstrate the
importance of seed files as well as illustrating what the output of finding a
crash looks like.  The following commands assume you are still in the directory
containing ./fuzzer.

```
# assuming that you're in $WORKDIR/build/killerbeez
echo "ABC@" > test1  # ABC@ is one bit different than ABCD, the crashing input
./fuzzer file return_code honggfuzz -n 2000 -sf ./test1 -d '{"path":"corpus/test-linux","arguments":"@@"}'
```

Which should yield output similar to this:

```
Thu Jul 19 12:03:11 2018 - INFO     - Logging Started
Thu Jul 19 12:03:13 2018 - CRITICAL - Found crashes
Thu Jul 19 12:03:13 2018 - CRITICAL - Found crashes
Thu Jul 19 12:03:19 2018 - CRITICAL - Found crashes
Thu Jul 19 12:03:22 2018 - CRITICAL - Found crashes
Thu Jul 19 12:03:22 2018 - INFO     - Ran 2000 iterations in 11 seconds
```

Looking in the output/crashes folder, we can see the inputs which were found to
crash this target and reproduce the crash manually.

```
$ ls output/crashes/
2B81D0C867F76051FD33D8690AA2AC68  5220E572A6F9DAAF522EF5C5698EAF4C  59F885D0289BE9A83E711C5E7CFCBE4D  ED5D34C74E59D16BD6D5B3683DB655C3
$ cat output/crashes/59F885D0289BE9A83E711C5E7CFCBE4D ; echo
ABCD
$ corpus/test-linux output/crashes/59F885D0289BE9A83E711C5E7CFCBE4D
Segmentation fault (core dumped)
```

## Documentation
Documentation of the API can be found in the [docs](docs) folder.  It's written in
LaTeX which can be used to generate a PDF, HTML, or various other formats.
PDFs are also included so the documentation is easy to read for those who
do not have a LaTeX typesetting environment set up.

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

Feel free to join the mailing list! Send a request to join to
`killerbeez-join@lists.grimm-co.com` then post your questions to
`killerbeez@lists.grimm-co.com`! We've also got #killerbeez on freenode,
but it's pretty quiet.

## License

This project is licensed under the UIUC License - see the
[LICENSE](LICENSE) file for details.  Some parts of this project have been
included from other software and will be under different licenses, where
marked.
