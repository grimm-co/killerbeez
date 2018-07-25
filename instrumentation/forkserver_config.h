#pragma once
//This header file controls the function that the forkserver hooks in order to
//startup in the target process.  By modifying these marcos, the forkserver can
//be made to start much later in the target process, allowing for reduced
//startup code of each new process.

//Whether we should hook __libc_start_main or not.  This is a default option
//that should work for most Linux programs.
#define USE_LIBC_START_MAIN 1

//If we're not hooking __libc_start_main, this defines the function to hook
#define CUSTOM_FUNCTION_NAME custom_function_to_hook

//If we're not hooking __libc_start_main, this defines whether we should start
//the forkserver before (1) or after (0) the function that we are hooking
#define RUN_BEFORE_CUSTOM_FUNCTION 0
